//! Linux host one-shot boot. Facts are read-only and available in every build; the backend that
//! runs `efibootmgr` exists only with `real-linux-boot` (or in tests, with a scripted runner).
//!
//! Mechanism, as proven in the disposable one-shot matrix: `efibootmgr --create-only` adds an
//! entry outside `BootOrder`, `--bootnext` selects it once, and cleanup deletes it.

#[cfg(any(target_os = "linux", feature = "real-linux-boot", test))]
use std::path::Path;
use std::path::PathBuf;

#[cfg(target_os = "linux")]
use nousb_core::{CommandRunner, FirmwareMode, HostBootFacts, NoUsbError, SecureBootState};
#[cfg(not(target_os = "linux"))]
#[allow(unused_imports)]
use nousb_core::{CommandRunner, HostBootFacts, NoUsbError};

/// One `findmnt -no TARGET,SOURCE,FSTYPE,FSROOT` row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountRow {
    pub target: String,
    pub source: String,
    pub fstype: String,
    pub fsroot: String,
}

pub fn parse_findmnt_row(text: &str) -> Option<MountRow> {
    let mut parts = text.split_whitespace();
    Some(MountRow {
        target: parts.next()?.into(),
        source: parts.next()?.into(),
        fstype: parts.next()?.into(),
        fsroot: parts.next().unwrap_or("/").into(),
    })
}

/// GRUB sees paths relative to the filesystem, so a btrfs subvolume (`[/root]` style FSROOT)
/// becomes the prefix. A bracketed source such as `/dev/sda2[/root]` is normalized too.
pub fn grub_prefix(row: &MountRow) -> String {
    let fsroot = row.fsroot.trim();
    if fsroot.is_empty() || fsroot == "/" {
        "/".into()
    } else {
        format!("/{}", fsroot.trim_matches('/'))
    }
}

pub fn source_device(row: &MountRow) -> String {
    row.source
        .split('[')
        .next()
        .unwrap_or(&row.source)
        .to_string()
}

/// `efibootmgr` listing: `BootOrder`, `BootNext`, and `Boot####` labels.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EfiBootListing {
    pub boot_order: Vec<String>,
    pub boot_next: Option<String>,
    pub entries: Vec<(String, String)>,
}

pub fn parse_efibootmgr(text: &str) -> EfiBootListing {
    let mut listing = EfiBootListing::default();
    for line in text.lines() {
        let line = line.trim();
        if let Some(order) = line.strip_prefix("BootOrder:") {
            listing.boot_order = order
                .split(',')
                .map(|id| id.trim().to_ascii_uppercase())
                .filter(|id| !id.is_empty())
                .collect();
        } else if let Some(next) = line.strip_prefix("BootNext:") {
            listing.boot_next = Some(next.trim().to_ascii_uppercase());
        } else if let Some(rest) = line.strip_prefix("Boot") {
            let id: String = rest.chars().take(4).collect();
            if id.len() == 4 && id.chars().all(|value| value.is_ascii_hexdigit()) {
                let label = rest[4..]
                    .trim_start_matches('*')
                    .trim()
                    .split('\t')
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                listing.entries.push((id.to_ascii_uppercase(), label));
            }
        }
    }
    listing
}

pub fn parse_df_available_bytes(text: &str) -> Option<u64> {
    text.lines().last()?.split_whitespace().nth(3)?.parse().ok()
}

/// Read-only facts for a staging root that must be a mount point (for example `/`).
#[cfg(target_os = "linux")]
pub fn linux_host_boot_facts(
    runner: &mut dyn CommandRunner,
    staging_root: &Path,
) -> Result<HostBootFacts, NoUsbError> {
    use std::fs;
    let root = staging_root.to_string_lossy().into_owned();
    let elevated = fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status.lines().find_map(|line| {
                line.strip_prefix("Uid:")?
                    .split_whitespace()
                    .nth(1)
                    .map(|uid| uid == "0")
            })
        })
        .unwrap_or(false);
    let firmware = if Path::new("/sys/firmware/efi").exists() {
        FirmwareMode::Uefi
    } else {
        FirmwareMode::Bios
    };
    let secure_boot = fs::read_dir("/sys/firmware/efi/efivars")
        .ok()
        .and_then(|entries| {
            entries.flatten().find_map(|entry| {
                if !entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("SecureBoot-")
                {
                    return None;
                }
                match fs::read(entry.path()).ok()?.get(4) {
                    Some(1) => Some(SecureBootState::Enabled),
                    Some(0) => Some(SecureBootState::Disabled),
                    _ => None,
                }
            })
        })
        .unwrap_or(SecureBootState::Unknown);
    let memory_total_mb = fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|meminfo| {
            meminfo.lines().find_map(|line| {
                let kib = line.strip_prefix("MemTotal:")?.split_whitespace().next()?;
                kib.parse::<u64>().ok().map(|kib| kib / 1024)
            })
        });
    let row = runner
        .run_checked(
            "findmnt",
            &["-no", "TARGET,SOURCE,FSTYPE,FSROOT", "--target", &root],
        )
        .ok()
        .and_then(|text| parse_findmnt_row(text.lines().next().unwrap_or_default()));
    let Some(row) = row else {
        return Err(NoUsbError::InvalidInput(format!(
            "cannot resolve the filesystem of {root}"
        )));
    };
    if Path::new(&row.target) != staging_root {
        return Err(NoUsbError::InvalidInput(format!(
            "staging root {root} must be a mount point; it lives on {}",
            row.target
        )));
    }
    let device = source_device(&row);
    let encrypted = runner
        .run_checked("lsblk", &["-nso", "TYPE", &device])
        .ok()
        .map(|types| types.lines().any(|kind| kind.trim() == "crypt"));
    let free = runner
        .run_checked("df", &["-PB1", "--", &root])
        .ok()
        .and_then(|text| parse_df_available_bytes(&text));
    Ok(HostBootFacts {
        os_name: "linux".into(),
        elevated,
        firmware,
        secure_boot,
        memory_total_mb,
        staging_volume_root: staging_root.to_path_buf(),
        staging_grub_prefix: grub_prefix(&row),
        staging_filesystem: Some(row.fstype.clone()),
        staging_volume_encrypted: encrypted,
        staging_free_bytes: free,
    })
}

pub fn default_linux_staging_root() -> PathBuf {
    PathBuf::from("/")
}

#[cfg(any(feature = "real-linux-boot", test))]
pub use backend::LinuxHostBootBackend;

#[cfg(any(feature = "real-linux-boot", test))]
mod backend {
    use super::*;
    use nousb_core::{EspMount, HostBootBackend};

    pub struct LinuxHostBootBackend<R: CommandRunner> {
        pub runner: R,
        /// Mounted ESP path, from `/proc/self/mountinfo`.
        pub esp: Option<PathBuf>,
    }

    impl<R: CommandRunner> LinuxHostBootBackend<R> {
        pub fn new(runner: R, esp: Option<PathBuf>) -> Self {
            Self { runner, esp }
        }

        fn listing(&mut self) -> Result<EfiBootListing, NoUsbError> {
            Ok(parse_efibootmgr(
                &self.runner.run_checked("efibootmgr", &[])?,
            ))
        }

        /// Whole-disk device and partition number backing the mounted ESP.
        fn esp_disk_partition(&mut self, mount: &EspMount) -> Result<(String, String), NoUsbError> {
            let esp = mount.path.to_string_lossy().into_owned();
            let source = self
                .runner
                .run_checked("findmnt", &["-no", "SOURCE", "--target", &esp])?
                .trim()
                .to_string();
            let parent = self
                .runner
                .run_checked("lsblk", &["-no", "PKNAME", &source])?
                .trim()
                .to_string();
            let name = source.rsplit('/').next().unwrap_or_default().to_string();
            let partition = std::fs::read_to_string(format!("/sys/class/block/{name}/partition"))
                .map(|text| text.trim().to_string())
                .or_else(|_| {
                    self.runner
                        .run_checked("lsblk", &["-no", "PARTN", &source])
                        .map(|text| text.trim().to_string())
                })?;
            if parent.is_empty() || partition.is_empty() {
                return Err(NoUsbError::Io(format!(
                    "cannot resolve the disk and partition of ESP {source}"
                )));
            }
            Ok((format!("/dev/{parent}"), partition))
        }
    }

    impl<R: CommandRunner> HostBootBackend for LinuxHostBootBackend<R> {
        fn name(&self) -> &'static str {
            "linux-efibootmgr-bootnext"
        }

        fn facts(&mut self, staging_root: &Path) -> Result<HostBootFacts, NoUsbError> {
            #[cfg(target_os = "linux")]
            {
                linux_host_boot_facts(&mut self.runner, staging_root)
            }
            #[cfg(not(target_os = "linux"))]
            {
                Err(NoUsbError::UnsafeExecution(format!(
                    "the Linux backend cannot run here (staging root {})",
                    staging_root.display()
                )))
            }
        }

        fn backup_boot_state(&mut self, dir: &Path) -> Result<Vec<PathBuf>, NoUsbError> {
            let path = dir.join("efibootmgr-v.txt");
            let listing = self.runner.run_checked("efibootmgr", &["-v"])?;
            std::fs::write(&path, listing)?;
            Ok(vec![path])
        }

        fn mount_esp(&mut self) -> Result<EspMount, NoUsbError> {
            let path = self.esp.clone().ok_or_else(|| {
                NoUsbError::UnsafeExecution(
                    "no mounted EFI System Partition at /boot/efi, /efi, or /boot".into(),
                )
            })?;
            Ok(EspMount {
                path,
                mounted_by_us: false,
            })
        }

        fn unmount_esp(&mut self, _mount: &EspMount) -> Result<(), NoUsbError> {
            Ok(())
        }

        fn esp_free_bytes(&mut self, mount: &EspMount) -> Result<Option<u64>, NoUsbError> {
            let esp = mount.path.to_string_lossy().into_owned();
            Ok(self
                .runner
                .run_checked("df", &["-PB1", "--", &esp])
                .ok()
                .and_then(|text| parse_df_available_bytes(&text)))
        }

        fn boot_order(&mut self) -> Result<Vec<String>, NoUsbError> {
            Ok(self.listing()?.boot_order)
        }

        fn create_entry(
            &mut self,
            label: &str,
            loader: &str,
            mount: &EspMount,
        ) -> Result<String, NoUsbError> {
            let before = self.listing()?;
            let (disk, partition) = self.esp_disk_partition(mount)?;
            self.runner.run_checked(
                "efibootmgr",
                &[
                    "--create-only",
                    "--disk",
                    &disk,
                    "--part",
                    &partition,
                    "--label",
                    label,
                    "--loader",
                    loader,
                ],
            )?;
            let after = self.listing()?;
            let created: Vec<String> = after
                .entries
                .iter()
                .filter(|(id, entry_label)| {
                    entry_label == label && !before.entries.iter().any(|(old, _)| old == id)
                })
                .map(|(id, _)| id.clone())
                .collect();
            match created.as_slice() {
                [id] => Ok(id.clone()),
                _ => Err(NoUsbError::Io(format!(
                    "expected exactly one new \"{label}\" entry, found {created:?}"
                ))),
            }
        }

        fn arm_one_shot(&mut self, entry: &str) -> Result<(), NoUsbError> {
            self.runner
                .run_checked("efibootmgr", &["--bootnext", entry])?;
            Ok(())
        }

        fn pending_one_shot(&mut self) -> Result<Option<String>, NoUsbError> {
            Ok(self.listing()?.boot_next)
        }

        fn clear_one_shot(&mut self) -> Result<(), NoUsbError> {
            self.runner
                .run_checked("efibootmgr", &["--delete-bootnext"])?;
            Ok(())
        }

        fn delete_entry(&mut self, entry: &str) -> Result<(), NoUsbError> {
            if !self.listing()?.entries.iter().any(|(id, _)| id == entry) {
                return Ok(());
            }
            self.runner
                .run_checked("efibootmgr", &["--bootnum", entry, "--delete-bootnum"])?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nousb_core::{EspMount, HostBootBackend, ScriptedCommandRunner};
    use std::cell::RefCell;
    use std::rc::Rc;

    #[test]
    fn parses_efibootmgr_listing() {
        let listing = parse_efibootmgr(
            "BootCurrent: 0001\nTimeout: 0 seconds\nBootOrder: 0001,0000,0002\nBoot0000* Windows Boot Manager\tHD(1,GPT,...)\nBoot0001* ubuntu\tHD(1,GPT,...)/File(\\EFI\\ubuntu\\shimx64.efi)\nBoot0002  UEFI PXEv4\n",
        );
        assert_eq!(listing.boot_order, vec!["0001", "0000", "0002"]);
        assert_eq!(listing.boot_next, None);
        assert_eq!(listing.entries[1], ("0001".into(), "ubuntu".into()));
        assert_eq!(listing.entries[2], ("0002".into(), "UEFI PXEv4".into()));
    }

    #[test]
    fn mount_rows_give_grub_prefix_and_device() {
        let ext4 = parse_findmnt_row("/ /dev/nvme0n1p2 ext4 /").unwrap();
        assert_eq!(grub_prefix(&ext4), "/");
        let btrfs = parse_findmnt_row("/ /dev/nvme0n1p3[/root] btrfs /root").unwrap();
        assert_eq!(grub_prefix(&btrfs), "/root");
        assert_eq!(source_device(&btrfs), "/dev/nvme0n1p3");
        assert_eq!(
            parse_df_available_bytes("Filesystem 1-blocks Used Available Capacity Mounted on\n/dev/sda2 100 40 60 40% /\n"),
            Some(60)
        );
    }

    #[test]
    fn backend_creates_outside_boot_order_and_arms_boot_next() {
        let state = Rc::new(RefCell::new((false, None::<String>)));
        let shared = Rc::clone(&state);
        let runner = ScriptedCommandRunner::new(move |line| {
            let mut state = shared.borrow_mut();
            if line.starts_with("efibootmgr --create-only") {
                state.0 = true;
                ScriptedCommandRunner::ok("")
            } else if line == "efibootmgr --bootnext 0003" {
                state.1 = Some("0003".into());
                ScriptedCommandRunner::ok("")
            } else if line == "efibootmgr --delete-bootnext" {
                state.1 = None;
                ScriptedCommandRunner::ok("")
            } else if line == "efibootmgr --bootnum 0003 --delete-bootnum" {
                state.0 = false;
                ScriptedCommandRunner::ok("")
            } else if line == "efibootmgr" {
                let mut text = String::from("BootCurrent: 0001\nBootOrder: 0001,0000\n");
                if let Some(next) = &state.1 {
                    text.push_str(&format!("BootNext: {next}\n"));
                }
                text.push_str("Boot0000* Windows Boot Manager\nBoot0001* ubuntu\n");
                if state.0 {
                    text.push_str("Boot0003  NoUSB One-Shot Installer\n");
                }
                ScriptedCommandRunner::ok(&text)
            } else if line.starts_with("findmnt -no SOURCE") {
                ScriptedCommandRunner::ok("/dev/nvme0n1p1\n")
            } else if line.starts_with("lsblk -no PKNAME") {
                ScriptedCommandRunner::ok("nvme0n1\n")
            } else if line.starts_with("lsblk -no PARTN") {
                ScriptedCommandRunner::ok("1\n")
            } else {
                ScriptedCommandRunner::ok("")
            }
        });
        let mut backend = LinuxHostBootBackend::new(runner, Some(PathBuf::from("/boot/efi")));
        let mount = backend.mount_esp().unwrap();
        assert_eq!(
            mount,
            EspMount {
                path: PathBuf::from("/boot/efi"),
                mounted_by_us: false
            }
        );
        let before = backend.boot_order().unwrap();
        let entry = backend
            .create_entry(
                "NoUSB One-Shot Installer",
                "\\EFI\\NoUSB\\BOOTX64.EFI",
                &mount,
            )
            .unwrap();
        assert_eq!(entry, "0003");
        backend.arm_one_shot(&entry).unwrap();
        assert_eq!(backend.pending_one_shot().unwrap().as_deref(), Some("0003"));
        assert_eq!(backend.boot_order().unwrap(), before);
        backend.clear_one_shot().unwrap();
        backend.delete_entry(&entry).unwrap();
        // Idempotent: a second delete finds nothing to remove.
        backend.delete_entry(&entry).unwrap();
        let calls = backend.runner.calls.join("\n");
        assert!(calls.contains("efibootmgr --create-only --disk /dev/nvme0n1 --part"));
        assert!(
            calls.contains("--label NoUSB One-Shot Installer --loader \\EFI\\NoUSB\\BOOTX64.EFI")
        );
        assert!(!calls.contains("--bootorder"));
        assert_eq!(calls.matches("--delete-bootnum").count(), 1);
    }
}
