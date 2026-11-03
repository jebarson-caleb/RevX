//! Windows host one-shot boot. Facts are read-only and available in every build; the backend
//! that runs `mountvol` and `bcdedit` exists only with `real-windows-boot` (or in tests, where a
//! scripted runner answers every command and nothing runs).
//!
//! Mechanism: `bcdedit /copy {bootmgr}` creates a firmware application entry on the same ESP,
//! its path is pointed at `\EFI\NoUSB\BOOTX64.EFI` (the ISO's signed shim), and
//! `bcdedit /set {fwbootmgr} bootsequence` writes UEFI `BootNext`. `{fwbootmgr} displayorder`
//! (UEFI `BootOrder`) is never changed; if Windows adds the copy to it, the entry is removed.

use std::path::{Path, PathBuf};

use nousb_core::{FirmwareMode, HostBootFacts, NoUsbError, SecureBootState};

/// Parses the key=value output of [`FACTS_SCRIPT`].
pub fn parse_windows_host_facts(stdout: &str, staging_root: &Path) -> HostBootFacts {
    let mut facts = HostBootFacts {
        os_name: "windows".into(),
        elevated: false,
        firmware: FirmwareMode::Unknown,
        secure_boot: SecureBootState::Unknown,
        memory_total_mb: None,
        staging_volume_root: staging_root.to_path_buf(),
        staging_grub_prefix: "/".into(),
        staging_filesystem: None,
        staging_volume_encrypted: None,
        staging_free_bytes: None,
    };
    let mut manage_bde = String::new();
    for line in stdout.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "elevated" => facts.elevated = value.eq_ignore_ascii_case("true"),
            // PEFirmwareType: 1 = BIOS, 2 = UEFI.
            "firmware" if value == "2" => facts.firmware = FirmwareMode::Uefi,
            "firmware" if value == "1" => facts.firmware = FirmwareMode::Bios,
            "secure_boot" if value == "1" => facts.secure_boot = SecureBootState::Enabled,
            "secure_boot" if value == "0" => facts.secure_boot = SecureBootState::Disabled,
            "memory_bytes" => {
                facts.memory_total_mb = value.parse::<u64>().ok().map(|bytes| bytes / 1024 / 1024)
            }
            "free_bytes" => facts.staging_free_bytes = value.parse().ok(),
            "format" if !value.is_empty() => facts.staging_filesystem = Some(value.into()),
            // Get-BitLockerVolume VolumeStatus is an enum name, independent of display language.
            "bitlocker_volume_status" if !value.is_empty() => {
                facts.staging_volume_encrypted = Some(value != "FullyDecrypted")
            }
            "manage_bde" => {
                manage_bde.push_str(value);
                manage_bde.push('\n');
            }
            _ => {}
        }
    }
    if facts.staging_volume_encrypted.is_none() {
        facts.staging_volume_encrypted = parse_manage_bde_encrypted(&manage_bde);
    }
    facts
}

/// English `manage-bde -status` fallback; any other language stays unknown (and blocks).
fn parse_manage_bde_encrypted(output: &str) -> Option<bool> {
    let status = output.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        (key.trim() == "Conversion Status").then(|| value.trim().to_string())
    })?;
    Some(status != "Fully Decrypted")
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const FACTS_SCRIPT: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
$root = $env:NOUSB_STAGING_ROOT
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
Write-Output "elevated=$($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"
Write-Output "firmware=$((Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name PEFirmwareType).PEFirmwareType)"
Write-Output "secure_boot=$((Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -Name UEFISecureBootEnabled).UEFISecureBootEnabled)"
$null = Add-Type -AssemblyName Microsoft.VisualBasic
Write-Output "memory_bytes=$((New-Object Microsoft.VisualBasic.Devices.ComputerInfo).TotalPhysicalMemory)"
$drive = [System.IO.DriveInfo]::new($root)
Write-Output "free_bytes=$($drive.AvailableFreeSpace)"
Write-Output "format=$($drive.DriveFormat)"
$letter = $root.Substring(0, 2)
$volume = Get-BitLockerVolume -MountPoint $letter
if ($volume) { Write-Output "bitlocker_volume_status=$($volume.VolumeStatus)" }
else { manage-bde -status $letter | ForEach-Object { Write-Output "manage_bde=$_" } }
"#;

/// Read-only host facts for a staging volume root such as `C:\`. Unknowns stay unknown.
#[cfg(target_os = "windows")]
pub fn windows_host_boot_facts(staging_root: &Path) -> Result<HostBootFacts, NoUsbError> {
    let root = validate_staging_root(staging_root)?;
    let output = std::process::Command::new("powershell.exe")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            FACTS_SCRIPT,
        ])
        .env("NOUSB_STAGING_ROOT", &root)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|error| NoUsbError::Io(format!("cannot query host facts: {error}")))?;
    Ok(parse_windows_host_facts(
        &String::from_utf8_lossy(&output.stdout),
        Path::new(&root),
    ))
}

/// The default staging root: the system drive (`C:\`).
pub fn default_windows_staging_root() -> PathBuf {
    let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
    PathBuf::from(format!("{}\\", drive.trim_end_matches('\\')))
}

/// Staging must be a whole-volume root like `D:\`, so GRUB paths start at the volume root.
pub fn validate_staging_root(root: &Path) -> Result<String, NoUsbError> {
    let text = root.to_string_lossy().replace('/', "\\");
    let bytes = text.as_bytes();
    let valid = (bytes.len() == 2 || (bytes.len() == 3 && bytes[2] == b'\\'))
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':';
    if valid {
        Ok(format!("{}:\\", (bytes[0] as char).to_ascii_uppercase()))
    } else {
        Err(NoUsbError::InvalidInput(format!(
            "staging root {text} must be a drive root such as D:\\"
        )))
    }
}

/// GUIDs in `bcdedit` output, in order.
pub fn bcd_guids(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'{' && index + 38 <= bytes.len() && bytes[index + 37] == b'}' {
            let candidate = &text[index..index + 38];
            let inner = &candidate[1..37];
            let shape = inner
                .char_indices()
                .all(|(position, value)| match position {
                    8 | 13 | 18 | 23 => value == '-',
                    _ => value.is_ascii_hexdigit(),
                });
            if shape {
                found.push(candidate.to_ascii_lowercase());
                index += 38;
                continue;
            }
        }
        index += 1;
    }
    found
}

/// Values of one element (`displayorder`, `bootsequence`) in `bcdedit /enum {fwbootmgr} /v`.
/// Element names are not localized; continuation lines start with whitespace.
pub fn bcd_element_guids(text: &str, element: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut inside = false;
    for line in text.lines() {
        let starts_with_space = line.starts_with(' ') || line.starts_with('\t');
        if !starts_with_space {
            inside = line
                .split_whitespace()
                .next()
                .is_some_and(|key| key.eq_ignore_ascii_case(element));
        }
        if inside {
            values.extend(bcd_guids(line));
        }
    }
    values
}

#[cfg(any(feature = "real-windows-boot", test))]
pub use backend::WindowsHostBootBackend;

#[cfg(any(feature = "real-windows-boot", test))]
mod backend {
    use super::*;
    use nousb_core::CommandRunner;
    use nousb_core::{EspMount, HostBootBackend};

    const FWBOOTMGR: &str = "{fwbootmgr}";

    pub struct WindowsHostBootBackend<R: CommandRunner> {
        pub runner: R,
        mounted_letter: Option<char>,
    }

    impl<R: CommandRunner> WindowsHostBootBackend<R> {
        pub fn new(runner: R) -> Self {
            Self {
                runner,
                mounted_letter: None,
            }
        }

        fn fwbootmgr(&mut self) -> Result<String, NoUsbError> {
            self.runner
                .run_checked("bcdedit", &["/enum", FWBOOTMGR, "/v"])
        }

        fn free_drive_letter() -> Result<char, NoUsbError> {
            ('M'..='Z')
                .rev()
                .find(|letter| !Path::new(&format!("{letter}:\\")).exists())
                .ok_or_else(|| NoUsbError::Io("no free drive letter to mount the ESP".into()))
        }
    }

    impl<R: CommandRunner> HostBootBackend for WindowsHostBootBackend<R> {
        fn name(&self) -> &'static str {
            "windows-bcdedit-bootsequence"
        }

        fn facts(&mut self, staging_root: &Path) -> Result<HostBootFacts, NoUsbError> {
            #[cfg(target_os = "windows")]
            {
                windows_host_boot_facts(staging_root)
            }
            #[cfg(not(target_os = "windows"))]
            {
                Err(NoUsbError::UnsafeExecution(format!(
                    "the Windows backend cannot run here (staging root {})",
                    staging_root.display()
                )))
            }
        }

        fn backup_boot_state(&mut self, dir: &Path) -> Result<Vec<PathBuf>, NoUsbError> {
            let store = dir.join("bcd-store.bak");
            let store_text = store.to_string_lossy().into_owned();
            self.runner
                .run_checked("bcdedit", &["/export", &store_text])?;
            let firmware = dir.join("bcdedit-enum-firmware.txt");
            let listing = self
                .runner
                .run_checked("bcdedit", &["/enum", "firmware", "/v"])?;
            std::fs::write(&firmware, listing)?;
            let all = dir.join("bcdedit-enum-all.txt");
            let listing = self
                .runner
                .run_checked("bcdedit", &["/enum", "all", "/v"])?;
            std::fs::write(&all, listing)?;
            Ok(vec![store, firmware, all])
        }

        fn mount_esp(&mut self) -> Result<EspMount, NoUsbError> {
            if let Some(letter) = self.mounted_letter {
                return Ok(EspMount {
                    path: PathBuf::from(format!("{letter}:\\")),
                    mounted_by_us: true,
                });
            }
            let letter = Self::free_drive_letter()?;
            let target = format!("{letter}:");
            self.runner.run_checked("mountvol", &[&target, "/S"])?;
            self.mounted_letter = Some(letter);
            Ok(EspMount {
                path: PathBuf::from(format!("{letter}:\\")),
                mounted_by_us: true,
            })
        }

        fn unmount_esp(&mut self, mount: &EspMount) -> Result<(), NoUsbError> {
            if !mount.mounted_by_us {
                return Ok(());
            }
            if let Some(letter) = self.mounted_letter.take() {
                let target = format!("{letter}:");
                self.runner.run_checked("mountvol", &[&target, "/D"])?;
            }
            Ok(())
        }

        fn esp_free_bytes(&mut self, mount: &EspMount) -> Result<Option<u64>, NoUsbError> {
            let script = format!(
                "([System.IO.DriveInfo]::new('{}')).AvailableFreeSpace",
                mount.path.display()
            );
            let output = self.runner.run(
                "powershell.exe",
                &[
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    &script,
                ],
            )?;
            Ok(output.stdout.trim().parse().ok())
        }

        fn boot_order(&mut self) -> Result<Vec<String>, NoUsbError> {
            Ok(bcd_element_guids(&self.fwbootmgr()?, "displayorder"))
        }

        fn create_entry(
            &mut self,
            label: &str,
            loader: &str,
            _mount: &EspMount,
        ) -> Result<String, NoUsbError> {
            let output = self
                .runner
                .run_checked("bcdedit", &["/copy", "{bootmgr}", "/d", label])?;
            let guid = bcd_guids(&output).into_iter().next().ok_or_else(|| {
                NoUsbError::Io(format!("bcdedit /copy returned no entry id: {output}"))
            })?;
            let configured = self
                .runner
                .run_checked("bcdedit", &["/set", &guid, "path", loader]);
            let in_order = self
                .boot_order()
                .map(|order| order.contains(&guid))
                .unwrap_or(false);
            if in_order {
                // Keep UEFI BootOrder exactly as it was.
                self.runner.run_checked(
                    "bcdedit",
                    &["/set", FWBOOTMGR, "displayorder", &guid, "/remove"],
                )?;
            }
            if let Err(error) = configured {
                let _ = self.runner.run("bcdedit", &["/delete", &guid]);
                return Err(error);
            }
            Ok(guid)
        }

        fn arm_one_shot(&mut self, entry: &str) -> Result<(), NoUsbError> {
            self.runner
                .run_checked("bcdedit", &["/set", FWBOOTMGR, "bootsequence", entry])?;
            Ok(())
        }

        fn pending_one_shot(&mut self) -> Result<Option<String>, NoUsbError> {
            Ok(bcd_element_guids(&self.fwbootmgr()?, "bootsequence")
                .into_iter()
                .next())
        }

        fn clear_one_shot(&mut self) -> Result<(), NoUsbError> {
            self.runner
                .run_checked("bcdedit", &["/deletevalue", FWBOOTMGR, "bootsequence"])?;
            Ok(())
        }

        fn delete_entry(&mut self, entry: &str) -> Result<(), NoUsbError> {
            let output = self.runner.run("bcdedit", &["/delete", entry])?;
            if output.success
                || !bcd_guids(&self.runner.run_checked("bcdedit", &["/enum", "firmware"])?)
                    .contains(&entry.to_ascii_lowercase())
            {
                Ok(())
            } else {
                Err(NoUsbError::Io(format!(
                    "bcdedit /delete {entry} failed: {}",
                    output.stdout.trim()
                )))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nousb_core::{EspMount, HostBootBackend, ScriptedCommandRunner};
    use std::cell::RefCell;
    use std::rc::Rc;

    const FWBOOTMGR_ENUM: &str = "Firmware Boot Manager\n---------------------\nidentifier              {fwbootmgr}\ndisplayorder            {9dea862c-5cdd-4e70-acc1-f32b344d4795}\n                        {d7b6c2a0-1111-2222-3333-444455556666}\ntimeout                 0\n";

    #[test]
    fn parses_facts_and_encryption_signals() {
        let facts = parse_windows_host_facts(
            "elevated=True\nfirmware=2\nsecure_boot=1\nmemory_bytes=17179869184\nfree_bytes=1000\nformat=NTFS\nbitlocker_volume_status=FullyEncrypted\n",
            Path::new("C:\\"),
        );
        assert!(facts.elevated);
        assert_eq!(facts.firmware, FirmwareMode::Uefi);
        assert_eq!(facts.secure_boot, SecureBootState::Enabled);
        assert_eq!(facts.memory_total_mb, Some(16384));
        assert_eq!(facts.staging_filesystem.as_deref(), Some("NTFS"));
        assert_eq!(facts.staging_volume_encrypted, Some(true));

        let decrypted = parse_windows_host_facts(
            "elevated=False\nmanage_bde=    Conversion Status:    Fully Decrypted\n",
            Path::new("D:\\"),
        );
        assert_eq!(decrypted.staging_volume_encrypted, Some(false));
        let localized = parse_windows_host_facts(
            "manage_bde=    Konvertierungsstatus:    Vollständig entschlüsselt\n",
            Path::new("D:\\"),
        );
        assert_eq!(localized.staging_volume_encrypted, None);
    }

    #[test]
    fn staging_root_must_be_a_drive_root() {
        assert_eq!(validate_staging_root(Path::new("d:")).unwrap(), "D:\\");
        assert_eq!(validate_staging_root(Path::new("C:\\")).unwrap(), "C:\\");
        assert!(validate_staging_root(Path::new("C:\\Users")).is_err());
        assert!(validate_staging_root(Path::new("/")).is_err());
    }

    #[test]
    fn reads_display_order_and_boot_sequence() {
        assert_eq!(
            bcd_element_guids(FWBOOTMGR_ENUM, "displayorder"),
            vec![
                "{9dea862c-5cdd-4e70-acc1-f32b344d4795}",
                "{d7b6c2a0-1111-2222-3333-444455556666}"
            ]
        );
        assert!(bcd_element_guids(FWBOOTMGR_ENUM, "bootsequence").is_empty());
        let armed = format!(
            "{FWBOOTMGR_ENUM}bootsequence            {{ABCDEF01-2345-6789-abcd-ef0123456789}}\n"
        );
        assert_eq!(
            bcd_element_guids(&armed, "bootsequence"),
            vec!["{abcdef01-2345-6789-abcd-ef0123456789}"]
        );
    }

    #[test]
    fn backend_issues_the_expected_bcdedit_sequence() {
        let armed = Rc::new(RefCell::new(false));
        let flag = Rc::clone(&armed);
        let runner = ScriptedCommandRunner::new(move |line| {
            if line.starts_with("bcdedit /copy") {
                ScriptedCommandRunner::ok(
                    "The entry was successfully copied to {abcdef01-2345-6789-abcd-ef0123456789}.",
                )
            } else if line.starts_with("bcdedit /set {fwbootmgr} bootsequence") {
                *flag.borrow_mut() = true;
                ScriptedCommandRunner::ok("The operation completed successfully.")
            } else if line == "bcdedit /enum {fwbootmgr} /v" {
                let mut text = FWBOOTMGR_ENUM.to_string();
                if *flag.borrow() {
                    text.push_str(
                        "bootsequence            {abcdef01-2345-6789-abcd-ef0123456789}\n",
                    );
                }
                ScriptedCommandRunner::ok(&text)
            } else {
                ScriptedCommandRunner::ok("The operation completed successfully.")
            }
        });
        let mut backend = WindowsHostBootBackend::new(runner);
        let mount = EspMount {
            path: PathBuf::from("Z:\\"),
            mounted_by_us: true,
        };
        let before = backend.boot_order().unwrap();
        let entry = backend
            .create_entry(
                "NoUSB One-Shot Installer",
                "\\EFI\\NoUSB\\BOOTX64.EFI",
                &mount,
            )
            .unwrap();
        assert_eq!(entry, "{abcdef01-2345-6789-abcd-ef0123456789}");
        backend.arm_one_shot(&entry).unwrap();
        assert_eq!(
            backend.pending_one_shot().unwrap().as_deref(),
            Some(entry.as_str())
        );
        assert_eq!(backend.boot_order().unwrap(), before);
        backend.clear_one_shot().unwrap();
        backend.delete_entry(&entry).unwrap();
        let calls = backend.runner.calls.join("\n");
        assert!(calls.contains("bcdedit /copy {bootmgr} /d NoUSB One-Shot Installer"));
        assert!(calls.contains(&format!(
            "bcdedit /set {entry} path \\EFI\\NoUSB\\BOOTX64.EFI"
        )));
        assert!(calls.contains(&format!("bcdedit /set {{fwbootmgr}} bootsequence {entry}")));
        assert!(calls.contains("bcdedit /deletevalue {fwbootmgr} bootsequence"));
        assert!(calls.contains(&format!("bcdedit /delete {entry}")));
        // The persistent order is never written.
        assert!(!calls.contains("displayorder"));
        assert!(!calls.contains("/default"));
    }

    #[test]
    fn copy_that_lands_in_display_order_is_removed_again() {
        let runner = ScriptedCommandRunner::new(|line| {
            if line.starts_with("bcdedit /copy") {
                ScriptedCommandRunner::ok("copied to {abcdef01-2345-6789-abcd-ef0123456789}.")
            } else if line == "bcdedit /enum {fwbootmgr} /v" {
                ScriptedCommandRunner::ok(&FWBOOTMGR_ENUM.replace(
                    "timeout",
                    "                        {abcdef01-2345-6789-abcd-ef0123456789}\ntimeout",
                ))
            } else {
                ScriptedCommandRunner::ok("ok")
            }
        });
        let mut backend = WindowsHostBootBackend::new(runner);
        let mount = EspMount {
            path: PathBuf::from("Z:\\"),
            mounted_by_us: true,
        };
        backend
            .create_entry("NoUSB", "\\EFI\\NoUSB\\BOOTX64.EFI", &mount)
            .unwrap();
        assert!(backend.runner.calls.iter().any(|call| call
            == "bcdedit /set {fwbootmgr} displayorder {abcdef01-2345-6789-abcd-ef0123456789} /remove"));
    }
}
