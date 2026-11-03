use nousb_core::{HostPlatform, NoUsbError, PlatformAdapter, SystemInventory};

#[cfg(target_os = "linux")]
use nousb_core::{
    parse_efi_boot_order, parse_efi_load_option, BootEntry, EfiBootTarget, EncryptionState,
    SecureBootState, EFI_GLOBAL_VARIABLE_GUID,
};

#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::path::Path;
#[cfg(target_os = "linux")]
use std::process::Command;

mod host_boot;
pub use host_boot::*;

pub struct LinuxSafeAdapter;

impl PlatformAdapter for LinuxSafeAdapter {
    fn inspect(&self) -> Result<SystemInventory, NoUsbError> {
        let inventory = HostPlatform.inspect()?;
        #[cfg(target_os = "linux")]
        {
            let mut inventory = inventory;
            enrich_linux_inventory(&mut inventory);
            Ok(inventory)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(inventory)
        }
    }

    fn name(&self) -> &'static str {
        "linux-safe-read-only"
    }
}

#[cfg(target_os = "linux")]
fn enrich_linux_inventory(inventory: &mut SystemInventory) {
    if let Ok(meminfo) = fs::read_to_string("/proc/meminfo") {
        inventory.memory_total_mb = meminfo.lines().find_map(|line| {
            let value = line.strip_prefix("MemTotal:")?.split_whitespace().next()?;
            value.parse::<u64>().ok().map(|kilobytes| kilobytes / 1024)
        });
    }

    if let Ok(entries) = fs::read_dir("/sys/firmware/efi/efivars") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            if !name.to_string_lossy().starts_with("SecureBoot-") {
                continue;
            }
            if let Ok(bytes) = fs::read(entry.path()) {
                inventory.secure_boot = match bytes.get(4) {
                    Some(1) => SecureBootState::Enabled,
                    Some(0) => SecureBootState::Disabled,
                    _ => SecureBootState::Unknown,
                };
            }
            break;
        }
    }

    if let Ok(output) = Command::new("df").args(["-Pk", "--", "/"]).output() {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            inventory.disk_inventory.available_space_gb = stdout
                .lines()
                .last()
                .and_then(|line| line.split_whitespace().nth(3))
                .and_then(|value| value.parse::<u64>().ok())
                .map(|kilobytes| (kilobytes / 1024 / 1024) as u32);
        }
    }

    if let Ok(crypttab) = fs::read_to_string("/etc/crypttab") {
        if crypttab
            .lines()
            .any(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
        {
            inventory.encryption = EncryptionState::Enabled("LUKS/dm-crypt configured".into());
        }
    }

    if Path::new("/boot/grub/grub.cfg").exists() || Path::new("/boot/grub2/grub.cfg").exists() {
        inventory.boot_entries.push(BootEntry {
            id: "grub-detected".into(),
            label: "GRUB configuration detected".into(),
            is_default: inventory.boot_entries.is_empty(),
        });
    }
    if Path::new("/boot/loader/loader.conf").exists() {
        inventory.boot_entries.push(BootEntry {
            id: "systemd-boot-detected".into(),
            label: "systemd-boot configuration detected".into(),
            is_default: inventory.boot_entries.is_empty(),
        });
    }
    enrich_linux_boot_hints(inventory);
    inventory
        .warnings
        .push("Linux platform inventory was collected read-only; no GRUB, systemd-boot, EFI, disk, or LUKS settings were changed.".into());
}

#[cfg(target_os = "linux")]
fn read_efi_global_variable(name: &str) -> Option<Vec<u8>> {
    let path = format!("/sys/firmware/efi/efivars/{name}-{EFI_GLOBAL_VARIABLE_GUID}");
    let bytes = fs::read(path).ok()?;
    // efivarfs prefixes every value with its four attribute bytes.
    bytes.get(4..).map(<[u8]>::to_vec)
}

#[cfg(target_os = "linux")]
fn enrich_linux_boot_hints(inventory: &mut SystemInventory) {
    let hints = &mut inventory.boot_hints;
    hints.unknowns.clear();

    if let Ok(mountinfo) = fs::read_to_string("/proc/self/mountinfo") {
        let esp = esp_mount_from_mountinfo(&mountinfo);
        hints.esp_present = Some(esp.is_some());
        hints.esp_location = esp;
    } else {
        hints
            .unknowns
            .push("ESP mount: /proc/self/mountinfo unreadable".into());
    }
    if let Some(esp) = hints.esp_location.clone() {
        match fs::read_dir(Path::new(&esp).join("EFI")) {
            Ok(entries) => {
                let mut vendors: Vec<String> = entries
                    .flatten()
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .collect();
                vendors.sort();
                hints.boot_managers.extend(
                    vendors
                        .into_iter()
                        .map(|vendor| format!("ESP vendor directory {vendor}")),
                );
            }
            Err(_) => hints.unknowns.push(format!(
                "ESP contents: {esp}/EFI is not readable without elevation"
            )),
        }
    }
    for (path, manager) in [
        ("/boot/grub/grub.cfg", "grub"),
        ("/boot/grub2/grub.cfg", "grub"),
        ("/boot/loader/loader.conf", "systemd-boot"),
        ("/efi/loader/loader.conf", "systemd-boot"),
    ] {
        if Path::new(path).exists() && !hints.boot_managers.iter().any(|item| item == manager) {
            hints.boot_managers.push(manager.into());
        }
    }

    if !Path::new("/sys/firmware/efi").exists() {
        hints
            .unknowns
            .push("firmware boot entries: not booted in UEFI mode".into());
        return;
    }
    let Some(order) = read_efi_global_variable("BootOrder") else {
        hints
            .unknowns
            .push("firmware boot entries: efivarfs BootOrder unreadable".into());
        return;
    };
    let order = parse_efi_boot_order(&order);
    hints.firmware_boot_current = read_efi_global_variable("BootCurrent")
        .and_then(|bytes| parse_efi_boot_order(&bytes).into_iter().next());
    hints.firmware_boot_next = read_efi_global_variable("BootNext")
        .and_then(|bytes| parse_efi_boot_order(&bytes).into_iter().next());

    let mut network = 0;
    let mut http = 0;
    let firmware_entries: Vec<BootEntry> = order
        .iter()
        .enumerate()
        .filter_map(|(position, id)| {
            let option = parse_efi_load_option(&read_efi_global_variable(id)?)?;
            if option.target.is_network() {
                network += 1;
            }
            if option.target == EfiBootTarget::NetworkHttp {
                http += 1;
            }
            Some(BootEntry {
                id: id.clone(),
                label: format!("{} [{}]", option.description, option.target.as_str()),
                is_default: position == 0,
            })
        })
        .collect();
    hints.network_boot_entries = Some(network);
    hints.http_boot_entries = Some(http);
    hints.firmware_boot_order = Some(order);
    if !firmware_entries.is_empty() {
        inventory.boot_entries = firmware_entries;
    }
}

/// Finds the mounted EFI System Partition: a FAT filesystem at `/boot/efi`, `/efi`, or `/boot`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn esp_mount_from_mountinfo(mountinfo: &str) -> Option<String> {
    let mut found = None;
    for line in mountinfo.lines() {
        let Some((left, right)) = line.split_once(" - ") else {
            continue;
        };
        let mount_point = left.split_whitespace().nth(4)?;
        let filesystem = right.split_whitespace().next()?;
        if !matches!(filesystem, "vfat" | "msdos") {
            continue;
        }
        for (rank, candidate) in ["/boot/efi", "/efi", "/boot"].iter().enumerate() {
            if mount_point == *candidate
                && found
                    .as_ref()
                    .is_none_or(|(best, _): &(usize, String)| rank < *best)
            {
                found = Some((rank, mount_point.to_string()));
            }
        }
    }
    found.map(|(_, mount_point)| mount_point)
}

/// The mounted EFI System Partition, if any.
#[cfg(target_os = "linux")]
pub fn mounted_esp() -> Option<std::path::PathBuf> {
    let mountinfo = fs::read_to_string("/proc/self/mountinfo").ok()?;
    esp_mount_from_mountinfo(&mountinfo).map(std::path::PathBuf::from)
}

pub fn real_boot_changes_enabled() -> bool {
    cfg!(feature = "real-linux-boot")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_esp_mount_and_ignores_non_fat_boot() {
        let mountinfo = "\
22 1 259:2 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw
24 22 259:3 / /boot rw,relatime shared:2 - ext4 /dev/nvme0n1p3 rw
25 24 259:1 / /boot/efi rw,relatime shared:3 - vfat /dev/nvme0n1p1 rw,fmask=0077
";
        assert_eq!(
            esp_mount_from_mountinfo(mountinfo).as_deref(),
            Some("/boot/efi")
        );
        assert_eq!(
            esp_mount_from_mountinfo("22 1 259:2 / / rw - ext4 /dev/sda2 rw\n"),
            None
        );
        assert_eq!(
            esp_mount_from_mountinfo("30 22 8:1 / /efi rw - vfat /dev/sda1 rw\n").as_deref(),
            Some("/efi")
        );
    }
}
