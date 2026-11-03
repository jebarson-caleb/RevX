#[cfg(target_os = "windows")]
use nousb_core::{sha256_file, verify_artifact};
use nousb_core::{
    EncryptionState, FirmwareMode, HostPlatform, NoUsbError, PartitionInfo, PlatformAdapter,
    SecureBootState, SystemInventory,
};

#[cfg(target_os = "windows")]
use std::fs::{self, File, OpenOptions};
#[cfg(target_os = "windows")]
use std::io::{self, Write};
#[cfg(target_os = "windows")]
use std::path::Path;
use std::path::PathBuf;
#[cfg(target_os = "windows")]
use std::process::{Child, Command, Output, Stdio};
#[cfg(target_os = "windows")]
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

mod host_boot;
pub use host_boot::*;
mod one_shot;
pub use one_shot::*;
mod secure_boot;
pub use secure_boot::*;

pub struct WindowsSafeAdapter;

impl PlatformAdapter for WindowsSafeAdapter {
    fn inspect(&self) -> Result<SystemInventory, NoUsbError> {
        let inventory = HostPlatform.inspect()?;
        #[cfg(target_os = "windows")]
        {
            let mut inventory = inventory;
            enrich_windows_inventory(&mut inventory);
            Ok(inventory)
        }
        #[cfg(not(target_os = "windows"))]
        {
            Ok(inventory)
        }
    }

    fn name(&self) -> &'static str {
        "windows-safe-read-only"
    }
}

#[cfg(target_os = "windows")]
fn enrich_windows_inventory(inventory: &mut SystemInventory) {
    let script = r#"
$ErrorActionPreference = 'SilentlyContinue'
$secure = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -Name UEFISecureBootEnabled).UEFISecureBootEnabled
$null = Add-Type -AssemblyName Microsoft.VisualBasic
$computer = New-Object Microsoft.VisualBasic.Devices.ComputerInfo
$memory = $computer.TotalPhysicalMemory
$drive = [System.IO.DriveInfo]::new($env:SystemDrive)
Write-Output "secure_boot=$secure"
Write-Output "memory_bytes=$memory"
Write-Output "free_bytes=$($drive.AvailableFreeSpace)"
Write-Output "drive_size_bytes=$($drive.TotalSize)"
Write-Output "drive_format=$($drive.DriveFormat)"
Write-Output "system_drive=$env:SystemDrive"
$parts = Get-Partition
if ($parts) {
    $esp = $parts | Where-Object { $_.GptType -eq '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}' } | Select-Object -First 1
    if ($esp) { Write-Output "esp=disk $($esp.DiskNumber) partition $($esp.PartitionNumber)|$($esp.Size)" } else { Write-Output "esp=none" }
    $recovery = $parts | Where-Object { $_.GptType -eq '{de94bba4-06d1-4d40-a16a-bfd50179d6ac}' } | Select-Object -First 1
    Write-Output "recovery_partition=$(if ($recovery) { 1 } else { 0 })"
}
"#;
    let output = match Command::new("powershell.exe")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ])
        .output()
    {
        Ok(output) if output.status.success() => output,
        _ => {
            inventory.warnings.push(
                "Windows read-only inventory could not query PowerShell/CIM; delivery capability remains unknown."
                    .into(),
            );
            return;
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    apply_windows_inventory_output(inventory, &stdout);
    if inventory.encryption == EncryptionState::Unknown {
        inventory.warnings.push(
            "BitLocker status remains unknown because the safe adapter does not request administrative access."
                .into(),
        );
    }
    inventory
        .warnings
        .push("Windows platform inventory was collected read-only; no BCD, EFI, disk, or BitLocker settings were changed.".into());
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn apply_windows_inventory_output(inventory: &mut SystemInventory, stdout: &str) {
    for line in stdout.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "secure_boot" if value == "1" => {
                inventory.firmware = FirmwareMode::Uefi;
                inventory.secure_boot = SecureBootState::Enabled;
            }
            "secure_boot" if value == "0" => {
                inventory.firmware = FirmwareMode::Uefi;
                inventory.secure_boot = SecureBootState::Disabled;
            }
            "memory_bytes" => {
                inventory.memory_total_mb =
                    value.parse::<u64>().ok().map(|bytes| bytes / 1024 / 1024);
            }
            "free_bytes" => {
                inventory.disk_inventory.available_space_gb = value
                    .parse::<u64>()
                    .ok()
                    .map(|bytes| (bytes / 1024 / 1024 / 1024) as u32);
            }
            "drive_size_bytes" => {
                let size_bytes = value.parse::<u64>().ok();
                if let Some(partition) = inventory
                    .disk_inventory
                    .partitions
                    .iter_mut()
                    .find(|partition| partition.name == "Windows system volume")
                {
                    partition.size_bytes = size_bytes;
                } else {
                    inventory.disk_inventory.partitions.push(PartitionInfo {
                        name: "Windows system volume".into(),
                        mount_point: None,
                        filesystem: None,
                        size_bytes,
                    });
                }
            }
            "drive_format" if !value.is_empty() => {
                if let Some(partition) = inventory
                    .disk_inventory
                    .partitions
                    .iter_mut()
                    .find(|partition| partition.name == "Windows system volume")
                {
                    partition.filesystem = Some(value.into());
                }
            }
            "system_drive" if !value.is_empty() => {
                inventory.disk_inventory.disks = vec![format!("Windows system drive {value}")];
                if let Some(partition) = inventory
                    .disk_inventory
                    .partitions
                    .iter_mut()
                    .find(|partition| partition.name == "Windows system volume")
                {
                    partition.mount_point = Some(value.into());
                }
            }
            "bitlocker" if value.eq_ignore_ascii_case("on") || value == "1" => {
                inventory.encryption = EncryptionState::Enabled("BitLocker".into());
            }
            "bitlocker" if value.eq_ignore_ascii_case("off") || value == "0" => {
                inventory.encryption = EncryptionState::Disabled;
            }
            "esp" if value == "none" => {
                inventory.boot_hints.esp_present = Some(false);
            }
            "esp" => {
                let (location, size) = value.split_once('|').unwrap_or((value, ""));
                inventory.boot_hints.esp_present = Some(true);
                inventory.boot_hints.esp_location = Some(location.trim().into());
                inventory.boot_hints.esp_size_bytes = size.trim().parse().ok();
            }
            "recovery_partition" => {
                inventory.boot_hints.recovery_partition_present = Some(value == "1");
            }
            _ => {}
        }
    }

    let hints = &mut inventory.boot_hints;
    hints.unknowns.clear();
    if hints.esp_present.is_none() {
        hints
            .unknowns
            .push("ESP: Get-Partition returned nothing for this identity".into());
    }
    if inventory.firmware == FirmwareMode::Uefi
        && hints.esp_present == Some(true)
        && !hints
            .boot_managers
            .iter()
            .any(|item| item.starts_with("Windows Boot Manager"))
    {
        hints
            .boot_managers
            .push("Windows Boot Manager (inferred from a UEFI Windows install)".into());
    }
    hints.unknowns.push(
        "firmware boot entries, BootNext, and BCD: need administrative rights (SeSystemEnvironmentPrivilege); not queried"
            .into(),
    );
}

pub fn real_boot_changes_enabled() -> bool {
    cfg!(feature = "real-windows-boot")
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowsQemuSmokePlan {
    pub runtime_version: String,
    pub runtime_binary: PathBuf,
    pub firmware_code: PathBuf,
    pub firmware_vars_template: PathBuf,
    pub accelerator: String,
    pub memory_mb: u32,
    pub cpu_count: u32,
    pub network_enabled: bool,
    pub physical_disks_attached: bool,
    pub host_boot_changes: bool,
    pub typed_confirmation: String,
}

impl WindowsQemuSmokePlan {
    pub fn preview(&self) -> String {
        format!(
            "Disposable QEMU UEFI smoke plan\nRuntime: {} ({})\nFirmware: {}\nAccelerator: {}\nMemory: {} MiB\nCPUs: {}\nNetwork enabled: {}\nPhysical disks attached: {}\nHost boot changes: {}\nOS installer attached: false\nRAM boot verified by this smoke: false\nConfirmation phrase: {}\n",
            self.runtime_version,
            self.runtime_binary.display(),
            self.firmware_code.display(),
            self.accelerator,
            self.memory_mb,
            self.cpu_count,
            self.network_enabled,
            self.physical_disks_attached,
            self.host_boot_changes,
            self.typed_confirmation,
        )
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{\"runtime_version\":\"{}\",\"runtime_binary\":\"{}\",\"firmware_code\":\"{}\",\"firmware_vars_template\":\"{}\",\"accelerator\":\"{}\",\"memory_mb\":{},\"cpu_count\":{},\"network_enabled\":{},\"physical_disks_attached\":{},\"host_boot_changes\":{},\"os_installer_attached\":false,\"ram_boot_verified\":false,\"typed_confirmation\":\"{}\"}}",
            escape_json(&self.runtime_version),
            escape_json(&self.runtime_binary.display().to_string()),
            escape_json(&self.firmware_code.display().to_string()),
            escape_json(&self.firmware_vars_template.display().to_string()),
            escape_json(&self.accelerator),
            self.memory_mb,
            self.cpu_count,
            self.network_enabled,
            self.physical_disks_attached,
            self.host_boot_changes,
            escape_json(&self.typed_confirmation),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowsQemuSmokeReport {
    pub run_directory: PathBuf,
    pub report_path: PathBuf,
    pub runtime_version: String,
    pub qmp_status_observed: bool,
    pub uefi_firmware_initialized: bool,
    pub real_vm_executed: bool,
    pub ram_boot_verified: bool,
    pub network_enabled: bool,
    pub physical_disks_attached: bool,
    pub host_boot_changes: bool,
}

impl WindowsQemuSmokeReport {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"run_directory\":\"{}\",\"report_path\":\"{}\",\"runtime_version\":\"{}\",\"qmp_status_observed\":{},\"uefi_firmware_initialized\":{},\"real_vm_executed\":{},\"ram_boot_verified\":{},\"network_enabled\":{},\"physical_disks_attached\":{},\"host_boot_changes\":{}}}",
            escape_json(&self.run_directory.display().to_string()),
            escape_json(&self.report_path.display().to_string()),
            escape_json(&self.runtime_version),
            self.qmp_status_observed,
            self.uefi_firmware_initialized,
            self.real_vm_executed,
            self.ram_boot_verified,
            self.network_enabled,
            self.physical_disks_attached,
            self.host_boot_changes,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowsQemuNetbootPlan {
    pub runtime_version: String,
    pub kernel: PathBuf,
    pub initrd: PathBuf,
    pub kernel_sha256: String,
    pub initrd_sha256: String,
    pub trust_level: String,
    pub accelerator: String,
    pub memory_mb: u32,
    pub network_enabled: bool,
    pub physical_disks_attached: bool,
    pub host_boot_changes: bool,
    pub direct_kernel_boot: bool,
    pub full_installer_payload_in_ram: bool,
    pub typed_confirmation: String,
}

impl WindowsQemuNetbootPlan {
    pub fn preview(&self) -> String {
        format!(
            "Disposable Ubuntu netboot kernel/initrd plan\nRuntime: {}\nKernel: {}\nInitrd: {}\nTrust level: {}\nAccelerator: {}\nMemory: {} MiB\nNetwork enabled: {}\nPhysical disks attached: {}\nHost boot changes: {}\nDirect kernel boot (UEFI bypassed): {}\nFull installer payload in RAM: {}\nConfirmation phrase: {}\n",
            self.runtime_version,
            self.kernel.display(),
            self.initrd.display(),
            self.trust_level,
            self.accelerator,
            self.memory_mb,
            self.network_enabled,
            self.physical_disks_attached,
            self.host_boot_changes,
            self.direct_kernel_boot,
            self.full_installer_payload_in_ram,
            self.typed_confirmation,
        )
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{\"runtime_version\":\"{}\",\"kernel\":\"{}\",\"initrd\":\"{}\",\"kernel_sha256\":\"{}\",\"initrd_sha256\":\"{}\",\"trust_level\":\"{}\",\"accelerator\":\"{}\",\"memory_mb\":{},\"network_enabled\":{},\"physical_disks_attached\":{},\"host_boot_changes\":{},\"direct_kernel_boot\":{},\"uefi_firmware_initialized\":false,\"kernel_initrd_ram_resident\":false,\"full_installer_payload_in_ram\":{},\"typed_confirmation\":\"{}\"}}",
            escape_json(&self.runtime_version),
            escape_json(&self.kernel.display().to_string()),
            escape_json(&self.initrd.display().to_string()),
            self.kernel_sha256,
            self.initrd_sha256,
            escape_json(&self.trust_level),
            escape_json(&self.accelerator),
            self.memory_mb,
            self.network_enabled,
            self.physical_disks_attached,
            self.host_boot_changes,
            self.direct_kernel_boot,
            self.full_installer_payload_in_ram,
            escape_json(&self.typed_confirmation),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowsQemuNetbootReport {
    pub run_directory: PathBuf,
    pub report_path: PathBuf,
    pub serial_log_path: PathBuf,
    pub kernel_sha256: String,
    pub initrd_sha256: String,
    pub serial_sha256: String,
    pub linux_banner_observed: bool,
    pub initramfs_scripts_observed: bool,
    pub real_vm_executed: bool,
    pub direct_kernel_boot: bool,
    pub uefi_firmware_initialized: bool,
    pub kernel_initrd_ram_resident: bool,
    pub full_installer_payload_in_ram: bool,
    pub network_enabled: bool,
    pub physical_disks_attached: bool,
    pub host_boot_changes: bool,
    pub trust_level: String,
}

impl WindowsQemuNetbootReport {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"run_directory\":\"{}\",\"report_path\":\"{}\",\"serial_log_path\":\"{}\",\"kernel_sha256\":\"{}\",\"initrd_sha256\":\"{}\",\"serial_sha256\":\"{}\",\"linux_banner_observed\":{},\"initramfs_scripts_observed\":{},\"real_vm_executed\":{},\"direct_kernel_boot\":{},\"uefi_firmware_initialized\":{},\"kernel_initrd_ram_resident\":{},\"full_installer_payload_in_ram\":{},\"network_enabled\":{},\"physical_disks_attached\":{},\"host_boot_changes\":{},\"trust_level\":\"{}\"}}",
            escape_json(&self.run_directory.display().to_string()),
            escape_json(&self.report_path.display().to_string()),
            escape_json(&self.serial_log_path.display().to_string()),
            self.kernel_sha256,
            self.initrd_sha256,
            self.serial_sha256,
            self.linux_banner_observed,
            self.initramfs_scripts_observed,
            self.real_vm_executed,
            self.direct_kernel_boot,
            self.uefi_firmware_initialized,
            self.kernel_initrd_ram_resident,
            self.full_installer_payload_in_ram,
            self.network_enabled,
            self.physical_disks_attached,
            self.host_boot_changes,
            escape_json(&self.trust_level),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowsQemuFullRamPlan {
    pub runtime_version: String,
    pub artifact: PathBuf,
    pub artifact_sha256: String,
    pub artifact_size_bytes: u64,
    pub kernel: PathBuf,
    pub initrd: PathBuf,
    pub kernel_sha256: String,
    pub initrd_sha256: String,
    pub accelerator: String,
    pub memory_mb: u32,
    pub cpu_count: u32,
    pub recovery_source_url: String,
    pub guest_transport_https: bool,
    pub network_enabled: bool,
    pub physical_disks_attached: bool,
    pub virtual_install_disks_attached: bool,
    pub host_boot_changes: bool,
    pub direct_kernel_boot: bool,
    pub uefi_firmware_initialized: bool,
    pub full_installer_payload_in_ram: bool,
    pub typed_confirmation: String,
}

impl WindowsQemuFullRamPlan {
    pub fn preview(&self) -> String {
        format!(
            "Disposable Ubuntu full-ISO RAM plan\nRuntime: {}\nArtifact: {}\nArtifact SHA-256: {}\nArtifact size: {} bytes\nKernel: {}\nInitrd: {}\nAccelerator: {}\nMemory: {} MiB\nCPUs: {}\nRecovery source: {}\nGuest transport is HTTPS: {}\nNetwork enabled: {}\nPhysical disks attached: {}\nVirtual install disks attached: {}\nHost boot changes: {}\nDirect kernel boot (UEFI bypassed): {}\nUEFI firmware initialized: {}\nFull installer payload in RAM (requires run evidence): {}\nConfirmation phrase: {}\n",
            self.runtime_version,
            self.artifact.display(),
            self.artifact_sha256,
            self.artifact_size_bytes,
            self.kernel.display(),
            self.initrd.display(),
            self.accelerator,
            self.memory_mb,
            self.cpu_count,
            self.recovery_source_url,
            self.guest_transport_https,
            self.network_enabled,
            self.physical_disks_attached,
            self.virtual_install_disks_attached,
            self.host_boot_changes,
            self.direct_kernel_boot,
            self.uefi_firmware_initialized,
            self.full_installer_payload_in_ram,
            self.typed_confirmation,
        )
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{\"runtime_version\":\"{}\",\"artifact\":\"{}\",\"artifact_sha256\":\"{}\",\"artifact_size_bytes\":{},\"kernel\":\"{}\",\"initrd\":\"{}\",\"kernel_sha256\":\"{}\",\"initrd_sha256\":\"{}\",\"accelerator\":\"{}\",\"memory_mb\":{},\"cpu_count\":{},\"recovery_source_url\":\"{}\",\"guest_transport_https\":{},\"network_enabled\":{},\"physical_disks_attached\":{},\"virtual_install_disks_attached\":{},\"host_boot_changes\":{},\"direct_kernel_boot\":{},\"uefi_firmware_initialized\":{},\"full_installer_payload_in_ram\":{},\"typed_confirmation\":\"{}\"}}",
            escape_json(&self.runtime_version),
            escape_json(&self.artifact.display().to_string()),
            self.artifact_sha256,
            self.artifact_size_bytes,
            escape_json(&self.kernel.display().to_string()),
            escape_json(&self.initrd.display().to_string()),
            self.kernel_sha256,
            self.initrd_sha256,
            escape_json(&self.accelerator),
            self.memory_mb,
            self.cpu_count,
            escape_json(&self.recovery_source_url),
            self.guest_transport_https,
            self.network_enabled,
            self.physical_disks_attached,
            self.virtual_install_disks_attached,
            self.host_boot_changes,
            self.direct_kernel_boot,
            self.uefi_firmware_initialized,
            self.full_installer_payload_in_ram,
            escape_json(&self.typed_confirmation),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowsQemuFullRamReport {
    pub run_directory: PathBuf,
    pub report_path: PathBuf,
    pub serial_log_path: PathBuf,
    pub qmp_log_path: PathBuf,
    pub artifact_sha256: String,
    pub artifact_size_bytes: u64,
    pub kernel_sha256: String,
    pub initrd_sha256: String,
    pub serial_sha256: String,
    pub linux_banner_observed: bool,
    pub iso_download_started: bool,
    pub iso_download_complete: bool,
    pub source_stopped_after_download: bool,
    pub systemd_started_after_source_stop: bool,
    pub subiquity_payload_mounted_after_source_stop: bool,
    pub qmp_running_observed: bool,
    pub qmp_empty_block_list_observed: bool,
    pub real_vm_executed: bool,
    pub direct_kernel_boot: bool,
    pub uefi_firmware_initialized: bool,
    pub full_installer_payload_in_ram: bool,
    pub guest_transport_https: bool,
    pub network_enabled: bool,
    pub physical_disks_attached: bool,
    pub virtual_install_disks_attached: bool,
    pub host_boot_changes: bool,
    pub fallback_boot_observed: bool,
    pub trust_level: String,
}

impl WindowsQemuFullRamReport {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"run_directory\":\"{}\",\"report_path\":\"{}\",\"serial_log_path\":\"{}\",\"qmp_log_path\":\"{}\",\"artifact_sha256\":\"{}\",\"artifact_size_bytes\":{},\"kernel_sha256\":\"{}\",\"initrd_sha256\":\"{}\",\"serial_sha256\":\"{}\",\"linux_banner_observed\":{},\"iso_download_started\":{},\"iso_download_complete\":{},\"source_stopped_after_download\":{},\"systemd_started_after_source_stop\":{},\"subiquity_payload_mounted_after_source_stop\":{},\"qmp_running_observed\":{},\"qmp_empty_block_list_observed\":{},\"real_vm_executed\":{},\"direct_kernel_boot\":{},\"uefi_firmware_initialized\":{},\"full_installer_payload_in_ram\":{},\"guest_transport_https\":{},\"network_enabled\":{},\"physical_disks_attached\":{},\"virtual_install_disks_attached\":{},\"host_boot_changes\":{},\"fallback_boot_observed\":{},\"trust_level\":\"{}\"}}",
            escape_json(&self.run_directory.display().to_string()),
            escape_json(&self.report_path.display().to_string()),
            escape_json(&self.serial_log_path.display().to_string()),
            escape_json(&self.qmp_log_path.display().to_string()),
            self.artifact_sha256,
            self.artifact_size_bytes,
            self.kernel_sha256,
            self.initrd_sha256,
            self.serial_sha256,
            self.linux_banner_observed,
            self.iso_download_started,
            self.iso_download_complete,
            self.source_stopped_after_download,
            self.systemd_started_after_source_stop,
            self.subiquity_payload_mounted_after_source_stop,
            self.qmp_running_observed,
            self.qmp_empty_block_list_observed,
            self.real_vm_executed,
            self.direct_kernel_boot,
            self.uefi_firmware_initialized,
            self.full_installer_payload_in_ram,
            self.guest_transport_https,
            self.network_enabled,
            self.physical_disks_attached,
            self.virtual_install_disks_attached,
            self.host_boot_changes,
            self.fallback_boot_observed,
            escape_json(&self.trust_level),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowsQemuUefiFullRamPlan {
    pub full_ram: WindowsQemuFullRamPlan,
    pub firmware_code: PathBuf,
    pub firmware_vars_template: PathBuf,
    pub bootx64: PathBuf,
    pub grubx64: PathBuf,
    pub mmx64: PathBuf,
    pub bootx64_sha256: String,
    pub grubx64_sha256: String,
    pub mmx64_sha256: String,
    pub secure_boot_enabled: bool,
    pub detachable_read_only_boot_source: bool,
    pub typed_confirmation: String,
}

impl WindowsQemuUefiFullRamPlan {
    pub fn preview(&self) -> String {
        format!(
            "Disposable Ubuntu UEFI + full-ISO RAM plan\n{}Firmware code: {}\nFirmware variables template: {}\nOfficial BOOTX64.EFI: {}\nOfficial grubx64.efi: {}\nOfficial mmx64.efi: {}\nSecure Boot enabled: {}\nDetachable read-only FAT boot source: {}\nConfirmation phrase: {}\n",
            self.full_ram.preview(),
            self.firmware_code.display(),
            self.firmware_vars_template.display(),
            self.bootx64.display(),
            self.grubx64.display(),
            self.mmx64.display(),
            self.secure_boot_enabled,
            self.detachable_read_only_boot_source,
            self.typed_confirmation,
        )
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{\"full_ram\":{},\"firmware_code\":\"{}\",\"firmware_vars_template\":\"{}\",\"bootx64\":\"{}\",\"grubx64\":\"{}\",\"mmx64\":\"{}\",\"bootx64_sha256\":\"{}\",\"grubx64_sha256\":\"{}\",\"mmx64_sha256\":\"{}\",\"secure_boot_enabled\":{},\"detachable_read_only_boot_source\":{},\"typed_confirmation\":\"{}\"}}",
            self.full_ram.to_json(),
            escape_json(&self.firmware_code.display().to_string()),
            escape_json(&self.firmware_vars_template.display().to_string()),
            escape_json(&self.bootx64.display().to_string()),
            escape_json(&self.grubx64.display().to_string()),
            escape_json(&self.mmx64.display().to_string()),
            self.bootx64_sha256,
            self.grubx64_sha256,
            self.mmx64_sha256,
            self.secure_boot_enabled,
            self.detachable_read_only_boot_source,
            escape_json(&self.typed_confirmation),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowsQemuUefiFullRamReport {
    pub run_directory: PathBuf,
    pub report_path: PathBuf,
    pub serial_log_path: PathBuf,
    pub qmp_log_path: PathBuf,
    pub artifact_sha256: String,
    pub artifact_size_bytes: u64,
    pub bootx64_sha256: String,
    pub grubx64_sha256: String,
    pub mmx64_sha256: String,
    pub serial_sha256: String,
    pub real_vm_executed: bool,
    pub direct_kernel_boot: bool,
    pub uefi_firmware_initialized: bool,
    pub secure_boot_enabled: bool,
    pub official_efi_assets_verified: bool,
    pub boot_source_device_deleted: bool,
    pub boot_source_block_node_deleted: bool,
    pub iso_download_complete: bool,
    pub http_source_stopped_after_download: bool,
    pub systemd_started_after_http_stop: bool,
    pub subiquity_payload_mounted_after_http_stop: bool,
    pub serial_getty_started_after_http_stop: bool,
    pub qmp_running_observed: bool,
    pub qmp_firmware_only_block_list_observed: bool,
    pub full_installer_payload_in_ram: bool,
    pub guest_transport_https: bool,
    pub network_enabled: bool,
    pub physical_disks_attached: bool,
    pub virtual_install_disks_attached: bool,
    pub host_boot_changes: bool,
    pub fallback_boot_observed: bool,
    pub trust_level: String,
}

impl WindowsQemuUefiFullRamReport {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"run_directory\":\"{}\",\"report_path\":\"{}\",\"serial_log_path\":\"{}\",\"qmp_log_path\":\"{}\",\"artifact_sha256\":\"{}\",\"artifact_size_bytes\":{},\"bootx64_sha256\":\"{}\",\"grubx64_sha256\":\"{}\",\"mmx64_sha256\":\"{}\",\"serial_sha256\":\"{}\",\"real_vm_executed\":{},\"direct_kernel_boot\":{},\"uefi_firmware_initialized\":{},\"secure_boot_enabled\":{},\"official_efi_assets_verified\":{},\"boot_source_device_deleted\":{},\"boot_source_block_node_deleted\":{},\"iso_download_complete\":{},\"http_source_stopped_after_download\":{},\"systemd_started_after_http_stop\":{},\"subiquity_payload_mounted_after_http_stop\":{},\"serial_getty_started_after_http_stop\":{},\"qmp_running_observed\":{},\"qmp_firmware_only_block_list_observed\":{},\"full_installer_payload_in_ram\":{},\"guest_transport_https\":{},\"network_enabled\":{},\"physical_disks_attached\":{},\"virtual_install_disks_attached\":{},\"host_boot_changes\":{},\"fallback_boot_observed\":{},\"trust_level\":\"{}\"}}",
            escape_json(&self.run_directory.display().to_string()),
            escape_json(&self.report_path.display().to_string()),
            escape_json(&self.serial_log_path.display().to_string()),
            escape_json(&self.qmp_log_path.display().to_string()),
            self.artifact_sha256,
            self.artifact_size_bytes,
            self.bootx64_sha256,
            self.grubx64_sha256,
            self.mmx64_sha256,
            self.serial_sha256,
            self.real_vm_executed,
            self.direct_kernel_boot,
            self.uefi_firmware_initialized,
            self.secure_boot_enabled,
            self.official_efi_assets_verified,
            self.boot_source_device_deleted,
            self.boot_source_block_node_deleted,
            self.iso_download_complete,
            self.http_source_stopped_after_download,
            self.systemd_started_after_http_stop,
            self.subiquity_payload_mounted_after_http_stop,
            self.serial_getty_started_after_http_stop,
            self.qmp_running_observed,
            self.qmp_firmware_only_block_list_observed,
            self.full_installer_payload_in_ram,
            self.guest_transport_https,
            self.network_enabled,
            self.physical_disks_attached,
            self.virtual_install_disks_attached,
            self.host_boot_changes,
            self.fallback_boot_observed,
            escape_json(&self.trust_level),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowsQemuCurrentOsPlan {
    pub runtime_version: String,
    pub runtime_root: PathBuf,
    pub firmware_code: PathBuf,
    pub firmware_vars_template: PathBuf,
    pub bootx64: PathBuf,
    pub grubx64: PathBuf,
    pub mmx64: PathBuf,
    pub kernel: PathBuf,
    pub initrd: PathBuf,
    pub root_disk_size_bytes: u64,
    pub memory_mb: u32,
    pub cpu_count: u32,
    pub network_enabled: bool,
    pub physical_disks_attached: bool,
    pub host_boot_changes: bool,
    pub uses_disposable_guest_disk: bool,
    pub secure_boot_enabled: bool,
    pub typed_confirmation: String,
}

impl WindowsQemuCurrentOsPlan {
    pub fn preview(&self) -> String {
        format!(
            "Disposable current-OS UEFI baseline plan\nRuntime: {}\nRoot filesystem source: {}\nFirmware: {}\nKernel: {}\nInitrd: {}\nDisposable root disk: {} bytes\nMemory: {} MiB\nCPUs: {}\nNetwork enabled: {}\nPhysical disks attached: {}\nHost boot changes: {}\nSecure Boot enabled: {}\nPurpose: prove the same disposable Linux guest boots before and after with the same guest disk and UEFI variable store; this does not yet prove installer fallback or BootNext.\nConfirmation phrase: {}\n",
            self.runtime_version,
            self.runtime_root.display(),
            self.firmware_code.display(),
            self.kernel.display(),
            self.initrd.display(),
            self.root_disk_size_bytes,
            self.memory_mb,
            self.cpu_count,
            self.network_enabled,
            self.physical_disks_attached,
            self.host_boot_changes,
            self.secure_boot_enabled,
            self.typed_confirmation,
        )
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{\"runtime_version\":\"{}\",\"runtime_root\":\"{}\",\"firmware_code\":\"{}\",\"firmware_vars_template\":\"{}\",\"bootx64\":\"{}\",\"grubx64\":\"{}\",\"mmx64\":\"{}\",\"kernel\":\"{}\",\"initrd\":\"{}\",\"root_disk_size_bytes\":{},\"memory_mb\":{},\"cpu_count\":{},\"network_enabled\":{},\"physical_disks_attached\":{},\"host_boot_changes\":{},\"uses_disposable_guest_disk\":{},\"secure_boot_enabled\":{},\"installer_fallback_proven\":false,\"uefi_bootnext_proven\":false,\"typed_confirmation\":\"{}\"}}",
            escape_json(&self.runtime_version),
            escape_json(&self.runtime_root.display().to_string()),
            escape_json(&self.firmware_code.display().to_string()),
            escape_json(&self.firmware_vars_template.display().to_string()),
            escape_json(&self.bootx64.display().to_string()),
            escape_json(&self.grubx64.display().to_string()),
            escape_json(&self.mmx64.display().to_string()),
            escape_json(&self.kernel.display().to_string()),
            escape_json(&self.initrd.display().to_string()),
            self.root_disk_size_bytes,
            self.memory_mb,
            self.cpu_count,
            self.network_enabled,
            self.physical_disks_attached,
            self.host_boot_changes,
            self.uses_disposable_guest_disk,
            self.secure_boot_enabled,
            escape_json(&self.typed_confirmation),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowsQemuCurrentOsReport {
    pub run_directory: PathBuf,
    pub report_path: PathBuf,
    pub first_serial_log_path: PathBuf,
    pub second_serial_log_path: PathBuf,
    pub root_disk_path: PathBuf,
    pub root_disk_sha256: String,
    pub first_boot_observed: bool,
    pub second_boot_observed: bool,
    pub same_guest_disk_reused: bool,
    pub same_uefi_variable_store_reused: bool,
    pub real_vm_executed: bool,
    pub uefi_firmware_initialized: bool,
    pub current_os_userspace_started: bool,
    pub network_enabled: bool,
    pub physical_disks_attached: bool,
    pub host_boot_changes: bool,
    pub installer_fallback_proven: bool,
    pub uefi_bootnext_proven: bool,
    pub power_loss_matrix_complete: bool,
    pub trust_level: String,
}

impl WindowsQemuCurrentOsReport {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"run_directory\":\"{}\",\"report_path\":\"{}\",\"first_serial_log_path\":\"{}\",\"second_serial_log_path\":\"{}\",\"root_disk_path\":\"{}\",\"root_disk_sha256\":\"{}\",\"first_boot_observed\":{},\"second_boot_observed\":{},\"same_guest_disk_reused\":{},\"same_uefi_variable_store_reused\":{},\"real_vm_executed\":{},\"uefi_firmware_initialized\":{},\"current_os_userspace_started\":{},\"network_enabled\":{},\"physical_disks_attached\":{},\"host_boot_changes\":{},\"installer_fallback_proven\":{},\"uefi_bootnext_proven\":{},\"power_loss_matrix_complete\":{},\"trust_level\":\"{}\"}}",
            escape_json(&self.run_directory.display().to_string()),
            escape_json(&self.report_path.display().to_string()),
            escape_json(&self.first_serial_log_path.display().to_string()),
            escape_json(&self.second_serial_log_path.display().to_string()),
            escape_json(&self.root_disk_path.display().to_string()),
            self.root_disk_sha256,
            self.first_boot_observed,
            self.second_boot_observed,
            self.same_guest_disk_reused,
            self.same_uefi_variable_store_reused,
            self.real_vm_executed,
            self.uefi_firmware_initialized,
            self.current_os_userspace_started,
            self.network_enabled,
            self.physical_disks_attached,
            self.host_boot_changes,
            self.installer_fallback_proven,
            self.uefi_bootnext_proven,
            self.power_loss_matrix_complete,
            escape_json(&self.trust_level),
        )
    }
}

#[cfg(target_os = "windows")]
const UBUNTU_NETBOOT_KERNEL_SHA256: &str =
    "d3f1cc6693d93fcf6663cd1e04d31031f41e8abd0c14b0ca953ef524a62e4489";
#[cfg(target_os = "windows")]
const UBUNTU_NETBOOT_INITRD_SHA256: &str =
    "82793369fda2356c7344bd37af2453ad56d797d49c01b9d7b3f2a85ce8178d86";
#[cfg(target_os = "windows")]
const UBUNTU_SERVER_ISO_SHA256: &str =
    "e907d92eeec9df64163a7e454cbc8d7755e8ddc7ed42f99dbc80c40f1a138433";
#[cfg(target_os = "windows")]
const UBUNTU_SERVER_ISO_SIZE: u64 = 3_405_469_696;
#[cfg(target_os = "windows")]
const UBUNTU_SERVER_KERNEL_SHA256: &str =
    "528d909745819a1464848a2c4d91c609db4f54b33ccae7069aad4178fb34606f";
#[cfg(target_os = "windows")]
const UBUNTU_SERVER_INITRD_SHA256: &str =
    "b91245030e13a1dc835205b77561323b26bea1cbbf4f5ed43aa0cfff08d4e353";
#[cfg(target_os = "windows")]
const UBUNTU_SERVER_BOOTX64_SHA256: &str =
    "6fe6e1bcbe6cf6baec8e056d40361ca1aa715cc04ddcc2855351de060b84350b";
#[cfg(target_os = "windows")]
const UBUNTU_SERVER_GRUBX64_SHA256: &str =
    "52b8b3503d3efabfac8793f07e1db5d22c51d90ebb5b6319962fab5d02f49956";
#[cfg(target_os = "windows")]
const UBUNTU_SERVER_MMX64_SHA256: &str =
    "d2fa8e52fddc99dad94a0009fee23cb2478c28373b777d50b2f784eb4e96f88e";
#[cfg(target_os = "windows")]
const UBUNTU_SERVER_RECOVERY_PORT: u16 = 18_080;
#[cfg(target_os = "windows")]
const DISPOSABLE_CURRENT_OS_DISK_SIZE: u64 = 536_870_912;
#[cfg(target_os = "windows")]
const DISPOSABLE_CURRENT_OS_MARKER: &str = "NOUSB_DISPOSABLE_CURRENT_OS_READY";

#[cfg(target_os = "windows")]
struct OwnedChild {
    child: Option<Child>,
}

#[cfg(target_os = "windows")]
impl OwnedChild {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    fn child_mut(&mut self) -> Result<&mut Child, NoUsbError> {
        self.child
            .as_mut()
            .ok_or_else(|| NoUsbError::Io("owned child process is no longer available".into()))
    }

    fn stop(&mut self) -> Result<Output, NoUsbError> {
        let mut child = self
            .child
            .take()
            .ok_or_else(|| NoUsbError::Io("owned child process is no longer available".into()))?;
        if child.try_wait()?.is_none() {
            child.kill()?;
        }
        Ok(child.wait_with_output()?)
    }

    fn wait_with_output(&mut self) -> Result<Output, NoUsbError> {
        let child = self
            .child
            .take()
            .ok_or_else(|| NoUsbError::Io("owned child process is no longer available".into()))?;
        Ok(child.wait_with_output()?)
    }
}

#[cfg(target_os = "windows")]
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[cfg(target_os = "windows")]
fn latest_ubuntu_server_staging_bundle(base: &Path) -> Result<PathBuf, NoUsbError> {
    let staging_root = base
        .join(".nousb")
        .join("staging")
        .join("ubuntu-24.04-server");
    let mut latest = None;
    for entry in fs::read_dir(&staging_root).map_err(|error| {
        NoUsbError::ArtifactUnavailable(format!(
            "Ubuntu Server staging root {} is unavailable: {error}",
            staging_root.display()
        ))
    })? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let modified = entry.metadata()?.modified()?;
        if latest
            .as_ref()
            .map(|(current, _): &(SystemTime, PathBuf)| modified > *current)
            .unwrap_or(true)
        {
            latest = Some((modified, entry.path()));
        }
    }
    latest.map(|(_, path)| path).ok_or_else(|| {
        NoUsbError::ArtifactUnavailable(format!(
            "no Ubuntu Server staging bundle exists under {}; run `nousb staging create ubuntu-24.04-server <verified-iso>` first",
            staging_root.display()
        ))
    })
}

#[cfg(target_os = "windows")]
fn latest_ubuntu_server_staging_assets(base: &Path) -> Result<(PathBuf, PathBuf), NoUsbError> {
    let bundle = latest_ubuntu_server_staging_bundle(base)?;
    let kernel = bundle.join("assets").join("casper").join("vmlinuz");
    let initrd = bundle.join("assets").join("casper").join("initrd");
    if !kernel.is_file() || !initrd.is_file() {
        return Err(NoUsbError::ArtifactUnavailable(format!(
            "latest Ubuntu Server staging bundle {} lacks kernel/initrd assets",
            bundle.display()
        )));
    }
    Ok((kernel, initrd))
}

#[cfg(target_os = "windows")]
fn project_qemu_root(base_dir: &Path) -> Result<PathBuf, NoUsbError> {
    let canonical = fs::canonicalize(base_dir).map_err(|error| {
        NoUsbError::Io(format!(
            "cannot resolve project directory {}: {error}",
            base_dir.display()
        ))
    })?;
    let canonical_text = canonical.display().to_string();
    let base = PathBuf::from(
        canonical_text
            .strip_prefix(r"\\?\")
            .unwrap_or(&canonical_text),
    );
    Ok(base.join(".nousb").join("tools").join("qemu-alpine-root"))
}

#[cfg(target_os = "windows")]
pub fn windows_qemu_smoke_plan(base_dir: &Path) -> Result<WindowsQemuSmokePlan, NoUsbError> {
    let runtime_root = project_qemu_root(base_dir)?;
    let runtime_binary = runtime_root.join("usr/bin/qemu-system-x86_64");
    let firmware_code = runtime_root.join("usr/share/OVMF/OVMF_CODE.fd");
    let firmware_vars_template = runtime_root.join("usr/share/OVMF/OVMF_VARS.fd");
    for path in [&runtime_binary, &firmware_code, &firmware_vars_template] {
        if !path.is_file() {
            return Err(NoUsbError::ArtifactUnavailable(format!(
                "project-local QEMU runtime is incomplete; missing {}",
                path.display()
            )));
        }
    }
    Ok(WindowsQemuSmokePlan {
        runtime_version: "10.1.5-alpine-v3.23".into(),
        runtime_binary,
        firmware_code,
        firmware_vars_template,
        accelerator: "tcg".into(),
        memory_mb: 256,
        cpu_count: 1,
        network_enabled: false,
        physical_disks_attached: false,
        host_boot_changes: false,
        typed_confirmation: "RUN DISPOSABLE QEMU UEFI SMOKE".into(),
    })
}

#[cfg(not(target_os = "windows"))]
pub fn windows_qemu_smoke_plan(
    _base_dir: &std::path::Path,
) -> Result<WindowsQemuSmokePlan, NoUsbError> {
    Err(NoUsbError::ArtifactUnavailable(
        "the WSL-backed QEMU smoke harness is only available on Windows".into(),
    ))
}

#[cfg(target_os = "windows")]
pub fn windows_qemu_netboot_plan(base_dir: &Path) -> Result<WindowsQemuNetbootPlan, NoUsbError> {
    let _runtime = windows_qemu_smoke_plan(base_dir)?;
    let base = fs::canonicalize(base_dir)?;
    let input_root = base
        .join(".nousb")
        .join("vm-inputs")
        .join("transport-only")
        .join("ubuntu-24.04.4-netboot")
        .join("extracted")
        .join("amd64");
    let kernel = input_root.join("linux");
    let initrd = input_root.join("initrd");
    if fs::metadata(&kernel).map(|item| item.len()).unwrap_or(0) != 16_738_376 {
        return Err(NoUsbError::ArtifactUnavailable(format!(
            "Ubuntu rehearsal kernel is missing or has the wrong size: {}",
            kernel.display()
        )));
    }
    if fs::metadata(&initrd).map(|item| item.len()).unwrap_or(0) != 79_072_248 {
        return Err(NoUsbError::ArtifactUnavailable(format!(
            "Ubuntu rehearsal initrd is missing or has the wrong size: {}",
            initrd.display()
        )));
    }
    let kernel_sha256 = sha256_file(&kernel)?;
    let initrd_sha256 = sha256_file(&initrd)?;
    if kernel_sha256 != UBUNTU_NETBOOT_KERNEL_SHA256
        || initrd_sha256 != UBUNTU_NETBOOT_INITRD_SHA256
    {
        return Err(NoUsbError::Verification(
            "Ubuntu netboot rehearsal assets differ from the observed transport-only digests"
                .into(),
        ));
    }
    Ok(WindowsQemuNetbootPlan {
        runtime_version: "10.1.5-alpine-v3.23".into(),
        kernel,
        initrd,
        kernel_sha256,
        initrd_sha256,
        trust_level: "official-https-observed-digest-transport-only-not-installable".into(),
        accelerator: "tcg".into(),
        memory_mb: 2_048,
        network_enabled: false,
        physical_disks_attached: false,
        host_boot_changes: false,
        direct_kernel_boot: true,
        full_installer_payload_in_ram: false,
        typed_confirmation: "RUN DISPOSABLE UBUNTU NETBOOT RAM REHEARSAL".into(),
    })
}

#[cfg(target_os = "windows")]
pub fn windows_qemu_full_ram_plan(base_dir: &Path) -> Result<WindowsQemuFullRamPlan, NoUsbError> {
    let runtime = windows_qemu_smoke_plan(base_dir)?;
    let base = fs::canonicalize(base_dir)?;
    let artifact = base
        .join(".nousb")
        .join("artifacts")
        .join("ubuntu-24.04-server")
        .join("ubuntu-24.04.4-live-server-amd64.iso");
    if !artifact.is_file() {
        return Err(NoUsbError::ArtifactUnavailable(format!(
            "pinned Ubuntu Server ISO is missing: {}; run `nousb image download ubuntu-24.04-server` first",
            artifact.display()
        )));
    }
    let manifest = verify_artifact("ubuntu-24.04-server", &artifact)?;
    if manifest.sha256 != UBUNTU_SERVER_ISO_SHA256 || manifest.size_bytes != UBUNTU_SERVER_ISO_SIZE
    {
        return Err(NoUsbError::Verification(
            "Ubuntu Server manifest no longer matches the pinned full-RAM rehearsal input".into(),
        ));
    }
    let (kernel, initrd) = latest_ubuntu_server_staging_assets(&base)?;
    let kernel_sha256 = sha256_file(&kernel)?;
    let initrd_sha256 = sha256_file(&initrd)?;
    if kernel_sha256 != UBUNTU_SERVER_KERNEL_SHA256 || initrd_sha256 != UBUNTU_SERVER_INITRD_SHA256
    {
        return Err(NoUsbError::Verification(
            "staged Ubuntu Server kernel/initrd differ from the pinned ISO assets".into(),
        ));
    }
    Ok(WindowsQemuFullRamPlan {
        runtime_version: runtime.runtime_version,
        artifact,
        artifact_sha256: manifest.sha256,
        artifact_size_bytes: manifest.size_bytes,
        kernel,
        initrd,
        kernel_sha256,
        initrd_sha256,
        accelerator: "tcg".into(),
        memory_mb: 8_192,
        cpu_count: 2,
        recovery_source_url: format!(
            "http://10.0.2.2:{UBUNTU_SERVER_RECOVERY_PORT}/{}",
            manifest.filename
        ),
        guest_transport_https: false,
        network_enabled: true,
        physical_disks_attached: false,
        virtual_install_disks_attached: false,
        host_boot_changes: false,
        direct_kernel_boot: true,
        uefi_firmware_initialized: false,
        full_installer_payload_in_ram: false,
        typed_confirmation: "RUN DISPOSABLE UBUNTU FULL ISO RAM REHEARSAL".into(),
    })
}

#[cfg(target_os = "windows")]
pub fn windows_qemu_uefi_full_ram_plan(
    base_dir: &Path,
) -> Result<WindowsQemuUefiFullRamPlan, NoUsbError> {
    let runtime = windows_qemu_smoke_plan(base_dir)?;
    let base = fs::canonicalize(base_dir)?;
    let bundle = latest_ubuntu_server_staging_bundle(&base)?;
    let efi_root = bundle.join("assets").join("EFI").join("BOOT");
    let bootx64 = efi_root.join("BOOTX64.EFI");
    let grubx64 = efi_root.join("grubx64.efi");
    let mmx64 = efi_root.join("mmx64.efi");
    for path in [&bootx64, &grubx64, &mmx64] {
        if !path.is_file() {
            return Err(NoUsbError::ArtifactUnavailable(format!(
                "latest Ubuntu Server staging bundle lacks official EFI asset {}",
                path.display()
            )));
        }
    }
    let bootx64_sha256 = sha256_file(&bootx64)?;
    let grubx64_sha256 = sha256_file(&grubx64)?;
    let mmx64_sha256 = sha256_file(&mmx64)?;
    if bootx64_sha256 != UBUNTU_SERVER_BOOTX64_SHA256
        || grubx64_sha256 != UBUNTU_SERVER_GRUBX64_SHA256
        || mmx64_sha256 != UBUNTU_SERVER_MMX64_SHA256
    {
        return Err(NoUsbError::Verification(
            "staged Ubuntu Server EFI assets differ from the pinned ISO assets".into(),
        ));
    }
    let typed_confirmation = "RUN DISPOSABLE UBUNTU UEFI FULL ISO RAM REHEARSAL".to_string();
    let mut full_ram = windows_qemu_full_ram_plan(&base)?;
    full_ram.direct_kernel_boot = false;
    full_ram.uefi_firmware_initialized = false;
    full_ram.full_installer_payload_in_ram = false;
    full_ram.typed_confirmation = typed_confirmation.clone();
    Ok(WindowsQemuUefiFullRamPlan {
        full_ram,
        firmware_code: runtime.firmware_code,
        firmware_vars_template: runtime.firmware_vars_template,
        bootx64,
        grubx64,
        mmx64,
        bootx64_sha256,
        grubx64_sha256,
        mmx64_sha256,
        secure_boot_enabled: false,
        detachable_read_only_boot_source: true,
        typed_confirmation,
    })
}

#[cfg(target_os = "windows")]
pub fn windows_qemu_current_os_plan(
    base_dir: &Path,
) -> Result<WindowsQemuCurrentOsPlan, NoUsbError> {
    let runtime = windows_qemu_smoke_plan(base_dir)?;
    let uefi = windows_qemu_uefi_full_ram_plan(base_dir)?;
    let runtime_root = project_qemu_root(base_dir)?;
    let busybox = runtime_root.join("bin").join("busybox");
    if !busybox.is_file() {
        return Err(NoUsbError::ArtifactUnavailable(format!(
            "project-local runtime cannot seed a disposable current OS; missing {}",
            busybox.display()
        )));
    }
    Ok(WindowsQemuCurrentOsPlan {
        runtime_version: runtime.runtime_version,
        runtime_root,
        firmware_code: runtime.firmware_code,
        firmware_vars_template: runtime.firmware_vars_template,
        bootx64: uefi.bootx64,
        grubx64: uefi.grubx64,
        mmx64: uefi.mmx64,
        kernel: uefi.full_ram.kernel,
        initrd: uefi.full_ram.initrd,
        root_disk_size_bytes: DISPOSABLE_CURRENT_OS_DISK_SIZE,
        memory_mb: 1_024,
        cpu_count: 1,
        network_enabled: false,
        physical_disks_attached: false,
        host_boot_changes: false,
        uses_disposable_guest_disk: true,
        secure_boot_enabled: false,
        typed_confirmation: "RUN DISPOSABLE CURRENT OS UEFI BASELINE".into(),
    })
}

#[cfg(not(target_os = "windows"))]
pub fn windows_qemu_uefi_full_ram_plan(
    _base_dir: &std::path::Path,
) -> Result<WindowsQemuUefiFullRamPlan, NoUsbError> {
    Err(NoUsbError::ArtifactUnavailable(
        "the WSL-backed Ubuntu UEFI full-ISO RAM rehearsal is only available on Windows".into(),
    ))
}

#[cfg(not(target_os = "windows"))]
pub fn windows_qemu_current_os_plan(
    _base_dir: &std::path::Path,
) -> Result<WindowsQemuCurrentOsPlan, NoUsbError> {
    Err(NoUsbError::ArtifactUnavailable(
        "the WSL-backed disposable current-OS baseline is only available on Windows".into(),
    ))
}

#[cfg(not(target_os = "windows"))]
pub fn windows_qemu_full_ram_plan(
    _base_dir: &std::path::Path,
) -> Result<WindowsQemuFullRamPlan, NoUsbError> {
    Err(NoUsbError::ArtifactUnavailable(
        "the WSL-backed Ubuntu full-ISO RAM rehearsal is only available on Windows".into(),
    ))
}

#[cfg(not(target_os = "windows"))]
pub fn windows_qemu_netboot_plan(
    _base_dir: &std::path::Path,
) -> Result<WindowsQemuNetbootPlan, NoUsbError> {
    Err(NoUsbError::ArtifactUnavailable(
        "the WSL-backed Ubuntu netboot rehearsal is only available on Windows".into(),
    ))
}

#[cfg(target_os = "windows")]
fn windows_to_docker_wsl_path(path: &Path) -> Result<String, NoUsbError> {
    let raw_value = path.display().to_string();
    let value = raw_value
        .strip_prefix(r"\\?\")
        .unwrap_or(&raw_value)
        .to_string();
    let bytes = value.as_bytes();
    if bytes.len() < 3 || bytes[1] != b':' || (bytes[2] != b'\\' && bytes[2] != b'/') {
        return Err(NoUsbError::InvalidInput(format!(
            "Docker Desktop WSL path conversion requires a local drive path, got {value}"
        )));
    }
    let drive = (bytes[0] as char).to_ascii_lowercase();
    let tail = value[3..].replace('\\', "/");
    Ok(format!("/mnt/host/{drive}/{tail}"))
}

#[cfg(target_os = "windows")]
fn copy_create_new(source: &Path, destination: &Path) -> Result<(), NoUsbError> {
    let mut input = File::open(source)?;
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)?;
    io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn write_create_new(path: &Path, contents: &[u8]) -> Result<(), NoUsbError> {
    let mut output = OpenOptions::new().create_new(true).write(true).open(path)?;
    output.write_all(contents)?;
    output.sync_all()?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn create_uefi_boot_source(
    run_directory: &Path,
    plan: &WindowsQemuUefiFullRamPlan,
) -> Result<PathBuf, NoUsbError> {
    let root = run_directory.join("uefi-boot-source");
    let efi = root.join("EFI").join("BOOT");
    let casper = root.join("casper");
    let boot_grub = root.join("boot").join("grub");
    let root_grub = root.join("grub");
    fs::create_dir(&root)?;
    fs::create_dir_all(&efi)?;
    fs::create_dir(&casper)?;
    fs::create_dir_all(&boot_grub)?;
    fs::create_dir(&root_grub)?;
    copy_create_new(&plan.bootx64, &efi.join("BOOTX64.EFI"))?;
    copy_create_new(&plan.grubx64, &efi.join("grubx64.efi"))?;
    copy_create_new(&plan.mmx64, &efi.join("mmx64.efi"))?;
    copy_create_new(&plan.full_ram.kernel, &casper.join("vmlinuz"))?;
    copy_create_new(&plan.full_ram.initrd, &casper.join("initrd"))?;
    let menu = format!(
        "set default=0\nset timeout=0\n\nmenuentry \"NoUSB disposable Ubuntu Server RAM rehearsal\" {{\n    linux /casper/vmlinuz console=ttyS0,115200n8 earlyprintk=serial root=/dev/ram0 ramdisk_size=1500000 ip=dhcp cloud-config-url=/dev/null url={} ---\n    initrd /casper/initrd\n}}\n",
        plan.full_ram.recovery_source_url
    );
    let redirect = b"search --file --set=root /casper/vmlinuz\nset prefix=($root)/boot/grub\nconfigfile $prefix/grub.cfg\n";
    write_create_new(&boot_grub.join("grub.cfg"), menu.as_bytes())?;
    write_create_new(&efi.join("grub.cfg"), redirect)?;
    write_create_new(&root_grub.join("grub.cfg"), redirect)?;
    Ok(root)
}

#[cfg(target_os = "windows")]
fn run_wsl_checked(arguments: &[String], description: &str) -> Result<(), NoUsbError> {
    let output = Command::new("wsl.exe")
        .args(["-d", "docker-desktop", "--"])
        .args(arguments)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| NoUsbError::Io(format!("cannot {description}: {error}")))?;
    if !output.status.success() {
        return Err(NoUsbError::Io(format!(
            "cannot {description} ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn run_wsl_output(arguments: &[String], description: &str) -> Result<String, NoUsbError> {
    let output = Command::new("wsl.exe")
        .args(["-d", "docker-desktop", "--"])
        .args(arguments)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| NoUsbError::Io(format!("cannot {description}: {error}")))?;
    if !output.status.success() {
        return Err(NoUsbError::Io(format!(
            "cannot {description} ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(target_os = "windows")]
fn disposable_current_os_baseline_init() -> String {
    format!(
        "#!/bin/sh\n/bin/mount -t proc proc /proc 2>/dev/null || true\n/bin/mount -t sysfs sysfs /sys 2>/dev/null || true\n/bin/mount -t devtmpfs devtmpfs /dev 2>/dev/null || true\n/bin/mkdir -p /dev/pts /run /tmp\n/bin/mount -t devpts devpts /dev/pts 2>/dev/null || true\necho '{DISPOSABLE_CURRENT_OS_MARKER}'\necho 'NoUSB disposable current OS userspace is running from /dev/vda.'\n"
    )
}

#[cfg(target_os = "windows")]
fn create_disposable_current_os_root(
    run_directory: &Path,
    plan: &WindowsQemuCurrentOsPlan,
    init_script: &str,
) -> Result<PathBuf, NoUsbError> {
    let rootfs = run_directory.join("current-os-rootfs");
    fs::create_dir(&rootfs)?;
    let runtime_wsl = windows_to_docker_wsl_path(&plan.runtime_root)?;
    let rootfs_wsl = windows_to_docker_wsl_path(&rootfs)?;
    run_wsl_checked(
        &[
            "cp".into(),
            "-a".into(),
            format!("{runtime_wsl}/."),
            rootfs_wsl.clone(),
        ],
        "copy the project-local runtime into the disposable guest root",
    )?;

    for relative in ["dev", "dev/pts", "proc", "sys", "run", "tmp", "etc/init.d"] {
        fs::create_dir_all(rootfs.join(relative))?;
    }
    write_create_new(
        &rootfs.join("etc/os-release"),
        b"NAME=\"NoUSB Disposable Linux\"\nID=nousb-disposable\nVERSION_ID=1\nPRETTY_NAME=\"NoUSB Disposable Linux baseline\"\n",
    )?;
    write_create_new(
        &rootfs.join("etc/passwd"),
        b"root:x:0:0:root:/root:/bin/sh\n",
    )?;
    write_create_new(&rootfs.join("etc/group"), b"root:x:0:\ntty:x:5:\n")?;
    write_create_new(&rootfs.join("etc/shadow"), b"root:*:0:0:99999:7:::\n")?;
    write_create_new(
        &rootfs.join("etc/fstab"),
        b"proc /proc proc defaults 0 0\nsysfs /sys sysfs defaults 0 0\n",
    )?;
    write_create_new(
        &rootfs.join("etc/inittab"),
        b"::sysinit:/etc/init.d/rcS\nttyS0::respawn:/sbin/getty -L 115200 ttyS0 vt100\n::ctrlaltdel:/sbin/reboot\n::shutdown:/bin/umount -a -r\n",
    )?;
    let init_path = rootfs.join("etc/init.d/rcS");
    write_create_new(&init_path, init_script.as_bytes())?;
    let init_wsl = windows_to_docker_wsl_path(&init_path)?;
    run_wsl_checked(
        &["chmod".into(), "0755".into(), init_wsl],
        "make the disposable guest init script executable",
    )?;

    let disk = run_directory.join("current-os-root.ext4");
    let disk_file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&disk)?;
    disk_file.set_len(plan.root_disk_size_bytes)?;
    disk_file.sync_all()?;
    drop(disk_file);
    let disk_wsl = windows_to_docker_wsl_path(&disk)?;
    run_wsl_checked(
        &[
            "mke2fs".into(),
            "-q".into(),
            "-t".into(),
            "ext4".into(),
            "-F".into(),
            "-L".into(),
            "NOUSB_CURRENT".into(),
            "-d".into(),
            rootfs_wsl,
            disk_wsl,
        ],
        "format the project-local disposable current-OS disk",
    )?;
    Ok(disk)
}

#[cfg(target_os = "windows")]
fn create_current_os_uefi_source(
    run_directory: &Path,
    plan: &WindowsQemuCurrentOsPlan,
) -> Result<PathBuf, NoUsbError> {
    let root = run_directory.join("current-os-uefi-source");
    let efi = root.join("EFI").join("BOOT");
    let boot = root.join("boot");
    let boot_grub = boot.join("grub");
    let root_grub = root.join("grub");
    fs::create_dir(&root)?;
    fs::create_dir_all(&efi)?;
    fs::create_dir_all(&boot_grub)?;
    fs::create_dir(&root_grub)?;
    copy_create_new(&plan.bootx64, &efi.join("BOOTX64.EFI"))?;
    copy_create_new(&plan.grubx64, &efi.join("grubx64.efi"))?;
    copy_create_new(&plan.mmx64, &efi.join("mmx64.efi"))?;
    copy_create_new(&plan.kernel, &boot.join("vmlinuz"))?;
    copy_create_new(&plan.initrd, &boot.join("initrd"))?;
    let menu = "set default=0\nset timeout=0\n\nmenuentry \"NoUSB disposable current OS\" {\n    linux /boot/vmlinuz console=ttyS0,115200n8 boot=local root=/dev/vda rootfstype=ext4 rw rootwait init=/sbin/init ---\n    initrd /boot/initrd\n}\n";
    let redirect = b"search --file --set=root /boot/vmlinuz\nset prefix=($root)/boot/grub\nconfigfile $prefix/grub.cfg\n";
    write_create_new(&boot_grub.join("grub.cfg"), menu.as_bytes())?;
    write_create_new(&efi.join("grub.cfg"), redirect)?;
    write_create_new(&root_grub.join("grub.cfg"), redirect)?;
    Ok(root)
}

#[cfg(target_os = "windows")]
struct CurrentOsBootObservation {
    uefi_firmware_initialized: bool,
    linux_banner_observed: bool,
    userspace_started: bool,
    qmp_running_observed: bool,
    qmp_output: Output,
}

#[cfg(target_os = "windows")]
fn run_disposable_current_os_boot_once(
    plan: &WindowsQemuCurrentOsPlan,
    firmware_vars: &Path,
    boot_source: &Path,
    root_disk: &Path,
    serial_log: &Path,
) -> Result<CurrentOsBootObservation, NoUsbError> {
    let runtime_binary = plan.runtime_root.join("usr/bin/qemu-system-x86_64");
    let runtime_root_wsl = windows_to_docker_wsl_path(&plan.runtime_root)?;
    let binary_wsl = windows_to_docker_wsl_path(&runtime_binary)?;
    let code_wsl = windows_to_docker_wsl_path(&plan.firmware_code)?;
    let vars_wsl = windows_to_docker_wsl_path(firmware_vars)?;
    let boot_wsl = windows_to_docker_wsl_path(boot_source)?;
    let disk_wsl = windows_to_docker_wsl_path(root_disk)?;
    let serial_wsl = windows_to_docker_wsl_path(serial_log)?;
    let library_path = format!("{runtime_root_wsl}/lib:{runtime_root_wsl}/usr/lib");
    let environment = format!("LD_LIBRARY_PATH={library_path}");
    let arguments = vec![
        "-d".to_string(),
        "docker-desktop".to_string(),
        "--".to_string(),
        "env".to_string(),
        environment,
        binary_wsl,
        "-machine".to_string(),
        "q35,accel=tcg".to_string(),
        "-cpu".to_string(),
        "max".to_string(),
        "-smp".to_string(),
        plan.cpu_count.to_string(),
        "-m".to_string(),
        plan.memory_mb.to_string(),
        "-nodefaults".to_string(),
        "-display".to_string(),
        "none".to_string(),
        "-serial".to_string(),
        format!("file:{serial_wsl}"),
        "-monitor".to_string(),
        "none".to_string(),
        "-nic".to_string(),
        "none".to_string(),
        "-no-reboot".to_string(),
        "-L".to_string(),
        format!("{runtime_root_wsl}/usr/share/qemu"),
        "-drive".to_string(),
        format!("if=pflash,format=raw,readonly=on,file={code_wsl}"),
        "-drive".to_string(),
        format!("if=pflash,format=raw,file={vars_wsl}"),
        "-drive".to_string(),
        format!("file={disk_wsl},format=raw,if=virtio,id=currentroot"),
        "-blockdev".to_string(),
        format!("driver=vvfat,node-name=currentbootfat,dir={boot_wsl},read-only=on"),
        "-device".to_string(),
        "qemu-xhci,id=currentxhci".to_string(),
        "-device".to_string(),
        "usb-storage,drive=currentbootfat,id=currentbootusb,removable=true,bootindex=0".to_string(),
        "-qmp".to_string(),
        "stdio".to_string(),
    ];
    let child = Command::new("wsl.exe")
        .args(&arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| NoUsbError::Io(format!("cannot start disposable current OS: {error}")))?;
    let mut qemu = OwnedChild::new(child);
    let mut qmp_input = qemu
        .child_mut()?
        .stdin
        .take()
        .ok_or_else(|| NoUsbError::Io("QEMU process did not expose QMP input".into()))?;
    qmp_input.write_all(b"{\"execute\":\"qmp_capabilities\"}\n")?;
    qmp_input.flush()?;

    let deadline = Instant::now() + Duration::from_secs(180);
    let mut uefi_firmware_initialized = false;
    let mut linux_banner_observed = false;
    let mut userspace_started = false;
    while Instant::now() < deadline {
        let serial_bytes = fs::read(serial_log).unwrap_or_default();
        let serial = String::from_utf8_lossy(&serial_bytes);
        uefi_firmware_initialized |= serial.contains("efi: EFI v2.7 by EDK II");
        linux_banner_observed |= serial.contains("Linux version");
        userspace_started |= serial.contains(DISPOSABLE_CURRENT_OS_MARKER);
        if uefi_firmware_initialized && linux_banner_observed && userspace_started {
            break;
        }
        if qemu.child_mut()?.try_wait()?.is_some() {
            return Err(NoUsbError::Verification(format!(
                "disposable current OS exited before userspace started; see {}",
                serial_log.display()
            )));
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    if !uefi_firmware_initialized || !linux_banner_observed || !userspace_started {
        return Err(NoUsbError::Verification(format!(
            "disposable current OS did not reach its UEFI userspace marker; see {}",
            serial_log.display()
        )));
    }
    qmp_input.write_all(
        b"{\"execute\":\"query-status\"}\n{\"execute\":\"query-block\"}\n{\"execute\":\"quit\"}\n",
    )?;
    qmp_input.flush()?;
    drop(qmp_input);
    let qmp_output = qemu.wait_with_output()?;
    let qmp = String::from_utf8_lossy(&qmp_output.stdout);
    let qmp_running_observed =
        qmp.contains("\"status\": \"running\"") || qmp.contains("\"status\":\"running\"");
    Ok(CurrentOsBootObservation {
        uefi_firmware_initialized,
        linux_banner_observed,
        userspace_started,
        qmp_running_observed,
        qmp_output,
    })
}

#[cfg(target_os = "windows")]
pub fn run_windows_qemu_current_os_rehearsal(
    base_dir: &Path,
    confirmation: &str,
) -> Result<WindowsQemuCurrentOsReport, NoUsbError> {
    let plan = windows_qemu_current_os_plan(base_dir)?;
    if confirmation.trim() != plan.typed_confirmation {
        return Err(NoUsbError::UnsafeExecution(format!(
            "type exactly: {}",
            plan.typed_confirmation
        )));
    }

    let base = fs::canonicalize(base_dir)?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| NoUsbError::Io(error.to_string()))?
        .as_secs();
    let run_directory = base.join(".nousb").join("vm").join("qemu").join(format!(
        "current-os-uefi-baseline-{stamp}-{}",
        std::process::id()
    ));
    fs::create_dir_all(run_directory.parent().ok_or_else(|| {
        NoUsbError::Io("current-OS baseline run directory has no parent".into())
    })?)?;
    fs::create_dir(&run_directory)?;
    let firmware_vars = run_directory.join("OVMF_VARS.fd");
    copy_create_new(&plan.firmware_vars_template, &firmware_vars)?;
    let root_disk = create_disposable_current_os_root(
        &run_directory,
        &plan,
        &disposable_current_os_baseline_init(),
    )?;
    let boot_source = create_current_os_uefi_source(&run_directory, &plan)?;
    let first_serial_log_path = run_directory.join("first-boot-serial.log");
    let second_serial_log_path = run_directory.join("second-boot-serial.log");

    let first = run_disposable_current_os_boot_once(
        &plan,
        &firmware_vars,
        &boot_source,
        &root_disk,
        &first_serial_log_path,
    )?;
    fs::write(
        run_directory.join("first-boot-qmp.log"),
        &first.qmp_output.stdout,
    )?;
    fs::write(
        run_directory.join("first-boot-qemu.stderr.log"),
        &first.qmp_output.stderr,
    )?;
    let second = run_disposable_current_os_boot_once(
        &plan,
        &firmware_vars,
        &boot_source,
        &root_disk,
        &second_serial_log_path,
    )?;
    fs::write(
        run_directory.join("second-boot-qmp.log"),
        &second.qmp_output.stdout,
    )?;
    fs::write(
        run_directory.join("second-boot-qemu.stderr.log"),
        &second.qmp_output.stderr,
    )?;

    let first_boot_observed = first.uefi_firmware_initialized
        && first.linux_banner_observed
        && first.userspace_started
        && first.qmp_running_observed;
    let second_boot_observed = second.uefi_firmware_initialized
        && second.linux_banner_observed
        && second.userspace_started
        && second.qmp_running_observed;
    let root_disk_sha256 = sha256_file(&root_disk)?;
    let report_path = run_directory.join("report.json");
    let report = WindowsQemuCurrentOsReport {
        run_directory,
        report_path: report_path.clone(),
        first_serial_log_path,
        second_serial_log_path,
        root_disk_path: root_disk,
        root_disk_sha256,
        first_boot_observed,
        second_boot_observed,
        same_guest_disk_reused: true,
        same_uefi_variable_store_reused: true,
        real_vm_executed: true,
        uefi_firmware_initialized: first.uefi_firmware_initialized
            && second.uefi_firmware_initialized,
        current_os_userspace_started: first.userspace_started && second.userspace_started,
        network_enabled: false,
        physical_disks_attached: false,
        host_boot_changes: false,
        installer_fallback_proven: false,
        uefi_bootnext_proven: false,
        power_loss_matrix_complete: false,
        trust_level: "project-local-disposable-linux-root-official-pinned-ubuntu-uefi-assets"
            .into(),
    };
    let mut report_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&report_path)?;
    report_file.write_all(report.to_json().as_bytes())?;
    report_file.sync_all()?;
    if !first_boot_observed || !second_boot_observed {
        return Err(NoUsbError::Verification(format!(
            "disposable current OS did not boot twice with the same guest state; see {}",
            report.report_path.display()
        )));
    }
    Ok(report)
}

#[cfg(target_os = "windows")]
pub fn run_windows_qemu_uefi_smoke(
    base_dir: &Path,
    confirmation: &str,
) -> Result<WindowsQemuSmokeReport, NoUsbError> {
    let plan = windows_qemu_smoke_plan(base_dir)?;
    if confirmation.trim() != plan.typed_confirmation {
        return Err(NoUsbError::UnsafeExecution(format!(
            "type exactly: {}",
            plan.typed_confirmation
        )));
    }

    let base = fs::canonicalize(base_dir)?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| NoUsbError::Io(error.to_string()))?
        .as_secs();
    let run_directory = base
        .join(".nousb")
        .join("vm")
        .join("qemu")
        .join(format!("uefi-smoke-{stamp}-{}", std::process::id()));
    fs::create_dir_all(
        run_directory
            .parent()
            .ok_or_else(|| NoUsbError::Io("QEMU smoke run directory has no parent".into()))?,
    )?;
    fs::create_dir(&run_directory)?;
    let firmware_vars = run_directory.join("OVMF_VARS.fd");
    copy_create_new(&plan.firmware_vars_template, &firmware_vars)?;

    let runtime_root = project_qemu_root(&base)?;
    let runtime_root_wsl = windows_to_docker_wsl_path(&runtime_root)?;
    let binary_wsl = windows_to_docker_wsl_path(&plan.runtime_binary)?;
    let code_wsl = windows_to_docker_wsl_path(&plan.firmware_code)?;
    let vars_wsl = windows_to_docker_wsl_path(&firmware_vars)?;
    let library_path = format!("{runtime_root_wsl}/lib:{runtime_root_wsl}/usr/lib");
    let data_path = format!("{runtime_root_wsl}/usr/share/qemu");

    let mut child = Command::new("wsl.exe")
        .args([
            "-d",
            "docker-desktop",
            "--",
            "env",
            &format!("LD_LIBRARY_PATH={library_path}"),
            &binary_wsl,
            "-machine",
            "q35,accel=tcg",
            "-cpu",
            "max",
            "-smp",
            "1",
            "-m",
            "256",
            "-nodefaults",
            "-display",
            "none",
            "-serial",
            "none",
            "-monitor",
            "none",
            "-nic",
            "none",
            "-L",
            &data_path,
            "-drive",
            &format!("if=pflash,format=raw,readonly=on,file={code_wsl}"),
            "-drive",
            &format!("if=pflash,format=raw,file={vars_wsl}"),
            "-qmp",
            "stdio",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| NoUsbError::Io(format!("cannot start WSL QEMU: {error}")))?;
    let mut stdin = child.stdin.take().ok_or_else(|| {
        NoUsbError::Io("QEMU process did not expose redirected standard input".into())
    })?;
    stdin.write_all(
        b"{\"execute\":\"qmp_capabilities\"}\n{\"execute\":\"query-status\"}\n{\"execute\":\"query-block\"}\n{\"execute\":\"quit\"}\n",
    )?;
    drop(stdin);
    let output = child.wait_with_output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    fs::write(run_directory.join("qmp.log"), stdout.as_bytes())?;
    fs::write(run_directory.join("qemu.stderr.log"), stderr.as_bytes())?;
    if !output.status.success() {
        return Err(NoUsbError::Verification(format!(
            "disposable QEMU smoke exited with {}; see {}",
            output.status,
            run_directory.display()
        )));
    }
    let qmp_status_observed =
        stdout.contains("\"status\": \"running\"") || stdout.contains("\"status\":\"running\"");
    let uefi_firmware_initialized = stdout.contains("\"QMP\"") && qmp_status_observed;
    if !uefi_firmware_initialized {
        return Err(NoUsbError::Verification(format!(
            "QEMU did not return the expected running QMP state; see {}",
            run_directory.join("qmp.log").display()
        )));
    }

    let report_path = run_directory.join("report.json");
    let report = WindowsQemuSmokeReport {
        run_directory,
        report_path: report_path.clone(),
        runtime_version: plan.runtime_version,
        qmp_status_observed,
        uefi_firmware_initialized,
        real_vm_executed: true,
        ram_boot_verified: false,
        network_enabled: false,
        physical_disks_attached: false,
        host_boot_changes: false,
    };
    let mut report_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&report_path)?;
    report_file.write_all(report.to_json().as_bytes())?;
    report_file.sync_all()?;
    Ok(report)
}

#[cfg(not(target_os = "windows"))]
pub fn run_windows_qemu_uefi_smoke(
    _base_dir: &std::path::Path,
    _confirmation: &str,
) -> Result<WindowsQemuSmokeReport, NoUsbError> {
    Err(NoUsbError::ArtifactUnavailable(
        "the WSL-backed QEMU smoke harness is only available on Windows".into(),
    ))
}

#[cfg(target_os = "windows")]
pub fn run_windows_qemu_netboot_rehearsal(
    base_dir: &Path,
    confirmation: &str,
) -> Result<WindowsQemuNetbootReport, NoUsbError> {
    let plan = windows_qemu_netboot_plan(base_dir)?;
    if confirmation.trim() != plan.typed_confirmation {
        return Err(NoUsbError::UnsafeExecution(format!(
            "type exactly: {}",
            plan.typed_confirmation
        )));
    }

    let base = fs::canonicalize(base_dir)?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| NoUsbError::Io(error.to_string()))?
        .as_secs();
    let run_directory = base
        .join(".nousb")
        .join("vm")
        .join("qemu")
        .join(format!("ubuntu-netboot-ram-{stamp}-{}", std::process::id()));
    fs::create_dir_all(
        run_directory
            .parent()
            .ok_or_else(|| NoUsbError::Io("Ubuntu netboot run directory has no parent".into()))?,
    )?;
    fs::create_dir(&run_directory)?;
    let serial_log_path = run_directory.join("serial.log");

    let runtime_root = project_qemu_root(&base)?;
    let runtime_binary = runtime_root.join("usr/bin/qemu-system-x86_64");
    let runtime_root_wsl = windows_to_docker_wsl_path(&runtime_root)?;
    let binary_wsl = windows_to_docker_wsl_path(&runtime_binary)?;
    let kernel_wsl = windows_to_docker_wsl_path(&plan.kernel)?;
    let initrd_wsl = windows_to_docker_wsl_path(&plan.initrd)?;
    let serial_wsl = windows_to_docker_wsl_path(&serial_log_path)?;
    let library_path = format!("{runtime_root_wsl}/lib:{runtime_root_wsl}/usr/lib");
    let data_path = format!("{runtime_root_wsl}/usr/share/qemu");
    let environment = format!("LD_LIBRARY_PATH={library_path}");
    let serial_argument = format!("file:{serial_wsl}");

    let arguments = vec![
        "-d".to_string(),
        "docker-desktop".to_string(),
        "--".to_string(),
        "env".to_string(),
        environment,
        binary_wsl,
        "-machine".to_string(),
        "q35,accel=tcg".to_string(),
        "-cpu".to_string(),
        "max".to_string(),
        "-smp".to_string(),
        "1".to_string(),
        "-m".to_string(),
        "2048".to_string(),
        "-nodefaults".to_string(),
        "-display".to_string(),
        "none".to_string(),
        "-serial".to_string(),
        serial_argument,
        "-monitor".to_string(),
        "none".to_string(),
        "-nic".to_string(),
        "none".to_string(),
        "-no-reboot".to_string(),
        "-L".to_string(),
        data_path,
        "-kernel".to_string(),
        kernel_wsl,
        "-initrd".to_string(),
        initrd_wsl,
        "-append".to_string(),
        "console=ttyS0,115200n8 earlyprintk=serial root=/dev/ram0 ramdisk_size=1500000 ip=none ---"
            .to_string(),
        "-qmp".to_string(),
        "stdio".to_string(),
    ];
    let mut child = Command::new("wsl.exe")
        .args(&arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| NoUsbError::Io(format!("cannot start WSL QEMU: {error}")))?;
    let mut stdin = child.stdin.take().ok_or_else(|| {
        NoUsbError::Io("QEMU process did not expose redirected standard input".into())
    })?;
    stdin.write_all(b"{\"execute\":\"qmp_capabilities\"}\n")?;
    stdin.flush()?;

    let deadline = Instant::now() + Duration::from_secs(90);
    let mut linux_banner_observed = false;
    let mut initramfs_scripts_observed = false;
    while Instant::now() < deadline {
        if let Ok(serial) = fs::read_to_string(&serial_log_path) {
            linux_banner_observed = serial.contains("Linux version");
            initramfs_scripts_observed = serial.contains("Begin: Running /scripts/init-premount");
            if linux_banner_observed && initramfs_scripts_observed {
                break;
            }
        }
        if child.try_wait()?.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }

    if child.try_wait()?.is_none() {
        stdin.write_all(
            b"{\"execute\":\"query-status\"}\n{\"execute\":\"query-block\"}\n{\"execute\":\"quit\"}\n",
        )?;
        stdin.flush()?;
    }
    drop(stdin);
    let output = child.wait_with_output()?;
    fs::write(run_directory.join("qmp.log"), &output.stdout)?;
    fs::write(run_directory.join("qemu.stderr.log"), &output.stderr)?;
    if !linux_banner_observed || !initramfs_scripts_observed {
        return Err(NoUsbError::Verification(format!(
            "Ubuntu kernel/initrd rehearsal did not reach the expected initramfs stage; see {}",
            serial_log_path.display()
        )));
    }
    let qmp = String::from_utf8_lossy(&output.stdout);
    if !qmp.contains("\"return\": []") && !qmp.contains("\"return\":[]") {
        return Err(NoUsbError::Verification(format!(
            "QMP did not confirm an empty block-device list; see {}",
            run_directory.join("qmp.log").display()
        )));
    }

    let serial_sha256 = sha256_file(&serial_log_path)?;
    let report_path = run_directory.join("report.json");
    let report = WindowsQemuNetbootReport {
        run_directory,
        report_path: report_path.clone(),
        serial_log_path,
        kernel_sha256: plan.kernel_sha256,
        initrd_sha256: plan.initrd_sha256,
        serial_sha256,
        linux_banner_observed,
        initramfs_scripts_observed,
        real_vm_executed: true,
        direct_kernel_boot: true,
        uefi_firmware_initialized: false,
        kernel_initrd_ram_resident: true,
        full_installer_payload_in_ram: false,
        network_enabled: false,
        physical_disks_attached: false,
        host_boot_changes: false,
        trust_level: plan.trust_level,
    };
    let mut report_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&report_path)?;
    report_file.write_all(report.to_json().as_bytes())?;
    report_file.sync_all()?;
    Ok(report)
}

#[cfg(target_os = "windows")]
pub fn run_windows_qemu_full_ram_rehearsal(
    base_dir: &Path,
    confirmation: &str,
) -> Result<WindowsQemuFullRamReport, NoUsbError> {
    let plan = windows_qemu_full_ram_plan(base_dir)?;
    if confirmation.trim() != plan.typed_confirmation {
        return Err(NoUsbError::UnsafeExecution(format!(
            "type exactly: {}",
            plan.typed_confirmation
        )));
    }

    let base = fs::canonicalize(base_dir)?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| NoUsbError::Io(error.to_string()))?
        .as_secs();
    let run_directory = base.join(".nousb").join("vm").join("qemu").join(format!(
        "ubuntu-full-iso-ram-{stamp}-{}",
        std::process::id()
    ));
    fs::create_dir_all(
        run_directory
            .parent()
            .ok_or_else(|| NoUsbError::Io("Ubuntu full-ISO run directory has no parent".into()))?,
    )?;
    fs::create_dir(&run_directory)?;
    let serial_log_path = run_directory.join("serial.log");
    let qmp_log_path = run_directory.join("qmp.log");

    let runtime_root = project_qemu_root(&base)?;
    let runtime_binary = runtime_root.join("usr/bin/qemu-system-x86_64");
    let http_binary = runtime_root.join("bin/busybox-extras");
    if !http_binary.is_file() {
        return Err(NoUsbError::ArtifactUnavailable(format!(
            "project-local HTTP recovery helper is missing: {}",
            http_binary.display()
        )));
    }
    let runtime_root_wsl = windows_to_docker_wsl_path(&runtime_root)?;
    let binary_wsl = windows_to_docker_wsl_path(&runtime_binary)?;
    let http_binary_wsl = windows_to_docker_wsl_path(&http_binary)?;
    let artifact_root = plan.artifact.parent().ok_or_else(|| {
        NoUsbError::Io("Ubuntu Server artifact path has no parent directory".into())
    })?;
    let artifact_root_wsl = windows_to_docker_wsl_path(artifact_root)?;
    let kernel_wsl = windows_to_docker_wsl_path(&plan.kernel)?;
    let initrd_wsl = windows_to_docker_wsl_path(&plan.initrd)?;
    let serial_wsl = windows_to_docker_wsl_path(&serial_log_path)?;
    let library_path = format!("{runtime_root_wsl}/lib:{runtime_root_wsl}/usr/lib");
    let environment = format!("LD_LIBRARY_PATH={library_path}");

    let http_child = Command::new("wsl.exe")
        .args([
            "-d",
            "docker-desktop",
            "--",
            "env",
            &environment,
            &http_binary_wsl,
            "httpd",
            "-f",
            "-vv",
            "-p",
            &UBUNTU_SERVER_RECOVERY_PORT.to_string(),
            "-h",
            &artifact_root_wsl,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| NoUsbError::Io(format!("cannot start recovery HTTP source: {error}")))?;
    let mut http = OwnedChild::new(http_child);
    std::thread::sleep(Duration::from_millis(300));
    if let Some(status) = http.child_mut()?.try_wait()? {
        return Err(NoUsbError::Verification(format!(
            "recovery HTTP source exited before QEMU started ({status}); port {UBUNTU_SERVER_RECOVERY_PORT} may already be in use"
        )));
    }

    let qemu_arguments = vec![
        "-d".to_string(),
        "docker-desktop".to_string(),
        "--".to_string(),
        "env".to_string(),
        environment,
        binary_wsl,
        "-machine".to_string(),
        "q35,accel=tcg".to_string(),
        "-cpu".to_string(),
        "max".to_string(),
        "-smp".to_string(),
        plan.cpu_count.to_string(),
        "-m".to_string(),
        plan.memory_mb.to_string(),
        "-nodefaults".to_string(),
        "-display".to_string(),
        "none".to_string(),
        "-serial".to_string(),
        format!("file:{serial_wsl}"),
        "-monitor".to_string(),
        "none".to_string(),
        "-nic".to_string(),
        "user,model=virtio-net-pci".to_string(),
        "-no-reboot".to_string(),
        "-L".to_string(),
        format!("{runtime_root_wsl}/usr/share/qemu"),
        "-kernel".to_string(),
        kernel_wsl,
        "-initrd".to_string(),
        initrd_wsl,
        "-append".to_string(),
        format!(
            "console=ttyS0,115200n8 earlyprintk=serial root=/dev/ram0 ramdisk_size=1500000 ip=dhcp cloud-config-url=/dev/null url={} ---",
            plan.recovery_source_url
        ),
        "-qmp".to_string(),
        "stdio".to_string(),
    ];
    let qemu_child = Command::new("wsl.exe")
        .args(&qemu_arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| NoUsbError::Io(format!("cannot start full-ISO QEMU: {error}")))?;
    let mut qemu = OwnedChild::new(qemu_child);
    let mut qmp_input =
        qemu.child_mut()?.stdin.take().ok_or_else(|| {
            NoUsbError::Io("QEMU process did not expose redirected QMP input".into())
        })?;
    qmp_input.write_all(b"{\"execute\":\"qmp_capabilities\"}\n")?;
    qmp_input.flush()?;

    let download_deadline = Instant::now() + Duration::from_secs(600);
    let mut linux_banner_observed = false;
    let mut iso_download_started = false;
    let mut iso_download_complete = false;
    let source_stop_serial_offset = loop {
        let serial_bytes = fs::read(&serial_log_path).unwrap_or_default();
        let serial = String::from_utf8_lossy(&serial_bytes);
        linux_banner_observed |= serial.contains("Linux version");
        iso_download_started |= serial.contains("saving to 'ubuntu-24.04.4-live-server-amd64.iso'");
        iso_download_complete |= serial.contains("'ubuntu-24.04.4-live-server-amd64.iso' saved")
            && serial.contains("Begin: Running /scripts/casper-bottom");
        if iso_download_complete {
            break serial_bytes.len();
        }
        if qemu.child_mut()?.try_wait()?.is_some() {
            return Err(NoUsbError::Verification(format!(
                "QEMU exited before the full ISO reached RAM; see {}",
                serial_log_path.display()
            )));
        }
        if http.child_mut()?.try_wait()?.is_some() {
            return Err(NoUsbError::Verification(format!(
                "recovery HTTP source exited before the ISO download completed; see {}",
                run_directory.display()
            )));
        }
        if Instant::now() >= download_deadline {
            return Err(NoUsbError::Verification(format!(
                "timed out waiting for the full ISO download; see {}",
                serial_log_path.display()
            )));
        }
        std::thread::sleep(Duration::from_millis(500));
    };

    let http_output = http.stop()?;
    fs::write(run_directory.join("http.stdout.log"), &http_output.stdout)?;
    fs::write(run_directory.join("http.stderr.log"), &http_output.stderr)?;
    let source_stopped_after_download = true;

    let installer_deadline = Instant::now() + Duration::from_secs(300);
    let mut systemd_started_after_source_stop = false;
    let mut subiquity_payload_mounted_after_source_stop = false;
    while Instant::now() < installer_deadline {
        let serial_bytes = fs::read(&serial_log_path).unwrap_or_default();
        if let Some(suffix_bytes) = serial_bytes.get(source_stop_serial_offset..) {
            let suffix = String::from_utf8_lossy(suffix_bytes);
            systemd_started_after_source_stop |=
                suffix.contains("Welcome to") && suffix.contains("Ubuntu 24.04.4 LTS");
            subiquity_payload_mounted_after_source_stop |=
                suffix.contains("Mounted") && suffix.contains("snap-subiquity-");
        }
        if systemd_started_after_source_stop && subiquity_payload_mounted_after_source_stop {
            break;
        }
        if qemu.child_mut()?.try_wait()?.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }

    if qemu.child_mut()?.try_wait()?.is_none() {
        qmp_input.write_all(
            b"{\"execute\":\"query-status\"}\n{\"execute\":\"query-block\"}\n{\"execute\":\"quit\"}\n",
        )?;
        qmp_input.flush()?;
    }
    drop(qmp_input);
    let qemu_output = qemu.wait_with_output()?;
    fs::write(&qmp_log_path, &qemu_output.stdout)?;
    fs::write(run_directory.join("qemu.stderr.log"), &qemu_output.stderr)?;
    let qmp = String::from_utf8_lossy(&qemu_output.stdout);
    let qmp_running_observed =
        qmp.contains("\"status\": \"running\"") || qmp.contains("\"status\":\"running\"");
    let qmp_empty_block_list_observed =
        qmp.contains("\"return\": []") || qmp.contains("\"return\":[]");
    let serial_sha256 = sha256_file(&serial_log_path)?;
    let full_installer_payload_in_ram = linux_banner_observed
        && iso_download_started
        && iso_download_complete
        && source_stopped_after_download
        && systemd_started_after_source_stop
        && subiquity_payload_mounted_after_source_stop
        && qmp_running_observed
        && qmp_empty_block_list_observed;

    let report_path = run_directory.join("report.json");
    let report = WindowsQemuFullRamReport {
        run_directory,
        report_path: report_path.clone(),
        serial_log_path,
        qmp_log_path,
        artifact_sha256: plan.artifact_sha256,
        artifact_size_bytes: plan.artifact_size_bytes,
        kernel_sha256: plan.kernel_sha256,
        initrd_sha256: plan.initrd_sha256,
        serial_sha256,
        linux_banner_observed,
        iso_download_started,
        iso_download_complete,
        source_stopped_after_download,
        systemd_started_after_source_stop,
        subiquity_payload_mounted_after_source_stop,
        qmp_running_observed,
        qmp_empty_block_list_observed,
        real_vm_executed: true,
        direct_kernel_boot: true,
        uefi_firmware_initialized: false,
        full_installer_payload_in_ram,
        guest_transport_https: false,
        network_enabled: true,
        physical_disks_attached: false,
        virtual_install_disks_attached: false,
        host_boot_changes: false,
        fallback_boot_observed: false,
        trust_level: "official-pinned-sha256-full-iso-local-http-handoff".into(),
    };
    let mut report_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&report_path)?;
    report_file.write_all(report.to_json().as_bytes())?;
    report_file.sync_all()?;
    if !full_installer_payload_in_ram {
        return Err(NoUsbError::Verification(format!(
            "full installer RAM invariants were not all observed; see {}",
            report.report_path.display()
        )));
    }
    Ok(report)
}

#[cfg(target_os = "windows")]
pub fn run_windows_qemu_uefi_full_ram_rehearsal(
    base_dir: &Path,
    confirmation: &str,
) -> Result<WindowsQemuUefiFullRamReport, NoUsbError> {
    let plan = windows_qemu_uefi_full_ram_plan(base_dir)?;
    if confirmation.trim() != plan.typed_confirmation {
        return Err(NoUsbError::UnsafeExecution(format!(
            "type exactly: {}",
            plan.typed_confirmation
        )));
    }

    let base = fs::canonicalize(base_dir)?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| NoUsbError::Io(error.to_string()))?
        .as_secs();
    let run_directory = base.join(".nousb").join("vm").join("qemu").join(format!(
        "ubuntu-uefi-full-ram-{stamp}-{}",
        std::process::id()
    ));
    fs::create_dir_all(run_directory.parent().ok_or_else(|| {
        NoUsbError::Io("Ubuntu UEFI full-RAM run directory has no parent".into())
    })?)?;
    fs::create_dir(&run_directory)?;
    let firmware_vars = run_directory.join("OVMF_VARS.fd");
    copy_create_new(&plan.firmware_vars_template, &firmware_vars)?;
    let boot_source = create_uefi_boot_source(&run_directory, &plan)?;
    let serial_log_path = run_directory.join("serial.log");
    let qmp_log_path = run_directory.join("qmp.log");

    let runtime_root = project_qemu_root(&base)?;
    let runtime_binary = runtime_root.join("usr/bin/qemu-system-x86_64");
    let http_binary = runtime_root.join("bin/busybox-extras");
    if !http_binary.is_file() {
        return Err(NoUsbError::ArtifactUnavailable(format!(
            "project-local HTTP recovery helper is missing: {}",
            http_binary.display()
        )));
    }
    let runtime_root_wsl = windows_to_docker_wsl_path(&runtime_root)?;
    let binary_wsl = windows_to_docker_wsl_path(&runtime_binary)?;
    let http_binary_wsl = windows_to_docker_wsl_path(&http_binary)?;
    let code_wsl = windows_to_docker_wsl_path(&plan.firmware_code)?;
    let vars_wsl = windows_to_docker_wsl_path(&firmware_vars)?;
    let boot_source_wsl = windows_to_docker_wsl_path(&boot_source)?;
    let serial_wsl = windows_to_docker_wsl_path(&serial_log_path)?;
    let artifact_root = plan.full_ram.artifact.parent().ok_or_else(|| {
        NoUsbError::Io("Ubuntu Server artifact path has no parent directory".into())
    })?;
    let artifact_root_wsl = windows_to_docker_wsl_path(artifact_root)?;
    let library_path = format!("{runtime_root_wsl}/lib:{runtime_root_wsl}/usr/lib");
    let environment = format!("LD_LIBRARY_PATH={library_path}");

    let http_child = Command::new("wsl.exe")
        .args([
            "-d",
            "docker-desktop",
            "--",
            "env",
            &environment,
            &http_binary_wsl,
            "httpd",
            "-f",
            "-vv",
            "-p",
            &UBUNTU_SERVER_RECOVERY_PORT.to_string(),
            "-h",
            &artifact_root_wsl,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| NoUsbError::Io(format!("cannot start recovery HTTP source: {error}")))?;
    let mut http = OwnedChild::new(http_child);
    std::thread::sleep(Duration::from_millis(300));
    if let Some(status) = http.child_mut()?.try_wait()? {
        return Err(NoUsbError::Verification(format!(
            "recovery HTTP source exited before QEMU started ({status}); port {UBUNTU_SERVER_RECOVERY_PORT} may already be in use"
        )));
    }

    let qemu_arguments = vec![
        "-d".to_string(),
        "docker-desktop".to_string(),
        "--".to_string(),
        "env".to_string(),
        environment,
        binary_wsl,
        "-machine".to_string(),
        "q35,accel=tcg".to_string(),
        "-cpu".to_string(),
        "max".to_string(),
        "-smp".to_string(),
        plan.full_ram.cpu_count.to_string(),
        "-m".to_string(),
        plan.full_ram.memory_mb.to_string(),
        "-nodefaults".to_string(),
        "-display".to_string(),
        "none".to_string(),
        "-serial".to_string(),
        format!("file:{serial_wsl}"),
        "-monitor".to_string(),
        "none".to_string(),
        "-nic".to_string(),
        "user,model=virtio-net-pci".to_string(),
        "-no-reboot".to_string(),
        "-L".to_string(),
        format!("{runtime_root_wsl}/usr/share/qemu"),
        "-drive".to_string(),
        format!("if=pflash,format=raw,readonly=on,file={code_wsl}"),
        "-drive".to_string(),
        format!("if=pflash,format=raw,file={vars_wsl}"),
        "-blockdev".to_string(),
        format!("driver=vvfat,node-name=bootfat,dir={boot_source_wsl},read-only=on"),
        "-device".to_string(),
        "qemu-xhci,id=xhci".to_string(),
        "-device".to_string(),
        "usb-storage,drive=bootfat,id=bootusb,removable=true,bootindex=0".to_string(),
        "-qmp".to_string(),
        "stdio".to_string(),
    ];
    let qemu_child = Command::new("wsl.exe")
        .args(&qemu_arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| NoUsbError::Io(format!("cannot start UEFI full-RAM QEMU: {error}")))?;
    let mut qemu = OwnedChild::new(qemu_child);
    let mut qmp_input =
        qemu.child_mut()?.stdin.take().ok_or_else(|| {
            NoUsbError::Io("QEMU process did not expose redirected QMP input".into())
        })?;
    qmp_input.write_all(b"{\"execute\":\"qmp_capabilities\"}\n")?;
    qmp_input.flush()?;

    let uefi_deadline = Instant::now() + Duration::from_secs(180);
    let mut uefi_firmware_initialized = false;
    let mut linux_banner_observed = false;
    while Instant::now() < uefi_deadline {
        let serial_bytes = fs::read(&serial_log_path).unwrap_or_default();
        let serial = String::from_utf8_lossy(&serial_bytes);
        uefi_firmware_initialized |= serial.contains("efi: EFI v2.7 by EDK II");
        linux_banner_observed |= serial.contains("Linux version");
        if uefi_firmware_initialized && linux_banner_observed {
            break;
        }
        if qemu.child_mut()?.try_wait()?.is_some() {
            return Err(NoUsbError::Verification(format!(
                "QEMU exited before the official UEFI chain reached Linux; see {}",
                serial_log_path.display()
            )));
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    if !uefi_firmware_initialized || !linux_banner_observed {
        return Err(NoUsbError::Verification(format!(
            "official UEFI boot chain did not reach the expected Linux EFI marker; see {}",
            serial_log_path.display()
        )));
    }

    qmp_input.write_all(b"{\"execute\":\"device_del\",\"arguments\":{\"id\":\"bootusb\"}}\n")?;
    qmp_input.flush()?;
    std::thread::sleep(Duration::from_secs(2));
    qmp_input
        .write_all(b"{\"execute\":\"blockdev-del\",\"arguments\":{\"node-name\":\"bootfat\"}}\n")?;
    qmp_input.flush()?;

    let download_deadline = Instant::now() + Duration::from_secs(600);
    let source_stop_serial_offset = loop {
        let serial_bytes = fs::read(&serial_log_path).unwrap_or_default();
        let serial = String::from_utf8_lossy(&serial_bytes);
        let iso_download_complete = serial.contains("'ubuntu-24.04.4-live-server-amd64.iso' saved")
            && serial.contains("Begin: Running /scripts/casper-bottom");
        if iso_download_complete {
            break serial_bytes.len();
        }
        if qemu.child_mut()?.try_wait()?.is_some() {
            return Err(NoUsbError::Verification(format!(
                "UEFI QEMU exited before the full ISO reached RAM; see {}",
                serial_log_path.display()
            )));
        }
        if http.child_mut()?.try_wait()?.is_some() {
            return Err(NoUsbError::Verification(format!(
                "recovery HTTP source exited before the ISO download completed; see {}",
                run_directory.display()
            )));
        }
        if Instant::now() >= download_deadline {
            return Err(NoUsbError::Verification(format!(
                "timed out waiting for the UEFI full-ISO download; see {}",
                serial_log_path.display()
            )));
        }
        std::thread::sleep(Duration::from_millis(500));
    };
    let iso_download_complete = true;

    let http_output = http.stop()?;
    fs::write(run_directory.join("http.stdout.log"), &http_output.stdout)?;
    fs::write(run_directory.join("http.stderr.log"), &http_output.stderr)?;
    let http_source_stopped_after_download = true;

    let installer_deadline = Instant::now() + Duration::from_secs(300);
    let mut systemd_started_after_http_stop = false;
    let mut subiquity_payload_mounted_after_http_stop = false;
    let mut serial_getty_started_after_http_stop = false;
    while Instant::now() < installer_deadline {
        let serial_bytes = fs::read(&serial_log_path).unwrap_or_default();
        if let Some(suffix_bytes) = serial_bytes.get(source_stop_serial_offset..) {
            let suffix = String::from_utf8_lossy(suffix_bytes);
            systemd_started_after_http_stop |=
                suffix.contains("Welcome to") && suffix.contains("Ubuntu 24.04.4 LTS");
            subiquity_payload_mounted_after_http_stop |=
                suffix.contains("Mounted") && suffix.contains("snap-subiquity-");
            serial_getty_started_after_http_stop |= (suffix.contains("serial-getty@ttyS0.service")
                && suffix.contains("installer for Ubuntu Server"))
                || suffix.contains("Ubuntu 24.04.4 LTS ubuntu-server ttyS0");
        }
        if systemd_started_after_http_stop
            && subiquity_payload_mounted_after_http_stop
            && serial_getty_started_after_http_stop
        {
            break;
        }
        if qemu.child_mut()?.try_wait()?.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }

    if qemu.child_mut()?.try_wait()?.is_none() {
        qmp_input.write_all(
            b"{\"execute\":\"query-status\"}\n{\"execute\":\"query-block\"}\n{\"execute\":\"quit\"}\n",
        )?;
        qmp_input.flush()?;
    }
    drop(qmp_input);
    let qemu_output = qemu.wait_with_output()?;
    fs::write(&qmp_log_path, &qemu_output.stdout)?;
    fs::write(run_directory.join("qemu.stderr.log"), &qemu_output.stderr)?;
    let qmp = String::from_utf8_lossy(&qemu_output.stdout);
    let boot_source_device_deleted =
        qmp.contains("\"event\": \"DEVICE_DELETED\"") && qmp.contains("\"device\": \"bootusb\"");
    let final_block_response = qmp
        .rfind("{\"return\": [")
        .and_then(|position| qmp.get(position..))
        .unwrap_or("");
    let qmp_firmware_only_block_list_observed = final_block_response
        .contains("\"device\": \"pflash0\"")
        && final_block_response.contains("\"device\": \"pflash1\"")
        && !final_block_response.contains("\"removable\": true")
        && !final_block_response.contains("\"format\": \"vvfat\"");
    let boot_source_block_node_deleted =
        boot_source_device_deleted && qmp_firmware_only_block_list_observed;
    let qmp_running_observed =
        qmp.contains("\"status\": \"running\"") || qmp.contains("\"status\":\"running\"");
    let serial_sha256 = sha256_file(&serial_log_path)?;
    let official_efi_assets_verified = true;
    let full_installer_payload_in_ram = uefi_firmware_initialized
        && linux_banner_observed
        && boot_source_device_deleted
        && boot_source_block_node_deleted
        && iso_download_complete
        && http_source_stopped_after_download
        && systemd_started_after_http_stop
        && subiquity_payload_mounted_after_http_stop
        && serial_getty_started_after_http_stop
        && qmp_running_observed
        && qmp_firmware_only_block_list_observed;

    let report_path = run_directory.join("report.json");
    let report = WindowsQemuUefiFullRamReport {
        run_directory,
        report_path: report_path.clone(),
        serial_log_path,
        qmp_log_path,
        artifact_sha256: plan.full_ram.artifact_sha256,
        artifact_size_bytes: plan.full_ram.artifact_size_bytes,
        bootx64_sha256: plan.bootx64_sha256,
        grubx64_sha256: plan.grubx64_sha256,
        mmx64_sha256: plan.mmx64_sha256,
        serial_sha256,
        real_vm_executed: true,
        direct_kernel_boot: false,
        uefi_firmware_initialized,
        secure_boot_enabled: false,
        official_efi_assets_verified,
        boot_source_device_deleted,
        boot_source_block_node_deleted,
        iso_download_complete,
        http_source_stopped_after_download,
        systemd_started_after_http_stop,
        subiquity_payload_mounted_after_http_stop,
        serial_getty_started_after_http_stop,
        qmp_running_observed,
        qmp_firmware_only_block_list_observed,
        full_installer_payload_in_ram,
        guest_transport_https: false,
        network_enabled: true,
        physical_disks_attached: false,
        virtual_install_disks_attached: false,
        host_boot_changes: false,
        fallback_boot_observed: false,
        trust_level: "official-pinned-sha256-uefi-full-iso-local-http-handoff".into(),
    };
    let mut report_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&report_path)?;
    report_file.write_all(report.to_json().as_bytes())?;
    report_file.sync_all()?;
    if !full_installer_payload_in_ram {
        return Err(NoUsbError::Verification(format!(
            "UEFI full installer RAM invariants were not all observed; see {}",
            report.report_path.display()
        )));
    }
    Ok(report)
}

#[cfg(not(target_os = "windows"))]
pub fn run_windows_qemu_uefi_full_ram_rehearsal(
    _base_dir: &std::path::Path,
    _confirmation: &str,
) -> Result<WindowsQemuUefiFullRamReport, NoUsbError> {
    Err(NoUsbError::ArtifactUnavailable(
        "the WSL-backed Ubuntu UEFI full-ISO RAM rehearsal is only available on Windows".into(),
    ))
}

#[cfg(not(target_os = "windows"))]
pub fn run_windows_qemu_current_os_rehearsal(
    _base_dir: &std::path::Path,
    _confirmation: &str,
) -> Result<WindowsQemuCurrentOsReport, NoUsbError> {
    Err(NoUsbError::ArtifactUnavailable(
        "the WSL-backed disposable current-OS baseline is only available on Windows".into(),
    ))
}

#[cfg(not(target_os = "windows"))]
pub fn run_windows_qemu_full_ram_rehearsal(
    _base_dir: &std::path::Path,
    _confirmation: &str,
) -> Result<WindowsQemuFullRamReport, NoUsbError> {
    Err(NoUsbError::ArtifactUnavailable(
        "the WSL-backed Ubuntu full-ISO RAM rehearsal is only available on Windows".into(),
    ))
}

#[cfg(not(target_os = "windows"))]
pub fn run_windows_qemu_netboot_rehearsal(
    _base_dir: &std::path::Path,
    _confirmation: &str,
) -> Result<WindowsQemuNetbootReport, NoUsbError> {
    Err(NoUsbError::ArtifactUnavailable(
        "the WSL-backed Ubuntu netboot rehearsal is only available on Windows".into(),
    ))
}

fn escape_json(value: &str) -> String {
    nousb_core::escape_json(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_non_privileged_windows_inventory_facts() {
        let mut inventory = HostPlatform.inspect().unwrap();
        apply_windows_inventory_output(
            &mut inventory,
            r#"secure_boot=0
memory_bytes=25769803776
free_bytes=268435456000
drive_size_bytes=512110190592
drive_format=NTFS
system_drive=C:\
bitlocker=1
esp=disk 0 partition 1|209715200
recovery_partition=1
"#,
        );

        assert_eq!(inventory.firmware, FirmwareMode::Uefi);
        assert_eq!(inventory.secure_boot, SecureBootState::Disabled);
        assert_eq!(inventory.memory_total_mb, Some(24_576));
        assert_eq!(inventory.disk_inventory.available_space_gb, Some(250));
        assert_eq!(
            inventory.encryption,
            EncryptionState::Enabled("BitLocker".into())
        );
        assert_eq!(inventory.disk_inventory.partitions.len(), 1);
        assert_eq!(
            inventory.disk_inventory.partitions[0].filesystem.as_deref(),
            Some("NTFS")
        );
        assert_eq!(
            inventory.disk_inventory.partitions[0]
                .mount_point
                .as_deref(),
            Some("C:\\")
        );
        let hints = &inventory.boot_hints;
        assert_eq!(hints.esp_present, Some(true));
        assert_eq!(hints.esp_location.as_deref(), Some("disk 0 partition 1"));
        assert_eq!(hints.esp_size_bytes, Some(209_715_200));
        assert_eq!(hints.recovery_partition_present, Some(true));
        assert!(hints.boot_managers[0].starts_with("Windows Boot Manager"));
        assert_eq!(hints.network_boot_entries, None);
        assert!(hints.unknowns.iter().any(|item| item.contains("BCD")));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn docker_wsl_path_conversion_rejects_non_drive_paths() {
        assert_eq!(
            windows_to_docker_wsl_path(Path::new("C:\\work\\RevX\\file.fd")).unwrap(),
            "/mnt/host/c/work/RevX/file.fd"
        );
        assert!(windows_to_docker_wsl_path(Path::new("\\\\server\\share\\file.fd")).is_err());
    }
}
