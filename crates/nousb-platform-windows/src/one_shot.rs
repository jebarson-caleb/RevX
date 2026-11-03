//! Disposable-guest UEFI one-shot (`BootNext`) rehearsal with a power-loss matrix, plus the
//! reproducible project-local QEMU runtime it runs on.
//!
//! Everything here runs inside a disposable QEMU guest launched through the existing
//! `docker-desktop` WSL2 distribution. The guest owns a copied OVMF variable store and a
//! project-local disk image; no host firmware variable, ESP, boot configuration, or physical
//! disk is ever attached.

use nousb_core::{NoUsbError, OneShotBootBackend};
use std::path::PathBuf;

use super::{escape_json, WindowsQemuCurrentOsPlan};

#[cfg(target_os = "windows")]
use super::{
    copy_create_new, create_disposable_current_os_root, project_qemu_root, run_wsl_output,
    windows_qemu_current_os_plan, windows_qemu_full_ram_plan, windows_to_docker_wsl_path,
    write_create_new, OwnedChild, UBUNTU_SERVER_RECOVERY_PORT,
};
#[cfg(target_os = "windows")]
use nousb_core::{fetch_https_bytes, sha256_file};
#[cfg(target_os = "windows")]
use std::fs::{self, OpenOptions};
#[cfg(target_os = "windows")]
use std::io::Write;
#[cfg(target_os = "windows")]
use std::path::Path;
#[cfg(target_os = "windows")]
use std::process::{Command, Stdio};
#[cfg(target_os = "windows")]
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(target_os = "windows")]
const QEMU_RUNTIME_ALPINE_RELEASE: &str = "v3.23";
#[cfg(target_os = "windows")]
const QEMU_RUNTIME_PACKAGES: [&str; 12] = [
    "busybox",
    "busybox-extras",
    "qemu-system-x86_64~10.1.5",
    "ovmf",
    "efibootmgr",
    "grub-efi",
    "sfdisk",
    "dosfstools",
    "mtools",
    "efitools",
    "openssl",
    "systemd-boot",
];
#[cfg(target_os = "windows")]
const QEMU_RUNTIME_VERSION_PREFIX: &str = "QEMU emulator version 10.1.5";
/// Microsoft Corporation UEFI CA 2011, which signs shim. Its digest matches both microsoft.com
/// and the copy bundled in Red Hat's virt-firmware 26.9 (`ms-uefi-2011.pem`).
#[cfg(target_os = "windows")]
const MICROSOFT_UEFI_CA_2011_URL: &str =
    "https://www.microsoft.com/pkiops/certs/MicCorUEFCA2011_2011-06-27.crt";
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) const MICROSOFT_UEFI_CA_2011_SHA256: &str =
    "48e99b991f57fc52f76149599bff0a58c47154229b9f8d603ac40d3500248507";
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) const MICROSOFT_UEFI_CA_2011_RUNTIME_PATH: &str =
    "usr/share/nousb/MicCorUEFCA2011_2011-06-27.crt";

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const ONE_SHOT_ENTRY_LABEL: &str = "NoUSB-OneShot";
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const ONE_SHOT_INSTALLER_DISK: &str = "/dev/vdc";
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const ONE_SHOT_CURRENT_OS_ESP_DEVICE: &str = "/dev/vdb1";
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const ONE_SHOT_INSTALLER_LOADER: &str = "\\EFI\\BOOT\\BOOTX64.EFI";
const ONE_SHOT_INSTALLER_MARKER: &str = "nousb.oneshot=installer";
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const ONE_SHOT_CURRENT_OS_CMDLINE: &str =
    "console=ttyS0,115200n8 boot=local root=/dev/vda rootfstype=ext4 rw rootwait init=/sbin/init";
const KERNEL_COMMAND_LINE: &str = "Kernel command line:";
const EARLY_COMMAND_LINE: &str = "] Command line:";
const LINUX_BANNER: &str = "Linux version ";
const FIRMWARE_START_PREFIX: &str = "BdsDxe: starting Boot";
/// Kernel option carried only by the systemd-boot temporary entry.
const SYSTEMD_BOOT_ONESHOT_TAG: &str = "nousb.loader=systemd-boot-oneshot";
/// systemd-boot's vendor GUID for `LoaderEntryOneShot` and friends.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const SYSTEMD_BOOT_VENDOR_GUID: &str = "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f";
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const SYSTEMD_BOOT_ONESHOT_ENTRY: &str = "nousb-oneshot.conf";
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const SYSTEMD_BOOT_RUNTIME_PATH: &str = "usr/lib/systemd/boot/efi/systemd-bootx64.efi";
#[cfg(target_os = "windows")]
const ONE_SHOT_CYCLE_TIMEOUT_SECS: u64 = 900;
/// Copying 3.2 GiB into guest RAM and starting Subiquity under TCG takes far longer.
#[cfg(target_os = "windows")]
const ONE_SHOT_FULL_RAM_CYCLE_TIMEOUT_SECS: u64 = 2_700;
#[cfg(target_os = "windows")]
const ONE_SHOT_CURRENT_OS_ESP_BYTES: u64 = 256 * 1024 * 1024;
#[cfg(target_os = "windows")]
const ONE_SHOT_ESP_START_SECTOR: u64 = 2_048;
#[cfg(target_os = "windows")]
const ONE_SHOT_ESP_SECTORS: u64 = 520_192;

/// Guest `rcS` for the disposable current OS. It is a small persisted state machine:
/// `none` records the baseline and arms a one-shot entry, `arming`/`armed` means control came
/// back to the current OS and cleanup must run, and `verify` checks the final state.
/// Every step syncs before printing its marker so a host-side power cut after a marker
/// leaves exactly that step durable. The one-shot mechanism itself lives in the
/// backend-specific `selector_*` functions substituted for `@SELECTOR_FUNCTIONS@`.
/// Marker fields keep their UEFI names: `entry` is the temporary entry, `bootnext` is the
/// pending one-shot selector of whichever backend runs, and `bootcurrent`/`bootorder` are
/// always the firmware's own variables.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const ONE_SHOT_GUEST_INIT: &str = r#"#!/bin/sh
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH MTOOLS_SKIP_CHECK=1
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null
mount -t devtmpfs devtmpfs /dev 2>/dev/null
mkdir -p /dev/pts /run /tmp /var/lib/nousb
mount -t efivarfs efivarfs /sys/firmware/efi/efivars 2>/dev/null
echo 'NOUSB_DISPOSABLE_CURRENT_OS_READY'
STATE=/var/lib/nousb
LABEL='@LABEL@'
INSTALLER_DISK='@DISK@'
ESP_DEV='@ESP@'
fail() { echo "NOUSB_ERROR reason=$1"; sync; poweroff -f; sleep 30; }
pause() { sleep 4; }
efi() { efibootmgr 2>/dev/null; }
field() { efi | sed -n "s/^$1: //p" | head -n 1; }
dump() { efibootmgr -v 2>/dev/null | sed "s/^/NOUSB_EFI stage=$1 /"; }
@SELECTOR_FUNCTIONS@
[ -n "$(ls /sys/firmware/efi/efivars 2>/dev/null)" ] || fail efivarfs-unavailable
command -v efibootmgr >/dev/null 2>&1 || fail efibootmgr-missing
selector_ready || fail selector-tools-missing
phase=$(cat "$STATE/phase" 2>/dev/null || echo none)
current=$(field BootCurrent)
order=$(field BootOrder)
next=$(selector_pending)
echo "NOUSB_BOOT phase=$phase bootcurrent=$current bootnext=$next bootorder=$order"
case "$phase" in
none)
  [ -n "$order" ] || fail bootorder-unavailable
  [ -n "$current" ] || fail bootcurrent-unavailable
  [ -b "$INSTALLER_DISK" ] || fail installer-disk-missing
  echo "$order" > "$STATE/baseline-bootorder"
  echo "$current" > "$STATE/baseline-bootcurrent"
  echo arming > "$STATE/phase"
  sync
  echo "NOUSB_BASELINE bootcurrent=$current bootorder=$order"
  dump baseline
  selector_create || fail create-temporary-entry
  entry=$(selector_entries | head -n 1)
  [ -n "$entry" ] || fail temporary-entry-not-found
  sync
  echo "NOUSB_STEP=temporary-entry-created entry=$entry bootorder=$(field BootOrder)"
  dump created
  pause
  selector_arm "$entry" || fail arm-one-shot-selector
  echo armed > "$STATE/phase"
  sync
  echo "NOUSB_STEP=bootnext-armed bootnext=$(selector_pending) bootorder=$(field BootOrder)"
  pause
  sync
  reboot -f
  ;;
arming|armed)
  baseline_current=$(cat "$STATE/baseline-bootcurrent")
  echo "NOUSB_STEP=returned-to-current-os bootcurrent=$current baseline_bootcurrent=$baseline_current bootnext=$next bootorder=$order"
  dump returned
  pause
  cleared=0
  if [ "$next" != absent ]; then
    selector_clear || fail clear-one-shot-selector
    cleared=1
  fi
  removed=0
  for stale in $(selector_entries); do
    selector_delete "$stale" || fail delete-temporary-entry
    removed=$((removed + 1))
  done
  sync
  echo "NOUSB_STEP=temporary-entry-deleted removed=$removed bootnext_cleared=$cleared"
  pause
  echo verify > "$STATE/phase"
  sync
  echo "NOUSB_STEP=cleanup-committed"
  reboot -f
  ;;
verify)
  baseline=$(cat "$STATE/baseline-bootorder")
  baseline_current=$(cat "$STATE/baseline-bootcurrent")
  remaining=$(selector_entries | wc -l | tr -d ' ')
  firmware_next=$(field BootNext)
  result=fail
  if [ "$order" = "$baseline" ] && [ "$next" = absent ] && [ -z "$firmware_next" ] && [ "$remaining" = 0 ] && [ "$current" = "$baseline_current" ]; then
    result=pass
  fi
  echo done > "$STATE/phase"
  sync
  dump final
  echo "NOUSB_FINAL result=$result bootcurrent=$current bootorder=$order baseline_bootorder=$baseline bootnext=$next temporary_entries=$remaining"
  sync
  poweroff -f
  ;;
*)
  echo "NOUSB_FINAL result=fail reason=unexpected-phase-$phase"
  sync
  poweroff -f
  ;;
esac
sleep 30
"#;

/// UEFI `BootNext`: a firmware `Boot####` entry created outside `BootOrder`.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const UEFI_BOOTNEXT_SELECTOR: &str = r#"selector_ready() { true; }
selector_entries() {
  efi | awk -v label="$LABEL" '/^Boot[0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f]/ {
    name = $0; sub(/^Boot[0-9A-Fa-f]+\*? ?/, "", name); split(name, parts, "\t");
    if (parts[1] == label) print substr($0, 5, 4) }'
}
selector_create() { efibootmgr -q -C -d "$INSTALLER_DISK" -p 1 -l '@LOADER@' -L "$LABEL" >/dev/null 2>&1; }
selector_arm() { efibootmgr -q -n "$1" >/dev/null 2>&1; }
selector_pending() { value=$(field BootNext); echo "${value:-absent}"; }
selector_clear() { efibootmgr -q -N >/dev/null 2>&1; }
selector_delete() { efibootmgr -q -b "$1" -B >/dev/null 2>&1; }"#;

/// GRUB `next_entry` (what `grub-reboot` writes): a temporary menu entry file on the current
/// OS's ESP plus `next_entry` in its `grubenv`. The current OS's GRUB clears `next_entry` with
/// `save_env` before booting the selected entry. The guest edits the ESP with mtools because
/// the disposable root carries no vfat kernel module.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const GRUB_NEXT_ENTRY_SELECTOR: &str = r#"selector_ready() { command -v grub-editenv >/dev/null 2>&1 && command -v mcopy >/dev/null 2>&1 && [ -b "$ESP_DEV" ]; }
selector_entries() { mdir -b -i "$ESP_DEV" ::/grub/@GRUB_ENTRY@.cfg >/dev/null 2>&1 && echo '@GRUB_ENTRY@'; }
selector_create() {
  cat > /tmp/@GRUB_ENTRY@.cfg <<'NOUSB_ENTRY'
@GRUB_ENTRY_CONFIG@
NOUSB_ENTRY
  mcopy -o -i "$ESP_DEV" /tmp/@GRUB_ENTRY@.cfg ::/grub/@GRUB_ENTRY@.cfg
}
grubenv_fetch() { rm -f /tmp/grubenv; mcopy -n -i "$ESP_DEV" ::/grub/grubenv /tmp/grubenv >/dev/null 2>&1; }
grubenv_store() { mcopy -o -i "$ESP_DEV" /tmp/grubenv ::/grub/grubenv; }
selector_arm() { grubenv_fetch && grub-editenv /tmp/grubenv set "next_entry=$1" && grubenv_store; }
selector_pending() {
  if grubenv_fetch; then value=$(sed -n 's/^next_entry=//p' /tmp/grubenv); echo "${value:-absent}"; else echo unreadable; fi
}
selector_clear() { grubenv_fetch && grub-editenv /tmp/grubenv unset next_entry && grubenv_store; }
selector_delete() { mdel -i "$ESP_DEV" "::/grub/$1.cfg"; }"#;

/// systemd-boot `LoaderEntryOneShot` (what `bootctl set-oneshot` writes): installer assets are
/// staged onto the current OS's ESP next to a temporary Boot Loader Specification entry, and the
/// EFI variable names that entry. systemd-boot deletes the variable when it consumes it.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const SYSTEMD_BOOT_SELECTOR: &str = r#"ONESHOT="/sys/firmware/efi/efivars/LoaderEntryOneShot-@SD_GUID@"
INSTALLER_PART="${INSTALLER_DISK}1"
selector_ready() { command -v mcopy >/dev/null 2>&1 && [ -b "$ESP_DEV" ] && [ -b "$INSTALLER_PART" ]; }
selector_entries() {
  if mdir -b -i "$ESP_DEV" ::/loader/entries/@SD_ENTRY@ >/dev/null 2>&1 || mdir -b -i "$ESP_DEV" ::/nousb >/dev/null 2>&1; then
    echo '@SD_ENTRY@'
  fi
}
selector_create() {
  rm -rf /tmp/nousb-stage && mkdir -p /tmp/nousb-stage || return 1
  mcopy -n -i "$INSTALLER_PART" ::/casper/vmlinuz ::/casper/initrd /tmp/nousb-stage/ || return 1
  mmd -i "$ESP_DEV" ::/nousb >/dev/null 2>&1
  mcopy -o -i "$ESP_DEV" /tmp/nousb-stage/vmlinuz /tmp/nousb-stage/initrd ::/nousb/ || return 1
  cat > /tmp/@SD_ENTRY@ <<'NOUSB_ENTRY'
@SD_ENTRY_CONFIG@
NOUSB_ENTRY
  mcopy -o -i "$ESP_DEV" /tmp/@SD_ENTRY@ ::/loader/entries/@SD_ENTRY@
}
selector_arm() {
  # Attributes NV|BS|RT, then the entry id as NUL-terminated UTF-16LE, in one write.
  printf '@SD_ONESHOT_VALUE@' > /tmp/oneshot.var && cat /tmp/oneshot.var > "$ONESHOT"
}
selector_pending() {
  if [ -f "$ONESHOT" ]; then
    value=$(dd if="$ONESHOT" bs=1 skip=4 2>/dev/null | tr -d '\000')
    echo "${value:-absent}"
  else
    echo absent
  fi
}
selector_clear() { chattr -i "$ONESHOT" 2>/dev/null; rm -f "$ONESHOT" && [ ! -e "$ONESHOT" ]; }
selector_delete() {
  mdel -i "$ESP_DEV" "::/loader/entries/$1" >/dev/null 2>&1
  mdeltree -i "$ESP_DEV" ::/nousb >/dev/null 2>&1
  ! mdir -b -i "$ESP_DEV" ::/nousb >/dev/null 2>&1
}"#;

/// A Boot Loader Specification type #1 entry.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn systemd_boot_entry_config(title: &str, linux: &str, initrd: &str, options: &str) -> String {
    format!("title {title}\nlinux {linux}\ninitrd {initrd}\noptions {options}\n")
}

/// The efivarfs payload for a systemd-boot string variable, as a `printf` format of octal
/// escapes: attribute bytes 0x07 (NV|BS|RT), then UTF-16LE text with a terminating NUL.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn efivar_utf16_printf(value: &str) -> String {
    let mut bytes = vec![7u8, 0, 0, 0];
    for unit in value.encode_utf16().chain([0]) {
        bytes.extend(unit.to_le_bytes());
    }
    bytes.iter().map(|byte| format!("\\{byte:03o}")).collect()
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const GRUB_ONE_SHOT_ENTRY_ID: &str = "nousb-oneshot";

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn grub_one_shot_entry_config(installer_arguments: &str) -> String {
    format!(
        "menuentry \"NoUSB one-shot installer\" --id {GRUB_ONE_SHOT_ENTRY_ID} {{\n  search --no-floppy --file --set=installer /casper/vmlinuz\n  echo \"NOUSB_GRUB loader=current-os-standalone booting={GRUB_ONE_SHOT_ENTRY_ID}\"\n  linux ($installer)/casper/vmlinuz {installer_arguments} ---\n  initrd ($installer)/casper/initrd\n}}"
    )
}

/// Kernel arguments of the one-shot installer entry. Without a source it panics early (an
/// installer failure); with one it runs casper with the full ISO copied into RAM.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn installer_kernel_arguments(source_url: Option<&str>) -> String {
    match source_url {
        Some(url) => format!(
            "console=ttyS0,115200n8 {ONE_SHOT_INSTALLER_MARKER} root=/dev/ram0 ramdisk_size=1500000 ip=dhcp cloud-config-url=/dev/null url={url}"
        ),
        None => format!(
            "console=ttyS0,115200n8 {ONE_SHOT_INSTALLER_MARKER} panic=5 rdinit=/nousb-installer-halt root=/dev/nousb-installer-absent"
        ),
    }
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn one_shot_guest_init(backend: OneShotBootBackend, installer_arguments: &str) -> String {
    let selector = match backend {
        OneShotBootBackend::LinuxGrubReboot => GRUB_NEXT_ENTRY_SELECTOR
            .replace(
                "@GRUB_ENTRY_CONFIG@",
                &grub_one_shot_entry_config(installer_arguments),
            )
            .replace("@GRUB_ENTRY@", GRUB_ONE_SHOT_ENTRY_ID),
        OneShotBootBackend::LinuxSystemdBootOneShot => SYSTEMD_BOOT_SELECTOR
            .replace(
                "@SD_ENTRY_CONFIG@",
                &systemd_boot_entry_config(
                    "NoUSB one-shot installer",
                    "/nousb/vmlinuz",
                    "/nousb/initrd",
                    &format!("{installer_arguments} {SYSTEMD_BOOT_ONESHOT_TAG}"),
                ),
            )
            .replace("@SD_ENTRY@", SYSTEMD_BOOT_ONESHOT_ENTRY)
            .replace("@SD_GUID@", SYSTEMD_BOOT_VENDOR_GUID)
            .replace(
                "@SD_ONESHOT_VALUE@",
                &efivar_utf16_printf(SYSTEMD_BOOT_ONESHOT_ENTRY),
            ),
        _ => UEFI_BOOTNEXT_SELECTOR.to_string(),
    };
    ONE_SHOT_GUEST_INIT
        .replace("@SELECTOR_FUNCTIONS@", &selector)
        .replace("@LABEL@", ONE_SHOT_ENTRY_LABEL)
        .replace("@DISK@", ONE_SHOT_INSTALLER_DISK)
        .replace("@ESP@", ONE_SHOT_CURRENT_OS_ESP_DEVICE)
        .replace("@LOADER@", ONE_SHOT_INSTALLER_LOADER)
}

/// The one-shot backends the disposable guest can exercise. Windows BCD needs a Windows guest.
pub fn disposable_one_shot_backend_supported(backend: OneShotBootBackend) -> bool {
    matches!(
        backend,
        OneShotBootBackend::UefiBootNext
            | OneShotBootBackend::LinuxGrubReboot
            | OneShotBootBackend::LinuxSystemdBootOneShot
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowsQemuRuntimeBootstrapPlan {
    pub runtime_root: PathBuf,
    pub manifest_path: PathBuf,
    pub alpine_release: String,
    pub repositories: Vec<String>,
    pub packages: Vec<String>,
    pub keys_directory: String,
    pub runtime_present: bool,
    pub installs_into_windows: bool,
    pub host_boot_changes: bool,
    pub typed_confirmation: String,
}

impl WindowsQemuRuntimeBootstrapPlan {
    pub fn preview(&self) -> String {
        format!(
            "Project-local QEMU runtime bootstrap plan\nRuntime root: {}\nManifest: {}\nAlpine release: {}\nRepositories: {}\nPackages: {}\nSignature keys: {} (inside the docker-desktop WSL2 distribution)\nRuntime already present: {}\nInstalls into Windows: {}\nHost boot changes: {}\nPurpose: assemble QEMU, OVMF, busybox, efibootmgr, GRUB, and ESP image tools from signed Alpine packages so disposable rehearsals are reproducible.\nConfirmation phrase: {}\n",
            self.runtime_root.display(),
            self.manifest_path.display(),
            self.alpine_release,
            self.repositories.join(", "),
            self.packages.join(", "),
            self.keys_directory,
            self.runtime_present,
            self.installs_into_windows,
            self.host_boot_changes,
            self.typed_confirmation,
        )
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{\"runtime_root\":\"{}\",\"manifest_path\":\"{}\",\"alpine_release\":\"{}\",\"repositories\":[{}],\"packages\":[{}],\"keys_directory\":\"{}\",\"runtime_present\":{},\"installs_into_windows\":{},\"host_boot_changes\":{},\"typed_confirmation\":\"{}\"}}",
            escape_json(&self.runtime_root.display().to_string()),
            escape_json(&self.manifest_path.display().to_string()),
            escape_json(&self.alpine_release),
            json_string_list(&self.repositories),
            json_string_list(&self.packages),
            escape_json(&self.keys_directory),
            self.runtime_present,
            self.installs_into_windows,
            self.host_boot_changes,
            escape_json(&self.typed_confirmation),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowsQemuRuntimeBootstrapReport {
    pub runtime_root: PathBuf,
    pub manifest_path: PathBuf,
    pub qemu_version: String,
    pub installed_packages: Vec<String>,
    pub signing_key_digests: Vec<String>,
    pub runtime_was_present: bool,
    pub installs_into_windows: bool,
    pub host_boot_changes: bool,
}

impl WindowsQemuRuntimeBootstrapReport {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"runtime_root\":\"{}\",\"manifest_path\":\"{}\",\"qemu_version\":\"{}\",\"installed_packages\":[{}],\"signing_key_digests\":[{}],\"runtime_was_present\":{},\"installs_into_windows\":{},\"host_boot_changes\":{}}}",
            escape_json(&self.runtime_root.display().to_string()),
            escape_json(&self.manifest_path.display().to_string()),
            escape_json(&self.qemu_version),
            json_string_list(&self.installed_packages),
            json_string_list(&self.signing_key_digests),
            self.runtime_was_present,
            self.installs_into_windows,
            self.host_boot_changes,
        )
    }
}

/// One step of the one-shot transaction after which the host cuts power (QMP `quit`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OneShotPowerLossPoint {
    CompleteCycle,
    AfterTemporaryEntryCreated,
    AfterBootNextArmed,
    DuringInstallerBoot,
    AfterReturnBeforeCleanup,
    AfterTemporaryEntryDeleted,
}

impl OneShotPowerLossPoint {
    pub const ALL: [Self; 6] = [
        Self::CompleteCycle,
        Self::AfterTemporaryEntryCreated,
        Self::AfterBootNextArmed,
        Self::DuringInstallerBoot,
        Self::AfterReturnBeforeCleanup,
        Self::AfterTemporaryEntryDeleted,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::CompleteCycle => "complete-cycle",
            Self::AfterTemporaryEntryCreated => "after-temporary-entry-created",
            Self::AfterBootNextArmed => "after-bootnext-armed",
            Self::DuringInstallerBoot => "during-installer-boot",
            Self::AfterReturnBeforeCleanup => "after-return-before-cleanup",
            Self::AfterTemporaryEntryDeleted => "after-temporary-entry-deleted",
        }
    }

    pub fn parse(value: &str) -> Result<Self, NoUsbError> {
        Self::ALL
            .into_iter()
            .find(|point| point.as_str() == value)
            .ok_or_else(|| {
                NoUsbError::InvalidInput(format!(
                    "unknown one-shot scenario {value}; expected one of: {}",
                    Self::ALL
                        .iter()
                        .map(|point| point.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ))
            })
    }

    /// Serial text whose first appearance triggers the power cut.
    pub fn trigger(self) -> Option<&'static str> {
        match self {
            Self::CompleteCycle => None,
            Self::AfterTemporaryEntryCreated => Some("NOUSB_STEP=temporary-entry-created"),
            Self::AfterBootNextArmed => Some("NOUSB_STEP=bootnext-armed"),
            Self::DuringInstallerBoot => Some(ONE_SHOT_INSTALLER_MARKER),
            Self::AfterReturnBeforeCleanup => Some("NOUSB_STEP=returned-to-current-os"),
            Self::AfterTemporaryEntryDeleted => Some("NOUSB_STEP=temporary-entry-deleted"),
        }
    }

    /// Power loss before `BootNext` is written aborts the transaction, so the installer must
    /// never run; every later point must show exactly one installer boot.
    pub fn installer_boot_expected(self) -> bool {
        !matches!(self, Self::AfterTemporaryEntryCreated)
    }
}

/// What the one-shot installer entry does once the selector has started it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OneShotInstallerMode {
    /// Boot the official kernel and force an early panic and reboot (an installer failure).
    ForcedFailure,
    /// Boot casper with the full pinned ISO copied into RAM, stop its HTTP source, wait for
    /// Subiquity, then reset the machine as a user would after leaving the installer.
    FullRamInstaller,
}

impl OneShotInstallerMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ForcedFailure => "forced-failure",
            Self::FullRamInstaller => "full-ram-installer",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "forced-failure" => Some(Self::ForcedFailure),
            "full-ram-installer" => Some(Self::FullRamInstaller),
            _ => None,
        }
    }
}

impl std::fmt::Display for OneShotPowerLossPoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowsQemuOneShotPlan {
    pub backend: OneShotBootBackend,
    pub installer_mode: OneShotInstallerMode,
    /// Pinned Server ISO and the guest URL serving it; set only for the full-RAM installer.
    pub installer_artifact: Option<PathBuf>,
    pub installer_source_url: Option<String>,
    pub current_os: WindowsQemuCurrentOsPlan,
    pub efibootmgr: PathBuf,
    pub grub_mkstandalone: PathBuf,
    pub current_os_loader: String,
    pub temporary_entry_label: String,
    pub installer_disk_guest_path: String,
    pub installer_loader_path: String,
    pub installer_outcome: String,
    pub scenarios: Vec<OneShotPowerLossPoint>,
    pub power_cut_method: String,
    pub persistent_boot_order_changes: bool,
    pub typed_confirmation: String,
}

impl WindowsQemuOneShotPlan {
    fn temporary_entry_description(&self) -> String {
        match self.backend {
            OneShotBootBackend::LinuxGrubReboot => format!(
                "menu entry `{GRUB_ONE_SHOT_ENTRY_ID}` in {ONE_SHOT_CURRENT_OS_ESP_DEVICE}:/grub/{GRUB_ONE_SHOT_ENTRY_ID}.cfg, booting the installer kernel on {}",
                self.installer_disk_guest_path
            ),
            OneShotBootBackend::LinuxSystemdBootOneShot => format!(
                "Boot Loader Specification entry {ONE_SHOT_CURRENT_OS_ESP_DEVICE}:/loader/entries/{SYSTEMD_BOOT_ONESHOT_ENTRY}, with the installer kernel/initrd copied from {} to {ONE_SHOT_CURRENT_OS_ESP_DEVICE}:/nousb",
                self.installer_disk_guest_path
            ),
            _ => format!(
                "firmware entry {} -> {} on {} (created outside BootOrder)",
                self.temporary_entry_label, self.installer_loader_path, self.installer_disk_guest_path
            ),
        }
    }

    fn selector_description(&self) -> &'static str {
        match self.backend {
            OneShotBootBackend::LinuxGrubReboot => {
                "GRUB next_entry in the current OS's grubenv (cleared by GRUB with save_env before booting it)"
            }
            OneShotBootBackend::LinuxSystemdBootOneShot => {
                "systemd-boot LoaderEntryOneShot EFI variable (deleted by systemd-boot when it boots the entry)"
            }
            _ => "UEFI BootNext (consumed by firmware before it starts the entry)",
        }
    }

    pub fn preview(&self) -> String {
        format!(
            "Disposable current-OS one-shot plan ({}, {})\nRuntime: {}\nFirmware: {}\nDisposable root disk: {} bytes\nMemory: {} MiB\nCPUs: {}\nGuest boot tool: {}\nCurrent OS loader: {}\nTemporary entry: {}\nOne-shot selector: {}\nInstaller outcome: {}\nScenarios: {}\nPower cut: {}\nPersistent BootOrder changes: {}\nNetwork enabled: {}\nPhysical disks attached: {}\nHost boot changes: {}\nSecure Boot enabled: {}\nPurpose: prove that a real one-shot selection boots the installer once, that the current OS's default boot path is unchanged and taken again, and that cleanup recovers after power loss at every step.\nConfirmation phrase: {}\n",
            self.backend.id(),
            self.installer_mode.as_str(),
            self.current_os.runtime_version,
            self.current_os.firmware_code.display(),
            self.current_os.root_disk_size_bytes,
            self.current_os.memory_mb,
            self.current_os.cpu_count,
            self.efibootmgr.display(),
            self.current_os_loader,
            self.temporary_entry_description(),
            self.selector_description(),
            self.installer_outcome,
            self.scenarios
                .iter()
                .map(|point| point.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            self.power_cut_method,
            self.persistent_boot_order_changes,
            self.current_os.network_enabled,
            self.current_os.physical_disks_attached,
            self.current_os.host_boot_changes,
            self.current_os.secure_boot_enabled,
            self.typed_confirmation,
        )
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{\"backend\":\"{}\",\"installer_mode\":\"{}\",\"installer_source_url\":{},\"current_os\":{},\"efibootmgr\":\"{}\",\"grub_mkstandalone\":\"{}\",\"current_os_loader\":\"{}\",\"temporary_entry_label\":\"{}\",\"installer_disk_guest_path\":\"{}\",\"installer_loader_path\":\"{}\",\"installer_outcome\":\"{}\",\"scenarios\":[{}],\"power_cut_method\":\"{}\",\"persistent_boot_order_changes\":{},\"typed_confirmation\":\"{}\"}}",
            self.backend.id(),
            self.installer_mode.as_str(),
            json_optional(self.installer_source_url.as_deref()),
            self.current_os.to_json(),
            escape_json(&self.efibootmgr.display().to_string()),
            escape_json(&self.grub_mkstandalone.display().to_string()),
            escape_json(&self.current_os_loader),
            escape_json(&self.temporary_entry_label),
            escape_json(&self.installer_disk_guest_path),
            escape_json(&self.installer_loader_path),
            escape_json(&self.installer_outcome),
            self.scenarios
                .iter()
                .map(|point| format!("\"{}\"", point.as_str()))
                .collect::<Vec<_>>()
                .join(","),
            escape_json(&self.power_cut_method),
            self.persistent_boot_order_changes,
            escape_json(&self.typed_confirmation),
        )
    }
}

/// Evidence parsed from the concatenated serial logs of one scenario.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OneShotScenarioEvaluation {
    pub baseline_boot_current: Option<String>,
    pub baseline_boot_order: Option<String>,
    pub temporary_entry: Option<String>,
    pub boot_order_unchanged_while_armed: bool,
    pub bootnext_armed: bool,
    pub installer_boots: usize,
    pub temporary_entry_starts: usize,
    pub returned_to_current_os: bool,
    pub bootnext_absent_after_return: bool,
    pub final_boot_order: Option<String>,
    pub final_bootnext_absent: bool,
    pub temporary_entries_remaining: Option<u32>,
    pub failures: Vec<String>,
}

impl OneShotScenarioEvaluation {
    pub fn passed(&self) -> bool {
        self.failures.is_empty()
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{\"baseline_boot_current\":{},\"baseline_boot_order\":{},\"temporary_entry\":{},\"boot_order_unchanged_while_armed\":{},\"bootnext_armed\":{},\"installer_boots\":{},\"temporary_entry_starts\":{},\"returned_to_current_os\":{},\"bootnext_absent_after_return\":{},\"final_boot_order\":{},\"final_bootnext_absent\":{},\"temporary_entries_remaining\":{},\"passed\":{},\"failures\":[{}]}}",
            json_optional(self.baseline_boot_current.as_deref()),
            json_optional(self.baseline_boot_order.as_deref()),
            json_optional(self.temporary_entry.as_deref()),
            self.boot_order_unchanged_while_armed,
            self.bootnext_armed,
            self.installer_boots,
            self.temporary_entry_starts,
            self.returned_to_current_os,
            self.bootnext_absent_after_return,
            json_optional(self.final_boot_order.as_deref()),
            self.final_bootnext_absent,
            self.temporary_entries_remaining
                .map(|count| count.to_string())
                .unwrap_or_else(|| "null".into()),
            self.passed(),
            json_string_list(&self.failures),
        )
    }
}

/// Payload evidence for the full-RAM installer mode, all observed on the serial console.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FullRamInstallerEvidence {
    pub iso_copied_into_ram: bool,
    pub http_source_stopped_after_copy: bool,
    pub systemd_started_after_stop: bool,
    pub subiquity_payload_mounted_after_stop: bool,
    pub serial_getty_started_after_stop: bool,
    pub reset_after_installer: bool,
}

impl FullRamInstallerEvidence {
    pub fn complete(&self) -> bool {
        self.iso_copied_into_ram
            && self.http_source_stopped_after_copy
            && self.systemd_started_after_stop
            && self.subiquity_payload_mounted_after_stop
            && self.serial_getty_started_after_stop
            && self.reset_after_installer
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{\"iso_copied_into_ram\":{},\"http_source_stopped_after_copy\":{},\"systemd_started_after_stop\":{},\"subiquity_payload_mounted_after_stop\":{},\"serial_getty_started_after_stop\":{},\"reset_after_installer\":{},\"complete\":{}}}",
            self.iso_copied_into_ram,
            self.http_source_stopped_after_copy,
            self.systemd_started_after_stop,
            self.subiquity_payload_mounted_after_stop,
            self.serial_getty_started_after_stop,
            self.reset_after_installer,
            self.complete(),
        )
    }

    /// Updates the post-copy evidence from serial output written after the source stopped.
    pub fn observe_after_stop(&mut self, suffix: &str) {
        self.systemd_started_after_stop |=
            suffix.contains("Welcome to") && suffix.contains("Ubuntu 24.04.4 LTS");
        self.subiquity_payload_mounted_after_stop |=
            suffix.contains("Mounted") && suffix.contains("snap-subiquity-");
        self.serial_getty_started_after_stop |= (suffix.contains("serial-getty@ttyS0.service")
            && suffix.contains("installer for Ubuntu Server"))
            || suffix.contains("Ubuntu 24.04.4 LTS ubuntu-server ttyS0");
    }

    pub fn installer_ready(&self) -> bool {
        self.systemd_started_after_stop
            && self.subiquity_payload_mounted_after_stop
            && self.serial_getty_started_after_stop
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowsQemuOneShotScenarioReport {
    pub point: OneShotPowerLossPoint,
    pub scenario_directory: PathBuf,
    pub power_cycles: u32,
    pub power_cut_applied: bool,
    pub evaluation: OneShotScenarioEvaluation,
    pub full_ram: Option<FullRamInstallerEvidence>,
}

impl WindowsQemuOneShotScenarioReport {
    pub fn passed(&self) -> bool {
        self.evaluation.passed()
            && self
                .full_ram
                .as_ref()
                .is_none_or(FullRamInstallerEvidence::complete)
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{\"scenario\":\"{}\",\"scenario_directory\":\"{}\",\"power_cycles\":{},\"power_cut_applied\":{},\"installer_boot_expected\":{},\"evaluation\":{},\"full_ram_installer\":{},\"passed\":{}}}",
            self.point.as_str(),
            escape_json(&self.scenario_directory.display().to_string()),
            self.power_cycles,
            self.power_cut_applied,
            self.point.installer_boot_expected(),
            self.evaluation.to_json(),
            self.full_ram
                .as_ref()
                .map(FullRamInstallerEvidence::to_json)
                .unwrap_or_else(|| "null".into()),
            self.passed(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowsQemuOneShotReport {
    pub backend: OneShotBootBackend,
    pub run_directory: PathBuf,
    pub report_path: PathBuf,
    pub scenarios: Vec<WindowsQemuOneShotScenarioReport>,
    pub real_vm_executed: bool,
    pub one_shot_selection_proven: bool,
    pub installer_fallback_proven: bool,
    pub power_loss_matrix_complete: bool,
    pub all_scenarios_passed: bool,
    pub secure_boot_enabled: bool,
    pub network_enabled: bool,
    pub physical_disks_attached: bool,
    pub host_boot_changes: bool,
    pub full_installer_payload_in_ram: bool,
    pub trust_level: String,
}

impl WindowsQemuOneShotReport {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"backend\":\"{}\",\"run_directory\":\"{}\",\"report_path\":\"{}\",\"scenarios\":[{}],\"real_vm_executed\":{},\"one_shot_selection_proven\":{},\"installer_fallback_proven\":{},\"power_loss_matrix_complete\":{},\"all_scenarios_passed\":{},\"secure_boot_enabled\":{},\"network_enabled\":{},\"physical_disks_attached\":{},\"host_boot_changes\":{},\"full_installer_payload_in_ram\":{},\"trust_level\":\"{}\"}}",
            self.backend.id(),
            escape_json(&self.run_directory.display().to_string()),
            escape_json(&self.report_path.display().to_string()),
            self.scenarios
                .iter()
                .map(WindowsQemuOneShotScenarioReport::to_json)
                .collect::<Vec<_>>()
                .join(","),
            self.real_vm_executed,
            self.one_shot_selection_proven,
            self.installer_fallback_proven,
            self.power_loss_matrix_complete,
            self.all_scenarios_passed,
            self.secure_boot_enabled,
            self.network_enabled,
            self.physical_disks_attached,
            self.host_boot_changes,
            self.full_installer_payload_in_ram,
            escape_json(&self.trust_level),
        )
    }
}

fn json_string_list(values: &[String]) -> String {
    values
        .iter()
        .map(|value| format!("\"{}\"", escape_json(value)))
        .collect::<Vec<_>>()
        .join(",")
}

fn json_optional(value: Option<&str>) -> String {
    value
        .map(|value| format!("\"{}\"", escape_json(value)))
        .unwrap_or_else(|| "null".into())
}

/// Number of kernel boots whose command line carries the installer marker. Each `Linux version`
/// banner starts a boot; the kernel echoes its command line twice (`Command line:` early and
/// `Kernel command line:` later), and a power cut can land between them, so any marker line
/// within a boot counts that boot once.
pub fn one_shot_installer_boot_count(serial: &str) -> usize {
    let mut count = 0;
    let mut counted_this_boot = false;
    for line in serial.lines() {
        if line.contains(LINUX_BANNER) {
            counted_this_boot = false;
        }
        if !counted_this_boot && is_installer_command_line(line) {
            count += 1;
            counted_this_boot = true;
        }
    }
    count
}

fn is_installer_command_line(line: &str) -> bool {
    (line.contains(KERNEL_COMMAND_LINE) || line.contains(EARLY_COMMAND_LINE))
        && line.contains(ONE_SHOT_INSTALLER_MARKER)
}

struct MarkerLine<'a> {
    index: usize,
    fields: Vec<(&'a str, &'a str)>,
}

impl MarkerLine<'_> {
    fn field(&self, key: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(name, _)| *name == key)
            .map(|(_, value)| *value)
    }
}

fn marker_lines<'a>(lines: &[&'a str], marker: &str) -> Vec<MarkerLine<'a>> {
    lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| {
            let start = line.find(marker)?;
            let rest = &line[start + marker.len()..];
            if !(rest.is_empty() || rest.starts_with(' ')) {
                return None;
            }
            let fields = rest
                .split_whitespace()
                .filter_map(|token| token.split_once('='))
                .collect();
            Some(MarkerLine { index, fields })
        })
        .collect()
}

/// The serial line proving that the one-shot selector actually started the temporary entry:
/// OVMF's boot manager for `BootNext`, or the current OS's GRUB for `next_entry`.
fn temporary_entry_start_marker(backend: OneShotBootBackend, entry: &str) -> String {
    match backend {
        OneShotBootBackend::LinuxGrubReboot => {
            format!("NOUSB_GRUB loader=current-os-standalone booting={entry}")
        }
        _ => format!("{FIRMWARE_START_PREFIX}{entry} "),
    }
}

/// Index of the first line containing `needle` in each kernel boot (split at the Linux banner).
fn first_match_per_boot(lines: &[&str], needle: &str) -> Vec<usize> {
    let mut found = Vec::new();
    let mut matched_this_boot = false;
    for (index, line) in lines.iter().enumerate() {
        if line.contains(LINUX_BANNER) {
            matched_this_boot = false;
        }
        if !matched_this_boot && line.contains(needle) {
            found.push(index);
            matched_this_boot = true;
        }
    }
    found
}

/// Checks the serial evidence of one scenario against the one-shot invariants.
pub fn evaluate_one_shot_serial(
    backend: OneShotBootBackend,
    point: OneShotPowerLossPoint,
    power_cut_applied: bool,
    serial: &str,
) -> OneShotScenarioEvaluation {
    let lines: Vec<&str> = serial
        .lines()
        .map(|line| line.trim_end_matches('\r'))
        .collect();
    let mut evaluation = OneShotScenarioEvaluation::default();
    let failures = &mut evaluation.failures;

    if point.trigger().is_some() && !power_cut_applied {
        failures.push(format!("power cut for {point} was never applied"));
    }
    for error in marker_lines(&lines, "NOUSB_ERROR") {
        failures.push(format!(
            "guest reported error {}",
            error.field("reason").unwrap_or("unknown")
        ));
    }

    let baselines = marker_lines(&lines, "NOUSB_BASELINE");
    match baselines.as_slice() {
        [baseline] => {
            evaluation.baseline_boot_current = baseline.field("bootcurrent").map(str::to_owned);
            evaluation.baseline_boot_order = baseline.field("bootorder").map(str::to_owned);
        }
        [] => failures.push("baseline boot state was never recorded".into()),
        _ => failures.push("baseline boot state was recorded more than once".into()),
    }
    let baseline_order = evaluation.baseline_boot_order.clone();
    let baseline_current = evaluation.baseline_boot_current.clone();

    let created = marker_lines(&lines, "NOUSB_STEP=temporary-entry-created");
    let mut boot_order_unchanged = true;
    match created.first() {
        Some(line) => {
            evaluation.temporary_entry = line.field("entry").map(str::to_owned);
            if line.field("bootorder") != baseline_order.as_deref() {
                boot_order_unchanged = false;
                failures.push("creating the temporary entry changed BootOrder".into());
            }
        }
        None => failures.push("temporary one-shot entry was never created".into()),
    }
    if evaluation.temporary_entry.as_deref() == baseline_current.as_deref() {
        failures.push("temporary entry collides with the current OS boot entry".into());
    }

    let armed = marker_lines(&lines, "NOUSB_STEP=bootnext-armed");
    if let Some(line) = armed.first() {
        evaluation.bootnext_armed = line.field("bootnext").is_some()
            && line.field("bootnext") == evaluation.temporary_entry.as_deref();
        if !evaluation.bootnext_armed {
            failures.push("BootNext did not name the temporary entry".into());
        }
        if line.field("bootorder") != baseline_order.as_deref() {
            boot_order_unchanged = false;
            failures.push("arming BootNext changed BootOrder".into());
        }
    } else if point.installer_boot_expected() {
        failures.push("BootNext was never armed".into());
    }
    evaluation.boot_order_unchanged_while_armed = boot_order_unchanged;

    evaluation.installer_boots = one_shot_installer_boot_count(serial);
    let expected_installer_boots = usize::from(point.installer_boot_expected());
    if evaluation.installer_boots != expected_installer_boots {
        failures.push(format!(
            "expected {expected_installer_boots} installer boot(s), observed {}",
            evaluation.installer_boots
        ));
    }
    let firmware_starts: Vec<usize> = match evaluation.temporary_entry.as_deref() {
        // systemd-boot is silent on serial; its temporary entry tags the kernel options instead.
        Some(_) if backend == OneShotBootBackend::LinuxSystemdBootOneShot => {
            first_match_per_boot(&lines, SYSTEMD_BOOT_ONESHOT_TAG)
        }
        Some(entry) => {
            let start = temporary_entry_start_marker(backend, entry);
            lines
                .iter()
                .enumerate()
                .filter(|(_, line)| line.contains(&start))
                .map(|(index, _)| index)
                .collect()
        }
        None => Vec::new(),
    };
    evaluation.temporary_entry_starts = firmware_starts.len();
    if firmware_starts.len() != expected_installer_boots {
        failures.push(format!(
            "expected the boot loader to start the temporary entry {expected_installer_boots} time(s), observed {}",
            firmware_starts.len()
        ));
    }
    let installer_kernel = lines
        .iter()
        .position(|line| is_installer_command_line(line));
    if let (Some(firmware_start), Some(kernel)) = (firmware_starts.first(), installer_kernel) {
        if kernel < *firmware_start {
            failures.push(
                "installer kernel ran before the boot loader started the temporary entry".into(),
            );
        }
    }

    let returns = marker_lines(&lines, "NOUSB_STEP=returned-to-current-os");
    evaluation.returned_to_current_os = !returns.is_empty()
        && returns.iter().all(|line| {
            line.field("bootcurrent") == baseline_current.as_deref()
                && line.field("bootcurrent") != evaluation.temporary_entry.as_deref()
        });
    if !evaluation.returned_to_current_os {
        failures.push("firmware did not return to the original current-OS entry".into());
    }
    evaluation.bootnext_absent_after_return = !returns.is_empty()
        && returns
            .iter()
            .all(|line| line.field("bootnext") == Some("absent"));
    if !evaluation.bootnext_absent_after_return {
        failures.push("BootNext was still pending after control returned".into());
    }
    if let (Some(first_return), Some(armed_line)) = (returns.first(), armed.first()) {
        if point.installer_boot_expected() {
            match installer_kernel {
                Some(index) if index > armed_line.index && index < first_return.index => {}
                _ => failures
                    .push("installer boot was not observed between arming and the return".into()),
            }
        }
    }

    let finals = marker_lines(&lines, "NOUSB_FINAL");
    match finals.as_slice() {
        [final_line] => {
            evaluation.final_boot_order = final_line.field("bootorder").map(str::to_owned);
            evaluation.final_bootnext_absent = final_line.field("bootnext") == Some("absent");
            evaluation.temporary_entries_remaining = final_line
                .field("temporary_entries")
                .and_then(|value| value.parse().ok());
            if final_line.field("result") != Some("pass") {
                failures.push("guest final verification did not pass".into());
            }
            if evaluation.final_boot_order.is_none()
                || evaluation.final_boot_order != baseline_order
            {
                failures.push("final BootOrder differs from the baseline".into());
            }
            if final_line.field("bootcurrent") != baseline_current.as_deref() {
                failures.push("final boot did not use the original current-OS entry".into());
            }
            if !evaluation.final_bootnext_absent {
                failures.push("BootNext remained set after cleanup".into());
            }
            if evaluation.temporary_entries_remaining != Some(0) {
                failures.push("temporary boot entries remained after cleanup".into());
            }
            if final_line.index + 1 < lines.len()
                && lines[final_line.index + 1..]
                    .iter()
                    .any(|line| line.contains("NOUSB_STEP="))
            {
                failures.push("guest kept changing boot state after final verification".into());
            }
        }
        [] => failures.push("final verification boot never completed".into()),
        _ => failures.push("final verification ran more than once".into()),
    }
    evaluation
}

#[cfg(target_os = "windows")]
fn runtime_manifest_path(runtime_root: &Path) -> PathBuf {
    runtime_root.with_extension("manifest.json")
}

/// Places Microsoft's UEFI CA 2011 certificate in the runtime for the Secure Boot rehearsal's
/// guest-side `db` enrollment, refusing any bytes that do not match the pinned digest.
#[cfg(target_os = "windows")]
fn install_microsoft_uefi_ca(runtime_root: &Path) -> Result<(), NoUsbError> {
    let certificate = runtime_root.join(MICROSOFT_UEFI_CA_2011_RUNTIME_PATH);
    if certificate.is_file() && sha256_file(&certificate)? == MICROSOFT_UEFI_CA_2011_SHA256 {
        return Ok(());
    }
    let bytes = fetch_https_bytes(MICROSOFT_UEFI_CA_2011_URL)?;
    if let Some(parent) = certificate.parent() {
        fs::create_dir_all(parent)?;
    }
    let partial = certificate.with_extension("crt.part");
    fs::write(&partial, bytes)?;
    let digest = sha256_file(&partial)?;
    if digest != MICROSOFT_UEFI_CA_2011_SHA256 {
        let _ = fs::remove_file(&partial);
        return Err(NoUsbError::Verification(format!(
            "Microsoft UEFI CA 2011 download has SHA-256 {digest}, expected {MICROSOFT_UEFI_CA_2011_SHA256}"
        )));
    }
    fs::rename(&partial, &certificate)?;
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn windows_qemu_runtime_bootstrap_plan(
    base_dir: &Path,
) -> Result<WindowsQemuRuntimeBootstrapPlan, NoUsbError> {
    let runtime_root = project_qemu_root(base_dir)?;
    let runtime_present = runtime_root.join("lib/apk/db/installed").is_file();
    let mirror = format!("https://dl-cdn.alpinelinux.org/alpine/{QEMU_RUNTIME_ALPINE_RELEASE}");
    Ok(WindowsQemuRuntimeBootstrapPlan {
        manifest_path: runtime_manifest_path(&runtime_root),
        runtime_root,
        alpine_release: QEMU_RUNTIME_ALPINE_RELEASE.into(),
        repositories: vec![format!("{mirror}/main"), format!("{mirror}/community")],
        packages: QEMU_RUNTIME_PACKAGES
            .iter()
            .map(|item| (*item).into())
            .collect(),
        keys_directory: "/etc/apk/keys".into(),
        runtime_present,
        installs_into_windows: false,
        host_boot_changes: false,
        typed_confirmation: "ASSEMBLE PROJECT-LOCAL QEMU RUNTIME".into(),
    })
}

#[cfg(not(target_os = "windows"))]
pub fn windows_qemu_runtime_bootstrap_plan(
    _base_dir: &std::path::Path,
) -> Result<WindowsQemuRuntimeBootstrapPlan, NoUsbError> {
    Err(NoUsbError::ArtifactUnavailable(
        "the WSL-backed project-local QEMU runtime is only available on Windows".into(),
    ))
}

#[cfg(target_os = "windows")]
pub fn run_windows_qemu_runtime_bootstrap(
    base_dir: &Path,
    confirmation: &str,
) -> Result<WindowsQemuRuntimeBootstrapReport, NoUsbError> {
    let plan = windows_qemu_runtime_bootstrap_plan(base_dir)?;
    if confirmation.trim() != plan.typed_confirmation {
        return Err(NoUsbError::UnsafeExecution(format!(
            "type exactly: {}",
            plan.typed_confirmation
        )));
    }
    if plan.runtime_root.exists() && !plan.runtime_present {
        let empty = fs::read_dir(&plan.runtime_root)?.next().is_none();
        if !empty {
            return Err(NoUsbError::UnsafeExecution(format!(
                "{} exists but is not an apk-managed runtime; move it aside before bootstrapping",
                plan.runtime_root.display()
            )));
        }
    }
    fs::create_dir_all(&plan.runtime_root)?;
    let runtime_wsl = windows_to_docker_wsl_path(&plan.runtime_root)?;

    let mut arguments = vec!["apk".to_string(), "--root".to_string(), runtime_wsl.clone()];
    if !plan.runtime_present {
        arguments.push("--initdb".into());
    }
    arguments.extend([
        "--keys-dir".to_string(),
        plan.keys_directory.clone(),
        "--repositories-file".to_string(),
        "/dev/null".to_string(),
        "--arch".to_string(),
        "x86_64".to_string(),
        "--no-interactive".to_string(),
    ]);
    for repository in &plan.repositories {
        arguments.push("--repository".into());
        arguments.push(repository.clone());
    }
    arguments.push("add".into());
    arguments.extend(plan.packages.iter().cloned());
    run_wsl_output(
        &arguments,
        "install signed Alpine packages into the project-local runtime",
    )?;
    install_microsoft_uefi_ca(&plan.runtime_root)?;

    let qemu_output = run_wsl_output(
        &[
            "env".into(),
            format!("LD_LIBRARY_PATH={runtime_wsl}/lib:{runtime_wsl}/usr/lib"),
            format!("{runtime_wsl}/usr/bin/qemu-system-x86_64"),
            "--version".into(),
        ],
        "query the project-local QEMU version",
    )?;
    let qemu_version = qemu_output
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_string();
    if !qemu_version.starts_with(QEMU_RUNTIME_VERSION_PREFIX) {
        return Err(NoUsbError::Verification(format!(
            "project-local runtime reports `{qemu_version}`, expected {QEMU_RUNTIME_VERSION_PREFIX}"
        )));
    }
    for required in [
        "usr/share/OVMF/OVMF_CODE.fd",
        "usr/share/OVMF/OVMF_VARS.fd",
        "usr/sbin/efibootmgr",
        "bin/busybox",
        "bin/busybox-extras",
        "usr/bin/grub-mkstandalone",
        "usr/lib/grub/x86_64-efi/linux.mod",
        "sbin/sfdisk",
        "sbin/mkfs.fat",
        "usr/bin/mtools",
        "usr/bin/efi-updatevar",
        "usr/bin/cert-to-efi-sig-list",
        "usr/bin/sign-efi-sig-list",
        "usr/bin/openssl",
        "usr/share/qemu/edk2-x86_64-secure-code.fd",
        "usr/share/qemu/edk2-i386-vars.fd",
        SYSTEMD_BOOT_RUNTIME_PATH,
    ] {
        if !plan.runtime_root.join(required).is_file() {
            return Err(NoUsbError::Verification(format!(
                "project-local runtime is missing {required} after bootstrap"
            )));
        }
    }
    let installed_packages: Vec<String> = run_wsl_output(
        &[
            "apk".into(),
            "--root".into(),
            runtime_wsl,
            "info".into(),
            "-v".into(),
        ],
        "list project-local runtime packages",
    )?
    .lines()
    .map(str::trim)
    .filter(|line| !line.is_empty())
    .map(str::to_owned)
    .collect();
    let signing_key_digests: Vec<String> = run_wsl_output(
        &[
            "sh".into(),
            "-c".into(),
            format!("sha256sum {}/*.pub", plan.keys_directory),
        ],
        "record Alpine signing key digests",
    )?
    .lines()
    .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
    .filter(|line| !line.is_empty())
    .collect();

    let report = WindowsQemuRuntimeBootstrapReport {
        runtime_root: plan.runtime_root,
        manifest_path: plan.manifest_path,
        qemu_version,
        installed_packages,
        signing_key_digests,
        runtime_was_present: plan.runtime_present,
        installs_into_windows: false,
        host_boot_changes: false,
    };
    fs::write(&report.manifest_path, report.to_json())?;
    Ok(report)
}

#[cfg(not(target_os = "windows"))]
pub fn run_windows_qemu_runtime_bootstrap(
    _base_dir: &std::path::Path,
    _confirmation: &str,
) -> Result<WindowsQemuRuntimeBootstrapReport, NoUsbError> {
    Err(NoUsbError::ArtifactUnavailable(
        "the WSL-backed project-local QEMU runtime is only available on Windows".into(),
    ))
}

#[cfg(target_os = "windows")]
pub fn windows_qemu_one_shot_plan(
    base_dir: &Path,
    backend: OneShotBootBackend,
    installer_mode: OneShotInstallerMode,
) -> Result<WindowsQemuOneShotPlan, NoUsbError> {
    if !disposable_one_shot_backend_supported(backend) {
        return Err(NoUsbError::ArtifactUnavailable(format!(
            "{backend} cannot be rehearsed in the disposable Linux guest; it needs a disposable Windows guest image, which this harness does not provide"
        )));
    }
    let mut current_os = windows_qemu_current_os_plan(base_dir)?;
    let efibootmgr = current_os.runtime_root.join("usr/sbin/efibootmgr");
    let grub_mkstandalone = current_os.runtime_root.join("usr/bin/grub-mkstandalone");
    let runtime_root = &current_os.runtime_root;
    for required in [
        efibootmgr.clone(),
        grub_mkstandalone.clone(),
        runtime_root.join("usr/lib/grub/x86_64-efi/linux.mod"),
        runtime_root.join("sbin/sfdisk"),
        runtime_root.join("sbin/mkfs.fat"),
        runtime_root.join("usr/bin/mtools"),
        runtime_root.join(SYSTEMD_BOOT_RUNTIME_PATH),
    ] {
        if !required.is_file() {
            return Err(NoUsbError::ArtifactUnavailable(format!(
                "project-local runtime lacks {}; run `nousb vm qemu bootstrap-runtime` first",
                required.display()
            )));
        }
    }
    current_os.cpu_count = 2;
    let (installer_artifact, installer_source_url) = match installer_mode {
        OneShotInstallerMode::ForcedFailure => (None, None),
        OneShotInstallerMode::FullRamInstaller => {
            // Re-verifies the pinned 3.2 GiB Server ISO and reuses the proven RAM transport.
            let full_ram = windows_qemu_full_ram_plan(base_dir)?;
            current_os.memory_mb = full_ram.memory_mb;
            current_os.network_enabled = true;
            (Some(full_ram.artifact), Some(full_ram.recovery_source_url))
        }
    };
    let typed_confirmation = "RUN DISPOSABLE CURRENT OS UEFI ONE-SHOT MATRIX".to_string();
    current_os.typed_confirmation = typed_confirmation.clone();
    let current_os_loader = match backend {
        OneShotBootBackend::LinuxSystemdBootOneShot => {
            "systemd-boot 258 from the runtime's signed Alpine systemd-boot package on its own writable GPT ESP image; loader.conf defaults to current.conf"
        }
        OneShotBootBackend::LinuxGrubReboot => {
            "standalone GRUB 2.12 from the runtime's signed Alpine grub-efi package on its own writable GPT ESP image; embedded configuration honours next_entry from the ESP's grubenv"
        }
        _ => {
            "standalone GRUB 2.12 from the runtime's signed Alpine grub-efi package (configuration embedded in memdisk) on its own GPT ESP image"
        }
    };
    Ok(WindowsQemuOneShotPlan {
        backend,
        installer_mode,
        installer_artifact,
        installer_source_url,
        current_os,
        efibootmgr,
        grub_mkstandalone,
        current_os_loader: current_os_loader.into(),
        temporary_entry_label: ONE_SHOT_ENTRY_LABEL.into(),
        installer_disk_guest_path: ONE_SHOT_INSTALLER_DISK.into(),
        installer_loader_path: ONE_SHOT_INSTALLER_LOADER.into(),
        installer_outcome: match (backend, installer_mode) {
            (_, OneShotInstallerMode::FullRamInstaller) => {
                "official pinned Ubuntu boot chain into casper with the full verified Server ISO copied into RAM over an isolated HTTP source that is stopped after the copy; Subiquity must start afterwards, then the machine is reset as after leaving the installer"
            }
            (OneShotBootBackend::LinuxGrubReboot, _) => {
                "official pinned Ubuntu kernel/initrd booted by the current OS's GRUB, then a forced kernel panic and reboot to model an installer failure"
            }
            _ => {
                "official pinned Ubuntu shim/GRUB/kernel boot, then a forced kernel panic and reboot to model an installer failure"
            }
        }
        .into(),
        scenarios: match installer_mode {
            // The power-loss matrix is selector logic; one full-RAM cycle joins it to the payload proof.
            OneShotInstallerMode::FullRamInstaller => vec![OneShotPowerLossPoint::CompleteCycle],
            OneShotInstallerMode::ForcedFailure => OneShotPowerLossPoint::ALL.to_vec(),
        },
        power_cut_method: "QMP quit of the disposable QEMU process after the step marker".into(),
        persistent_boot_order_changes: false,
        typed_confirmation,
    })
}

#[cfg(not(target_os = "windows"))]
pub fn windows_qemu_one_shot_plan(
    _base_dir: &std::path::Path,
    _backend: OneShotBootBackend,
    _installer_mode: OneShotInstallerMode,
) -> Result<WindowsQemuOneShotPlan, NoUsbError> {
    Err(NoUsbError::ArtifactUnavailable(
        "the WSL-backed disposable current-OS one-shot rehearsal is only available on Windows"
            .into(),
    ))
}

/// Configuration embedded in the current OS's own standalone GRUB. It lives in GRUB's memdisk,
/// so it can never be replaced by a configuration file on the installer ESP.
/// For the GRUB backend it mirrors Ubuntu's `grub-reboot` handling: a pending `next_entry` in
/// the ESP's `grubenv` becomes the default and is cleared with `save_env` before booting.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn one_shot_current_os_grub_config(backend: OneShotBootBackend) -> String {
    match backend {
        OneShotBootBackend::LinuxGrubReboot => format!(
            "set timeout=0\nsearch --no-floppy --file --set=esp /boot/vmlinuz\nset root=$esp\nload_env --file ($esp)/grub/grubenv\nset default=current\nset fallback=current\nif [ -n \"${{next_entry}}\" ]; then\n  set default=\"${{next_entry}}\"\n  set next_entry=\n  save_env --file ($esp)/grub/grubenv next_entry\nfi\necho \"NOUSB_GRUB loader=current-os-standalone selected=${{default}}\"\nmenuentry \"NoUSB disposable current OS\" --id current {{\n  echo \"NOUSB_GRUB loader=current-os-standalone booting=current\"\n  linux ($esp)/boot/vmlinuz {ONE_SHOT_CURRENT_OS_CMDLINE} ---\n  initrd ($esp)/boot/initrd\n}}\nif [ -f ($esp)/grub/{GRUB_ONE_SHOT_ENTRY_ID}.cfg ]; then\n  source ($esp)/grub/{GRUB_ONE_SHOT_ENTRY_ID}.cfg\nfi\n"
        ),
        _ => format!(
            "set timeout=0\necho \"NOUSB_GRUB loader=current-os-standalone\"\nsearch --no-floppy --file --set=root /boot/vmlinuz\nlinux /boot/vmlinuz {ONE_SHOT_CURRENT_OS_CMDLINE} ---\ninitrd /boot/initrd\nboot\n"
        ),
    }
}

/// An empty GRUB environment block: the header plus `#` padding to exactly 1024 bytes, as
/// `grub-editenv create` writes it. GRUB's `save_env` rewrites this block in place.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn empty_grubenv() -> Vec<u8> {
    let mut block = b"# GRUB Environment Block\n".to_vec();
    block.resize(1024, b'#');
    block
}

/// Configuration for the official Ubuntu image GRUB on the installer ESP. That GRUB locates
/// its configuration by searching for `/.disk/info`, which only the installer ESP carries.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn one_shot_installer_grub_config(installer_arguments: &str) -> String {
    format!(
        "set default=0\nset timeout=0\necho \"NOUSB_GRUB loader=official-installer\"\nsearch --no-floppy --file --set=root /casper/vmlinuz\nmenuentry \"NoUSB one-shot installer\" {{\n    linux /casper/vmlinuz {installer_arguments} ---\n    initrd /casper/initrd\n}}\n"
    )
}

/// The disposable current OS boots through its own bootloader, as a real installed OS does:
/// a standalone GRUB from the runtime's signed Alpine `grub-efi` package plus the kernel.
#[cfg(target_os = "windows")]
pub(crate) fn create_one_shot_current_os_esp(
    run_directory: &Path,
    plan: &WindowsQemuOneShotPlan,
) -> Result<PathBuf, NoUsbError> {
    let root = run_directory.join("one-shot-current-os-esp");
    let efi = root.join("EFI").join("BOOT");
    let boot = root.join("boot");
    fs::create_dir(&root)?;
    fs::create_dir_all(&efi)?;
    fs::create_dir(&boot)?;
    copy_create_new(&plan.current_os.kernel, &boot.join("vmlinuz"))?;
    copy_create_new(&plan.current_os.initrd, &boot.join("initrd"))?;
    let runtime_wsl = windows_to_docker_wsl_path(&plan.current_os.runtime_root)?;
    if plan.backend == OneShotBootBackend::LinuxSystemdBootOneShot {
        install_systemd_boot(&root, &efi, plan)?;
    } else {
        install_standalone_grub(run_directory, &root, &efi, plan, &runtime_wsl)?;
    }
    let top_level: Vec<String> = fs::read_dir(&root)?
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();

    // A real GPT ESP gives the current OS unique disk and partition GUIDs. QEMU's vvfat
    // disks all share one MBR signature and geometry, which makes short-form HD() boot paths
    // ambiguous between the two ESPs.
    let image = run_directory.join("one-shot-current-os-esp.img");
    let image_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&image)?;
    image_file.set_len(ONE_SHOT_CURRENT_OS_ESP_BYTES)?;
    image_file.sync_all()?;
    drop(image_file);
    // wsl.exe re-parses its command line through a shell, so the script travels as a file
    // with its (drive-letter-derived, quote-free) paths inlined.
    let image_wsl = windows_to_docker_wsl_path(&image)?;
    let files_wsl = windows_to_docker_wsl_path(&root)?;
    let sources = top_level
        .iter()
        .map(|name| format!("'{files_wsl}/{name}'"))
        .collect::<Vec<_>>()
        .join(" ");
    let script = format!(
        "set -e\nexport LD_LIBRARY_PATH='{runtime_wsl}/lib:{runtime_wsl}/usr/lib' MTOOLS_SKIP_CHECK=1\nprintf 'label: gpt\\nstart={start}, size={sectors}, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, name=\"NoUSB current OS ESP\"\\n' | '{runtime_wsl}/sbin/sfdisk' --no-reread --no-tell-kernel -q '{image_wsl}'\n'{runtime_wsl}/sbin/mkfs.fat' -F 32 -n NOUSBESP --offset {start} '{image_wsl}' {kib} >/dev/null 2>&1\n'{runtime_wsl}/usr/bin/mcopy' -i '{image_wsl}@@{offset}' -s -Q {sources} ::/\n",
        start = ONE_SHOT_ESP_START_SECTOR,
        sectors = ONE_SHOT_ESP_SECTORS,
        kib = ONE_SHOT_ESP_SECTORS / 2,
        offset = ONE_SHOT_ESP_START_SECTOR * 512,
    );
    if [&runtime_wsl, &image_wsl, &files_wsl]
        .iter()
        .any(|path| path.contains('\''))
    {
        return Err(NoUsbError::InvalidInput(
            "disposable ESP paths must not contain single quotes".into(),
        ));
    }
    let script_path = run_directory.join("build-current-os-esp.sh");
    write_create_new(&script_path, script.as_bytes())?;
    run_wsl_output(
        &["sh".into(), windows_to_docker_wsl_path(&script_path)?],
        "build the disposable current OS GPT ESP image",
    )?;
    Ok(image)
}

/// systemd-boot as the removable-media loader, defaulting to the current OS's entry.
#[cfg(target_os = "windows")]
fn install_systemd_boot(
    root: &Path,
    efi: &Path,
    plan: &WindowsQemuOneShotPlan,
) -> Result<(), NoUsbError> {
    copy_create_new(
        &plan.current_os.runtime_root.join(SYSTEMD_BOOT_RUNTIME_PATH),
        &efi.join("BOOTX64.EFI"),
    )?;
    let entries = root.join("loader").join("entries");
    fs::create_dir_all(&entries)?;
    write_create_new(
        &root.join("loader").join("loader.conf"),
        b"default current.conf\ntimeout 0\n",
    )?;
    write_create_new(
        &entries.join("current.conf"),
        systemd_boot_entry_config(
            "NoUSB disposable current OS",
            "/boot/vmlinuz",
            "/boot/initrd",
            ONE_SHOT_CURRENT_OS_CMDLINE,
        )
        .as_bytes(),
    )?;
    Ok(())
}

/// A standalone GRUB whose configuration lives in its memdisk (plus `grubenv` for next_entry).
#[cfg(target_os = "windows")]
fn install_standalone_grub(
    run_directory: &Path,
    root: &Path,
    efi: &Path,
    plan: &WindowsQemuOneShotPlan,
    runtime_wsl: &str,
) -> Result<(), NoUsbError> {
    let grub = root.join("grub");
    fs::create_dir(&grub)?;
    write_create_new(&grub.join("grubenv"), &empty_grubenv())?;
    let config = run_directory.join("current-os-grub.cfg");
    write_create_new(
        &config,
        one_shot_current_os_grub_config(plan.backend).as_bytes(),
    )?;
    run_wsl_output(
        &[
            "env".into(),
            format!("LD_LIBRARY_PATH={runtime_wsl}/lib:{runtime_wsl}/usr/lib"),
            windows_to_docker_wsl_path(&plan.grub_mkstandalone)?,
            "-d".into(),
            format!("{runtime_wsl}/usr/lib/grub/x86_64-efi"),
            "-O".into(),
            "x86_64-efi".into(),
            "--locales=".into(),
            "--fonts=".into(),
            "--themes=".into(),
            "--install-modules=normal configfile echo test search search_fs_file part_msdos part_gpt fat ext2 linux boot loadenv".into(),
            "--modules=part_gpt part_msdos fat search search_fs_file linux echo test normal loadenv configfile".into(),
            "-o".into(),
            windows_to_docker_wsl_path(&efi.join("BOOTX64.EFI"))?,
            format!("boot/grub/grub.cfg={}", windows_to_docker_wsl_path(&config)?),
        ],
        "build the disposable current OS standalone GRUB",
    )?;
    Ok(())
}

#[cfg(target_os = "windows")]
pub(crate) fn create_one_shot_installer_esp(
    run_directory: &Path,
    plan: &WindowsQemuOneShotPlan,
) -> Result<PathBuf, NoUsbError> {
    let root = run_directory.join("one-shot-installer-esp");
    let efi = root.join("EFI").join("BOOT");
    let casper = root.join("casper");
    let disk_info = root.join(".disk");
    let boot_grub = root.join("boot").join("grub");
    let root_grub = root.join("grub");
    fs::create_dir(&root)?;
    fs::create_dir_all(&efi)?;
    fs::create_dir(&casper)?;
    fs::create_dir(&disk_info)?;
    fs::create_dir_all(&boot_grub)?;
    fs::create_dir(&root_grub)?;
    let current_os = &plan.current_os;
    copy_create_new(&current_os.bootx64, &efi.join("BOOTX64.EFI"))?;
    copy_create_new(&current_os.grubx64, &efi.join("grubx64.efi"))?;
    copy_create_new(&current_os.mmx64, &efi.join("mmx64.efi"))?;
    copy_create_new(&current_os.kernel, &casper.join("vmlinuz"))?;
    copy_create_new(&current_os.initrd, &casper.join("initrd"))?;
    write_create_new(
        &disk_info.join("info"),
        b"NoUSB disposable one-shot installer (Ubuntu 24.04.4 Server boot assets)\n",
    )?;
    let config = one_shot_installer_grub_config(&installer_kernel_arguments(
        plan.installer_source_url.as_deref(),
    ));
    write_create_new(&boot_grub.join("grub.cfg"), config.as_bytes())?;
    write_create_new(&efi.join("grub.cfg"), config.as_bytes())?;
    write_create_new(&root_grub.join("grub.cfg"), config.as_bytes())?;
    Ok(root)
}

#[cfg(target_os = "windows")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PowerCycleOutcome {
    PoweredOff,
    PowerCut,
    InstallerLoop,
    BootloaderPrompt,
    TimedOut,
}

#[cfg(target_os = "windows")]
struct OneShotMachine<'a> {
    plan: &'a WindowsQemuOneShotPlan,
    firmware_code: PathBuf,
    firmware_vars: PathBuf,
    root_disk: PathBuf,
    current_esp: PathBuf,
    installer_esp: &'a Path,
}

#[cfg(target_os = "windows")]
impl OneShotMachine<'_> {
    fn arguments(&self, serial_log: &Path) -> Result<Vec<String>, NoUsbError> {
        let current_os = &self.plan.current_os;
        let runtime_root_wsl = windows_to_docker_wsl_path(&current_os.runtime_root)?;
        let binary_wsl = windows_to_docker_wsl_path(
            &current_os.runtime_root.join("usr/bin/qemu-system-x86_64"),
        )?;
        let code_wsl = windows_to_docker_wsl_path(&self.firmware_code)?;
        let vars_wsl = windows_to_docker_wsl_path(&self.firmware_vars)?;
        let disk_wsl = windows_to_docker_wsl_path(&self.root_disk)?;
        let current_esp_wsl = windows_to_docker_wsl_path(&self.current_esp)?;
        // GRUB's save_env and the guest's systemd-boot staging write to the current OS's ESP;
        // BootNext needs no ESP writes.
        let esp_read_only = if matches!(
            self.plan.backend,
            OneShotBootBackend::LinuxGrubReboot | OneShotBootBackend::LinuxSystemdBootOneShot
        ) {
            "off"
        } else {
            "on"
        };
        let installer_esp_wsl = windows_to_docker_wsl_path(self.installer_esp)?;
        let serial_wsl = windows_to_docker_wsl_path(serial_log)?;
        // Fixed PCI slots keep guest names stable: root=/dev/vda, current ESP=/dev/vdb,
        // installer ESP=/dev/vdc. Only the current ESP carries a firmware boot index.
        Ok(vec![
            "-d".into(),
            "docker-desktop".into(),
            "--".into(),
            "env".into(),
            format!("LD_LIBRARY_PATH={runtime_root_wsl}/lib:{runtime_root_wsl}/usr/lib"),
            binary_wsl,
            "-machine".into(),
            "q35,accel=tcg".into(),
            "-cpu".into(),
            "max".into(),
            "-smp".into(),
            current_os.cpu_count.to_string(),
            "-m".into(),
            current_os.memory_mb.to_string(),
            "-nodefaults".into(),
            "-display".into(),
            "none".into(),
            "-serial".into(),
            format!("file:{serial_wsl}"),
            "-monitor".into(),
            "none".into(),
            "-nic".into(),
            if self.plan.installer_mode == OneShotInstallerMode::FullRamInstaller {
                "user,model=virtio-net-pci".into()
            } else {
                "none".into()
            },
            "-L".into(),
            format!("{runtime_root_wsl}/usr/share/qemu"),
            "-drive".into(),
            format!("if=pflash,format=raw,readonly=on,file={code_wsl}"),
            "-drive".into(),
            format!("if=pflash,format=raw,file={vars_wsl}"),
            "-drive".into(),
            format!("file={disk_wsl},format=raw,if=none,id=currentroot"),
            "-device".into(),
            "virtio-blk-pci,drive=currentroot,addr=0x4".into(),
            "-blockdev".into(),
            format!("driver=file,node-name=currentesp,filename={current_esp_wsl},read-only={esp_read_only}"),
            "-device".into(),
            "virtio-blk-pci,drive=currentesp,addr=0x5,bootindex=0".into(),
            "-blockdev".into(),
            format!("driver=vvfat,node-name=installeresp,dir={installer_esp_wsl},read-only=on"),
            "-device".into(),
            // OVMF connects only devices in QEMU's boot order. BootNext names the installer disk
            // itself, but the GRUB backend reaches it from the current OS's GRUB, so it must be
            // connected: a lower-priority boot index keeps the current OS the default.
            if self.plan.backend == OneShotBootBackend::LinuxGrubReboot {
                "virtio-blk-pci,drive=installeresp,addr=0x6,bootindex=1".into()
            } else {
                "virtio-blk-pci,drive=installeresp,addr=0x6".into()
            },
            "-qmp".into(),
            "stdio".into(),
        ])
    }

    /// Powers the disposable machine on once and runs it until the guest powers off, the
    /// trigger text appears (then cuts power), the installer loops, or the deadline passes.
    fn power_cycle(
        &self,
        serial_log: &Path,
        trigger: Option<&str>,
        mut full_ram: Option<&mut FullRamWatch>,
    ) -> Result<PowerCycleOutcome, NoUsbError> {
        let arguments = self.arguments(serial_log)?;
        let child = Command::new("wsl.exe")
            .args(&arguments)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| {
                NoUsbError::Io(format!("cannot start disposable one-shot machine: {error}"))
            })?;
        let mut qemu = OwnedChild::new(child);
        let mut qmp_input = qemu
            .child_mut()?
            .stdin
            .take()
            .ok_or_else(|| NoUsbError::Io("QEMU process did not expose QMP input".into()))?;
        qmp_input.write_all(b"{\"execute\":\"qmp_capabilities\"}\n")?;
        qmp_input.flush()?;

        let timeout = if full_ram.is_some() {
            ONE_SHOT_FULL_RAM_CYCLE_TIMEOUT_SECS
        } else {
            ONE_SHOT_CYCLE_TIMEOUT_SECS
        };
        let deadline = Instant::now() + Duration::from_secs(timeout);
        let outcome = loop {
            if qemu.child_mut()?.try_wait()?.is_some() {
                break PowerCycleOutcome::PoweredOff;
            }
            let serial_bytes = fs::read(serial_log).unwrap_or_default();
            let serial = String::from_utf8_lossy(&serial_bytes);
            if let Some(watch) = full_ram.as_deref_mut() {
                if watch.advance(&serial_bytes)? {
                    // Leaving the installer: reset the machine like a user would.
                    qmp_input.write_all(b"{\"execute\":\"system_reset\"}\n")?;
                    qmp_input.flush()?;
                }
            }
            if trigger.is_some_and(|text| serial.contains(text)) {
                break PowerCycleOutcome::PowerCut;
            }
            if one_shot_installer_boot_count(&serial) > 1 {
                break PowerCycleOutcome::InstallerLoop;
            }
            if serial.contains("grub> ") || serial.contains("Shell> ") {
                break PowerCycleOutcome::BootloaderPrompt;
            }
            if Instant::now() >= deadline {
                break PowerCycleOutcome::TimedOut;
            }
            std::thread::sleep(Duration::from_millis(500));
        };
        if outcome != PowerCycleOutcome::PoweredOff {
            // A failed write only means QEMU already exited; the bounded wait below covers it.
            let _ = qmp_input
                .write_all(b"{\"execute\":\"quit\"}\n")
                .and_then(|()| qmp_input.flush());
            let quit_deadline = Instant::now() + Duration::from_secs(30);
            while qemu.child_mut()?.try_wait()?.is_none() && Instant::now() < quit_deadline {
                std::thread::sleep(Duration::from_millis(200));
            }
        }
        drop(qmp_input);
        let output = qemu.stop()?;
        let log_stem = serial_log.with_extension("");
        fs::write(log_stem.with_extension("qmp.log"), &output.stdout)?;
        fs::write(log_stem.with_extension("qemu.stderr.log"), &output.stderr)?;
        Ok(outcome)
    }
}

/// Tracks the full-RAM installer through one power cycle: stop the HTTP source once the whole
/// ISO is in guest RAM, require the installer to come up afterwards, then request a reset.
#[cfg(target_os = "windows")]
struct FullRamWatch {
    http: Option<OwnedChild>,
    log_directory: PathBuf,
    iso_filename: String,
    stop_offset: Option<usize>,
    evidence: FullRamInstallerEvidence,
}

#[cfg(target_os = "windows")]
impl FullRamWatch {
    fn start(plan: &WindowsQemuOneShotPlan, log_directory: &Path) -> Result<Self, NoUsbError> {
        let artifact = plan.installer_artifact.as_ref().ok_or_else(|| {
            NoUsbError::InvalidInput("full-RAM installer mode needs the pinned Server ISO".into())
        })?;
        let artifact_root = artifact.parent().ok_or_else(|| {
            NoUsbError::Io("Ubuntu Server artifact path has no parent directory".into())
        })?;
        let iso_filename = artifact
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .ok_or_else(|| NoUsbError::Io("Ubuntu Server artifact has no file name".into()))?;
        let runtime_root_wsl = windows_to_docker_wsl_path(&plan.current_os.runtime_root)?;
        let child = Command::new("wsl.exe")
            .args([
                "-d".to_string(),
                "docker-desktop".to_string(),
                "--".to_string(),
                "env".to_string(),
                format!("LD_LIBRARY_PATH={runtime_root_wsl}/lib:{runtime_root_wsl}/usr/lib"),
                windows_to_docker_wsl_path(
                    &plan.current_os.runtime_root.join("bin/busybox-extras"),
                )?,
                "httpd".to_string(),
                "-f".to_string(),
                "-vv".to_string(),
                "-p".to_string(),
                UBUNTU_SERVER_RECOVERY_PORT.to_string(),
                "-h".to_string(),
                windows_to_docker_wsl_path(artifact_root)?,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| {
                NoUsbError::Io(format!("cannot start the ISO HTTP source: {error}"))
            })?;
        let mut http = OwnedChild::new(child);
        std::thread::sleep(Duration::from_millis(300));
        if let Some(status) = http.child_mut()?.try_wait()? {
            return Err(NoUsbError::Verification(format!(
                "ISO HTTP source exited before QEMU started ({status}); port {UBUNTU_SERVER_RECOVERY_PORT} may be in use"
            )));
        }
        Ok(Self {
            http: Some(http),
            log_directory: log_directory.to_path_buf(),
            iso_filename,
            stop_offset: None,
            evidence: FullRamInstallerEvidence::default(),
        })
    }

    fn stop_source(&mut self) -> Result<(), NoUsbError> {
        if let Some(mut http) = self.http.take() {
            let output = http.stop()?;
            fs::write(self.log_directory.join("http.stdout.log"), &output.stdout)?;
            fs::write(self.log_directory.join("http.stderr.log"), &output.stderr)?;
        }
        Ok(())
    }

    /// Returns true exactly once: when the installer is up and the machine should be reset.
    fn advance(&mut self, serial: &[u8]) -> Result<bool, NoUsbError> {
        if self.evidence.reset_after_installer {
            return Ok(false);
        }
        let Some(offset) = self.stop_offset else {
            let text = String::from_utf8_lossy(serial);
            if text.contains(&format!("'{}' saved", self.iso_filename))
                && text.contains("Begin: Running /scripts/casper-bottom")
            {
                self.evidence.iso_copied_into_ram = true;
                self.stop_source()?;
                self.evidence.http_source_stopped_after_copy = true;
                self.stop_offset = Some(serial.len());
            }
            return Ok(false);
        };
        if let Some(suffix) = serial.get(offset..) {
            self.evidence
                .observe_after_stop(&String::from_utf8_lossy(suffix));
        }
        if self.evidence.installer_ready() {
            self.evidence.reset_after_installer = true;
            return Ok(true);
        }
        Ok(false)
    }
}

/// Deletes disposable disk images and staging trees once their evidence has been recorded, so
/// repeated matrices do not fill the disk (each scenario copies a 512 MiB root and 256 MiB ESP).
/// Failing runs keep everything for inspection.
#[cfg(target_os = "windows")]
pub(crate) fn remove_disposable_images(paths: &[&Path]) {
    for path in paths {
        let _ = if path.is_dir() {
            fs::remove_dir_all(path)
        } else {
            fs::remove_file(path)
        };
    }
}

#[cfg(target_os = "windows")]
fn run_one_shot_scenario(
    plan: &WindowsQemuOneShotPlan,
    run_directory: &Path,
    template_disk: &Path,
    current_esp: &Path,
    installer_esp: &Path,
    point: OneShotPowerLossPoint,
) -> Result<WindowsQemuOneShotScenarioReport, NoUsbError> {
    let scenario_directory = run_directory.join(point.as_str());
    fs::create_dir(&scenario_directory)?;
    let machine = OneShotMachine {
        plan,
        firmware_code: scenario_directory.join("OVMF_CODE.fd"),
        firmware_vars: scenario_directory.join("OVMF_VARS.fd"),
        root_disk: scenario_directory.join("current-os-root.ext4"),
        current_esp: scenario_directory.join("current-os-esp.img"),
        installer_esp,
    };
    // A private read-only firmware copy keeps scenarios from sharing image locks over drvfs.
    copy_create_new(&plan.current_os.firmware_code, &machine.firmware_code)?;
    copy_create_new(
        &plan.current_os.firmware_vars_template,
        &machine.firmware_vars,
    )?;
    copy_create_new(template_disk, &machine.root_disk)?;
    copy_create_new(current_esp, &machine.current_esp)?;

    let mut full_ram = match plan.installer_mode {
        OneShotInstallerMode::FullRamInstaller => {
            Some(FullRamWatch::start(plan, &scenario_directory)?)
        }
        OneShotInstallerMode::ForcedFailure => None,
    };
    let mut serial = String::new();
    let mut power_cut_applied = false;
    let mut power_cycles = 0;
    let mut cycle_failures = Vec::new();
    loop {
        power_cycles += 1;
        let serial_log = scenario_directory.join(format!("power-cycle-{power_cycles}-serial.log"));
        let trigger = if power_cut_applied {
            None
        } else {
            point.trigger()
        };
        let outcome = machine.power_cycle(&serial_log, trigger, full_ram.as_mut())?;
        serial.push_str(&String::from_utf8_lossy(
            &fs::read(&serial_log).unwrap_or_default(),
        ));
        serial.push('\n');
        match outcome {
            PowerCycleOutcome::PowerCut => power_cut_applied = true,
            PowerCycleOutcome::PoweredOff => break,
            PowerCycleOutcome::InstallerLoop => {
                cycle_failures.push(format!(
                    "power cycle {power_cycles}: installer booted repeatedly; BootNext was not one-shot"
                ));
                break;
            }
            PowerCycleOutcome::BootloaderPrompt => {
                cycle_failures.push(format!(
                    "power cycle {power_cycles}: stopped at an interactive bootloader or firmware prompt"
                ));
                break;
            }
            PowerCycleOutcome::TimedOut => {
                cycle_failures.push(format!(
                    "power cycle {power_cycles}: timed out after {ONE_SHOT_CYCLE_TIMEOUT_SECS}s"
                ));
                break;
            }
        }
    }

    let mut evaluation = evaluate_one_shot_serial(plan.backend, point, power_cut_applied, &serial);
    evaluation.failures.extend(cycle_failures);
    let full_ram = match full_ram {
        Some(mut watch) => {
            watch.stop_source()?;
            Some(watch.evidence)
        }
        None => None,
    };
    let report = WindowsQemuOneShotScenarioReport {
        point,
        scenario_directory,
        power_cycles,
        power_cut_applied,
        evaluation,
        full_ram,
    };
    fs::write(
        report.scenario_directory.join("scenario.json"),
        report.to_json(),
    )?;
    if report.passed() {
        // Logs, QMP output, the final variable store, and scenario.json remain as evidence.
        remove_disposable_images(&[
            machine.root_disk.as_path(),
            machine.current_esp.as_path(),
            machine.firmware_code.as_path(),
        ]);
    }
    Ok(report)
}

#[cfg(target_os = "windows")]
pub fn run_windows_qemu_one_shot_rehearsal(
    base_dir: &Path,
    confirmation: &str,
    backend: OneShotBootBackend,
    installer_mode: OneShotInstallerMode,
    only: Option<OneShotPowerLossPoint>,
) -> Result<WindowsQemuOneShotReport, NoUsbError> {
    let plan = windows_qemu_one_shot_plan(base_dir, backend, installer_mode)?;
    if let Some(point) = only {
        if !plan.scenarios.contains(&point) {
            return Err(NoUsbError::InvalidInput(format!(
                "scenario {point} is not part of the {} matrix",
                installer_mode.as_str()
            )));
        }
    }
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
        "current-os-one-shot-{}-{stamp}-{}",
        backend.id(),
        std::process::id()
    ));
    fs::create_dir_all(run_directory.parent().ok_or_else(|| {
        NoUsbError::Io("current-OS one-shot run directory has no parent".into())
    })?)?;
    fs::create_dir(&run_directory)?;
    let template_disk = create_disposable_current_os_root(
        &run_directory,
        &plan.current_os,
        &one_shot_guest_init(
            backend,
            &installer_kernel_arguments(plan.installer_source_url.as_deref()),
        ),
    )?;
    let current_esp = create_one_shot_current_os_esp(&run_directory, &plan)?;
    let installer_esp = create_one_shot_installer_esp(&run_directory, &plan)?;

    let points: Vec<OneShotPowerLossPoint> = match only {
        Some(point) => vec![point],
        None => plan.scenarios.clone(),
    };
    let mut scenarios = Vec::with_capacity(points.len());
    for point in points {
        scenarios.push(run_one_shot_scenario(
            &plan,
            &run_directory,
            &template_disk,
            &current_esp,
            &installer_esp,
            point,
        )?);
    }

    let complete_cycle_passed = scenarios.iter().any(|scenario| {
        scenario.point == OneShotPowerLossPoint::CompleteCycle && scenario.passed()
    });
    let all_scenarios_passed = scenarios
        .iter()
        .all(WindowsQemuOneShotScenarioReport::passed);
    let power_loss_matrix_complete = all_scenarios_passed
        && OneShotPowerLossPoint::ALL
            .iter()
            .all(|point| scenarios.iter().any(|scenario| scenario.point == *point));
    let full_installer_payload_in_ram = scenarios.iter().any(|scenario| {
        scenario.passed()
            && scenario
                .full_ram
                .as_ref()
                .is_some_and(FullRamInstallerEvidence::complete)
    });
    let report_path = run_directory.join("report.json");
    let report = WindowsQemuOneShotReport {
        backend,
        run_directory,
        report_path: report_path.clone(),
        scenarios,
        real_vm_executed: true,
        one_shot_selection_proven: complete_cycle_passed,
        installer_fallback_proven: complete_cycle_passed,
        power_loss_matrix_complete,
        all_scenarios_passed,
        secure_boot_enabled: plan.current_os.secure_boot_enabled,
        network_enabled: plan.current_os.network_enabled,
        physical_disks_attached: false,
        host_boot_changes: false,
        full_installer_payload_in_ram,
        trust_level: format!(
            "project-local-disposable-linux-root-official-pinned-ubuntu-assets-{}",
            backend.id()
        ),
    };
    let mut report_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&report_path)?;
    report_file.write_all(report.to_json().as_bytes())?;
    report_file.sync_all()?;
    if report.all_scenarios_passed {
        remove_disposable_images(&[
            template_disk.as_path(),
            current_esp.as_path(),
            installer_esp.as_path(),
            &report.run_directory.join("current-os-rootfs"),
            &report.run_directory.join("one-shot-current-os-esp"),
        ]);
    }
    if !report.all_scenarios_passed {
        let failed: Vec<String> = report
            .scenarios
            .iter()
            .filter(|scenario| !scenario.passed())
            .map(|scenario| {
                let mut failures = scenario.evaluation.failures.clone();
                if let Some(evidence) = scenario
                    .full_ram
                    .as_ref()
                    .filter(|evidence| !evidence.complete())
                {
                    failures.push(format!(
                        "full-RAM installer evidence incomplete: {}",
                        evidence.to_json()
                    ));
                }
                format!("{}: {}", scenario.point, failures.join("; "))
            })
            .collect();
        return Err(NoUsbError::Verification(format!(
            "one-shot rehearsal failed ({}); see {}",
            failed.join(" | "),
            report.report_path.display()
        )));
    }
    Ok(report)
}

#[cfg(not(target_os = "windows"))]
pub fn run_windows_qemu_one_shot_rehearsal(
    _base_dir: &std::path::Path,
    _confirmation: &str,
    _backend: OneShotBootBackend,
    _installer_mode: OneShotInstallerMode,
    _only: Option<OneShotPowerLossPoint>,
) -> Result<WindowsQemuOneShotReport, NoUsbError> {
    Err(NoUsbError::ArtifactUnavailable(
        "the WSL-backed disposable current-OS one-shot rehearsal is only available on Windows"
            .into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENTRY: &str = "0003";

    fn baseline() -> String {
        "BdsDxe: starting Boot0001\nNOUSB_BOOT phase=none bootcurrent=0001 bootnext=absent bootorder=0001,0000\nNOUSB_BASELINE bootcurrent=0001 bootorder=0001,0000\n".to_string()
    }

    fn created() -> String {
        format!("NOUSB_STEP=temporary-entry-created entry={ENTRY} bootorder=0001,0000\n")
    }

    fn armed() -> String {
        format!("NOUSB_STEP=bootnext-armed bootnext={ENTRY} bootorder=0001,0000\n")
    }

    fn installer() -> String {
        format!("{FIRMWARE_START_PREFIX}{ENTRY} \"NoUSB-OneShot\" from HD(1,MBR,0xBE1AFDFA,0x3F,0xFBFC1)/\\EFI\\BOOT\\BOOTX64.EFI\n[    0.000000] Linux version 6.8.0\n[    0.000000] Command line: BOOT_IMAGE=/casper/vmlinuz console=ttyS0,115200n8 {ONE_SHOT_INSTALLER_MARKER} panic=5\n[    0.090000] {KERNEL_COMMAND_LINE} BOOT_IMAGE=/casper/vmlinuz console=ttyS0,115200n8 {ONE_SHOT_INSTALLER_MARKER} panic=5\n[    3.000000] Kernel panic - not syncing: VFS: Unable to mount root fs\n")
    }

    fn returned() -> String {
        "NOUSB_STEP=returned-to-current-os bootcurrent=0001 baseline_bootcurrent=0001 bootnext=absent bootorder=0001,0000\n".to_string()
    }

    fn cleanup() -> String {
        "NOUSB_STEP=temporary-entry-deleted removed=1 bootnext_cleared=0\nNOUSB_STEP=cleanup-committed\n".to_string()
    }

    fn final_pass() -> String {
        "NOUSB_FINAL result=pass bootcurrent=0001 bootorder=0001,0000 baseline_bootorder=0001,0000 bootnext=absent temporary_entries=0\n".to_string()
    }

    fn complete_cycle() -> String {
        [
            baseline(),
            created(),
            armed(),
            installer(),
            returned(),
            cleanup(),
            final_pass(),
        ]
        .concat()
    }

    #[test]
    fn complete_cycle_serial_passes() {
        let evaluation = evaluate_one_shot_serial(
            OneShotBootBackend::UefiBootNext,
            OneShotPowerLossPoint::CompleteCycle,
            false,
            &complete_cycle(),
        );
        assert!(evaluation.passed(), "{:?}", evaluation.failures);
        assert_eq!(evaluation.temporary_entry.as_deref(), Some(ENTRY));
        assert_eq!(evaluation.installer_boots, 1);
        assert!(evaluation.bootnext_armed);
        assert!(evaluation.returned_to_current_os);
        assert!(evaluation.bootnext_absent_after_return);
        assert_eq!(evaluation.temporary_entries_remaining, Some(0));
    }

    #[test]
    fn power_cut_before_bootnext_must_not_reach_installer() {
        let serial = [
            baseline(),
            created(),
            "\n".into(),
            returned(),
            cleanup(),
            final_pass(),
        ]
        .concat();
        let evaluation = evaluate_one_shot_serial(
            OneShotBootBackend::UefiBootNext,
            OneShotPowerLossPoint::AfterTemporaryEntryCreated,
            true,
            &serial,
        );
        assert!(evaluation.passed(), "{:?}", evaluation.failures);
        assert_eq!(evaluation.installer_boots, 0);
    }

    #[test]
    fn repeated_installer_boot_fails_one_shot_invariant() {
        let serial = [
            baseline(),
            created(),
            armed(),
            installer(),
            installer(),
            returned(),
            cleanup(),
            final_pass(),
        ]
        .concat();
        let evaluation = evaluate_one_shot_serial(
            OneShotBootBackend::UefiBootNext,
            OneShotPowerLossPoint::DuringInstallerBoot,
            true,
            &serial,
        );
        assert!(!evaluation.passed());
        assert_eq!(evaluation.installer_boots, 2);
    }

    #[test]
    fn firmware_selected_entry_that_booted_the_current_os_fails() {
        // Observed on a real run before the GRUB dispatcher: firmware honoured BootNext, but
        // GRUB read the current OS configuration from the other ESP.
        let serial = [
            baseline(),
            created(),
            armed(),
            format!("{FIRMWARE_START_PREFIX}{ENTRY} \"NoUSB-OneShot\" from HD(1,MBR,0xBE1AFDFA,0x3F,0xFBFC1)/\\EFI\\BOOT\\BOOTX64.EFI\n"),
            returned().replace("bootcurrent=0001 baseline", "bootcurrent=0003 baseline"),
            cleanup(),
            final_pass(),
        ]
        .concat();
        let evaluation = evaluate_one_shot_serial(
            OneShotBootBackend::UefiBootNext,
            OneShotPowerLossPoint::CompleteCycle,
            false,
            &serial,
        );
        assert_eq!(evaluation.temporary_entry_starts, 1);
        assert_eq!(evaluation.installer_boots, 0);
        assert!(!evaluation.returned_to_current_os);
        assert!(!evaluation.passed());
    }

    #[test]
    fn grub_next_entry_cycle_uses_grub_evidence_instead_of_firmware_boot_entries() {
        let grub_entry = GRUB_ONE_SHOT_ENTRY_ID;
        let installer = format!(
            "NOUSB_GRUB loader=current-os-standalone selected={grub_entry}\nNOUSB_GRUB loader=current-os-standalone booting={grub_entry}\n[    0.000000] Linux version 6.8.0\n[    0.090000] {KERNEL_COMMAND_LINE} BOOT_IMAGE=/casper/vmlinuz {ONE_SHOT_INSTALLER_MARKER} panic=5\n"
        );
        let serial = [
            baseline(),
            format!("NOUSB_STEP=temporary-entry-created entry={grub_entry} bootorder=0001,0000\n"),
            format!("NOUSB_STEP=bootnext-armed bootnext={grub_entry} bootorder=0001,0000\n"),
            installer.clone(),
            returned(),
            cleanup(),
            final_pass(),
        ]
        .concat();
        let evaluation = evaluate_one_shot_serial(
            OneShotBootBackend::LinuxGrubReboot,
            OneShotPowerLossPoint::CompleteCycle,
            false,
            &serial,
        );
        assert!(evaluation.passed(), "{:?}", evaluation.failures);
        assert_eq!(evaluation.temporary_entry_starts, 1);

        // The same serial judged as UEFI BootNext lacks firmware evidence and must fail.
        let as_uefi = evaluate_one_shot_serial(
            OneShotBootBackend::UefiBootNext,
            OneShotPowerLossPoint::CompleteCycle,
            false,
            &serial,
        );
        assert!(!as_uefi.passed());

        // A GRUB that ignored next_entry (no `booting=` line) fails even if a kernel ran.
        let ignored = serial.replace(&format!("booting={grub_entry}"), "booting=current");
        assert!(!evaluate_one_shot_serial(
            OneShotBootBackend::LinuxGrubReboot,
            OneShotPowerLossPoint::CompleteCycle,
            false,
            &ignored,
        )
        .passed());
    }

    #[test]
    fn systemd_boot_oneshot_payload_script_and_evidence() {
        // NV|BS|RT, then "ab" + NUL in UTF-16LE.
        assert_eq!(
            efivar_utf16_printf("ab"),
            "\\007\\000\\000\\000\\141\\000\\142\\000\\000\\000"
        );
        let script = one_shot_guest_init(
            OneShotBootBackend::LinuxSystemdBootOneShot,
            &installer_kernel_arguments(None),
        );
        assert!(!script.contains('@'));
        assert!(script.contains(&format!("LoaderEntryOneShot-{SYSTEMD_BOOT_VENDOR_GUID}")));
        assert!(script.contains(&format!(
            "options console=ttyS0,115200n8 {ONE_SHOT_INSTALLER_MARKER}"
        )));
        assert!(script.contains(SYSTEMD_BOOT_ONESHOT_TAG));
        for trigger in OneShotPowerLossPoint::ALL
            .iter()
            .filter_map(|point| point.trigger())
        {
            if trigger != ONE_SHOT_INSTALLER_MARKER {
                assert!(script.contains(trigger));
            }
        }

        let entry = SYSTEMD_BOOT_ONESHOT_ENTRY;
        // A power cut between the early and late command-line echoes still counts one start.
        let installer = format!(
            "[    0.000000] Linux version 6.8.0\n[    0.000000] Command line: initrd=\\nousb\\initrd console=ttyS0,115200n8 {ONE_SHOT_INSTALLER_MARKER} panic=5 {SYSTEMD_BOOT_ONESHOT_TAG}\n[    0.090000] {KERNEL_COMMAND_LINE} initrd=\\nousb\\initrd console=ttyS0,115200n8 {ONE_SHOT_INSTALLER_MARKER} panic=5 {SYSTEMD_BOOT_ONESHOT_TAG}\n"
        );
        let serial = [
            baseline(),
            format!("NOUSB_STEP=temporary-entry-created entry={entry} bootorder=0001,0000\n"),
            format!("NOUSB_STEP=bootnext-armed bootnext={entry} bootorder=0001,0000\n"),
            installer,
            returned(),
            cleanup(),
            final_pass(),
        ]
        .concat();
        let evaluation = evaluate_one_shot_serial(
            OneShotBootBackend::LinuxSystemdBootOneShot,
            OneShotPowerLossPoint::CompleteCycle,
            false,
            &serial,
        );
        assert!(evaluation.passed(), "{:?}", evaluation.failures);
        assert_eq!(evaluation.temporary_entry_starts, 1);
        // Without the systemd-boot tag the installer kernel was not started by that entry.
        let untagged = serial.replace(SYSTEMD_BOOT_ONESHOT_TAG, "");
        assert!(!evaluate_one_shot_serial(
            OneShotBootBackend::LinuxSystemdBootOneShot,
            OneShotPowerLossPoint::CompleteCycle,
            false,
            &untagged,
        )
        .passed());
    }

    #[test]
    fn empty_grubenv_matches_grub_editenv_layout() {
        let block = empty_grubenv();
        assert_eq!(block.len(), 1024);
        assert!(block.starts_with(b"# GRUB Environment Block\n"));
        assert!(block[25..].iter().all(|byte| *byte == b'#'));
        let config = one_shot_current_os_grub_config(OneShotBootBackend::LinuxGrubReboot);
        let clear = config.find("set next_entry=\n").unwrap();
        let save = config
            .find("save_env --file ($esp)/grub/grubenv next_entry")
            .unwrap();
        let menu = config.find("menuentry").unwrap();
        assert!(
            clear < save && save < menu,
            "next_entry must be cleared before any entry boots"
        );
        assert!(config.contains("set fallback=current"));
        assert!(disposable_one_shot_backend_supported(
            OneShotBootBackend::LinuxGrubReboot
        ));
        assert!(!disposable_one_shot_backend_supported(
            OneShotBootBackend::WindowsBcdBootSequence
        ));
    }

    #[test]
    fn grub_configs_keep_installer_and_current_os_kernels_apart() {
        let current = one_shot_current_os_grub_config(OneShotBootBackend::UefiBootNext);
        let installer = one_shot_installer_grub_config(&installer_kernel_arguments(None));
        assert!(current.contains("--set=root /boot/vmlinuz"));
        assert!(current.contains("boot=local root=/dev/vda"));
        assert!(current.trim_end().ends_with("boot"));
        assert!(!current.contains(ONE_SHOT_INSTALLER_MARKER));
        assert!(!current.contains("/casper/"));
        assert!(installer.contains("--set=root /casper/vmlinuz"));
        assert!(installer.contains(ONE_SHOT_INSTALLER_MARKER));
        assert!(installer.contains("panic=5"));
        assert!(!installer.contains("/boot/vmlinuz"));
        assert!(!installer.contains("root=/dev/vda"));
    }

    #[test]
    fn power_cut_between_early_and_late_command_line_still_counts_one_installer_boot() {
        // Observed on a real run: QMP quit landed after the early `Command line:` echo.
        let cut_installer = format!(
            "{FIRMWARE_START_PREFIX}{ENTRY} \"NoUSB-OneShot\" from HD(1,MBR,0xBE1AFDFA,0x3F,0xFBFC1)/\\EFI\\BOOT\\BOOTX64.EFI\n[    0.000000] Linux version 6.8.0\n[    0.000000] Command line: BOOT_IMAGE=/casper/vmlinuz console=ttyS0,115200n8 {ONE_SHOT_INSTALLER_MARKER} panic=5\n[    0.000000] BIOS-e820: [mem 0x0000000000811000-0x0000000000\n"
        );
        let serial = [
            baseline(),
            created(),
            armed(),
            cut_installer,
            "\n[    0.000000] Linux version 6.8.0\n[    0.000000] Command line: BOOT_IMAGE=/boot/vmlinuz boot=local\n[    0.090000] Kernel command line: BOOT_IMAGE=/boot/vmlinuz boot=local\n".into(),
            returned(),
            cleanup(),
            final_pass(),
        ]
        .concat();
        let evaluation = evaluate_one_shot_serial(
            OneShotBootBackend::UefiBootNext,
            OneShotPowerLossPoint::DuringInstallerBoot,
            true,
            &serial,
        );
        assert!(evaluation.passed(), "{:?}", evaluation.failures);
        assert_eq!(evaluation.installer_boots, 1);
        assert_eq!(
            one_shot_installer_boot_count(&installer()),
            1,
            "both command-line echoes of one boot count once"
        );
    }

    #[test]
    fn changed_boot_order_or_leftovers_fail() {
        let serial = complete_cycle()
            .replace(
                "NOUSB_FINAL result=pass bootcurrent=0001 bootorder=0001,0000",
                "NOUSB_FINAL result=pass bootcurrent=0001 bootorder=0003,0001,0000",
            )
            .replace("temporary_entries=0", "temporary_entries=1");
        let evaluation = evaluate_one_shot_serial(
            OneShotBootBackend::UefiBootNext,
            OneShotPowerLossPoint::CompleteCycle,
            false,
            &serial,
        );
        assert!(evaluation
            .failures
            .iter()
            .any(|failure| failure.contains("BootOrder differs")));
        assert!(evaluation
            .failures
            .iter()
            .any(|failure| failure.contains("temporary boot entries remained")));
    }

    #[test]
    fn pending_bootnext_after_return_fails() {
        let serial = complete_cycle().replace(
            "baseline_bootcurrent=0001 bootnext=absent",
            "baseline_bootcurrent=0001 bootnext=0003",
        );
        let evaluation = evaluate_one_shot_serial(
            OneShotBootBackend::UefiBootNext,
            OneShotPowerLossPoint::CompleteCycle,
            false,
            &serial,
        );
        assert!(!evaluation.bootnext_absent_after_return);
        assert!(!evaluation.passed());
    }

    #[test]
    fn missing_power_cut_and_guest_errors_fail() {
        let serial = format!("{}NOUSB_ERROR reason=efivarfs-unavailable\n", baseline());
        let evaluation = evaluate_one_shot_serial(
            OneShotBootBackend::UefiBootNext,
            OneShotPowerLossPoint::AfterBootNextArmed,
            false,
            &serial,
        );
        assert!(evaluation
            .failures
            .iter()
            .any(|failure| failure.contains("power cut")));
        assert!(evaluation
            .failures
            .iter()
            .any(|failure| failure.contains("efivarfs-unavailable")));
    }

    #[test]
    fn scenario_names_round_trip_and_triggers_exist_in_guest_script() {
        let script = one_shot_guest_init(
            OneShotBootBackend::UefiBootNext,
            &installer_kernel_arguments(None),
        );
        let grub_script = one_shot_guest_init(
            OneShotBootBackend::LinuxGrubReboot,
            &installer_kernel_arguments(None),
        );
        assert!(grub_script.contains("selector_arm() { grubenv_fetch"));
        assert!(grub_script.contains("--id nousb-oneshot"));
        assert!(!grub_script.contains('@'));
        for trigger in OneShotPowerLossPoint::ALL
            .iter()
            .filter_map(|point| point.trigger())
        {
            if trigger != ONE_SHOT_INSTALLER_MARKER {
                assert!(grub_script.contains(trigger));
            }
        }
        for point in OneShotPowerLossPoint::ALL {
            assert_eq!(OneShotPowerLossPoint::parse(point.as_str()).unwrap(), point);
            if let Some(trigger) = point.trigger() {
                if trigger != ONE_SHOT_INSTALLER_MARKER {
                    assert!(
                        script.contains(trigger),
                        "{trigger} missing from guest init"
                    );
                }
            }
        }
        assert!(OneShotPowerLossPoint::parse("bogus").is_err());
        assert!(!script.contains('@'));
        assert!(script.contains("INSTALLER_DISK='/dev/vdc'"));
        assert!(script.contains("efibootmgr -q -C -d \"$INSTALLER_DISK\" -p 1"));
    }
}
