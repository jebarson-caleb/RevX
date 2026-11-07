//! Disposable Secure Boot rehearsal: enroll keys from inside a disposable guest, then prove the
//! pinned official Ubuntu chain boots under enforcement and an unsigned loader is refused.
//!
//! The firmware is QEMU's Secure Boot capable edk2 build (SMM) with an initially empty variable
//! store. The guest generates its own PK and KEK, enrolls Microsoft's UEFI CA 2011 into `db`
//! (it signs shim), and selects the installer once with `BootNext`. Nothing touches the host.

use nousb_core::NoUsbError;
use std::path::PathBuf;

use super::escape_json;
use super::one_shot::{
    WindowsQemuOneShotPlan, MICROSOFT_UEFI_CA_2011_RUNTIME_PATH, MICROSOFT_UEFI_CA_2011_SHA256,
};

#[cfg(target_os = "windows")]
use super::one_shot::OneShotInstallerMode;
#[cfg(target_os = "windows")]
use nousb_core::OneShotBootBackend;

#[cfg(target_os = "windows")]
use super::one_shot::{
    create_one_shot_current_os_esp, create_one_shot_installer_esp, remove_disposable_images,
    windows_qemu_one_shot_plan,
};
#[cfg(target_os = "windows")]
use super::{
    copy_create_new, create_disposable_current_os_root, windows_to_docker_wsl_path, OwnedChild,
};
#[cfg(target_os = "windows")]
use nousb_core::sha256_file;
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

const SECURE_BOOT_ENTRY_LABEL: &str = "NoUSB-SecureBoot";
/// Microsoft's owner GUID for its signature-database entries.
const MICROSOFT_OWNER_GUID: &str = "77fa9abd-0359-4d32-bd60-28f4e78f784b";
const KERNEL_SECURE_BOOT_ENABLED: &str = "Secure boot enabled";
#[cfg(target_os = "windows")]
const SECURE_BOOT_TIMEOUT_SECS: u64 = 1_200;

/// Guest `rcS` for the enrollment boot. If the unsigned current OS ever boots again after
/// enrollment, Secure Boot was not enforced and the guest reports it.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const SECURE_BOOT_GUEST_INIT: &str = r#"#!/bin/sh
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null
mount -t devtmpfs devtmpfs /dev 2>/dev/null
mkdir -p /dev/pts /run /tmp /var/lib/nousb
mount -t efivarfs efivarfs /sys/firmware/efi/efivars 2>/dev/null
echo 'NOUSB_DISPOSABLE_CURRENT_OS_READY'
STATE=/var/lib/nousb
GLOBAL=8be4df61-93ca-11d2-aa0d-00e098032b8c
fail() { echo "NOUSB_SB_ERROR reason=$1"; sync; poweroff -f; sleep 30; }
# efivarfs prefixes each value with 4 attribute bytes; busybox od cannot seek past them here.
var_byte() { dd if="/sys/firmware/efi/efivars/$1-$GLOBAL" bs=1 skip=4 count=1 2>/dev/null | od -An -t u1 | tr -d ' \n'; }
if [ -f "$STATE/enrolled" ]; then
  echo "NOUSB_SB_ERROR reason=unsigned-current-os-booted-after-enrollment secure_boot=$(var_byte SecureBoot)"
  sync
  poweroff -f
fi
setup=$(var_byte SetupMode)
secure=$(var_byte SecureBoot)
echo "NOUSB_SB_BEFORE setup_mode=${setup:-unknown} secure_boot=${secure:-unknown}"
[ "$setup" = 1 ] || fail firmware-not-in-setup-mode
cd /tmp || fail no-tmp
owner=$(cat /proc/sys/kernel/random/uuid)
for name in PK KEK; do
  openssl req -new -x509 -newkey rsa:2048 -nodes -sha256 -days 3650 -subj "/CN=NoUSB disposable $name/" -keyout "$name.key" -out "$name.crt" >/dev/null 2>&1 || fail "generate-$name"
  cert-to-efi-sig-list -g "$owner" "$name.crt" "$name.esl" >/dev/null 2>&1 || fail "esl-$name"
done
openssl x509 -inform der -in '@MS_CERT@' -out microsoft-uefi-ca.pem >/dev/null 2>&1 || fail read-microsoft-ca
cert-to-efi-sig-list -g '@MS_OWNER@' microsoft-uefi-ca.pem db.esl >/dev/null 2>&1 || fail esl-db
sign-efi-sig-list -k PK.key -c PK.crt PK PK.esl PK.auth >/dev/null 2>&1 || fail sign-PK
sign-efi-sig-list -k PK.key -c PK.crt KEK KEK.esl KEK.auth >/dev/null 2>&1 || fail sign-KEK
sign-efi-sig-list -k KEK.key -c KEK.crt db db.esl db.auth >/dev/null 2>&1 || fail sign-db
efi-updatevar -f db.auth db >/dev/null 2>&1 || fail enroll-db
efi-updatevar -f KEK.auth KEK >/dev/null 2>&1 || fail enroll-KEK
efi-updatevar -f PK.auth PK >/dev/null 2>&1 || fail enroll-PK
echo "NOUSB_SB_ENROLLED setup_mode=$(var_byte SetupMode) db=microsoft-uefi-ca-2011 kek=disposable pk=disposable"
efibootmgr -q -C -d /dev/vdc -p 1 -l '\EFI\BOOT\BOOTX64.EFI' -L '@LABEL@' >/dev/null 2>&1 || fail create-installer-entry
entry=$(efibootmgr 2>/dev/null | awk -v label='@LABEL@' '/^Boot[0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f]/ {
  name = $0; sub(/^Boot[0-9A-Fa-f]+\*? ?/, "", name); split(name, parts, "\t");
  if (parts[1] == label) print substr($0, 5, 4) }' | head -n 1)
[ -n "$entry" ] || fail installer-entry-missing
efibootmgr -q -n "$entry" >/dev/null 2>&1 || fail arm-bootnext
current=$(efibootmgr 2>/dev/null | sed -n 's/^BootCurrent: //p')
touch "$STATE/enrolled"
sync
echo "NOUSB_SB_ARMED entry=$entry current=$current"
sleep 2
reboot -f
sleep 30
"#;

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn secure_boot_guest_init() -> String {
    SECURE_BOOT_GUEST_INIT
        .replace(
            "@MS_CERT@",
            &format!("/{MICROSOFT_UEFI_CA_2011_RUNTIME_PATH}"),
        )
        .replace("@MS_OWNER@", MICROSOFT_OWNER_GUID)
        .replace("@LABEL@", SECURE_BOOT_ENTRY_LABEL)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowsQemuSecureBootPlan {
    pub one_shot: WindowsQemuOneShotPlan,
    pub secure_firmware_code: PathBuf,
    pub empty_variable_template: PathBuf,
    pub microsoft_uefi_ca: PathBuf,
    pub typed_confirmation: String,
}

impl WindowsQemuSecureBootPlan {
    pub fn preview(&self) -> String {
        format!(
            "Disposable Secure Boot plan\nFirmware: {} (Secure Boot capable, SMM)\nVariable store: fresh copy of {} (setup mode, no keys)\nKeys enrolled by the guest: disposable PK and KEK generated in the guest; db = Microsoft UEFI CA 2011 ({}, SHA-256 {})\nSigned chain under test: pinned official Ubuntu shim -> GRUB -> kernel, selected once with BootNext\nUnsigned loader under test: the disposable current OS's standalone GRUB (must be refused)\nNetwork enabled: false\nPhysical disks attached: false\nHost boot changes: false\nConfirmation phrase: {}\n",
            self.secure_firmware_code.display(),
            self.empty_variable_template.display(),
            self.microsoft_uefi_ca.display(),
            MICROSOFT_UEFI_CA_2011_SHA256,
            self.typed_confirmation,
        )
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{\"secure_firmware_code\":\"{}\",\"empty_variable_template\":\"{}\",\"microsoft_uefi_ca\":\"{}\",\"microsoft_uefi_ca_sha256\":\"{}\",\"network_enabled\":false,\"physical_disks_attached\":false,\"host_boot_changes\":false,\"typed_confirmation\":\"{}\"}}",
            escape_json(&self.secure_firmware_code.display().to_string()),
            escape_json(&self.empty_variable_template.display().to_string()),
            escape_json(&self.microsoft_uefi_ca.display().to_string()),
            MICROSOFT_UEFI_CA_2011_SHA256,
            escape_json(&self.typed_confirmation),
        )
    }
}

/// Serial evidence of one Secure Boot rehearsal.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SecureBootEvaluation {
    pub setup_mode_before_enrollment: bool,
    pub keys_enrolled: bool,
    pub setup_mode_left: bool,
    pub installer_entry: Option<String>,
    pub current_os_entry: Option<String>,
    pub firmware_started_signed_chain: bool,
    pub kernel_reported_secure_boot: bool,
    pub unsigned_loader_rejected: bool,
    pub failures: Vec<String>,
}

impl SecureBootEvaluation {
    pub fn passed(&self) -> bool {
        self.failures.is_empty()
    }

    pub fn to_json(&self) -> String {
        let optional = |value: &Option<String>| {
            value
                .as_deref()
                .map(|value| format!("\"{}\"", escape_json(value)))
                .unwrap_or_else(|| "null".into())
        };
        format!(
            "{{\"setup_mode_before_enrollment\":{},\"keys_enrolled\":{},\"setup_mode_left\":{},\"installer_entry\":{},\"current_os_entry\":{},\"firmware_started_signed_chain\":{},\"kernel_reported_secure_boot\":{},\"unsigned_loader_rejected\":{},\"passed\":{},\"failures\":[{}]}}",
            self.setup_mode_before_enrollment,
            self.keys_enrolled,
            self.setup_mode_left,
            optional(&self.installer_entry),
            optional(&self.current_os_entry),
            self.firmware_started_signed_chain,
            self.kernel_reported_secure_boot,
            self.unsigned_loader_rejected,
            self.passed(),
            self.failures
                .iter()
                .map(|failure| format!("\"{}\"", escape_json(failure)))
                .collect::<Vec<_>>()
                .join(","),
        )
    }
}

fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.split_whitespace()
        .find_map(|token| token.strip_prefix(key)?.strip_prefix('='))
}

/// The firmware refused a boot option: OVMF prints the option, then the EFI status.
fn is_rejection(line: &str, entry: &str) -> bool {
    line.contains(&format!("Boot{entry} "))
        && (line.contains("Access Denied") || line.contains("Security Violation"))
}

/// Checks enrollment, the signed boot under enforcement, and the refusal of the unsigned loader,
/// in that order.
pub fn evaluate_secure_boot_serial(serial: &str) -> SecureBootEvaluation {
    let lines: Vec<&str> = serial
        .lines()
        .map(|line| line.trim_end_matches('\r'))
        .collect();
    let mut evaluation = SecureBootEvaluation::default();
    let position = |predicate: &dyn Fn(&str) -> bool| lines.iter().position(|line| predicate(line));

    for line in lines.iter().filter(|line| line.contains("NOUSB_SB_ERROR")) {
        evaluation.failures.push(format!(
            "guest reported {}",
            field(line, "reason").unwrap_or("an error")
        ));
    }
    if let Some(before) = lines.iter().find(|line| line.contains("NOUSB_SB_BEFORE")) {
        evaluation.setup_mode_before_enrollment =
            field(before, "setup_mode") == Some("1") && field(before, "secure_boot") != Some("1");
    }
    if !evaluation.setup_mode_before_enrollment {
        evaluation
            .failures
            .push("firmware did not start in setup mode with Secure Boot off".into());
    }
    let enrolled = position(&|line| line.contains("NOUSB_SB_ENROLLED"));
    if let Some(index) = enrolled {
        evaluation.keys_enrolled = true;
        evaluation.setup_mode_left = field(lines[index], "setup_mode") == Some("0");
    }
    if !evaluation.keys_enrolled || !evaluation.setup_mode_left {
        evaluation
            .failures
            .push("PK/KEK/db enrollment did not leave setup mode".into());
    }
    let armed = position(&|line| line.contains("NOUSB_SB_ARMED"));
    if let Some(index) = armed {
        evaluation.installer_entry = field(lines[index], "entry").map(str::to_owned);
        evaluation.current_os_entry = field(lines[index], "current").map(str::to_owned);
    }
    let (Some(armed), Some(entry), Some(current)) = (
        armed,
        evaluation.installer_entry.clone(),
        evaluation.current_os_entry.clone(),
    ) else {
        evaluation
            .failures
            .push("the signed installer was never selected with BootNext".into());
        return evaluation;
    };

    let firmware_start = lines
        .iter()
        .enumerate()
        .skip(armed)
        .find(|(_, line)| line.contains(&format!("BdsDxe: starting Boot{entry} ")))
        .map(|(index, _)| index);
    evaluation.firmware_started_signed_chain = firmware_start.is_some();
    let kernel = firmware_start.and_then(|start| {
        lines
            .iter()
            .enumerate()
            .skip(start)
            .find(|(_, line)| line.contains(KERNEL_SECURE_BOOT_ENABLED))
            .map(|(index, _)| index)
    });
    evaluation.kernel_reported_secure_boot = kernel.is_some();
    if !evaluation.firmware_started_signed_chain || !evaluation.kernel_reported_secure_boot {
        evaluation.failures.push(
            "firmware did not start the signed official chain with Secure Boot enforced".into(),
        );
    }
    evaluation.unsigned_loader_rejected = kernel.is_some_and(|start| {
        lines
            .iter()
            .skip(start)
            .any(|line| is_rejection(line, &current))
    });
    if !evaluation.unsigned_loader_rejected {
        evaluation
            .failures
            .push("firmware did not refuse the unsigned current-OS loader".into());
    }
    evaluation
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowsQemuSecureBootReport {
    pub run_directory: PathBuf,
    pub report_path: PathBuf,
    pub serial_log_path: PathBuf,
    pub evaluation: SecureBootEvaluation,
    pub secure_boot_enabled: bool,
    pub signed_chain_accepted: bool,
    pub unsigned_loader_rejected: bool,
    pub host_boot_changes: bool,
}

impl WindowsQemuSecureBootReport {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"run_directory\":\"{}\",\"report_path\":\"{}\",\"serial_log_path\":\"{}\",\"evaluation\":{},\"secure_boot_enabled\":{},\"signed_chain_accepted\":{},\"unsigned_loader_rejected\":{},\"host_boot_changes\":{}}}",
            escape_json(&self.run_directory.display().to_string()),
            escape_json(&self.report_path.display().to_string()),
            escape_json(&self.serial_log_path.display().to_string()),
            self.evaluation.to_json(),
            self.secure_boot_enabled,
            self.signed_chain_accepted,
            self.unsigned_loader_rejected,
            self.host_boot_changes,
        )
    }
}

#[cfg(target_os = "windows")]
pub fn windows_qemu_secure_boot_plan(
    base_dir: &Path,
) -> Result<WindowsQemuSecureBootPlan, NoUsbError> {
    let mut one_shot = windows_qemu_one_shot_plan(
        base_dir,
        OneShotBootBackend::UefiBootNext,
        OneShotInstallerMode::ForcedFailure,
    )?;
    let runtime_root = one_shot.current_os.runtime_root.clone();
    let secure_firmware_code = runtime_root.join("usr/share/qemu/edk2-x86_64-secure-code.fd");
    let empty_variable_template = runtime_root.join("usr/share/qemu/edk2-i386-vars.fd");
    let microsoft_uefi_ca = runtime_root.join(MICROSOFT_UEFI_CA_2011_RUNTIME_PATH);
    for required in [
        &secure_firmware_code,
        &empty_variable_template,
        &microsoft_uefi_ca,
        &runtime_root.join("usr/bin/efi-updatevar"),
        &runtime_root.join("usr/bin/openssl"),
    ] {
        if !required.is_file() {
            return Err(NoUsbError::ArtifactUnavailable(format!(
                "project-local runtime lacks {}; run `nousb vm qemu bootstrap-runtime` first",
                required.display()
            )));
        }
    }
    if sha256_file(&microsoft_uefi_ca)? != MICROSOFT_UEFI_CA_2011_SHA256 {
        return Err(NoUsbError::Verification(format!(
            "{} does not match the pinned Microsoft UEFI CA 2011 digest",
            microsoft_uefi_ca.display()
        )));
    }
    one_shot.current_os.secure_boot_enabled = true;
    let typed_confirmation = "RUN DISPOSABLE SECURE BOOT REHEARSAL".to_string();
    one_shot.typed_confirmation = typed_confirmation.clone();
    Ok(WindowsQemuSecureBootPlan {
        one_shot,
        secure_firmware_code,
        empty_variable_template,
        microsoft_uefi_ca,
        typed_confirmation,
    })
}

#[cfg(not(target_os = "windows"))]
pub fn windows_qemu_secure_boot_plan(
    _base_dir: &std::path::Path,
) -> Result<WindowsQemuSecureBootPlan, NoUsbError> {
    Err(NoUsbError::ArtifactUnavailable(
        "the WSL-backed disposable Secure Boot rehearsal is only available on Windows".into(),
    ))
}

#[cfg(target_os = "windows")]
pub fn run_windows_qemu_secure_boot_rehearsal(
    base_dir: &Path,
    confirmation: &str,
) -> Result<WindowsQemuSecureBootReport, NoUsbError> {
    let plan = windows_qemu_secure_boot_plan(base_dir)?;
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
        .join(format!("secure-boot-{stamp}-{}", std::process::id()));
    fs::create_dir_all(&run_directory)?;

    let current_os = &plan.one_shot.current_os;
    let root_disk =
        create_disposable_current_os_root(&run_directory, current_os, &secure_boot_guest_init())?;
    let current_esp = create_one_shot_current_os_esp(&run_directory, &plan.one_shot)?;
    let installer_esp = create_one_shot_installer_esp(&run_directory, &plan.one_shot)?;
    let firmware_code = run_directory.join("edk2-x86_64-secure-code.fd");
    let firmware_vars = run_directory.join("edk2-vars.fd");
    copy_create_new(&plan.secure_firmware_code, &firmware_code)?;
    copy_create_new(&plan.empty_variable_template, &firmware_vars)?;
    let serial_log_path = run_directory.join("serial.log");

    let runtime_root_wsl = windows_to_docker_wsl_path(&current_os.runtime_root)?;
    let arguments = vec![
        "-d".to_string(),
        "docker-desktop".into(),
        "--".into(),
        "env".into(),
        format!("LD_LIBRARY_PATH={runtime_root_wsl}/lib:{runtime_root_wsl}/usr/lib"),
        windows_to_docker_wsl_path(&current_os.runtime_root.join("usr/bin/qemu-system-x86_64"))?,
        "-machine".into(),
        "q35,smm=on,accel=tcg".into(),
        "-global".into(),
        "driver=cfi.pflash01,property=secure,value=on".into(),
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
        format!("file:{}", windows_to_docker_wsl_path(&serial_log_path)?),
        "-monitor".into(),
        "none".into(),
        "-nic".into(),
        "none".into(),
        "-L".into(),
        format!("{runtime_root_wsl}/usr/share/qemu"),
        "-drive".into(),
        format!(
            "if=pflash,format=raw,unit=0,readonly=on,file={}",
            windows_to_docker_wsl_path(&firmware_code)?
        ),
        "-drive".into(),
        format!(
            "if=pflash,format=raw,unit=1,file={}",
            windows_to_docker_wsl_path(&firmware_vars)?
        ),
        "-drive".into(),
        format!(
            "file={},format=raw,if=none,id=currentroot",
            windows_to_docker_wsl_path(&root_disk)?
        ),
        "-device".into(),
        "virtio-blk-pci,drive=currentroot,addr=0x4".into(),
        "-blockdev".into(),
        format!(
            "driver=file,node-name=currentesp,filename={},read-only=on",
            windows_to_docker_wsl_path(&current_esp)?
        ),
        "-device".into(),
        "virtio-blk-pci,drive=currentesp,addr=0x5,bootindex=0".into(),
        "-blockdev".into(),
        format!(
            "driver=vvfat,node-name=installeresp,dir={},read-only=on",
            windows_to_docker_wsl_path(&installer_esp)?
        ),
        "-device".into(),
        "virtio-blk-pci,drive=installeresp,addr=0x6".into(),
        "-qmp".into(),
        "stdio".into(),
    ];
    let child = Command::new("wsl.exe")
        .args(&arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| NoUsbError::Io(format!("cannot start Secure Boot machine: {error}")))?;
    let mut qemu = OwnedChild::new(child);
    let mut qmp_input = qemu
        .child_mut()?
        .stdin
        .take()
        .ok_or_else(|| NoUsbError::Io("QEMU process did not expose QMP input".into()))?;
    qmp_input.write_all(b"{\"execute\":\"qmp_capabilities\"}\n")?;
    qmp_input.flush()?;

    let deadline = Instant::now() + Duration::from_secs(SECURE_BOOT_TIMEOUT_SECS);
    loop {
        if qemu.child_mut()?.try_wait()?.is_some() {
            break;
        }
        let serial =
            String::from_utf8_lossy(&fs::read(&serial_log_path).unwrap_or_default()).into_owned();
        let evaluation = evaluate_secure_boot_serial(&serial);
        if evaluation.unsigned_loader_rejected
            || serial.contains("NOUSB_SB_ERROR")
            || Instant::now() >= deadline
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    // The firmware stops in its boot menu after the refusal; end the run.
    let _ = qmp_input
        .write_all(b"{\"execute\":\"quit\"}\n")
        .and_then(|()| qmp_input.flush());
    drop(qmp_input);
    let output = qemu.stop()?;
    fs::write(run_directory.join("qmp.log"), &output.stdout)?;
    fs::write(run_directory.join("qemu.stderr.log"), &output.stderr)?;

    let serial =
        String::from_utf8_lossy(&fs::read(&serial_log_path).unwrap_or_default()).into_owned();
    let evaluation = evaluate_secure_boot_serial(&serial);
    let report_path = run_directory.join("report.json");
    let report = WindowsQemuSecureBootReport {
        run_directory,
        report_path: report_path.clone(),
        serial_log_path,
        secure_boot_enabled: evaluation.setup_mode_left && evaluation.kernel_reported_secure_boot,
        signed_chain_accepted: evaluation.firmware_started_signed_chain
            && evaluation.kernel_reported_secure_boot,
        unsigned_loader_rejected: evaluation.unsigned_loader_rejected,
        host_boot_changes: false,
        evaluation,
    };
    let mut report_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&report_path)?;
    report_file.write_all(report.to_json().as_bytes())?;
    report_file.sync_all()?;
    if report.evaluation.passed() {
        remove_disposable_images(&[
            root_disk.as_path(),
            current_esp.as_path(),
            installer_esp.as_path(),
            firmware_code.as_path(),
            &report.run_directory.join("current-os-rootfs"),
            &report.run_directory.join("one-shot-current-os-esp"),
        ]);
    }
    if !report.evaluation.passed() {
        return Err(NoUsbError::Verification(format!(
            "Secure Boot rehearsal failed ({}); see {}",
            report.evaluation.failures.join("; "),
            report.report_path.display()
        )));
    }
    Ok(report)
}

#[cfg(not(target_os = "windows"))]
pub fn run_windows_qemu_secure_boot_rehearsal(
    _base_dir: &std::path::Path,
    _confirmation: &str,
) -> Result<WindowsQemuSecureBootReport, NoUsbError> {
    Err(NoUsbError::ArtifactUnavailable(
        "the WSL-backed disposable Secure Boot rehearsal is only available on Windows".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passing_serial() -> String {
        [
            "BdsDxe: starting Boot0002 \"UEFI Misc Device\" from PciRoot(0x0)/Pci(0x5,0x0)",
            "NOUSB_SB_BEFORE setup_mode=1 secure_boot=0",
            "NOUSB_SB_ENROLLED setup_mode=0 db=microsoft-uefi-ca-2011 kek=disposable pk=disposable",
            "NOUSB_SB_ARMED entry=0004 current=0002",
            "BdsDxe: starting Boot0004 \"NoUSB-SecureBoot\" from HD(1,MBR,0xBE1AFDFA,0x3F,0xFBFC1)/\\EFI\\BOOT\\BOOTX64.EFI",
            "[    0.000000] secureboot: Secure boot enabled",
            "[    9.000000] Kernel panic - not syncing: VFS: Unable to mount root fs",
            "BdsDxe: failed to load Boot0002 \"UEFI Misc Device\" from PciRoot(0x0)/Pci(0x5,0x0): Access Denied",
        ]
        .join("\n")
    }

    #[test]
    fn enforced_signed_boot_and_refused_unsigned_loader_pass() {
        let evaluation = evaluate_secure_boot_serial(&passing_serial());
        assert!(evaluation.passed(), "{:?}", evaluation.failures);
        assert_eq!(evaluation.installer_entry.as_deref(), Some("0004"));
        assert!(evaluation.unsigned_loader_rejected);
    }

    #[test]
    fn unsigned_loader_booting_after_enrollment_fails() {
        let serial = passing_serial()
            .replace(
                "BdsDxe: failed to load Boot0002 \"UEFI Misc Device\" from PciRoot(0x0)/Pci(0x5,0x0): Access Denied",
                "BdsDxe: starting Boot0002 \"UEFI Misc Device\" from PciRoot(0x0)/Pci(0x5,0x0)\nNOUSB_SB_ERROR reason=unsigned-current-os-booted-after-enrollment secure_boot=0",
            );
        let evaluation = evaluate_secure_boot_serial(&serial);
        assert!(!evaluation.passed());
        assert!(!evaluation.unsigned_loader_rejected);
    }

    #[test]
    fn missing_enforcement_evidence_fails() {
        let serial = passing_serial().replace(
            "secureboot: Secure boot enabled",
            "secureboot: Secure boot disabled",
        );
        let evaluation = evaluate_secure_boot_serial(&serial);
        assert!(!evaluation.kernel_reported_secure_boot);
        assert!(!evaluation.passed());
        let never_in_setup =
            passing_serial().replace("setup_mode=1 secure_boot=0", "setup_mode=0 secure_boot=1");
        assert!(!evaluate_secure_boot_serial(&never_in_setup).passed());
    }

    #[test]
    fn guest_script_enrolls_microsoft_ca_into_db_and_pk_last() {
        let script = secure_boot_guest_init();
        assert!(!script.contains('@'));
        assert!(script.contains(&format!("/{MICROSOFT_UEFI_CA_2011_RUNTIME_PATH}")));
        let db = script.find("efi-updatevar -f db.auth db").unwrap();
        let kek = script.find("efi-updatevar -f KEK.auth KEK").unwrap();
        let pk = script.find("efi-updatevar -f PK.auth PK").unwrap();
        assert!(
            db < kek && kek < pk,
            "PK must be written last to leave setup mode"
        );
        assert!(script.contains(MICROSOFT_OWNER_GUID));
    }
}
