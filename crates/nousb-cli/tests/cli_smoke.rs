use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

fn nousb() -> Command {
    Command::new(env!("CARGO_BIN_EXE_nousb"))
}

/// Disposable QEMU rehearsals run through WSL2 and fail closed elsewhere.
fn only_on_windows(stderr: &str) -> bool {
    !cfg!(target_os = "windows") && stderr.contains("only available on Windows")
}

#[test]
fn json_plan_contains_machine_readable_fields() {
    let output = nousb()
        .args(["--json", "plan", "boot-once", "ubuntu-24.04-desktop"])
        .output()
        .expect("run nousb");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"kind\":\"boot-once\""));
    assert!(stdout.contains("\"risk\":\"medium\""));
    assert!(stdout.contains("\"steps\""));
}

#[test]
fn yes_does_not_bypass_critical_confirmation() {
    let output = nousb()
        .args(["--yes", "execute", "replace-os", "ubuntu-24.04-desktop"])
        .output()
        .expect("run nousb");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(stderr.contains("--yes cannot approve critical risk plan"));
}

#[test]
fn fake_linux_low_space_plan_surfaces_manual_intervention() {
    let output = nousb()
        .args([
            "plan-fake",
            "linux-luks-low-space",
            "boot-once",
            "ubuntu-24.04-desktop",
        ])
        .output()
        .expect("run nousb");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("resolve-low-disk-space"));
    assert!(stdout.contains("LUKS"));
}

#[test]
fn fake_windows_inspect_json_is_available() {
    let output = nousb()
        .args(["--json", "system", "inspect-fake", "windows-bitlocker"])
        .output()
        .expect("run nousb");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"adapter\":\"fake-windows-uefi-bitlocker\""));
    assert!(stdout.contains("\"memory_total_mb\":32768"));
    assert!(stdout.contains("BitLocker"));
}

#[test]
fn delivery_assessment_exposes_ram_and_firmware_routes() {
    let output = nousb()
        .args([
            "--json",
            "workflow",
            "assess-fake",
            "windows-bitlocker",
            "ubuntu-24.04-desktop",
        ])
        .output()
        .expect("run nousb workflow assess-fake");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"recommended_route\":\"host-staged-ram-boot\""));
    assert!(stdout.contains("\"id\":\"uefi-http-boot\""));
    assert!(stdout.contains("\"safe_default_execution_enabled\":false"));
    assert!(stdout.contains("\"universal_no_usb_guarantee\":false"));
}

#[test]
fn artifact_manifest_is_machine_readable_and_pinned() {
    let output = nousb()
        .args(["--json", "image", "manifest", "ubuntu-24.04-desktop"])
        .output()
        .expect("run nousb image manifest");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"filename\":\"ubuntu-24.04.4-desktop-amd64.iso\""));
    assert!(stdout.contains("\"size_bytes\":6655619072"));
    assert!(stdout.contains("3a4c9877b483ab46d7c3fbe165a0db275e1ae3cfe56a5657e5a47c2f99a99d1e"));
}

#[test]
fn ubuntu_server_manifest_is_machine_readable_and_pinned() {
    let output = nousb()
        .args(["--json", "image", "manifest", "ubuntu-24.04-server"])
        .output()
        .expect("run nousb image manifest");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"filename\":\"ubuntu-24.04.4-live-server-amd64.iso\""));
    assert!(stdout.contains("\"size_bytes\":3405469696"));
    assert!(stdout.contains("e907d92eeec9df64163a7e454cbc8d7755e8ddc7ed42f99dbc80c40f1a138433"));
}

#[test]
fn vendor_mediated_image_download_fails_closed() {
    let output = nousb()
        .args(["image", "manifest", "windows-11"])
        .output()
        .expect("run nousb image manifest");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(stderr.contains("no stable vendor artifact URL"));
}

#[test]
fn guided_tui_runs_as_a_safe_terminal_application() {
    let mut child = nousb()
        .arg("tui")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("start nousb tui");
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(b"3\n4\n8\n9\n").expect("script tui input");
    }
    let output = child.wait_with_output().expect("wait for nousb tui");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("NoUSB guided terminal application"));
    assert!(stdout.contains("Universal no-USB guarantee: false"));
    assert!(stdout.contains("ubuntu-24.04.4-desktop-amd64.iso"));
    assert!(stdout.contains("Preview only: no executor was invoked."));
}

#[test]
fn vm_doctor_reports_disposable_runtime_separately_from_host_boot_execution() {
    let output = nousb()
        .args(["--json", "vm", "doctor"])
        .output()
        .expect("run nousb vm doctor");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"runtime_access_verified\":"));
    assert!(stdout.contains("\"disposable_vm_execution_enabled\":"));
    assert!(stdout.contains("\"real_boot_execution_enabled\":false"));
    assert!(stdout.contains("\"host_boot_changes\":false"));
}

#[test]
fn qemu_runtime_manifest_is_pinned_and_does_not_execute_installer() {
    let output = nousb()
        .args(["--json", "vm", "qemu", "manifest"])
        .output()
        .expect("run nousb vm qemu manifest");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"version\":\"11.0.0\""));
    assert!(stdout.contains("\"size_bytes\":185604552"));
    assert!(stdout.contains("64a43c0d39acddc9d30d290935a312a2"));
    assert!(stdout.contains("\"project_local_only\":true"));
}

#[test]
fn qemu_smoke_plan_never_attaches_host_storage_or_network() {
    let output = nousb()
        .args(["--json", "vm", "qemu", "plan-smoke"])
        .output()
        .expect("run nousb vm qemu plan-smoke");

    if output.status.success() {
        let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
        assert!(stdout.contains("\"accelerator\":\"tcg\""));
        assert!(stdout.contains("\"network_enabled\":false"));
        assert!(stdout.contains("\"physical_disks_attached\":false"));
        assert!(stdout.contains("\"host_boot_changes\":false"));
        assert!(stdout.contains("\"ram_boot_verified\":false"));
    } else {
        let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
        assert!(
            stderr.contains("project-local QEMU runtime is incomplete") || only_on_windows(&stderr)
        );
    }
}

#[test]
fn ubuntu_netboot_plan_labels_partial_ram_evidence_and_direct_boot() {
    let output = nousb()
        .args(["--json", "vm", "qemu", "plan-ubuntu-netboot"])
        .output()
        .expect("run nousb vm qemu plan-ubuntu-netboot");

    if output.status.success() {
        let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
        assert!(stdout.contains("\"direct_kernel_boot\":true"));
        assert!(stdout.contains("\"uefi_firmware_initialized\":false"));
        assert!(stdout.contains("\"full_installer_payload_in_ram\":false"));
        assert!(stdout.contains("\"network_enabled\":false"));
        assert!(stdout.contains("\"physical_disks_attached\":false"));
        assert!(stdout.contains("transport-only-not-installable"));
    } else {
        let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
        assert!(
            stderr.contains("Ubuntu rehearsal")
                || stderr.contains("QEMU runtime")
                || only_on_windows(&stderr)
        );
    }
}

#[test]
fn ubuntu_full_ram_plan_is_explicit_about_network_http_and_uefi_limits() {
    let output = nousb()
        .args(["--json", "vm", "qemu", "plan-ubuntu-full-ram"])
        .output()
        .expect("run nousb vm qemu plan-ubuntu-full-ram");

    if output.status.success() {
        let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
        assert!(stdout.contains("\"artifact_size_bytes\":3405469696"));
        assert!(stdout.contains("\"direct_kernel_boot\":true"));
        assert!(stdout.contains("\"uefi_firmware_initialized\":false"));
        assert!(stdout.contains("\"full_installer_payload_in_ram\":false"));
        assert!(stdout.contains("\"guest_transport_https\":false"));
        assert!(stdout.contains("\"network_enabled\":true"));
        assert!(stdout.contains("\"physical_disks_attached\":false"));
        assert!(stdout.contains("\"virtual_install_disks_attached\":false"));
        assert!(stdout.contains("\"host_boot_changes\":false"));
    } else {
        let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
        assert!(
            stderr.contains("pinned Ubuntu Server ISO is missing")
                || stderr.contains("QEMU runtime")
                || stderr.contains("staging")
                || only_on_windows(&stderr)
        );
    }
}

#[test]
fn ubuntu_uefi_full_ram_plan_requires_verified_official_boot_assets() {
    let output = nousb()
        .args(["--json", "vm", "qemu", "plan-ubuntu-uefi-full-ram"])
        .output()
        .expect("run nousb vm qemu plan-ubuntu-uefi-full-ram");

    if output.status.success() {
        let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
        assert!(stdout.contains("\"direct_kernel_boot\":false"));
        assert!(stdout.contains("\"uefi_firmware_initialized\":false"));
        assert!(stdout.contains("\"full_installer_payload_in_ram\":false"));
        assert!(stdout.contains("\"secure_boot_enabled\":false"));
        assert!(stdout.contains("\"detachable_read_only_boot_source\":true"));
        assert!(stdout.contains("6fe6e1bcbe6cf6baec8e056d40361ca1"));
        assert!(stdout.contains("52b8b3503d3efabfac8793f07e1db5d"));
        assert!(stdout.contains("d2fa8e52fddc99dad94a0009fee23cb"));
        assert!(stdout.contains("\"physical_disks_attached\":false"));
        assert!(stdout.contains("\"host_boot_changes\":false"));
    } else {
        let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
        assert!(
            stderr.contains("pinned Ubuntu Server ISO is missing")
                || stderr.contains("QEMU runtime")
                || stderr.contains("staging")
                || stderr.contains("EFI asset")
                || only_on_windows(&stderr)
        );
    }
}

#[test]
fn current_os_baseline_plan_is_disposable_and_does_not_overclaim_fallback() {
    let output = nousb()
        .args(["--json", "vm", "qemu", "plan-current-os-baseline"])
        .output()
        .expect("run nousb vm qemu plan-current-os-baseline");

    if output.status.success() {
        let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
        assert!(stdout.contains("\"root_disk_size_bytes\":536870912"));
        assert!(stdout.contains("\"uses_disposable_guest_disk\":true"));
        assert!(stdout.contains("\"network_enabled\":false"));
        assert!(stdout.contains("\"physical_disks_attached\":false"));
        assert!(stdout.contains("\"host_boot_changes\":false"));
        assert!(stdout.contains("\"secure_boot_enabled\":false"));
        assert!(stdout.contains("\"installer_fallback_proven\":false"));
        assert!(stdout.contains("\"uefi_bootnext_proven\":false"));
        assert!(stdout.contains("RUN DISPOSABLE CURRENT OS UEFI BASELINE"));
    } else {
        let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
        assert!(
            stderr.contains("pinned Ubuntu Server ISO is missing")
                || stderr.contains("QEMU runtime")
                || stderr.contains("staging")
                || stderr.contains("EFI asset")
                || stderr.contains("disposable current OS")
                || only_on_windows(&stderr)
        );
    }
}

#[test]
fn runtime_bootstrap_plan_is_project_local_and_confirmation_gated() {
    let output = nousb()
        .args(["--json", "vm", "qemu", "plan-runtime"])
        .output()
        .expect("run nousb vm qemu plan-runtime");
    if output.status.success() {
        let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
        assert!(stdout.contains("qemu-system-x86_64~10.1.5"));
        assert!(stdout.contains("efibootmgr"));
        assert!(stdout.contains("\"installs_into_windows\":false"));
        assert!(stdout.contains("\"host_boot_changes\":false"));
        assert!(stdout.contains("ASSEMBLE PROJECT-LOCAL QEMU RUNTIME"));
    } else {
        let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
        assert!(only_on_windows(&stderr));
    }

    let output = nousb()
        .args(["vm", "qemu", "bootstrap-runtime", "yes"])
        .output()
        .expect("run nousb vm qemu bootstrap-runtime");
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(stderr.contains("type exactly") || only_on_windows(&stderr));
}

#[test]
fn one_shot_plan_uses_bootnext_without_persistent_order_changes() {
    let output = nousb()
        .args(["--json", "vm", "qemu", "plan-current-os-one-shot"])
        .output()
        .expect("run nousb vm qemu plan-current-os-one-shot");

    if output.status.success() {
        let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
        assert!(stdout.contains("\"persistent_boot_order_changes\":false"));
        assert!(stdout.contains("\"temporary_entry_label\":\"NoUSB-OneShot\""));
        assert!(stdout.contains("\"after-bootnext-armed\""));
        assert!(stdout.contains("\"during-installer-boot\""));
        assert!(stdout.contains("\"network_enabled\":false"));
        assert!(stdout.contains("\"physical_disks_attached\":false"));
        assert!(stdout.contains("\"host_boot_changes\":false"));
        assert!(stdout.contains("\"secure_boot_enabled\":false"));
        assert!(stdout.contains("RUN DISPOSABLE CURRENT OS UEFI ONE-SHOT MATRIX"));
    } else {
        let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
        assert!(
            stderr.contains("pinned Ubuntu Server ISO is missing")
                || stderr.contains("QEMU runtime")
                || stderr.contains("staging")
                || stderr.contains("EFI asset")
                || stderr.contains("disposable current OS")
                || stderr.contains("efibootmgr")
                || only_on_windows(&stderr)
        );
    }
}

#[test]
fn one_shot_rehearsal_rejects_unknown_scenarios_and_loose_confirmation() {
    let output = nousb()
        .args([
            "vm",
            "qemu",
            "rehearse-current-os-one-shot",
            "RUN DISPOSABLE CURRENT OS UEFI ONE-SHOT MATRIX",
            "skip-cleanup",
        ])
        .output()
        .expect("run nousb with unknown scenario");
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(stderr.contains("unknown one-shot scenario skip-cleanup"));

    let output = nousb()
        .args(["--yes", "vm", "qemu", "rehearse-current-os-one-shot", "yes"])
        .output()
        .expect("run nousb with loose confirmation");
    assert!(!output.status.success());
}

#[test]
fn vm_rehearsal_persists_full_recovery_matrix() {
    let temp_dir = std::env::temp_dir().join(format!(
        "nousb-cli-vm-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp_dir).expect("create temp dir");
    let output = nousb()
        .current_dir(&temp_dir)
        .args([
            "--json",
            "vm",
            "rehearse",
            "windows-bcd-bootsequence",
            "ubuntu-24.04-desktop",
        ])
        .output()
        .expect("run nousb vm rehearse");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"all_invariants_hold\":true"));
    assert!(stdout.contains("\"real_vm_executed\":false"));
    assert!(stdout.contains("\"host_boot_changes\":false"));
    assert_eq!(stdout.matches("\"invariants_hold\":true").count(), 9);
    let report_dir = temp_dir.join(".nousb/vm-rehearsals");
    assert_eq!(
        std::fs::read_dir(&report_dir)
            .expect("read vm reports")
            .count(),
        1
    );

    let _ = std::fs::remove_dir_all(temp_dir);
}

#[test]
fn simulate_can_interrupt_plan() {
    let output = nousb()
        .args([
            "--interrupt-after",
            "2",
            "simulate",
            "boot-once",
            "ubuntu-24.04-desktop",
        ])
        .output()
        .expect("run nousb");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("Status: interrupted"));
    assert!(stdout.contains("verify-installer: pending"));
}

#[test]
fn simulate_json_rollback_reports_rolled_back_state() {
    let output = nousb()
        .args([
            "--json",
            "--rollback",
            "--interrupt-after",
            "2",
            "simulate",
            "boot-once",
            "ubuntu-24.04-desktop",
        ])
        .output()
        .expect("run nousb");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"status\":\"rolled_back\""));
    assert!(stdout.contains("\"state\":\"rolled_back\""));
}

#[test]
fn simulate_persists_report_for_listing_and_showing() {
    let temp_dir = std::env::temp_dir().join(format!(
        "nousb-cli-smoke-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp_dir).expect("create temp dir");

    let simulate = nousb()
        .current_dir(&temp_dir)
        .args([
            "--interrupt-after",
            "1",
            "simulate",
            "boot-once",
            "ubuntu-24.04-desktop",
        ])
        .output()
        .expect("run nousb simulate");
    assert!(simulate.status.success());

    let list = nousb()
        .current_dir(&temp_dir)
        .args(["--json", "reports", "list"])
        .output()
        .expect("run nousb reports list");
    assert!(list.status.success());
    let list_stdout = String::from_utf8(list.stdout).expect("utf8 list stdout");
    assert!(list_stdout.contains("\"status\":\"interrupted\""));
    assert!(list_stdout.contains("\"recovery_required\":true"));

    let plan_id = extract_json_string(&list_stdout, "plan_id").expect("plan id");
    let show = nousb()
        .current_dir(&temp_dir)
        .args(["reports", "show", &plan_id])
        .output()
        .expect("run nousb reports show");
    assert!(show.status.success());
    let show_stdout = String::from_utf8(show.stdout).expect("utf8 show stdout");
    assert!(show_stdout.contains("\"status\":\"interrupted\""));

    let _ = std::fs::remove_dir_all(temp_dir);
}

#[test]
fn signature_check_fails_closed_without_a_pinned_vendor_key() {
    let output = nousb()
        .args(["image", "verify-signature", "windows-11"])
        .output()
        .expect("run nousb image verify-signature");
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(stderr.contains("no pinned vendor signing key"));

    let catalog = nousb()
        .args(["--json", "catalog", "list"])
        .output()
        .expect("run nousb catalog list");
    let stdout = String::from_utf8(catalog.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"signing_key\":\"ubuntu-cdimage-2012\""));
    assert!(stdout.contains("\"signing_key\":\"fedora-44\""));
}

#[test]
fn saved_reports_drive_recover_resume_and_rollback() {
    let temp_dir = std::env::temp_dir().join(format!(
        "nousb-cli-recover-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp_dir).expect("create temp dir");
    let run = |args: &[&str]| {
        nousb()
            .current_dir(&temp_dir)
            .args(args)
            .output()
            .expect("run nousb")
    };

    let simulate = run(&[
        "--json",
        "--interrupt-after",
        "2",
        "simulate",
        "boot-once",
        "ubuntu-24.04-desktop",
    ]);
    assert!(simulate.status.success());
    let plan_id = extract_json_string(&String::from_utf8_lossy(&simulate.stdout), "plan_id")
        .expect("plan id");

    let recover = run(&["--json", "reports", "recover", &plan_id]);
    assert!(recover.status.success());
    let recover_stdout = String::from_utf8_lossy(&recover.stdout);
    assert!(recover_stdout.contains("\"recommended\":\"resume\""));

    let resume = run(&["--json", "resume", &plan_id]);
    assert!(resume.status.success());
    assert!(String::from_utf8_lossy(&resume.stdout).contains("\"status\":\"completed\""));

    // A completed operation is neither resumed again nor rolled back automatically.
    assert!(!run(&["resume", &plan_id]).status.success());
    assert!(!run(&["rollback", &plan_id]).status.success());

    let failed = run(&[
        "--json",
        "--fail-step",
        "verify-installer",
        "simulate",
        "boot-once",
        "ubuntu-24.04-desktop",
    ]);
    assert!(failed.status.success());
    let failed_stdout = String::from_utf8_lossy(&failed.stdout);
    assert!(failed_stdout.contains("\"status\":\"failed\""));
    let failed_id = extract_json_string(&failed_stdout, "plan_id").expect("failed plan id");
    let recover = run(&["--json", "reports", "recover", &failed_id]);
    assert!(String::from_utf8_lossy(&recover.stdout).contains("\"recommended\":\"rollback\""));
    assert!(!run(&["resume", &failed_id]).status.success());
    let rollback = run(&["--json", "rollback", &failed_id]);
    assert!(rollback.status.success());
    assert!(String::from_utf8_lossy(&rollback.stdout).contains("\"status\":\"rolled_back\""));

    assert!(!run(&["rollback", "no-such-operation"]).status.success());

    // Reports are mirrored into the SQLite journal, so recovery survives a lost JSON file.
    let migrate = run(&["--json", "journal", "migrate"]);
    assert!(migrate.status.success());
    assert!(String::from_utf8_lossy(&migrate.stdout).contains("\"imported_reports\":2"));
    std::fs::remove_file(
        temp_dir
            .join(".nousb")
            .join("reports")
            .join(format!("{failed_id}.json")),
    )
    .expect("remove saved JSON report");
    let recover = run(&["--json", "reports", "recover", &failed_id]);
    assert!(recover.status.success());
    assert!(String::from_utf8_lossy(&recover.stdout).contains("\"plan_id\""));
    let _ = std::fs::remove_dir_all(temp_dir);
}

#[test]
fn diagnostics_export_creates_redacted_bundle() {
    let temp_dir = std::env::temp_dir().join(format!(
        "nousb-cli-diag-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    ));
    std::fs::create_dir_all(temp_dir.join(".nousb/journal")).expect("create journal dir");
    std::fs::write(
        temp_dir.join(".nousb/journal/operations.log"),
        "token=super-secret\nnormal=value\n",
    )
    .expect("write log");

    let simulate = nousb()
        .current_dir(&temp_dir)
        .args([
            "--interrupt-after",
            "1",
            "simulate",
            "boot-once",
            "ubuntu-24.04-desktop",
        ])
        .output()
        .expect("run nousb simulate");
    assert!(simulate.status.success());

    let export = nousb()
        .current_dir(&temp_dir)
        .args(["--json", "diagnostics", "export"])
        .output()
        .expect("run diagnostics export");
    assert!(export.status.success());
    let stdout = String::from_utf8(export.stdout).expect("utf8 stdout");
    let bundle_path = extract_json_string(&stdout, "path").expect("bundle path");
    let log = std::fs::read_to_string(std::path::Path::new(&bundle_path).join("operations.log"))
        .expect("read bundle log");
    assert!(log.contains("token=[REDACTED]"));
    assert!(!log.contains("super-secret"));
    assert!(std::path::Path::new(&bundle_path)
        .join("execution-report-index.json")
        .exists());

    let _ = std::fs::remove_dir_all(temp_dir);
}

#[test]
fn dashboard_export_contains_preview_data() {
    let output = nousb()
        .args(["dashboard", "export"])
        .output()
        .expect("run dashboard export");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"catalog\""));
    assert!(stdout.contains("\"artifact_manifests\""));
    assert!(stdout.contains("\"real_vm_reports\""));
    assert!(stdout.contains("\"fake_scenarios\""));
    assert!(stdout.contains("\"sample_plan\""));
    assert!(stdout.contains("\"sample_vm_rehearsal\""));
    assert!(stdout.contains("\"all_invariants_hold\":true"));
    assert!(stdout.contains("\"boot_plan\""));
    assert!(stdout.contains("ubuntu-24.04-desktop"));
    assert!(stdout.contains("linux-luks-low-space"));
}

/// A fresh working directory, so `.nousb/` state from other tests or the repo is not seen.
fn boot_scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "nousb-cli-boot-{name}-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

#[test]
fn boot_plan_for_a_pinned_profile_is_read_only_and_names_how_to_get_the_iso() {
    let dir = boot_scratch("pinned");
    let output = nousb()
        .current_dir(&dir)
        .args(["boot", "plan", "ubuntu-24.04-server"])
        .output()
        .expect("run nousb boot plan");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("Ready: no"));
    assert!(stdout.contains("nousb image download ubuntu-24.04-server"));
    assert!(stdout.contains("--iso"));
    // Planning leaves no host boot transaction behind.
    assert!(!dir.join(".nousb").join("host-boot").exists());

    let status = nousb()
        .current_dir(&dir)
        .args(["image", "status", "ubuntu-24.04-server"])
        .output()
        .expect("run nousb image status");
    assert!(status.status.success());
    let stdout = String::from_utf8(status.stdout).expect("utf8 stdout");
    assert!(stdout.contains("present: false"));
    assert!(stdout.contains("downloading: false"));

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn image_status_with_stale_empty_or_corrupt_lock_reports_not_downloading_and_preserves_lock() {
    let dir = boot_scratch("stale-lock");
    let lock_dir = dir.join(".nousb/artifacts/ubuntu-24.04-server");
    std::fs::create_dir_all(&lock_dir).expect("create artifact dir");
    let lock_path = lock_dir.join("download.lock");

    // 1. Stale lock whose PID is gone. Status must report downloading: false and NOT delete the lock.
    std::fs::write(&lock_path, "pid=99999999\n").expect("write stale lock");
    let status = nousb()
        .current_dir(&dir)
        .args(["image", "status", "ubuntu-24.04-server"])
        .output()
        .expect("run nousb image status with stale lock");
    assert!(status.status.success());
    let stdout = String::from_utf8(status.stdout).expect("utf8 stdout");
    if cfg!(any(target_os = "linux", target_os = "windows")) {
        assert!(stdout.contains("downloading: false"));
    }
    assert!(
        lock_path.exists(),
        "read-only status must not delete stale lock"
    );

    // 2. Empty 0-byte lock file.
    std::fs::write(&lock_path, "").expect("write empty lock");
    let status = nousb()
        .current_dir(&dir)
        .args(["image", "status", "ubuntu-24.04-server"])
        .output()
        .expect("run nousb image status with empty lock");
    assert!(status.status.success());
    let stdout = String::from_utf8(status.stdout).expect("utf8 stdout");
    assert!(stdout.contains("downloading: false"));
    assert!(
        lock_path.exists(),
        "read-only status must not delete empty lock"
    );

    // 3. Garbage / unparseable lock file.
    std::fs::write(&lock_path, "garbage_pid_data\n").expect("write garbage lock");
    let status = nousb()
        .current_dir(&dir)
        .args(["image", "status", "ubuntu-24.04-server"])
        .output()
        .expect("run nousb image status with garbage lock");
    assert!(status.status.success());
    let stdout = String::from_utf8(status.stdout).expect("utf8 stdout");
    assert!(stdout.contains("downloading: false"));
    assert!(
        lock_path.exists(),
        "read-only status must not delete garbage lock"
    );

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn custom_boot_plan_needs_an_iso_and_reports_a_missing_one_as_a_blocker() {
    let dir = boot_scratch("custom");
    let bare = nousb()
        .current_dir(&dir)
        .args(["boot", "plan", "custom"])
        .output()
        .expect("run nousb boot plan custom");
    assert!(!bare.status.success());
    assert!(String::from_utf8_lossy(&bare.stderr).contains("--iso"));

    let missing = nousb()
        .current_dir(&dir)
        .args(["--json", "boot", "plan", "custom", "--iso", "no-such.iso"])
        .output()
        .expect("run nousb boot plan custom --iso");
    assert!(missing.status.success());
    let stdout = String::from_utf8(missing.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"profile_id\":\"custom\""));
    assert!(stdout.contains("\"iso_verification\":\"unverified\""));
    assert!(stdout.contains("custom ISO not found"));

    let bad_digest = nousb()
        .current_dir(&dir)
        .args([
            "boot", "plan", "custom", "--iso", "x.iso", "--sha256", "1234",
        ])
        .output()
        .expect("run nousb boot plan custom --sha256");
    assert!(!bad_digest.status.success());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn windows_target_is_plan_only_and_arming_it_is_refused() {
    let dir = boot_scratch("windows");
    let plan = nousb()
        .current_dir(&dir)
        .args(["--json", "boot", "plan", "windows-11"])
        .output()
        .expect("run nousb boot plan windows-11");
    assert!(plan.status.success());
    let stdout = String::from_utf8(plan.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"target_kind\":\"windows_setup\""));
    assert!(stdout.contains("\"execution_enabled\":false"));
    assert!(stdout.contains("plan-only"));
    assert!(stdout.contains("\"files\":[]"));

    let arm = nousb()
        .current_dir(&dir)
        .args(["boot", "arm", "windows-11", "BOOT ONCE INTO windows-11"])
        .output()
        .expect("run nousb boot arm windows-11");
    assert!(!arm.status.success());
    assert!(!dir.join(".nousb").join("host-boot").exists());
    let _ = std::fs::remove_dir_all(dir);
}

fn extract_json_string(source: &str, key: &str) -> Option<String> {
    let marker = format!("\"{key}\":\"");
    let start = source.find(&marker)? + marker.len();
    let end = source[start..].find('"')?;
    Some(source[start..start + end].to_string())
}
