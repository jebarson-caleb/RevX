#[cfg(not(any(target_os = "windows", target_os = "linux")))]
use nousb_core::HostPlatform;
mod tui;
use nousb_core::{
    acquire_qemu_windows_runtime, arm_host_one_shot, artifact_cache_path, artifact_manifest,
    assess_delivery, assess_recovery, built_in_profiles, cleanup_host_one_shot,
    create_recovery_pack, create_staging_bundle, download_artifact, embedded_profiles,
    execute_plan_safe, export_diagnostic_bundle, inspect_staging_artifact,
    list_saved_execution_reports, load_execution_report, load_execution_report_json,
    load_host_boot_state, plan_host_one_shot, plan_operation, plan_operation_for_inventory,
    probe_artifact, qemu_runtime_cache_path, qemu_windows_runtime_manifest, rehearse_vm_one_shot,
    resume_simulated_report, rollback_simulated_report, save_execution_report, save_vm_rehearsal,
    verify_artifact, verify_sha256_with_system_tool, write_journal_entry, FakePlatformAdapter,
    HostBootBackend, HostBootFacts, HostBootPlan, NoUsbError, OneShotBootBackend,
    OperationExecutor, OperationKind, PlatformAdapter, RecoveryAction, SavedExecutionReportSummary,
    SimulatedExecutor, SimulationConfig, SystemInventory, CLEANUP_CONFIRMATION_PHRASE,
};
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let raw_args: Vec<String> = env::args().skip(1).collect();
    let options = CliOptions::parse(raw_args)?;
    let args = options.args.as_slice();
    let cwd = env::current_dir()?;
    match args {
        [] => {
            print_help();
        }
        [cmd] if cmd == "help" || cmd == "--help" || cmd == "-h" => {
            print_help();
        }
        [cmd] if cmd == "tui" => {
            let (inventory, adapter_name) = inspect_host()?;
            let stdin = io::stdin();
            let stdout = io::stdout();
            tui::run(
                &cwd,
                &inventory,
                adapter_name,
                &mut stdin.lock(),
                &mut stdout.lock(),
            )?;
        }
        [cmd, sub] if cmd == "system" && sub == "inspect" => {
            let (inventory, adapter_name) = inspect_host()?;
            if options.json {
                println!("{}", inventory.to_json(adapter_name));
            } else {
                println!("adapter: {adapter_name}");
                println!("os: {}", inventory.os_name);
                println!("arch: {}", inventory.arch);
                println!("memory_total_mb: {:?}", inventory.memory_total_mb);
                println!("firmware: {:?}", inventory.firmware);
                println!("secure_boot: {:?}", inventory.secure_boot);
                println!("encryption: {:?}", inventory.encryption);
                println!(
                    "available_space_gb: {:?}",
                    inventory.disk_inventory.available_space_gb
                );
                for line in inventory.boot_hints.preview_lines() {
                    println!("boot_hint: {line}");
                }
                for warning in inventory.warnings {
                    println!("warning: {warning}");
                }
            }
            write_journal_entry(&cwd, "system inspect")?;
        }
        [cmd, sub, scenario] if cmd == "system" && sub == "inspect-fake" => {
            let adapter = fake_adapter(scenario)?;
            let inventory = adapter.inspect()?;
            if options.json {
                println!("{}", inventory.to_json(adapter.name()));
            } else {
                println!("adapter: {}", adapter.name());
                println!("os: {}", inventory.os_name);
                println!("arch: {}", inventory.arch);
                println!("firmware: {:?}", inventory.firmware);
                println!("secure_boot: {:?}", inventory.secure_boot);
                println!("encryption: {:?}", inventory.encryption);
                println!(
                    "available_space_gb: {:?}",
                    inventory.disk_inventory.available_space_gb
                );
                println!("capabilities: {:?}", adapter.capabilities());
                for line in inventory.boot_hints.preview_lines() {
                    println!("boot_hint: {line}");
                }
                for warning in inventory.warnings {
                    println!("warning: {warning}");
                }
            }
        }
        [cmd, sub] if cmd == "catalog" && sub == "list" => {
            let profiles = built_in_profiles();
            if options.json {
                let json_profiles: Vec<String> =
                    profiles.iter().map(|profile| profile.to_json()).collect();
                println!("[{}]", json_profiles.join(","));
            } else {
                for profile in profiles {
                    println!(
                        "{} | {} {} | {}",
                        profile.id, profile.name, profile.version, profile.source_url
                    );
                }
            }
        }
        [cmd, sub] if cmd == "catalog" && sub == "validate" => {
            let profiles = embedded_profiles()?;
            if options.json {
                println!(
                    "{{\"valid\":true,\"profile_count\":{},\"profile_ids\":[{}]}}",
                    profiles.len(),
                    profiles
                        .iter()
                        .map(|profile| format!("\"{}\"", profile.id))
                        .collect::<Vec<_>>()
                        .join(",")
                );
            } else {
                println!("catalog valid: {} profiles", profiles.len());
                for profile in profiles {
                    println!("- {}", profile.id);
                }
            }
        }
        [cmd, sub, profile] if cmd == "workflow" && sub == "assess" => {
            let (inventory, _) = inspect_host()?;
            let assessment = assess_delivery(&inventory, profile)?;
            if options.json {
                println!("{}", assessment.to_json());
            } else {
                println!("{}", assessment.preview());
            }
            write_journal_entry(&cwd, &format!("assessed delivery profile={profile}"))?;
        }
        [cmd, sub, scenario, profile] if cmd == "workflow" && sub == "assess-fake" => {
            let adapter = fake_adapter(scenario)?;
            let inventory = adapter.inspect()?;
            let assessment = assess_delivery(&inventory, profile)?;
            if options.json {
                println!("{}", assessment.to_json());
            } else {
                println!("Scenario: {}", adapter.name());
                println!("{}", assessment.preview());
            }
        }
        [cmd, sub, profile] if cmd == "plan" => {
            let kind = parse_plan_kind(sub)?;
            let plan = plan_operation(kind, Some(profile))?;
            if options.json {
                println!("{}", plan.to_json());
            } else {
                if options.dry_run {
                    println!("Dry run: no execution will be attempted.");
                }
                println!("{}", plan.preview());
            }
            write_journal_entry(
                &cwd,
                &format!("planned {} dry_run={}", plan.id, options.dry_run),
            )?;
        }
        [cmd, scenario, plan_kind, profile] if cmd == "plan-fake" => {
            let adapter = fake_adapter(scenario)?;
            let inventory = adapter.inspect()?;
            let kind = parse_plan_kind(plan_kind)?;
            let plan = plan_operation_for_inventory(kind, Some(profile), &inventory)?;
            if options.json {
                println!("{}", plan.to_json());
            } else {
                if options.dry_run {
                    println!("Dry run: fake scenario only; no execution will be attempted.");
                }
                println!("Scenario: {}", adapter.name());
                println!("{}", plan.preview());
            }
            write_journal_entry(
                &cwd,
                &format!("planned fake scenario={} plan={}", adapter.name(), plan.id),
            )?;
        }
        [cmd, plan_kind, profile] if cmd == "simulate" => {
            let kind = parse_plan_kind(plan_kind)?;
            let plan = plan_operation(kind, Some(profile))?;
            let report = run_simulation(&plan, &options)?;
            print_execution_report(&report, options.json);
            let path = save_execution_report(&cwd, &report)?;
            if !options.json {
                println!("Saved report: {}", path.display());
            }
        }
        [cmd, scenario, plan_kind, profile] if cmd == "simulate-fake" => {
            let adapter = fake_adapter(scenario)?;
            let inventory = adapter.inspect()?;
            let kind = parse_plan_kind(plan_kind)?;
            let plan = plan_operation_for_inventory(kind, Some(profile), &inventory)?;
            let report = run_simulation(&plan, &options)?;
            if !options.json {
                println!("Scenario: {}", adapter.name());
            }
            print_execution_report(&report, options.json);
            let path = save_execution_report(&cwd, &report)?;
            write_journal_entry(
                &cwd,
                &format!(
                    "simulated fake scenario={} report={}",
                    adapter.name(),
                    path.display()
                ),
            )?;
            if !options.json {
                println!("Saved report: {}", path.display());
            }
        }
        [cmd, sub] if cmd == "recovery-pack" && sub == "create" => {
            let (inventory, _) = inspect_host()?;
            let path = create_recovery_pack(&cwd, &inventory)?;
            write_journal_entry(&cwd, &format!("created recovery pack {}", path.display()))?;
            if options.json {
                println!("{{\"path\":\"{}\"}}", path.display());
            } else {
                println!("{}", path.display());
            }
        }
        [cmd, sub, profile] if cmd == "image" && sub == "manifest" => {
            let manifest = artifact_manifest(profile)?;
            if options.json {
                println!("{}", manifest.to_json());
            } else {
                println!("profile: {}", manifest.profile_id);
                println!("filename: {}", manifest.filename);
                println!("source: {}", manifest.source_url);
                println!("size_bytes: {}", manifest.size_bytes);
                println!("sha256: {}", manifest.sha256);
            }
        }
        [cmd, sub, profile] if cmd == "image" && sub == "verify-signature" => {
            let verification = nousb_core::verify_profile_signature(profile)?;
            write_journal_entry(
                &cwd,
                &format!(
                    "verified vendor signature profile={} key={} pinned_digest_signed={}",
                    verification.profile_id,
                    verification.key_fingerprint,
                    verification.pinned_digest_signed
                ),
            )?;
            if options.json {
                println!("{}", verification.to_json());
            } else {
                println!("profile: {}", verification.profile_id);
                println!(
                    "signing key: {} ({})",
                    verification.key_id, verification.key_fingerprint
                );
                println!("checksum document: {}", verification.checksum_url);
                if let Some(signature_url) = &verification.signature_url {
                    println!("detached signature: {signature_url}");
                }
                println!("signature_valid: {}", verification.signature_valid);
                println!(
                    "pinned sha256 {} is vendor-signed for {}: {}",
                    verification.pinned_sha256,
                    verification.artifact_filename,
                    verification.pinned_digest_signed
                );
            }
        }
        [cmd, sub, profile] if cmd == "image" && sub == "probe" => {
            let probe = probe_artifact(profile)?;
            if options.json {
                println!("{}", probe.to_json());
            } else {
                println!("source reachable: {}", probe.final_url);
                println!("content_length: {:?}", probe.content_length);
                println!("accepts_ranges: {}", probe.accepts_ranges);
            }
        }
        [cmd, sub, profile] if cmd == "image" && sub == "download" => {
            let download = download_artifact(&cwd, profile)?;
            write_journal_entry(
                &cwd,
                &format!(
                    "downloaded verified artifact profile={} path={} already_present={}",
                    profile,
                    download.path.display(),
                    download.already_present
                ),
            )?;
            if options.json {
                println!("{}", download.to_json());
            } else {
                println!("verified artifact: {}", download.path.display());
                println!("downloaded_bytes: {}", download.downloaded_bytes);
                println!("resumed_from_bytes: {}", download.resumed_from_bytes);
                println!("already_present: {}", download.already_present);
            }
        }
        [cmd, sub, profile, path] if cmd == "image" && sub == "verify-profile" => {
            let manifest = verify_artifact(profile, Path::new(path))?;
            if options.json {
                println!(
                    "{{\"verified\":true,\"manifest\":{},\"path\":\"{}\"}}",
                    manifest.to_json(),
                    escape_json_for_cli(path)
                );
            } else {
                println!("verified {} against profile {}", path, profile);
            }
        }
        [cmd, sub, path, expected] if cmd == "image" && sub == "verify" => {
            let ok = verify_sha256_with_system_tool(Path::new(path), expected)?;
            if ok {
                println!("verified: {path}");
            } else {
                println!("verification failed: {path}");
                return Err("checksum mismatch".into());
            }
        }
        [cmd, sub, profile, path] if cmd == "staging" && sub == "inspect" => {
            let preview = inspect_staging_artifact(profile, Path::new(path))?;
            if options.json {
                println!("{}", preview.to_json());
            } else {
                println!("verified artifact: {}", preview.artifact_path.display());
                for asset in preview.assets {
                    println!("{} | {} bytes", asset.source_path, asset.size_bytes);
                }
                println!("execution_enabled: {}", preview.execution_enabled);
            }
        }
        [cmd, sub, profile, path] if cmd == "staging" && sub == "create" => {
            let bundle = create_staging_bundle(&cwd, profile, Path::new(path))?;
            write_journal_entry(
                &cwd,
                &format!(
                    "created verified non-executable staging bundle profile={} path={}",
                    profile,
                    bundle.path.display()
                ),
            )?;
            if options.json {
                println!("{}", bundle.to_json());
            } else {
                println!("staging bundle: {}", bundle.path.display());
                println!("execution_enabled: {}", bundle.execution_enabled);
            }
        }
        [cmd, sub] if cmd == "journal" && sub == "migrate" => {
            let migration = nousb_core::migrate_saved_reports(&cwd)?;
            if options.json {
                println!("{}", migration.to_json());
            } else {
                println!("journal: {}", migration.database.display());
                println!("schema_version: {}", migration.schema_version);
                println!("imported_reports: {}", migration.imported_reports);
                for skipped in &migration.skipped {
                    println!("skipped: {skipped}");
                }
            }
        }
        [cmd, sub] if cmd == "logs" && sub == "export" => {
            let sqlite_path = nousb_core::journal_database_path(&cwd);
            let log_path = cwd.join(".nousb").join("journal").join("operations.log");
            if sqlite_path.exists() {
                println!("{}", sqlite_path.display());
            } else if log_path.exists() {
                println!("{}", log_path.display());
            } else {
                println!("no logs yet");
            }
        }
        [cmd, sub] if cmd == "reports" && sub == "list" => {
            let reports = list_saved_execution_reports(&cwd)?;
            if options.json {
                println!("{}", report_summaries_json(&reports));
            } else if reports.is_empty() {
                println!("no saved execution reports");
            } else {
                for report in reports {
                    println!(
                        "{} | {} | recovery_required={} | {}",
                        report.plan_id,
                        report.status,
                        report.recovery_required,
                        report.path.display()
                    );
                }
            }
        }
        [cmd, sub, plan_id] if cmd == "reports" && sub == "show" => {
            let report = load_execution_report_json(&cwd, plan_id)?;
            println!("{report}");
        }
        [cmd, sub, plan_id] if cmd == "reports" && sub == "recover" => {
            let report = load_execution_report(&cwd, plan_id)?;
            let assessment = assess_recovery(&report);
            if options.json {
                println!("{}", assessment.to_json());
            } else {
                println!("{}", assessment.preview());
                println!(
                    "Saved reports come from simulations; no host boot state was read or changed."
                );
            }
        }
        [cmd, plan_id] if cmd == "resume" => {
            let report = load_execution_report(&cwd, plan_id)?;
            let resumed = resume_simulated_report(&report)?;
            let path = save_execution_report(&cwd, &resumed)?;
            write_journal_entry(
                &cwd,
                &format!(
                    "resumed simulated operation {plan_id} report={}",
                    path.display()
                ),
            )?;
            print_execution_report(&resumed, options.json);
            if !options.json {
                println!("Saved report: {}", path.display());
            }
        }
        [cmd, sub] if cmd == "diagnostics" && sub == "export" => {
            let (inventory, _) = inspect_host()?;
            let bundle = export_diagnostic_bundle(&cwd, &inventory)?;
            if options.json {
                println!("{}", bundle.to_json());
            } else {
                println!("Diagnostic bundle: {}", bundle.path.display());
                for file in bundle.files {
                    println!("- {}", file.display());
                }
            }
        }
        [cmd, sub] if cmd == "dashboard" && sub == "export" => {
            println!("{}", dashboard_export_json(&cwd)?);
        }
        [cmd, sub] if cmd == "vm" && sub == "doctor" => {
            print_vm_doctor(&cwd, options.json);
        }
        [cmd, scope, sub] if cmd == "vm" && scope == "qemu" && sub == "manifest" => {
            let manifest = qemu_windows_runtime_manifest();
            if options.json {
                println!("{}", manifest.to_json());
            } else {
                println!("QEMU project-local runtime");
                println!("version: {}", manifest.version);
                println!("platform: {}", manifest.platform);
                println!("source: {}", manifest.source_url);
                println!("size_bytes: {}", manifest.size_bytes);
                println!("sha512: {}", manifest.sha512);
                println!("warning: {}", manifest.signature_warning);
            }
        }
        [cmd, scope, sub] if cmd == "vm" && scope == "qemu" && sub == "plan-smoke" => {
            let plan = nousb_platform_windows::windows_qemu_smoke_plan(&cwd)?;
            if options.json {
                println!("{}", plan.to_json());
            } else {
                println!("{}", plan.preview());
            }
        }
        [cmd, scope, sub] if cmd == "vm" && scope == "qemu" && sub == "plan-ubuntu-netboot" => {
            let plan = nousb_platform_windows::windows_qemu_netboot_plan(&cwd)?;
            if options.json {
                println!("{}", plan.to_json());
            } else {
                println!("{}", plan.preview());
            }
        }
        [cmd, scope, sub] if cmd == "vm" && scope == "qemu" && sub == "plan-ubuntu-full-ram" => {
            let plan = nousb_platform_windows::windows_qemu_full_ram_plan(&cwd)?;
            if options.json {
                println!("{}", plan.to_json());
            } else {
                println!("{}", plan.preview());
            }
        }
        [cmd, scope, sub]
            if cmd == "vm" && scope == "qemu" && sub == "plan-ubuntu-uefi-full-ram" =>
        {
            let plan = nousb_platform_windows::windows_qemu_uefi_full_ram_plan(&cwd)?;
            if options.json {
                println!("{}", plan.to_json());
            } else {
                println!("{}", plan.preview());
            }
        }
        [cmd, scope, sub]
            if cmd == "vm" && scope == "qemu" && sub == "plan-current-os-baseline" =>
        {
            let plan = nousb_platform_windows::windows_qemu_current_os_plan(&cwd)?;
            if options.json {
                println!("{}", plan.to_json());
            } else {
                println!("{}", plan.preview());
            }
        }
        [cmd, scope, sub, confirmation] if cmd == "vm" && scope == "qemu" && sub == "smoke" => {
            let plan = nousb_platform_windows::windows_qemu_smoke_plan(&cwd)?;
            if !options.json {
                println!("{}", plan.preview());
                println!("Starting only after exact typed confirmation was supplied.");
            }
            let report = nousb_platform_windows::run_windows_qemu_uefi_smoke(&cwd, confirmation)?;
            write_journal_entry(
                &cwd,
                &format!(
                    "completed disposable QEMU UEFI smoke report={} real_vm=true physical_disks=false network=false host_boot_changes=false ram_boot_verified=false",
                    report.report_path.display()
                ),
            )?;
            if options.json {
                println!("{}", report.to_json());
            } else {
                println!("Disposable QEMU UEFI smoke completed.");
                println!("report: {}", report.report_path.display());
                println!("real_vm_executed: {}", report.real_vm_executed);
                println!(
                    "uefi_firmware_initialized: {}",
                    report.uefi_firmware_initialized
                );
                println!("ram_boot_verified: {}", report.ram_boot_verified);
                println!(
                    "physical_disks_attached: {}",
                    report.physical_disks_attached
                );
                println!("network_enabled: {}", report.network_enabled);
                println!("host_boot_changes: {}", report.host_boot_changes);
            }
        }
        [cmd, scope, sub, confirmation]
            if cmd == "vm" && scope == "qemu" && sub == "rehearse-ubuntu-netboot" =>
        {
            let plan = nousb_platform_windows::windows_qemu_netboot_plan(&cwd)?;
            if !options.json {
                println!("{}", plan.preview());
                println!("Starting only after exact typed confirmation was supplied.");
            }
            let report =
                nousb_platform_windows::run_windows_qemu_netboot_rehearsal(&cwd, confirmation)?;
            write_journal_entry(
                &cwd,
                &format!(
                    "completed disposable Ubuntu netboot RAM rehearsal report={} kernel_initrd_ram=true full_installer_ram=false direct_kernel=true uefi=false physical_disks=false network=false host_boot_changes=false",
                    report.report_path.display()
                ),
            )?;
            if options.json {
                println!("{}", report.to_json());
            } else {
                println!("Disposable Ubuntu kernel/initrd rehearsal completed.");
                println!("report: {}", report.report_path.display());
                println!("real_vm_executed: {}", report.real_vm_executed);
                println!("direct_kernel_boot: {}", report.direct_kernel_boot);
                println!(
                    "uefi_firmware_initialized: {}",
                    report.uefi_firmware_initialized
                );
                println!(
                    "kernel_initrd_ram_resident: {}",
                    report.kernel_initrd_ram_resident
                );
                println!(
                    "full_installer_payload_in_ram: {}",
                    report.full_installer_payload_in_ram
                );
                println!("network_enabled: {}", report.network_enabled);
                println!(
                    "physical_disks_attached: {}",
                    report.physical_disks_attached
                );
                println!("host_boot_changes: {}", report.host_boot_changes);
                println!("trust_level: {}", report.trust_level);
            }
        }
        [cmd, scope, sub, confirmation]
            if cmd == "vm" && scope == "qemu" && sub == "rehearse-ubuntu-full-ram" =>
        {
            let plan = nousb_platform_windows::windows_qemu_full_ram_plan(&cwd)?;
            if !options.json {
                println!("{}", plan.preview());
                println!("Starting only after exact typed confirmation was supplied.");
            }
            let report =
                nousb_platform_windows::run_windows_qemu_full_ram_rehearsal(&cwd, confirmation)?;
            write_journal_entry(
                &cwd,
                &format!(
                    "completed disposable Ubuntu full-ISO RAM rehearsal report={} full_installer_ram={} source_stopped={} qmp_empty_blocks={} direct_kernel=true uefi=false physical_disks=false virtual_install_disks=false network=true guest_https=false host_boot_changes=false fallback=false",
                    report.report_path.display(),
                    report.full_installer_payload_in_ram,
                    report.source_stopped_after_download,
                    report.qmp_empty_block_list_observed,
                ),
            )?;
            if options.json {
                println!("{}", report.to_json());
            } else {
                println!("Disposable Ubuntu full-ISO RAM rehearsal completed.");
                println!("report: {}", report.report_path.display());
                println!(
                    "full_installer_payload_in_ram: {}",
                    report.full_installer_payload_in_ram
                );
                println!(
                    "source_stopped_after_download: {}",
                    report.source_stopped_after_download
                );
                println!(
                    "subiquity_payload_mounted_after_source_stop: {}",
                    report.subiquity_payload_mounted_after_source_stop
                );
                println!(
                    "qmp_empty_block_list_observed: {}",
                    report.qmp_empty_block_list_observed
                );
                println!("direct_kernel_boot: {}", report.direct_kernel_boot);
                println!(
                    "uefi_firmware_initialized: {}",
                    report.uefi_firmware_initialized
                );
                println!("guest_transport_https: {}", report.guest_transport_https);
                println!(
                    "physical_disks_attached: {}",
                    report.physical_disks_attached
                );
                println!(
                    "virtual_install_disks_attached: {}",
                    report.virtual_install_disks_attached
                );
                println!("host_boot_changes: {}", report.host_boot_changes);
                println!("fallback_boot_observed: {}", report.fallback_boot_observed);
                println!("trust_level: {}", report.trust_level);
            }
        }
        [cmd, scope, sub, confirmation]
            if cmd == "vm" && scope == "qemu" && sub == "rehearse-ubuntu-uefi-full-ram" =>
        {
            let plan = nousb_platform_windows::windows_qemu_uefi_full_ram_plan(&cwd)?;
            if !options.json {
                println!("{}", plan.preview());
                println!("Starting only after exact typed confirmation was supplied.");
            }
            let report = nousb_platform_windows::run_windows_qemu_uefi_full_ram_rehearsal(
                &cwd,
                confirmation,
            )?;
            write_journal_entry(
                &cwd,
                &format!(
                    "completed disposable Ubuntu UEFI full-ISO RAM rehearsal report={} uefi={} full_installer_ram={} boot_source_deleted={} http_source_stopped={} firmware_only_blocks={} direct_kernel=false secure_boot=false physical_disks=false virtual_install_disks=false network=true guest_https=false host_boot_changes=false fallback=false",
                    report.report_path.display(),
                    report.uefi_firmware_initialized,
                    report.full_installer_payload_in_ram,
                    report.boot_source_block_node_deleted,
                    report.http_source_stopped_after_download,
                    report.qmp_firmware_only_block_list_observed,
                ),
            )?;
            if options.json {
                println!("{}", report.to_json());
            } else {
                println!("Disposable Ubuntu UEFI full-ISO RAM rehearsal completed.");
                println!("report: {}", report.report_path.display());
                println!(
                    "uefi_firmware_initialized: {}",
                    report.uefi_firmware_initialized
                );
                println!("secure_boot_enabled: {}", report.secure_boot_enabled);
                println!(
                    "official_efi_assets_verified: {}",
                    report.official_efi_assets_verified
                );
                println!(
                    "boot_source_device_deleted: {}",
                    report.boot_source_device_deleted
                );
                println!(
                    "boot_source_block_node_deleted: {}",
                    report.boot_source_block_node_deleted
                );
                println!(
                    "http_source_stopped_after_download: {}",
                    report.http_source_stopped_after_download
                );
                println!(
                    "serial_getty_started_after_http_stop: {}",
                    report.serial_getty_started_after_http_stop
                );
                println!(
                    "qmp_firmware_only_block_list_observed: {}",
                    report.qmp_firmware_only_block_list_observed
                );
                println!(
                    "full_installer_payload_in_ram: {}",
                    report.full_installer_payload_in_ram
                );
                println!("direct_kernel_boot: {}", report.direct_kernel_boot);
                println!("guest_transport_https: {}", report.guest_transport_https);
                println!(
                    "physical_disks_attached: {}",
                    report.physical_disks_attached
                );
                println!("host_boot_changes: {}", report.host_boot_changes);
                println!("fallback_boot_observed: {}", report.fallback_boot_observed);
                println!("trust_level: {}", report.trust_level);
            }
        }
        [cmd, scope, sub, confirmation]
            if cmd == "vm" && scope == "qemu" && sub == "rehearse-current-os-baseline" =>
        {
            let plan = nousb_platform_windows::windows_qemu_current_os_plan(&cwd)?;
            if !options.json {
                println!("{}", plan.preview());
                println!("Starting only after exact typed confirmation was supplied.");
            }
            let report =
                nousb_platform_windows::run_windows_qemu_current_os_rehearsal(&cwd, confirmation)?;
            write_journal_entry(
                &cwd,
                &format!(
                    "completed disposable current-OS UEFI baseline report={} first_boot={} second_boot={} same_disk=true same_uefi_vars=true physical_disks=false network=false host_boot_changes=false installer_fallback=false bootnext=false power_loss_matrix=false",
                    report.report_path.display(),
                    report.first_boot_observed,
                    report.second_boot_observed,
                ),
            )?;
            if options.json {
                println!("{}", report.to_json());
            } else {
                println!("Disposable current-OS UEFI baseline completed.");
                println!("report: {}", report.report_path.display());
                println!("first_boot_observed: {}", report.first_boot_observed);
                println!("second_boot_observed: {}", report.second_boot_observed);
                println!("same_guest_disk_reused: {}", report.same_guest_disk_reused);
                println!(
                    "same_uefi_variable_store_reused: {}",
                    report.same_uefi_variable_store_reused
                );
                println!(
                    "current_os_userspace_started: {}",
                    report.current_os_userspace_started
                );
                println!(
                    "installer_fallback_proven: {}",
                    report.installer_fallback_proven
                );
                println!("uefi_bootnext_proven: {}", report.uefi_bootnext_proven);
                println!(
                    "power_loss_matrix_complete: {}",
                    report.power_loss_matrix_complete
                );
                println!("host_boot_changes: {}", report.host_boot_changes);
                println!("trust_level: {}", report.trust_level);
            }
        }
        [cmd, scope, sub] if cmd == "vm" && scope == "qemu" && sub == "plan-secure-boot" => {
            let plan = nousb_platform_windows::windows_qemu_secure_boot_plan(&cwd)?;
            if options.json {
                println!("{}", plan.to_json());
            } else {
                println!("{}", plan.preview());
            }
        }
        [cmd, scope, sub, confirmation]
            if cmd == "vm" && scope == "qemu" && sub == "rehearse-secure-boot" =>
        {
            let plan = nousb_platform_windows::windows_qemu_secure_boot_plan(&cwd)?;
            if !options.json {
                println!("{}", plan.preview());
                println!("Starting only after exact typed confirmation was supplied.");
            }
            let report =
                nousb_platform_windows::run_windows_qemu_secure_boot_rehearsal(&cwd, confirmation)?;
            write_journal_entry(
                &cwd,
                &format!(
                    "completed disposable Secure Boot rehearsal report={} secure_boot={} signed_chain_accepted={} unsigned_loader_rejected={} host_boot_changes=false",
                    report.report_path.display(),
                    report.secure_boot_enabled,
                    report.signed_chain_accepted,
                    report.unsigned_loader_rejected,
                ),
            )?;
            if options.json {
                println!("{}", report.to_json());
            } else {
                println!("Disposable Secure Boot rehearsal completed.");
                println!("report: {}", report.report_path.display());
                println!("secure_boot_enabled: {}", report.secure_boot_enabled);
                println!("signed_chain_accepted: {}", report.signed_chain_accepted);
                println!(
                    "unsigned_loader_rejected: {}",
                    report.unsigned_loader_rejected
                );
                println!("host_boot_changes: {}", report.host_boot_changes);
            }
        }
        [cmd, scope, sub] if cmd == "vm" && scope == "qemu" && sub == "plan-runtime" => {
            let plan = nousb_platform_windows::windows_qemu_runtime_bootstrap_plan(&cwd)?;
            if options.json {
                println!("{}", plan.to_json());
            } else {
                println!("{}", plan.preview());
            }
        }
        [cmd, scope, sub, confirmation]
            if cmd == "vm" && scope == "qemu" && sub == "bootstrap-runtime" =>
        {
            let plan = nousb_platform_windows::windows_qemu_runtime_bootstrap_plan(&cwd)?;
            if !options.json {
                println!("{}", plan.preview());
                println!("Starting only after exact typed confirmation was supplied.");
            }
            let report =
                nousb_platform_windows::run_windows_qemu_runtime_bootstrap(&cwd, confirmation)?;
            write_journal_entry(
                &cwd,
                &format!(
                    "bootstrapped project-local QEMU runtime manifest={} qemu={} packages={} installs_into_windows=false host_boot_changes=false",
                    report.manifest_path.display(),
                    report.qemu_version,
                    report.installed_packages.len(),
                ),
            )?;
            if options.json {
                println!("{}", report.to_json());
            } else {
                println!("Project-local QEMU runtime ready.");
                println!("runtime: {}", report.runtime_root.display());
                println!("manifest: {}", report.manifest_path.display());
                println!("qemu_version: {}", report.qemu_version);
                println!("packages: {}", report.installed_packages.len());
                println!("runtime_was_present: {}", report.runtime_was_present);
                println!("installs_into_windows: {}", report.installs_into_windows);
                println!("host_boot_changes: {}", report.host_boot_changes);
            }
        }
        [cmd, scope, sub, rest @ ..]
            if cmd == "vm"
                && scope == "qemu"
                && sub == "plan-current-os-one-shot"
                && rest.len() <= 2 =>
        {
            let arguments = parse_one_shot_arguments(rest)?;
            let plan = nousb_platform_windows::windows_qemu_one_shot_plan(
                &cwd,
                arguments.backend,
                arguments.mode,
            )?;
            if options.json {
                println!("{}", plan.to_json());
            } else {
                println!("{}", plan.preview());
            }
        }
        [cmd, scope, sub, confirmation, rest @ ..]
            if cmd == "vm"
                && scope == "qemu"
                && sub == "rehearse-current-os-one-shot"
                && rest.len() <= 3 =>
        {
            let arguments = parse_one_shot_arguments(rest)?;
            let backend = arguments.backend;
            let plan =
                nousb_platform_windows::windows_qemu_one_shot_plan(&cwd, backend, arguments.mode)?;
            if !options.json {
                println!("{}", plan.preview());
                println!("Starting only after exact typed confirmation was supplied.");
            }
            let report = nousb_platform_windows::run_windows_qemu_one_shot_rehearsal(
                &cwd,
                confirmation,
                backend,
                arguments.mode,
                arguments.scenario,
            )?;
            write_journal_entry(
                &cwd,
                &format!(
                    "completed disposable current-OS one-shot rehearsal backend={} report={} scenarios={} selection={} installer_fallback={} power_loss_matrix={} secure_boot=false physical_disks=false network=false host_boot_changes=false",
                    backend,
                    report.report_path.display(),
                    report.scenarios.len(),
                    report.one_shot_selection_proven,
                    report.installer_fallback_proven,
                    report.power_loss_matrix_complete,
                ),
            )?;
            if options.json {
                println!("{}", report.to_json());
            } else {
                println!("Disposable current-OS UEFI one-shot rehearsal completed.");
                println!("report: {}", report.report_path.display());
                for scenario in &report.scenarios {
                    println!(
                        "scenario {}: passed={} power_cycles={} power_cut={} installer_boots={}",
                        scenario.point,
                        scenario.passed(),
                        scenario.power_cycles,
                        scenario.power_cut_applied,
                        scenario.evaluation.installer_boots,
                    );
                }
                println!(
                    "one_shot_selection_proven: {}",
                    report.one_shot_selection_proven
                );
                println!(
                    "installer_fallback_proven: {}",
                    report.installer_fallback_proven
                );
                println!(
                    "power_loss_matrix_complete: {}",
                    report.power_loss_matrix_complete
                );
                println!("secure_boot_enabled: {}", report.secure_boot_enabled);
                println!(
                    "full_installer_payload_in_ram: {}",
                    report.full_installer_payload_in_ram
                );
                println!("host_boot_changes: {}", report.host_boot_changes);
                println!("trust_level: {}", report.trust_level);
            }
        }
        [cmd, scope, sub] if cmd == "vm" && scope == "qemu" && sub == "acquire" => {
            let download = acquire_qemu_windows_runtime(&cwd)?;
            write_journal_entry(
                &cwd,
                &format!(
                    "acquired verified project-local QEMU runtime artifact path={} already_present={}",
                    download.path.display(),
                    download.already_present
                ),
            )?;
            if options.json {
                println!("{}", download.to_json());
            } else {
                println!(
                    "verified QEMU runtime artifact: {}",
                    download.path.display()
                );
                println!("downloaded_bytes: {}", download.downloaded_bytes);
                println!("resumed_from_bytes: {}", download.resumed_from_bytes);
                println!("already_present: {}", download.already_present);
                println!("installer_executed: false");
                println!("host_boot_changes: false");
            }
        }
        [cmd, sub, backend, profile] if cmd == "vm" && sub == "rehearse" => {
            let backend = OneShotBootBackend::parse(backend)?;
            let report = rehearse_vm_one_shot(backend, profile)?;
            let path = save_vm_rehearsal(&cwd, &report)?;
            write_journal_entry(
                &cwd,
                &format!(
                    "completed VM one-shot rehearsal backend={} profile={} invariants={} real_vm=false",
                    backend, profile, report.all_invariants_hold
                ),
            )?;
            if options.json {
                println!("{}", report.to_json());
            } else {
                println!("{}", report.preview());
                println!("Saved rehearsal: {}", path.display());
            }
        }
        [cmd] if cmd == "doctor" => {
            let (inventory, _) = inspect_host()?;
            if options.json {
                println!(
                    "{{\"safe_default_build\":\"ok\",\"host\":\"{} {}\",\"real_boot_adapters\":\"{}\"}}",
                    inventory.os_name,
                    inventory.arch,
                    if real_boot_compiled() { "compiled-in" } else { "disabled" }
                );
            } else {
                println!("NoUSB doctor");
                println!("safe default build: ok");
                println!("host: {} {}", inventory.os_name, inventory.arch);
                println!(
                    "real boot adapters: {}",
                    if real_boot_compiled() {
                        "compiled in (typed confirmation required; see nousb boot plan)"
                    } else {
                        "disabled"
                    }
                );
            }
        }
        [cmd, sub, profile] if cmd == "boot" && sub == "plan" => {
            let plan = host_boot_plan(&cwd, profile, &options)?;
            if options.json {
                println!("{}", plan.to_json());
            } else {
                print!("{}", plan.preview());
            }
        }
        [cmd, sub, profile, confirmation] if cmd == "boot" && sub == "arm" => {
            let plan = host_boot_plan(&cwd, profile, &options)?;
            if options.dry_run {
                print!("{}", plan.preview());
                return Ok(());
            }
            let mut backend = real_boot_backend()?;
            let state = arm_host_one_shot(&cwd, &plan, backend.as_mut(), confirmation)?;
            if options.json {
                println!("{}", state.to_json());
            } else {
                println!(
                    "Armed: {} will start once on the next reboot.",
                    plan.profile_name
                );
                println!(
                    "Firmware entry: {}",
                    state.entry_id.as_deref().unwrap_or("?")
                );
                println!("Reboot when ready ({}).", reboot_hint());
                println!(
                    "Back in this OS afterwards, run: nousb boot cleanup \"{CLEANUP_CONFIRMATION_PHRASE}\""
                );
            }
        }
        [cmd, sub, profile] if cmd == "boot" && sub == "arm" => {
            let plan = host_boot_plan(&cwd, profile, &options)?;
            return Err(format!(
                "boot arm requires typed confirmation: nousb boot arm {profile} \"{}\"",
                plan.confirmation_phrase
            )
            .into());
        }
        [cmd, sub] if cmd == "boot" && sub == "status" => {
            let state = load_host_boot_state(&cwd)?;
            match (state, options.json) {
                (Some(state), true) => println!("{}", state.to_json()),
                (None, true) => println!("null"),
                (Some(state), false) => {
                    println!("Transaction: {}", state.plan_id);
                    println!("Profile: {}", state.profile_id);
                    println!("Phase: {:?}", state.phase);
                    println!(
                        "Firmware entry: {}",
                        state.entry_id.as_deref().unwrap_or("none")
                    );
                    println!("Needs cleanup: {}", state.needs_cleanup());
                    let skip = state.events.len().saturating_sub(8);
                    for event in state.events.iter().skip(skip) {
                        println!("  {event}");
                    }
                }
                (None, false) => println!("No host boot transaction is recorded."),
            }
        }
        [cmd, sub, confirmation] if cmd == "boot" && sub == "cleanup" => {
            let mut backend = real_boot_backend()?;
            let state = cleanup_host_one_shot(&cwd, backend.as_mut(), confirmation)?;
            if options.json {
                println!("{}", state.to_json());
            } else {
                println!("Cleanup complete: {:?}", state.phase);
            }
        }
        [cmd, sub] if cmd == "boot" && sub == "cleanup" => {
            return Err(format!(
                "boot cleanup requires typed confirmation: nousb boot cleanup \"{CLEANUP_CONFIRMATION_PHRASE}\""
            )
            .into());
        }
        [cmd, plan_kind, profile] if cmd == "execute" => {
            let kind = parse_plan_kind(plan_kind)?;
            let plan = plan_operation(kind, Some(profile))?;
            let outcome = execute_plan_safe(&plan, options.yes)?;
            if options.json {
                println!("{}", outcome.to_json());
            } else {
                println!("{}", outcome.message);
            }
        }
        [cmd, plan_id] if cmd == "execute" => {
            return Err(format!("execute now expects <plan-kind> <profile>; got {plan_id}").into());
        }
        [cmd, operation_id] if cmd == "rollback" => {
            let report = load_execution_report(&cwd, operation_id).map_err(|_| {
                format!(
                    "no saved report for {operation_id}; rollback of real operations requires a real adapter journal; see recovery pack"
                )
            })?;
            let assessment = assess_recovery(&report);
            if !matches!(
                assessment.recommended,
                RecoveryAction::Rollback | RecoveryAction::Resume
            ) {
                return Err(format!(
                    "{operation_id} needs no automatic rollback (recommended: {})",
                    assessment.recommended.as_str()
                )
                .into());
            }
            let rolled_back = rollback_simulated_report(&report);
            let path = save_execution_report(&cwd, &rolled_back)?;
            write_journal_entry(
                &cwd,
                &format!(
                    "rolled back simulated operation {operation_id} report={}",
                    path.display()
                ),
            )?;
            print_execution_report(&rolled_back, options.json);
            if !options.json {
                println!("Saved report: {}", path.display());
            }
        }
        _ => {
            print_help();
            return Err("unknown command".into());
        }
    }
    Ok(())
}

/// Optional `[backend] [installer-mode] [scenario]` arguments of the disposable one-shot
/// commands, in any order. Backend ids, installer modes, and scenario names never overlap.
fn parse_one_shot_arguments(
    arguments: &[String],
) -> Result<OneShotArguments, Box<dyn std::error::Error>> {
    let mut backend = None;
    let mut mode = None;
    let mut scenario = None;
    for argument in arguments {
        if let Some(parsed) = nousb_platform_windows::OneShotInstallerMode::parse(argument) {
            if mode.replace(parsed).is_some() {
                return Err("give at most one installer mode".into());
            }
        } else if let Ok(parsed) = OneShotBootBackend::parse(argument) {
            if backend.replace(parsed).is_some() {
                return Err("give at most one one-shot backend".into());
            }
        } else {
            let parsed = nousb_platform_windows::OneShotPowerLossPoint::parse(argument)?;
            if scenario.replace(parsed).is_some() {
                return Err("give at most one one-shot scenario".into());
            }
        }
    }
    Ok(OneShotArguments {
        backend: backend.unwrap_or(OneShotBootBackend::UefiBootNext),
        mode: mode.unwrap_or(nousb_platform_windows::OneShotInstallerMode::ForcedFailure),
        scenario,
    })
}

struct OneShotArguments {
    backend: OneShotBootBackend,
    mode: nousb_platform_windows::OneShotInstallerMode,
    scenario: Option<nousb_platform_windows::OneShotPowerLossPoint>,
}

fn staging_root(options: &CliOptions) -> PathBuf {
    if let Some(root) = &options.staging_root {
        return root.clone();
    }
    #[cfg(target_os = "windows")]
    {
        nousb_platform_windows::default_windows_staging_root()
    }
    #[cfg(not(target_os = "windows"))]
    {
        nousb_platform_linux::default_linux_staging_root()
    }
}

fn read_host_boot_facts(root: &Path) -> Result<HostBootFacts, NoUsbError> {
    #[cfg(target_os = "windows")]
    {
        nousb_platform_windows::windows_host_boot_facts(root)
    }
    #[cfg(target_os = "linux")]
    {
        nousb_platform_linux::linux_host_boot_facts(&mut nousb_core::SystemCommandRunner, root)
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        Err(NoUsbError::UnsafeExecution(format!(
            "host boot is supported on Windows and Linux only (staging root {})",
            root.display()
        )))
    }
}

/// True only in builds with the real boot backend for this host OS.
fn real_boot_compiled() -> bool {
    cfg!(any(
        all(target_os = "windows", feature = "real-windows-boot"),
        all(target_os = "linux", feature = "real-linux-boot")
    ))
}

fn host_boot_backend_name() -> &'static str {
    if cfg!(target_os = "windows") {
        "windows-bcdedit-bootsequence"
    } else {
        "linux-efibootmgr-bootnext"
    }
}

fn reboot_hint() -> &'static str {
    if cfg!(target_os = "windows") {
        "use Restart, not Shut down, or run: shutdown /r /t 0"
    } else {
        "systemctl reboot"
    }
}

fn host_boot_plan(
    cwd: &Path,
    profile: &str,
    options: &CliOptions,
) -> Result<HostBootPlan, Box<dyn std::error::Error>> {
    let iso = match &options.iso {
        Some(path) => path.clone(),
        None => artifact_cache_path(cwd, profile)?,
    };
    let facts = read_host_boot_facts(&staging_root(options))?;
    Ok(plan_host_one_shot(
        profile,
        &iso,
        &facts,
        host_boot_backend_name(),
        real_boot_compiled(),
    )?)
}

/// The real backend for this host. Absent unless built with the matching real-boot feature.
fn real_boot_backend() -> Result<Box<dyn HostBootBackend>, Box<dyn std::error::Error>> {
    #[cfg(all(target_os = "windows", feature = "real-windows-boot"))]
    {
        Ok(Box::new(
            nousb_platform_windows::WindowsHostBootBackend::new(nousb_core::SystemCommandRunner),
        ))
    }
    #[cfg(all(target_os = "linux", feature = "real-linux-boot"))]
    {
        Ok(Box::new(nousb_platform_linux::LinuxHostBootBackend::new(
            nousb_core::SystemCommandRunner,
            nousb_platform_linux::mounted_esp(),
        )))
    }
    #[cfg(not(any(
        all(target_os = "windows", feature = "real-windows-boot"),
        all(target_os = "linux", feature = "real-linux-boot")
    )))]
    {
        Err("this nousb build has no real boot backend (safe default build). Build with --features real-windows-boot or real-linux-boot for physical testing; see docs/PHYSICAL_TESTING.md".into())
    }
}

fn parse_plan_kind(value: &str) -> Result<OperationKind, Box<dyn std::error::Error>> {
    match value {
        "boot-once" => Ok(OperationKind::BootOnce),
        "dual-boot" => Ok(OperationKind::DualBoot),
        "replace-os" => Ok(OperationKind::ReplaceOs),
        "reinstall-current-os" => Ok(OperationKind::ReinstallCurrentOs),
        _ => Err(format!("unknown plan kind: {value}").into()),
    }
}

fn inspect_host() -> Result<(SystemInventory, &'static str), NoUsbError> {
    #[cfg(target_os = "windows")]
    {
        let adapter = nousb_platform_windows::WindowsSafeAdapter;
        Ok((adapter.inspect()?, adapter.name()))
    }
    #[cfg(target_os = "linux")]
    {
        let adapter = nousb_platform_linux::LinuxSafeAdapter;
        Ok((adapter.inspect()?, adapter.name()))
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        let adapter = HostPlatform;
        Ok((adapter.inspect()?, adapter.name()))
    }
}

fn fake_adapter(value: &str) -> Result<FakePlatformAdapter, Box<dyn std::error::Error>> {
    match value {
        "windows-bitlocker" => Ok(FakePlatformAdapter::windows_uefi_bitlocker()),
        "linux-luks-low-space" => Ok(FakePlatformAdapter::linux_grub_luks_btrfs_low_space()),
        _ => Err(format!(
            "unknown fake scenario: {value}; expected windows-bitlocker or linux-luks-low-space"
        )
        .into()),
    }
}

fn run_simulation(
    plan: &nousb_core::OperationPlan,
    options: &CliOptions,
) -> Result<nousb_core::ExecutionReport, Box<dyn std::error::Error>> {
    let config = if let Some(step_id) = &options.fail_step {
        SimulationConfig::fail_step(step_id.clone())
    } else if let Some(count) = options.interrupt_after {
        SimulationConfig::interrupt_after(count)
    } else {
        SimulationConfig::complete()
    };
    let report = SimulatedExecutor::new(config).execute(plan)?;
    if options.rollback {
        Ok(rollback_simulated_report(&report))
    } else {
        Ok(report)
    }
}

fn print_execution_report(report: &nousb_core::ExecutionReport, json: bool) {
    if json {
        println!("{}", report.to_json());
    } else {
        println!("{}", report.preview());
    }
}

fn report_summaries_json(reports: &[SavedExecutionReportSummary]) -> String {
    let reports: Vec<String> = reports.iter().map(|report| report.to_json()).collect();
    format!("[{}]", reports.join(","))
}

fn dashboard_export_json(base_dir: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let profiles: Vec<String> = built_in_profiles()
        .iter()
        .map(|profile| profile.to_json())
        .collect();
    let artifact_manifests: Vec<String> = built_in_profiles()
        .iter()
        .filter_map(|profile| artifact_manifest(&profile.id).ok())
        .map(|manifest| manifest.to_json())
        .collect();

    let fake_scenarios = [
        (
            "windows-bitlocker",
            FakePlatformAdapter::windows_uefi_bitlocker(),
        ),
        (
            "linux-luks-low-space",
            FakePlatformAdapter::linux_grub_luks_btrfs_low_space(),
        ),
    ];
    let scenario_json: Vec<String> = fake_scenarios
        .iter()
        .map(|(id, adapter)| {
            let inventory = adapter.inspect()?;
            Ok::<String, nousb_core::NoUsbError>(format!(
                "{{\"id\":\"{}\",\"adapter\":\"{}\",\"inventory\":{}}}",
                id,
                adapter.name(),
                inventory.to_json(adapter.name())
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let linux_inventory = FakePlatformAdapter::linux_grub_luks_btrfs_low_space().inspect()?;
    let sample_plan = plan_operation_for_inventory(
        OperationKind::BootOnce,
        Some("ubuntu-24.04-desktop"),
        &linux_inventory,
    )?;
    let windows_inventory = FakePlatformAdapter::windows_uefi_bitlocker().inspect()?;
    let sample_delivery = assess_delivery(&windows_inventory, "ubuntu-24.04-desktop")?;
    let sample_vm_rehearsal = rehearse_vm_one_shot(
        OneShotBootBackend::WindowsBcdBootSequence,
        "ubuntu-24.04-desktop",
    )?;

    let commands = [
        "cargo run -p nousb -- tui",
        "cargo run -p nousb -- vm doctor",
        "cargo run -p nousb -- vm rehearse windows-bcd-bootsequence ubuntu-24.04-desktop",
        "cargo run -p nousb -- vm qemu plan-smoke",
        "cargo run -p nousb -- vm qemu plan-ubuntu-netboot",
        "cargo run -p nousb -- vm qemu plan-ubuntu-full-ram",
        "cargo run -p nousb -- vm qemu plan-ubuntu-uefi-full-ram",
        "cargo run -p nousb -- vm qemu rehearse-ubuntu-uefi-full-ram \"RUN DISPOSABLE UBUNTU UEFI FULL ISO RAM REHEARSAL\"",
        "cargo run -p nousb -- vm qemu plan-current-os-baseline",
        "cargo run -p nousb -- vm qemu rehearse-current-os-baseline \"RUN DISPOSABLE CURRENT OS UEFI BASELINE\"",
        "cargo run -p nousb -- catalog validate",
        "cargo run -p nousb -- image manifest ubuntu-24.04-desktop",
        "cargo run -p nousb -- workflow assess-fake windows-bitlocker ubuntu-24.04-desktop",
        "cargo run -p nousb -- system inspect-fake windows-bitlocker",
        "cargo run -p nousb -- plan-fake linux-luks-low-space boot-once ubuntu-24.04-desktop",
        "cargo run -p nousb -- --interrupt-after 2 simulate boot-once ubuntu-24.04-desktop",
        "cargo run -p nousb -- reports list",
        "cargo run -p nousb -- diagnostics export",
        "cargo run -p nousb -- dashboard export",
    ];
    let commands: Vec<String> = commands
        .iter()
        .map(|command| format!("\"{}\"", escape_json_for_cli(command)))
        .collect();

    let reports = list_saved_execution_reports(base_dir)?;
    let real_vm_reports = load_qemu_reports_json(base_dir)?;

    Ok(format!(
        "{{\"generated_by\":\"nousb dashboard export\",\"safe_default_build\":true,\"catalog\":[{}],\"artifact_manifests\":[{}],\"fake_scenarios\":[{}],\"sample_plan\":{},\"sample_delivery\":{},\"sample_vm_rehearsal\":{},\"reports\":{},\"real_vm_reports\":[{}],\"commands\":[{}]}}",
        profiles.join(","),
        artifact_manifests.join(","),
        scenario_json.join(","),
        sample_plan.to_json(),
        sample_delivery.to_json(),
        sample_vm_rehearsal.to_json(),
        report_summaries_json(&reports),
        real_vm_reports.join(","),
        commands.join(",")
    ))
}

fn load_qemu_reports_json(base_dir: &Path) -> io::Result<Vec<String>> {
    let root = base_dir.join(".nousb").join("vm").join("qemu");
    if !root.is_dir() {
        return Ok(Vec::new());
    }
    let mut paths = fs::read_dir(root)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path().join("report.json"))
        .filter(|path| path.is_file())
        .collect::<Vec<_>>();
    paths.sort();
    paths
        .into_iter()
        .map(|path| {
            let value = fs::read_to_string(&path)?;
            let trimmed = value.trim();
            if !trimmed.starts_with('{') || !trimmed.ends_with('}') {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("VM report {} is not a JSON object", path.display()),
                ));
            }
            Ok(trimmed.to_string())
        })
        .collect()
}

fn escape_json_for_cli(value: &str) -> String {
    nousb_core::escape_json(value)
}

struct CliOptions {
    json: bool,
    dry_run: bool,
    yes: bool,
    rollback: bool,
    interrupt_after: Option<usize>,
    fail_step: Option<String>,
    iso: Option<PathBuf>,
    staging_root: Option<PathBuf>,
    args: Vec<String>,
}

impl CliOptions {
    fn parse(raw_args: Vec<String>) -> Result<Self, Box<dyn std::error::Error>> {
        let mut json = false;
        let mut dry_run = false;
        let mut yes = false;
        let mut rollback = false;
        let mut interrupt_after = None;
        let mut fail_step = None;
        let mut iso = None;
        let mut staging_root = None;
        let mut args = Vec::new();
        let mut index = 0usize;

        while index < raw_args.len() {
            let arg = &raw_args[index];
            match arg.as_str() {
                "--json" => json = true,
                "--dry-run" => dry_run = true,
                "--yes" | "-y" => yes = true,
                "--rollback" => rollback = true,
                "--interrupt-after" => {
                    index += 1;
                    let Some(value) = raw_args.get(index) else {
                        return Err("--interrupt-after requires a count".into());
                    };
                    interrupt_after = Some(value.parse()?);
                }
                "--fail-step" => {
                    index += 1;
                    let Some(value) = raw_args.get(index) else {
                        return Err("--fail-step requires a step id".into());
                    };
                    fail_step = Some(value.clone());
                }
                "--iso" | "--staging-root" => {
                    index += 1;
                    let Some(value) = raw_args.get(index) else {
                        return Err(format!("{arg} requires a path").into());
                    };
                    if arg == "--iso" {
                        iso = Some(PathBuf::from(value));
                    } else {
                        staging_root = Some(PathBuf::from(value));
                    }
                }
                "--" => {}
                value if value.starts_with('-') => {
                    return Err(format!("unknown option: {value}").into());
                }
                _ => args.push(arg.clone()),
            }
            index += 1;
        }

        Ok(Self {
            json,
            dry_run,
            yes,
            rollback,
            interrupt_after,
            fail_step,
            iso,
            staging_root,
            args,
        })
    }
}

fn print_vm_doctor(cwd: &Path, json: bool) {
    let qemu = command_version("qemu-system-x86_64", &["--version"]);
    let project_local_qemu_artifact = qemu_runtime_cache_path(cwd)
        .ok()
        .filter(|path| path.is_file());
    let project_local_runtime = nousb_platform_windows::windows_qemu_smoke_plan(cwd).ok();
    let real_vm_evidence = latest_qemu_report(cwd);
    let runtime_access_verified = real_vm_evidence.is_some();
    let disposable_vm_execution_enabled = project_local_runtime.is_some();
    let virtualbox = command_version("VBoxManage", &["--version"]);
    #[cfg(target_os = "windows")]
    let hyper_v_components_present = Path::new("C:\\Windows\\System32\\vmcompute.exe").exists()
        && Path::new("C:\\Windows\\System32\\vmconnect.exe").exists();
    #[cfg(not(target_os = "windows"))]
    let hyper_v_components_present = false;
    if json {
        println!(
            "{{\"qemu\":{},\"project_local_qemu_artifact\":{},\"project_local_qemu_runtime\":{},\"real_vm_evidence\":{},\"virtualbox\":{},\"hyper_v_components_present\":{},\"runtime_access_verified\":{},\"disposable_vm_execution_enabled\":{},\"real_boot_execution_enabled\":false,\"host_boot_changes\":false}}",
            qemu.as_deref()
                .map(|value| format!("\"{}\"", escape_json_for_cli(value)))
                .unwrap_or_else(|| "null".into()),
            project_local_qemu_artifact
                .as_ref()
                .map(|path| format!("\"{}\"", escape_json_for_cli(&path.display().to_string())))
                .unwrap_or_else(|| "null".into()),
            project_local_runtime
                .as_ref()
                .map(|plan| format!("\"{}\"", escape_json_for_cli(&plan.runtime_version)))
                .unwrap_or_else(|| "null".into()),
            real_vm_evidence
                .as_ref()
                .map(|path| format!("\"{}\"", escape_json_for_cli(&path.display().to_string())))
                .unwrap_or_else(|| "null".into()),
            virtualbox
                .as_deref()
                .map(|value| format!("\"{}\"", escape_json_for_cli(value)))
                .unwrap_or_else(|| "null".into()),
            hyper_v_components_present,
            runtime_access_verified,
            disposable_vm_execution_enabled,
        );
    } else {
        println!("NoUSB VM doctor");
        println!("QEMU: {}", qemu.as_deref().unwrap_or("not found"));
        println!(
            "Project-local QEMU artifact: {}",
            project_local_qemu_artifact
                .as_ref()
                .map(|path| path.display().to_string())
                .as_deref()
                .unwrap_or("not acquired")
        );
        println!(
            "Project-local QEMU runtime: {}",
            project_local_runtime
                .as_ref()
                .map(|plan| plan.runtime_version.as_str())
                .unwrap_or("not prepared")
        );
        if project_local_runtime.is_none() && cfg!(target_os = "windows") {
            println!(
                "Prepare it with: nousb vm qemu plan-runtime, then nousb vm qemu bootstrap-runtime \"ASSEMBLE PROJECT-LOCAL QEMU RUNTIME\""
            );
        }
        println!(
            "Latest real-VM evidence: {}",
            real_vm_evidence
                .as_ref()
                .map(|path| path.display().to_string())
                .as_deref()
                .unwrap_or("none")
        );
        println!(
            "VirtualBox: {}",
            virtualbox.as_deref().unwrap_or("not found")
        );
        println!(
            "Hyper-V components present: {} (current-process VM access not verified)",
            hyper_v_components_present
        );
        println!("Runtime access verified: {runtime_access_verified}");
        println!("Disposable VM execution enabled: {disposable_vm_execution_enabled}");
        println!("Real host boot execution enabled: false");
        println!("Host boot changes: false");
    }
}

fn latest_qemu_report(cwd: &Path) -> Option<PathBuf> {
    let root = cwd.join(".nousb").join("vm").join("qemu");
    fs::read_dir(root)
        .ok()?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path().join("report.json"))
        .filter(|path| path.is_file())
        .max_by_key(|path| fs::metadata(path).and_then(|item| item.modified()).ok())
}

fn command_version(command: &str, arguments: &[&str]) -> Option<String> {
    let output = Command::new(command).args(arguments).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    stdout
        .lines()
        .chain(stderr.lines())
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(str::to_string)
}

fn print_help() {
    println!("NoUSB OS Switcher");
    println!();
    println!("Commands:");
    println!("  nousb tui");
    println!("  nousb system inspect");
    println!("  nousb system inspect-fake <scenario>");
    println!("  nousb catalog list");
    println!("  nousb catalog validate");
    println!("  nousb workflow assess <profile>");
    println!("  nousb workflow assess-fake <scenario> <profile>");
    println!("  nousb image manifest <profile>");
    println!("  nousb image probe <profile>");
    println!("  nousb image verify-signature <profile>");
    println!("  nousb image download <profile>");
    println!("  nousb image verify-profile <profile> <path>");
    println!("  nousb image verify <path> <sha256>");
    println!("  nousb staging inspect <profile> <path>");
    println!("  nousb staging create <profile> <path>");
    println!("  nousb vm doctor");
    println!("  nousb vm qemu manifest");
    println!("  nousb vm qemu acquire");
    println!("  nousb vm qemu plan-runtime");
    println!("  nousb vm qemu bootstrap-runtime \"ASSEMBLE PROJECT-LOCAL QEMU RUNTIME\"");
    println!("  nousb vm qemu plan-smoke");
    println!("  nousb vm qemu smoke \"RUN DISPOSABLE QEMU UEFI SMOKE\"");
    println!("  nousb vm qemu plan-ubuntu-netboot");
    println!(
        "  nousb vm qemu rehearse-ubuntu-netboot \"RUN DISPOSABLE UBUNTU NETBOOT RAM REHEARSAL\""
    );
    println!("  nousb vm qemu plan-ubuntu-full-ram");
    println!(
        "  nousb vm qemu rehearse-ubuntu-full-ram \"RUN DISPOSABLE UBUNTU FULL ISO RAM REHEARSAL\""
    );
    println!("  nousb vm qemu plan-ubuntu-uefi-full-ram");
    println!(
        "  nousb vm qemu rehearse-ubuntu-uefi-full-ram \"RUN DISPOSABLE UBUNTU UEFI FULL ISO RAM REHEARSAL\""
    );
    println!("  nousb vm qemu plan-current-os-baseline");
    println!(
        "  nousb vm qemu rehearse-current-os-baseline \"RUN DISPOSABLE CURRENT OS UEFI BASELINE\""
    );
    println!("  nousb vm qemu plan-secure-boot");
    println!("  nousb vm qemu rehearse-secure-boot \"RUN DISPOSABLE SECURE BOOT REHEARSAL\"");
    println!("  nousb vm qemu plan-current-os-one-shot [uefi-bootnext|linux-grub-reboot] [forced-failure|full-ram-installer]");
    println!(
        "  nousb vm qemu rehearse-current-os-one-shot \"RUN DISPOSABLE CURRENT OS UEFI ONE-SHOT MATRIX\" [backend] [installer-mode] [scenario]"
    );
    println!("  nousb vm rehearse <backend> <profile>");
    println!("  nousb plan boot-once <profile>");
    println!("  nousb plan dual-boot <profile>");
    println!("  nousb plan replace-os <profile>");
    println!("  nousb plan reinstall-current-os <profile>");
    println!("  nousb plan-fake <scenario> <plan-kind> <profile>");
    println!("  nousb simulate <plan-kind> <profile>");
    println!("  nousb simulate-fake <scenario> <plan-kind> <profile>");
    println!("  nousb reports list");
    println!("  nousb reports show <plan-id>");
    println!("  nousb reports recover <plan-id>");
    println!("  nousb resume <plan-id>");
    println!("  nousb diagnostics export");
    println!("  nousb dashboard export");
    println!("  nousb boot plan <profile> [--iso <path>] [--staging-root <volume-root>]");
    println!(
        "  nousb boot arm <profile> \"BOOT ONCE INTO <profile>\"  (real-boot build, elevated)"
    );
    println!("  nousb boot status");
    println!("  nousb boot cleanup \"{CLEANUP_CONFIRMATION_PHRASE}\"");
    println!("  nousb execute <plan-kind> <profile>");
    println!("  nousb rollback <operation-id>");
    println!("  nousb recovery-pack create");
    println!("  nousb logs export");
    println!("  nousb journal migrate");
    println!("  nousb doctor");
    println!();
    println!("Options:");
    println!("  --json       Print machine-readable JSON where supported");
    println!("  --dry-run    Mark plan output as a dry run");
    println!("  --yes        Only allowed for low-risk actions; never bypasses typed confirmation");
    println!("  --interrupt-after <count>");
    println!("  --fail-step <step-id>");
    println!("  --rollback   Roll back the simulated report");
    println!("  --iso <path>             ISO for boot plan/arm (default: .nousb/artifacts/...)");
    println!("  --staging-root <root>    Unencrypted volume root for the ISO copy (C:\\ or /)");
    println!();
    println!("Fake scenarios:");
    println!("  windows-bitlocker");
    println!("  linux-luks-low-space");
}
