// Hide the console window in release builds on Windows.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Tauri command bridge. In the default build every command is read-only or simulation-only:
//! nothing can change boot configuration, partitions, encryption, or firmware. The opt-in
//! `real-boot` feature adds the host one-shot backend behind the same typed phrases as the CLI.
//! Commands return the same JSON the CLI prints with `--json`, so the UI and CLI never diverge.

use std::path::PathBuf;

use nousb_core::{
    assess_delivery, assess_recovery, built_in_profiles, list_saved_execution_reports,
    load_execution_report, plan_operation, resume_simulated_report, rollback_simulated_report,
    save_execution_report, verify_profile_signature, write_journal_entry, NoUsbError,
    OperationExecutor, OperationKind, PlatformAdapter, RecoveryAction, SimulatedExecutor,
    SimulationConfig, SystemInventory,
};

type CommandResult = Result<String, String>;

/// The project directory whose `.nousb/` holds journals, reports, and VM evidence.
fn project_dir() -> Result<PathBuf, String> {
    match std::env::var_os("NOUSB_PROJECT_DIR") {
        Some(dir) => Ok(PathBuf::from(dir)),
        None => std::env::current_dir().map_err(|error| error.to_string()),
    }
}

fn error_text(error: NoUsbError) -> String {
    error.to_string()
}

fn host_inventory() -> Result<(SystemInventory, &'static str), NoUsbError> {
    #[cfg(target_os = "windows")]
    let adapter = nousb_platform_windows::WindowsSafeAdapter;
    #[cfg(target_os = "linux")]
    let adapter = nousb_platform_linux::LinuxSafeAdapter;
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    let adapter = nousb_core::HostPlatform;
    Ok((adapter.inspect()?, adapter.name()))
}

fn plan_kind(value: &str) -> Result<OperationKind, String> {
    match value {
        "boot-once" => Ok(OperationKind::BootOnce),
        "dual-boot" => Ok(OperationKind::DualBoot),
        "replace-os" => Ok(OperationKind::ReplaceOs),
        "reinstall-current-os" => Ok(OperationKind::ReinstallCurrentOs),
        other => Err(format!("unknown plan kind: {other}")),
    }
}

/// Runs blocking work (host inspection, HTTPS) off the UI thread.
async fn blocking<F>(work: F) -> CommandResult
where
    F: FnOnce() -> CommandResult + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(work)
        .await
        .map_err(|error| error.to_string())?
}

#[tauri::command]
async fn inventory() -> CommandResult {
    blocking(|| {
        let (inventory, adapter) = host_inventory().map_err(error_text)?;
        Ok(inventory.to_json(adapter))
    })
    .await
}

#[tauri::command]
fn catalog() -> CommandResult {
    let profiles: Vec<String> = built_in_profiles()
        .iter()
        .map(|profile| profile.to_json())
        .collect();
    Ok(format!("[{}]", profiles.join(",")))
}

#[tauri::command]
async fn delivery(profile: String) -> CommandResult {
    blocking(move || {
        let (inventory, _) = host_inventory().map_err(error_text)?;
        assess_delivery(&inventory, &profile)
            .map(|assessment| assessment.to_json())
            .map_err(error_text)
    })
    .await
}

#[tauri::command]
fn plan_preview(kind: String, profile: String) -> CommandResult {
    plan_operation(plan_kind(&kind)?, Some(&profile))
        .map(|plan| plan.to_json())
        .map_err(error_text)
}

/// Simulates a plan (optionally interrupted) and saves the report like `nousb simulate`.
#[tauri::command]
fn simulate(kind: String, profile: String, interrupt_after: Option<usize>) -> CommandResult {
    let dir = project_dir()?;
    let plan = plan_operation(plan_kind(&kind)?, Some(&profile)).map_err(error_text)?;
    let config = match interrupt_after {
        Some(steps) => SimulationConfig::interrupt_after(steps),
        None => SimulationConfig::complete(),
    };
    let report = SimulatedExecutor::new(config)
        .execute(&plan)
        .map_err(error_text)?;
    save_execution_report(&dir, &report).map_err(error_text)?;
    Ok(report.to_json())
}

/// Saved reports, each with its recovery recommendation.
#[tauri::command]
fn reports() -> CommandResult {
    let dir = project_dir()?;
    let mut rows = Vec::new();
    for summary in list_saved_execution_reports(&dir).map_err(error_text)? {
        let recovery = load_execution_report(&dir, &summary.plan_id)
            .map(|report| assess_recovery(&report).to_json())
            .unwrap_or_else(|_| "null".into());
        rows.push(format!(
            "{{\"summary\":{},\"recovery\":{recovery}}}",
            summary.to_json()
        ));
    }
    Ok(format!("[{}]", rows.join(",")))
}

/// Resumes or rolls back a saved simulation, refusing whatever the assessment does not allow.
#[tauri::command]
fn recover(plan_id: String, action: String) -> CommandResult {
    let dir = project_dir()?;
    let report = load_execution_report(&dir, &plan_id).map_err(error_text)?;
    let assessment = assess_recovery(&report);
    let updated = match action.as_str() {
        "resume" => resume_simulated_report(&report).map_err(error_text)?,
        "rollback"
            if matches!(
                assessment.recommended,
                RecoveryAction::Rollback | RecoveryAction::Resume
            ) =>
        {
            rollback_simulated_report(&report)
        }
        "rollback" => {
            return Err(format!(
                "{plan_id} needs no automatic rollback (recommended: {})",
                assessment.recommended.as_str()
            ))
        }
        other => return Err(format!("unknown recovery action: {other}")),
    };
    save_execution_report(&dir, &updated).map_err(error_text)?;
    write_journal_entry(
        &dir,
        &format!("desktop {action} of simulated operation {plan_id}"),
    )
    .map_err(error_text)?;
    Ok(updated.to_json())
}

#[tauri::command]
async fn verify_signature(profile: String) -> CommandResult {
    blocking(move || {
        verify_profile_signature(&profile)
            .map(|verification| verification.to_json())
            .map_err(error_text)
    })
    .await
}

/// Saved disposable-VM reports (`.nousb/vm/qemu/*/report.json`), newest first, verbatim.
#[tauri::command]
fn vm_evidence() -> CommandResult {
    let root = project_dir()?.join(".nousb").join("vm").join("qemu");
    let Ok(entries) = std::fs::read_dir(&root) else {
        return Ok("[]".into());
    };
    let mut reports: Vec<(std::time::SystemTime, String, String)> = entries
        .flatten()
        .filter_map(|entry| {
            let path = entry.path().join("report.json");
            let modified = std::fs::metadata(&path)
                .and_then(|meta| meta.modified())
                .ok()?;
            let json = std::fs::read_to_string(&path).ok()?;
            let run = entry.file_name().to_string_lossy().into_owned();
            Some((modified, run, json))
        })
        .collect();
    reports.sort_by_key(|(modified, _, _)| std::cmp::Reverse(*modified));
    let rows: Vec<String> = reports
        .into_iter()
        .take(20)
        .map(|(_, run, json)| {
            format!(
                "{{\"run\":\"{}\",\"report\":{json}}}",
                nousb_core::escape_json(&run)
            )
        })
        .collect();
    Ok(format!("[{}]", rows.join(",")))
}

fn host_boot_facts(staging_root: &std::path::Path) -> Result<nousb_core::HostBootFacts, String> {
    #[cfg(target_os = "windows")]
    {
        nousb_platform_windows::windows_host_boot_facts(staging_root).map_err(error_text)
    }
    #[cfg(target_os = "linux")]
    {
        nousb_platform_linux::linux_host_boot_facts(
            &mut nousb_core::SystemCommandRunner,
            staging_root,
        )
        .map_err(error_text)
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        Err(format!(
            "host boot is Windows/Linux only (staging root {})",
            staging_root.display()
        ))
    }
}

fn default_staging_root() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        nousb_platform_windows::default_windows_staging_root()
    }
    #[cfg(not(target_os = "windows"))]
    {
        nousb_platform_linux::default_linux_staging_root()
    }
}

/// True only when this desktop build carries the real boot backend for this OS.
fn real_boot_compiled() -> bool {
    cfg!(all(
        feature = "real-boot",
        any(target_os = "windows", target_os = "linux")
    ))
}

fn build_host_boot_plan(
    profile: &str,
    staging_root: Option<String>,
) -> Result<nousb_core::HostBootPlan, String> {
    let dir = project_dir()?;
    let iso = nousb_core::artifact_cache_path(&dir, profile).map_err(error_text)?;
    let root = staging_root
        .map(PathBuf::from)
        .unwrap_or_else(default_staging_root);
    let facts = host_boot_facts(&root)?;
    let backend = if cfg!(target_os = "windows") {
        "windows-bcdedit-bootsequence"
    } else {
        "linux-efibootmgr-bootnext"
    };
    nousb_core::plan_host_one_shot(profile, &iso, &facts, backend, real_boot_compiled())
        .map_err(error_text)
}

/// Read-only: what arming would do on this host, with every blocker spelled out.
#[tauri::command]
async fn host_boot_plan(profile: String, staging_root: Option<String>) -> CommandResult {
    blocking(move || build_host_boot_plan(&profile, staging_root).map(|plan| plan.to_json())).await
}

/// Read-only: the recorded host boot transaction, or `null`.
#[tauri::command]
fn host_boot_status() -> CommandResult {
    let dir = project_dir()?;
    Ok(nousb_core::load_host_boot_state(&dir)
        .map_err(error_text)?
        .map(|state| state.to_json())
        .unwrap_or_else(|| "null".into()))
}

#[cfg(feature = "real-boot")]
fn real_backend() -> Result<Box<dyn nousb_core::HostBootBackend>, String> {
    #[cfg(target_os = "windows")]
    {
        Ok(Box::new(
            nousb_platform_windows::WindowsHostBootBackend::new(nousb_core::SystemCommandRunner),
        ))
    }
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(nousb_platform_linux::LinuxHostBootBackend::new(
            nousb_core::SystemCommandRunner,
            nousb_platform_linux::mounted_esp(),
        )))
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        Err("host boot is Windows/Linux only".into())
    }
}

#[cfg(not(feature = "real-boot"))]
fn real_backend() -> Result<Box<dyn nousb_core::HostBootBackend>, String> {
    Err("this desktop build has no real boot backend (safe default build); see docs/PHYSICAL_TESTING.md".into())
}

/// Arms the one-shot boot. Needs the `real-boot` build, an elevated app, and the exact phrase.
#[tauri::command]
async fn host_boot_arm(
    profile: String,
    staging_root: Option<String>,
    confirmation: String,
) -> CommandResult {
    blocking(move || {
        let dir = project_dir()?;
        let plan = build_host_boot_plan(&profile, staging_root)?;
        let mut backend = real_backend()?;
        nousb_core::arm_host_one_shot(&dir, &plan, backend.as_mut(), &confirmation)
            .map(|state| state.to_json())
            .map_err(error_text)
    })
    .await
}

#[tauri::command]
async fn host_boot_cleanup(confirmation: String) -> CommandResult {
    blocking(move || {
        let dir = project_dir()?;
        let mut backend = real_backend()?;
        nousb_core::cleanup_host_one_shot(&dir, backend.as_mut(), &confirmation)
            .map(|state| state.to_json())
            .map_err(error_text)
    })
    .await
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            inventory,
            catalog,
            delivery,
            plan_preview,
            simulate,
            reports,
            recover,
            verify_signature,
            vm_evidence,
            host_boot_plan,
            host_boot_status,
            host_boot_arm,
            host_boot_cleanup,
        ])
        .run(tauri::generate_context!())
        .unwrap_or_else(|error| {
            eprintln!("NoUSB desktop failed to start: {error}");
            std::process::exit(1);
        });
}
