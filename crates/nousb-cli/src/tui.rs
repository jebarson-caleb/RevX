use nousb_core::{
    artifact_cache_path, artifact_manifest, assess_delivery, built_in_profiles,
    create_staging_bundle, download_artifact, inspect_staging_artifact,
    plan_operation_for_inventory, probe_artifact, rehearse_vm_one_shot, save_vm_rehearsal,
    InstallerProfile, NoUsbError, OneShotBootBackend, OperationKind, SystemInventory,
};
use std::fs;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

pub fn run<R: BufRead, W: Write>(
    base_dir: &Path,
    inventory: &SystemInventory,
    adapter_name: &str,
    input: &mut R,
    output: &mut W,
) -> Result<(), NoUsbError> {
    let profiles = built_in_profiles()
        .into_iter()
        .filter(|profile| {
            profile
                .supported_platforms
                .iter()
                .any(|platform| platform.starts_with("windows") || platform.starts_with("linux"))
        })
        .collect::<Vec<_>>();
    let mut selected = profiles
        .iter()
        .position(|profile| profile.id == "ubuntu-24.04-desktop")
        .unwrap_or_default();

    writeln!(output, "NoUSB guided terminal application")?;
    writeln!(
        output,
        "Safe boundary: inspect, assess, acquire, verify, and stage only."
    )?;
    writeln!(
        output,
        "This build cannot install an OS or modify boot entries, disks, partitions, or firmware."
    )?;

    loop {
        let profile = profiles.get(selected).ok_or_else(|| {
            NoUsbError::InvalidInput("no Windows/Linux installer profiles are available".into())
        })?;
        render_menu(output, inventory, adapter_name, profile, base_dir)?;
        let choice = read_prompt(input, output, "Choose an action [1-9,v,r]: ")?;
        let result = match choice.as_str() {
            "1" => show_system(output, inventory, adapter_name),
            "2" => {
                if let Some(index) = choose_profile(input, output, &profiles)? {
                    selected = index;
                }
                Ok(())
            }
            "3" => show_assessment(output, inventory, &profile.id),
            "4" => show_manifest(output, &profile.id, base_dir),
            "5" => probe_manifest(output, &profile.id),
            "6" => download_with_confirmation(input, output, base_dir, &profile.id),
            "7" => stage_with_confirmation(input, output, base_dir, &profile.id),
            "8" => show_plan(output, inventory, &profile.id),
            "v" | "V" => show_vm_rehearsal(output, base_dir, inventory, &profile.id),
            "r" | "R" => show_real_vm_evidence(output, base_dir),
            "9" | "q" | "quit" => {
                writeln!(output, "Exited without changing boot or disk state.")?;
                break;
            }
            _ => {
                writeln!(
                    output,
                    "Unknown action. Enter a number from 1 to 9, v, or r."
                )?;
                Ok(())
            }
        };
        if let Err(error) = result {
            writeln!(output, "Action stopped safely: {error}")?;
        }
    }
    Ok(())
}

fn render_menu<W: Write>(
    output: &mut W,
    inventory: &SystemInventory,
    adapter_name: &str,
    profile: &InstallerProfile,
    base_dir: &Path,
) -> Result<(), NoUsbError> {
    let cached = artifact_cache_path(base_dir, &profile.id)
        .map(|path| path.exists())
        .unwrap_or(false);
    writeln!(output)?;
    writeln!(
        output,
        "------------------------------------------------------------"
    )?;
    writeln!(
        output,
        "Host: {} {} via {} | Profile: {} | Cached: {}",
        inventory.os_name, inventory.arch, adapter_name, profile.id, cached
    )?;
    writeln!(output, "1  System summary")?;
    writeln!(output, "2  Choose installer profile")?;
    writeln!(output, "3  Assess no-USB delivery routes")?;
    writeln!(output, "4  Show pinned artifact manifest")?;
    writeln!(output, "5  Probe official artifact (network, no download)")?;
    writeln!(output, "6  Download and verify official artifact")?;
    writeln!(
        output,
        "7  Inspect and create non-executable staging bundle"
    )?;
    writeln!(output, "8  Preview one-time boot plan (no execution)")?;
    writeln!(
        output,
        "v  Rehearse one-shot boot and fallback (simulation)"
    )?;
    writeln!(
        output,
        "r  Show disposable real-VM plans and saved evidence"
    )?;
    writeln!(output, "9  Exit")?;
    Ok(())
}

fn show_system<W: Write>(
    output: &mut W,
    inventory: &SystemInventory,
    adapter_name: &str,
) -> Result<(), NoUsbError> {
    writeln!(output, "Adapter: {adapter_name}")?;
    writeln!(
        output,
        "OS/architecture: {} {}",
        inventory.os_name, inventory.arch
    )?;
    writeln!(output, "Memory: {:?} MiB", inventory.memory_total_mb)?;
    writeln!(output, "Firmware: {:?}", inventory.firmware)?;
    writeln!(output, "Secure Boot: {:?}", inventory.secure_boot)?;
    writeln!(output, "Encryption: {:?}", inventory.encryption)?;
    writeln!(
        output,
        "Available staging space: {:?} GiB",
        inventory.disk_inventory.available_space_gb
    )?;
    for warning in &inventory.warnings {
        writeln!(output, "Warning: {warning}")?;
    }
    Ok(())
}

fn choose_profile<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    profiles: &[InstallerProfile],
) -> Result<Option<usize>, NoUsbError> {
    writeln!(output, "Windows/Linux installer profiles:")?;
    for (index, profile) in profiles.iter().enumerate() {
        let availability = if artifact_manifest(&profile.id).is_ok() {
            "pinned download"
        } else {
            "vendor-mediated"
        };
        writeln!(
            output,
            "{}  {} {} ({availability})",
            index + 1,
            profile.name,
            profile.version
        )?;
    }
    let value = read_prompt(input, output, "Profile number (blank cancels): ")?;
    if value.is_empty() {
        return Ok(None);
    }
    let index = match value.parse::<usize>() {
        Ok(value) if value > 0 && value <= profiles.len() => value - 1,
        _ => {
            writeln!(
                output,
                "Invalid profile selection; current profile was kept."
            )?;
            return Ok(None);
        }
    };
    writeln!(output, "Selected {}.", profiles[index].id)?;
    Ok(Some(index))
}

fn show_assessment<W: Write>(
    output: &mut W,
    inventory: &SystemInventory,
    profile_id: &str,
) -> Result<(), NoUsbError> {
    let assessment = assess_delivery(inventory, profile_id)?;
    writeln!(output, "{}", assessment.preview())?;
    writeln!(
        output,
        "Universal no-USB guarantee: {} | execution enabled: {}",
        assessment.universal_no_usb_guarantee, assessment.safe_default_execution_enabled
    )?;
    Ok(())
}

fn show_manifest<W: Write>(
    output: &mut W,
    profile_id: &str,
    base_dir: &Path,
) -> Result<(), NoUsbError> {
    let manifest = artifact_manifest(profile_id)?;
    let cache_path = artifact_cache_path(base_dir, profile_id)?;
    writeln!(output, "Official URL: {}", manifest.source_url)?;
    writeln!(output, "Filename: {}", manifest.filename)?;
    writeln!(output, "Size: {}", format_bytes(manifest.size_bytes))?;
    writeln!(output, "SHA-256: {}", manifest.sha256)?;
    writeln!(output, "Cache path: {}", cache_path.display())?;
    Ok(())
}

fn probe_manifest<W: Write>(output: &mut W, profile_id: &str) -> Result<(), NoUsbError> {
    writeln!(output, "Contacting the official HTTPS source...")?;
    output.flush()?;
    let probe = probe_artifact(profile_id)?;
    writeln!(output, "Final HTTPS URL: {}", probe.final_url)?;
    writeln!(output, "Content length: {:?}", probe.content_length)?;
    writeln!(output, "Range resume supported: {}", probe.accepts_ranges)?;
    Ok(())
}

fn download_with_confirmation<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    base_dir: &Path,
    profile_id: &str,
) -> Result<(), NoUsbError> {
    let manifest = artifact_manifest(profile_id)?;
    writeln!(
        output,
        "This will download {} into the project-local artifact cache.",
        format_bytes(manifest.size_bytes)
    )?;
    let phrase = format!("DOWNLOAD {profile_id}");
    let confirmation = read_prompt(input, output, &format!("Type '{phrase}' to continue: "))?;
    if confirmation != phrase {
        writeln!(output, "Download cancelled; no artifact data was changed.")?;
        return Ok(());
    }
    let download = download_artifact(base_dir, profile_id)?;
    writeln!(output, "Verified artifact: {}", download.path.display())?;
    writeln!(
        output,
        "Downloaded this run: {}",
        format_bytes(download.downloaded_bytes)
    )?;
    Ok(())
}

fn stage_with_confirmation<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    base_dir: &Path,
    profile_id: &str,
) -> Result<(), NoUsbError> {
    let default_path = artifact_cache_path(base_dir, profile_id)?;
    writeln!(
        output,
        "Default verified artifact: {}",
        default_path.display()
    )?;
    let entered = read_prompt(
        input,
        output,
        "ISO path (blank uses the default cache path): ",
    )?;
    let artifact_path = if entered.is_empty() {
        default_path
    } else {
        PathBuf::from(entered)
    };
    let preview = inspect_staging_artifact(profile_id, &artifact_path)?;
    writeln!(output, "Verified declared assets:")?;
    for asset in &preview.assets {
        writeln!(
            output,
            "- {} ({})",
            asset.source_path,
            format_bytes(asset.size_bytes)
        )?;
    }
    let phrase = format!("STAGE {profile_id}");
    let confirmation = read_prompt(
        input,
        output,
        &format!("Type '{phrase}' to create the non-executable bundle: "),
    )?;
    if confirmation != phrase {
        writeln!(
            output,
            "Staging cancelled; boot and disk state were unchanged."
        )?;
        return Ok(());
    }
    let bundle = create_staging_bundle(base_dir, profile_id, &artifact_path)?;
    writeln!(output, "Bundle created: {}", bundle.path.display())?;
    writeln!(output, "Execution enabled: {}", bundle.execution_enabled)?;
    Ok(())
}

fn show_plan<W: Write>(
    output: &mut W,
    inventory: &SystemInventory,
    profile_id: &str,
) -> Result<(), NoUsbError> {
    let plan = plan_operation_for_inventory(OperationKind::BootOnce, Some(profile_id), inventory)?;
    writeln!(output, "{}", plan.preview())?;
    writeln!(output, "Preview only: no executor was invoked.")?;
    Ok(())
}

fn show_vm_rehearsal<W: Write>(
    output: &mut W,
    base_dir: &Path,
    inventory: &SystemInventory,
    profile_id: &str,
) -> Result<(), NoUsbError> {
    let backend = if inventory.os_name == "windows" {
        OneShotBootBackend::WindowsBcdBootSequence
    } else if inventory
        .boot_entries
        .iter()
        .any(|entry| entry.label.to_ascii_lowercase().contains("grub"))
    {
        OneShotBootBackend::LinuxGrubReboot
    } else {
        OneShotBootBackend::LinuxSystemdBootOneShot
    };
    let report = rehearse_vm_one_shot(backend, profile_id)?;
    let path = save_vm_rehearsal(base_dir, &report)?;
    writeln!(output, "{}", report.preview())?;
    writeln!(output, "Saved rehearsal: {}", path.display())?;
    writeln!(
        output,
        "This was a state-machine rehearsal; no VM or host boot state was changed."
    )?;
    Ok(())
}

fn show_real_vm_evidence<W: Write>(output: &mut W, base_dir: &Path) -> Result<(), NoUsbError> {
    let smoke = nousb_platform_windows::windows_qemu_smoke_plan(base_dir)?;
    writeln!(output, "{}", smoke.preview())?;
    match nousb_platform_windows::windows_qemu_netboot_plan(base_dir) {
        Ok(netboot) => writeln!(output, "{}", netboot.preview())?,
        Err(error) => writeln!(output, "Ubuntu netboot plan unavailable: {error}")?,
    }
    match nousb_platform_windows::windows_qemu_full_ram_plan(base_dir) {
        Ok(full_ram) => writeln!(output, "{}", full_ram.preview())?,
        Err(error) => writeln!(output, "Ubuntu full-ISO RAM plan unavailable: {error}")?,
    }
    match nousb_platform_windows::windows_qemu_uefi_full_ram_plan(base_dir) {
        Ok(uefi_full_ram) => writeln!(output, "{}", uefi_full_ram.preview())?,
        Err(error) => writeln!(output, "Ubuntu UEFI full-RAM plan unavailable: {error}")?,
    }
    match nousb_platform_windows::windows_qemu_current_os_plan(base_dir) {
        Ok(current_os) => writeln!(output, "{}", current_os.preview())?,
        Err(error) => writeln!(output, "Disposable current-OS plan unavailable: {error}")?,
    }
    match nousb_platform_windows::windows_qemu_one_shot_plan(
        base_dir,
        nousb_core::OneShotBootBackend::UefiBootNext,
        nousb_platform_windows::OneShotInstallerMode::ForcedFailure,
    ) {
        Ok(one_shot) => writeln!(output, "{}", one_shot.preview())?,
        Err(error) => writeln!(
            output,
            "Disposable one-shot matrix plan unavailable: {error}"
        )?,
    }

    let evidence_root = base_dir.join(".nousb").join("vm").join("qemu");
    if !evidence_root.is_dir() {
        writeln!(output, "No disposable real-VM evidence has been saved yet.")?;
        return Ok(());
    }
    let mut reports = fs::read_dir(&evidence_root)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path().join("report.json"))
        .filter(|path| path.is_file())
        .collect::<Vec<_>>();
    reports.sort();
    writeln!(
        output,
        "Saved disposable real-VM reports: {}",
        reports.len()
    )?;
    for path in reports.iter().rev().take(5) {
        let evidence = fs::read_to_string(path).map_err(|error| {
            NoUsbError::Io(format!(
                "cannot read VM evidence {}: {error}",
                path.display()
            ))
        })?;
        let summary = if evidence.contains("\"first_boot_observed\":true")
            && evidence.contains("\"second_boot_observed\":true")
        {
            "disposable current-OS UEFI baseline (same disk/variables; installer fallback and BootNext false)"
        } else if evidence.contains("\"full_installer_payload_in_ram\":true")
            && evidence.contains("\"uefi_firmware_initialized\":true")
        {
            "UEFI + full installer RAM evidence (boot/HTTP sources detached; Secure Boot, guest HTTPS, and fallback false)"
        } else if evidence.contains("\"full_installer_payload_in_ram\":true") {
            "full installer RAM evidence (direct-kernel; guest HTTP; UEFI/fallback false)"
        } else if evidence.contains("\"kernel_initrd_ram_resident\":true") {
            "kernel+initrd RAM evidence (full payload false)"
        } else if evidence.contains("\"uefi_firmware_initialized\":true") {
            "UEFI firmware smoke evidence"
        } else {
            "unclassified VM evidence"
        };
        writeln!(output, "- {summary}: {}", path.display())?;
    }
    writeln!(
        output,
        "Evidence display is read-only; use the separate typed CLI commands to start a disposable VM."
    )?;
    Ok(())
}

fn read_prompt<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    prompt: &str,
) -> Result<String, NoUsbError> {
    write!(output, "{prompt}")?;
    output.flush()?;
    let mut value = String::new();
    if input.read_line(&mut value)? == 0 {
        return Ok("9".into());
    }
    Ok(value.trim().to_string())
}

fn format_bytes(value: u64) -> String {
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
    if value >= 1024 * 1024 * 1024 {
        format!("{:.2} GiB ({value} bytes)", value as f64 / GIB)
    } else {
        format!("{value} bytes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nousb_core::{FakePlatformAdapter, PlatformAdapter};
    use std::io::Cursor;

    #[test]
    fn guided_tui_exposes_safe_assessment_manifest_and_plan() {
        let inventory = FakePlatformAdapter::windows_uefi_bitlocker()
            .inspect()
            .unwrap();
        let mut input = Cursor::new(b"1\n3\n4\n8\n9\n");
        let mut output = Vec::new();
        run(
            Path::new("."),
            &inventory,
            "fake-windows-uefi-bitlocker",
            &mut input,
            &mut output,
        )
        .unwrap();
        let output = String::from_utf8(output).unwrap();

        assert!(output.contains("NoUSB guided terminal application"));
        assert!(output.contains("Universal no-USB guarantee: false"));
        assert!(output.contains("ubuntu-24.04.4-desktop-amd64.iso"));
        assert!(output.contains("Preview only: no executor was invoked."));
        assert!(output.contains("Exited without changing boot or disk state."));
    }

    #[test]
    fn guided_tui_rejects_incorrect_download_confirmation() {
        let inventory = FakePlatformAdapter::windows_uefi_bitlocker()
            .inspect()
            .unwrap();
        let mut input = Cursor::new(b"6\nno\n9\n");
        let mut output = Vec::new();
        run(
            Path::new("."),
            &inventory,
            "fake-windows-uefi-bitlocker",
            &mut input,
            &mut output,
        )
        .unwrap();
        let output = String::from_utf8(output).unwrap();

        assert!(output.contains("Download cancelled; no artifact data was changed."));
    }
}
