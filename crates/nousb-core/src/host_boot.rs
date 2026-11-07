//! Host one-shot boot of a verified Linux live installer.
//!
//! This is the transaction proven by the disposable one-shot matrix (`docs/VM_ONE_SHOT.md`),
//! applied to a real host: back up boot state, copy the verified ISO to an unencrypted volume,
//! place the ISO's own signed shim/GRUB on the EFI System Partition under `\EFI\NoUSB`, create a
//! temporary firmware entry outside the persistent boot order, and select it for exactly one
//! boot. Firmware consumes the one-shot selector, so every later boot returns to the unchanged
//! default. `cleanup` removes everything the transaction created.
//!
//! Planning is pure and works in every build. Execution needs a [`HostBootBackend`]; real
//! backends exist only in the platform crates behind `real-windows-boot` / `real-linux-boot`,
//! and every run requires the exact typed phrase from [`arm_confirmation_phrase`].

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{
    artifact_manifest, find_profile, now_stamp, read_iso_text_file, sha256_file,
    write_journal_entry, FirmwareMode, NoUsbError, SecureBootState,
};

/// Directory under the ESP's `\EFI` that holds the temporary loader chain.
pub const HOST_BOOT_ESP_DIR: &str = "NoUSB";
/// Firmware entry description. Cleanup only ever deletes the entry id recorded in the state.
pub const HOST_BOOT_ENTRY_LABEL: &str = "NoUSB One-Shot Installer";
/// Directory at the staging volume root that holds the verified ISO copy.
pub const HOST_BOOT_STAGING_DIR: &str = "NoUSB";
pub const CLEANUP_CONFIRMATION_PHRASE: &str = "CLEAN UP NOUSB BOOT";

/// Files the official ISO carries in `/EFI/BOOT`. shim (`BOOTX64.EFI`) loads `grubx64.efi` from
/// its own directory and `mmx64.efi` when a MOK prompt is needed.
const ISO_LOADERS: [(&str, &str, bool); 3] = [
    ("/EFI/BOOT/BOOTX64.EFI", "BOOTX64.EFI", true),
    ("/EFI/BOOT/grubx64.efi", "grubx64.efi", true),
    ("/EFI/BOOT/mmx64.efi", "mmx64.efi", false),
];

/// Official GRUB configurations to derive the live-boot recipe from, in order.
const ISO_GRUB_CONFIGS: [&str; 3] = [
    "/boot/grub/grub.cfg",
    "/EFI/BOOT/grub.cfg",
    "/boot/grub2/grub.cfg",
];

/// Headroom beyond the ISO size before `toram`/`rd.live.ram` is requested.
const RAM_COPY_HEADROOM_MB: u64 = 4096;

pub fn arm_confirmation_phrase(profile_id: &str) -> String {
    format!("BOOT ONCE INTO {profile_id}")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveBootFamily {
    /// Ubuntu and derivatives: `iso-scan/filename=` and `toram`.
    Casper,
    /// Fedora and other dracut live images: `iso-scan/filename=` and `rd.live.ram=1`.
    Dracut,
}

impl LiveBootFamily {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Casper => "casper",
            Self::Dracut => "dracut",
        }
    }
}

/// The kernel, initrds, and arguments of the official ISO's first live menu entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveBootRecipe {
    pub family: LiveBootFamily,
    pub kernel: String,
    pub initrds: Vec<String>,
    pub kernel_args: Vec<String>,
    pub source_config: String,
}

/// Derives the live-boot recipe from an official GRUB configuration. Only plain absolute paths
/// are accepted; anything that needs GRUB variable expansion fails closed.
pub fn derive_live_boot_recipe(
    grub_cfg: &str,
    source_config: &str,
) -> Result<LiveBootRecipe, NoUsbError> {
    let mut in_entry = false;
    let mut kernel_line: Option<Vec<String>> = None;
    let mut initrd_line: Option<Vec<String>> = None;
    for raw in grub_cfg.lines() {
        let line = raw.trim();
        if line.starts_with("menuentry ") {
            if kernel_line.is_some() {
                break;
            }
            in_entry = true;
            continue;
        }
        if !in_entry {
            continue;
        }
        if line == "}" {
            if kernel_line.is_some() {
                break;
            }
            in_entry = false;
            initrd_line = None;
            continue;
        }
        let mut tokens = line.split_whitespace().map(str::to_string);
        match tokens.next().as_deref() {
            Some("linux" | "linuxefi") => kernel_line = Some(tokens.collect()),
            Some("initrd" | "initrdefi") => initrd_line = Some(tokens.collect()),
            _ => {}
        }
    }
    let kernel_tokens = kernel_line.ok_or_else(|| {
        NoUsbError::Verification(format!("{source_config} has no linux line in a menu entry"))
    })?;
    let initrd_tokens = initrd_line.ok_or_else(|| {
        NoUsbError::Verification(format!(
            "{source_config} has no initrd line in a menu entry"
        ))
    })?;
    let mut kernel_tokens = kernel_tokens.into_iter();
    let kernel = iso_boot_path(kernel_tokens.next().as_deref(), source_config)?;
    let initrds = initrd_tokens
        .iter()
        .map(|token| iso_boot_path(Some(token), source_config))
        .collect::<Result<Vec<_>, _>>()?;
    if initrds.is_empty() {
        return Err(NoUsbError::Verification(format!(
            "{source_config} initrd line names no file"
        )));
    }
    let kernel_args: Vec<String> = kernel_tokens
        // Media checks re-read the whole ISO and are meaningless for a loopback image.
        .filter(|arg| arg != "rd.live.check" && arg != "integrity-check")
        .collect();
    if let Some(arg) = kernel_args.iter().find(|arg| arg.contains('$')) {
        return Err(NoUsbError::Verification(format!(
            "{source_config} kernel argument {arg} needs GRUB variable expansion; refusing to guess"
        )));
    }
    let family = if kernel.starts_with("/casper/")
        || kernel_args.iter().any(|arg| arg == "boot=casper")
    {
        LiveBootFamily::Casper
    } else if kernel_args
        .iter()
        .any(|arg| arg == "rd.live.image" || arg.starts_with("root=live:"))
    {
        LiveBootFamily::Dracut
    } else {
        return Err(NoUsbError::Verification(format!(
            "{source_config} is neither a casper nor a dracut live image; no loopback recipe exists for it"
        )));
    };
    Ok(LiveBootRecipe {
        family,
        kernel,
        initrds,
        kernel_args,
        source_config: source_config.into(),
    })
}

fn iso_boot_path(token: Option<&str>, source_config: &str) -> Result<String, NoUsbError> {
    let token = token.unwrap_or_default();
    let path = token
        .strip_prefix("($root)")
        .or_else(|| token.strip_prefix("${root}"))
        .unwrap_or(token);
    let valid = path.starts_with('/')
        && path.len() > 1
        && !path.contains("..")
        && path
            .chars()
            .all(|value| value.is_ascii_alphanumeric() || "/._-".contains(value));
    if valid {
        Ok(path.into())
    } else {
        Err(NoUsbError::Verification(format!(
            "{source_config} names unsupported boot path {token:?}"
        )))
    }
}

/// What the platform backend reports about the host before planning.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostBootFacts {
    pub os_name: String,
    pub elevated: bool,
    pub firmware: FirmwareMode,
    pub secure_boot: SecureBootState,
    pub memory_total_mb: Option<u64>,
    /// Volume root that will hold `NoUSB/<token>/<iso>` (for example `C:\` or `/`).
    pub staging_volume_root: PathBuf,
    /// GRUB-visible path of `staging_volume_root` inside its filesystem (`/` unless the volume
    /// is a btrfs subvolume, where it is the subvolume path, for example `/root`).
    pub staging_grub_prefix: String,
    pub staging_filesystem: Option<String>,
    /// `Some(true)` blocks: GRUB and the live initramfs cannot read BitLocker or LUKS volumes.
    pub staging_volume_encrypted: Option<bool>,
    pub staging_free_bytes: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedFile {
    /// `esp` or `staging`.
    pub location: String,
    /// Path relative to the ESP root or staging volume root, with `/` separators.
    pub relative_path: String,
    pub source: String,
    pub size_bytes: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostBootPlan {
    pub id: String,
    pub profile_id: String,
    pub profile_name: String,
    pub host_os: String,
    pub backend: String,
    pub iso_path: PathBuf,
    pub iso_filename: String,
    pub iso_sha256: String,
    pub iso_size_bytes: u64,
    pub recipe: LiveBootRecipe,
    pub ram_copy: bool,
    pub staging_volume_root: PathBuf,
    pub staging_relative_dir: String,
    pub grub_iso_path: String,
    pub grub_config: String,
    pub write_disk_info: bool,
    pub files: Vec<PlannedFile>,
    pub entry_label: String,
    pub loader_path: String,
    pub confirmation_phrase: String,
    pub blockers: Vec<String>,
    pub warnings: Vec<String>,
    pub steps: Vec<String>,
    pub recovery: Vec<String>,
    pub execution_enabled: bool,
}

impl HostBootPlan {
    pub fn ready(&self) -> bool {
        self.blockers.is_empty()
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|error| {
            format!(
                "{{\"error\":{}}}",
                serde_json::Value::String(error.to_string())
            )
        })
    }

    pub fn preview(&self) -> String {
        let mut out = String::new();
        out.push_str("NoUSB host one-shot boot plan\n");
        out.push_str(&format!(
            "Target: {} ({})\nHost: {} via {}\n",
            self.profile_name, self.profile_id, self.host_os, self.backend
        ));
        out.push_str(&format!(
            "Live family: {} (from official {}), RAM copy: {}\n",
            self.recipe.family.as_str(),
            self.recipe.source_config,
            self.ram_copy
        ));
        out.push_str(&format!(
            "Real execution compiled in: {}\n",
            self.execution_enabled
        ));
        out.push_str(&format!(
            "Ready: {}\n",
            if self.ready() { "yes" } else { "no" }
        ));
        for blocker in &self.blockers {
            out.push_str(&format!("BLOCKER: {blocker}\n"));
        }
        for warning in &self.warnings {
            out.push_str(&format!("warning: {warning}\n"));
        }
        out.push_str("Steps:\n");
        for (index, step) in self.steps.iter().enumerate() {
            out.push_str(&format!("  {}. {step}\n", index + 1));
        }
        out.push_str("Files created (all removed by cleanup):\n");
        for file in &self.files {
            out.push_str(&format!(
                "  [{}] {} <- {}\n",
                file.location, file.relative_path, file.source
            ));
        }
        out.push_str("Generated GRUB configuration:\n");
        for line in self.grub_config.lines() {
            out.push_str(&format!("  | {line}\n"));
        }
        out.push_str("If anything goes wrong:\n");
        for line in &self.recovery {
            out.push_str(&format!("  - {line}\n"));
        }
        out.push_str(&format!(
            "To arm (needs an elevated shell and a real-boot build): nousb boot arm {} \"{}\"\n",
            self.profile_id, self.confirmation_phrase
        ));
        out
    }
}

/// Plans a one-shot boot from facts and an already-verified ISO path. Pure apart from reading
/// the ISO's GRUB configuration; blockers are reported, never silently waived.
pub fn plan_host_one_shot(
    profile_id: &str,
    iso_path: &Path,
    facts: &HostBootFacts,
    backend: &str,
    execution_enabled: bool,
) -> Result<HostBootPlan, NoUsbError> {
    let profile = find_profile(profile_id)?;
    let manifest = artifact_manifest(profile_id)?;
    let mut blockers = Vec::new();
    let mut warnings = Vec::new();

    let iso_size = fs::metadata(iso_path).map(|meta| meta.len()).ok();
    match iso_size {
        None => blockers.push(format!(
            "verified ISO not found at {}; run `nousb image download {profile_id}` first",
            iso_path.display()
        )),
        Some(size) if size != manifest.size_bytes => blockers.push(format!(
            "{} is {size} bytes, but the pinned artifact is {} bytes",
            iso_path.display(),
            manifest.size_bytes
        )),
        Some(_) => {}
    }

    let recipe = if iso_size == Some(manifest.size_bytes) {
        Some(read_recipe_from_iso(iso_path)?)
    } else {
        None
    };
    let recipe = match recipe {
        Some(recipe) => recipe,
        None => placeholder_recipe(&profile.kernel_initrd_paths),
    };

    let (host_blockers, host_warnings) =
        host_preflight(facts, recipe.family, manifest.size_bytes, execution_enabled);
    blockers.extend(host_blockers);
    warnings.extend(host_warnings);

    let ram_copy = facts
        .memory_total_mb
        .is_some_and(|memory| memory >= manifest.size_bytes / (1024 * 1024) + RAM_COPY_HEADROOM_MB);
    if !ram_copy {
        warnings.push(
            "not enough RAM (or unknown) to copy the live medium to RAM; the live session keeps reading the ISO from disk".into(),
        );
    }

    let token = format!("{}-{}", profile.id, now_stamp());
    let staging_relative_dir = format!("{HOST_BOOT_STAGING_DIR}/{token}");
    let prefix = facts.staging_grub_prefix.trim_end_matches('/');
    let grub_iso_path = format!("{prefix}/{staging_relative_dir}/{}", manifest.filename);
    let marker_name = format!("nousb-{token}.marker");
    let grub_marker_path = format!("{prefix}/{staging_relative_dir}/{marker_name}");
    let grub_config = render_grub_config(
        &profile.name,
        &recipe,
        &grub_iso_path,
        &grub_marker_path,
        ram_copy,
    );
    let write_disk_info = recipe.family == LiveBootFamily::Casper;

    let mut files = vec![
        PlannedFile {
            location: "staging".into(),
            relative_path: format!("{staging_relative_dir}/{}", manifest.filename),
            source: format!("verified copy of {}", iso_path.display()),
            size_bytes: Some(manifest.size_bytes),
        },
        PlannedFile {
            location: "staging".into(),
            relative_path: format!("{staging_relative_dir}/{marker_name}"),
            source: "generated marker that GRUB searches for".into(),
            size_bytes: None,
        },
    ];
    for (iso_file, name, _) in ISO_LOADERS {
        files.push(PlannedFile {
            location: "esp".into(),
            relative_path: format!("EFI/{HOST_BOOT_ESP_DIR}/{name}"),
            source: format!("ISO {iso_file} (official, signed; optional files only if present)"),
            size_bytes: None,
        });
    }
    files.push(PlannedFile {
        location: "esp".into(),
        relative_path: format!("EFI/{HOST_BOOT_ESP_DIR}/grub.cfg"),
        source: "generated GRUB configuration".into(),
        size_bytes: Some(grub_config.len() as u64),
    });
    if write_disk_info {
        // Ubuntu's image GRUB finds its configuration by searching for /.disk/info and then
        // reading $root/boot/grub/grub.cfg; both are created only if absent.
        for (path, source) in [
            (
                ".disk/info",
                "generated ISO-style volume marker for Ubuntu's image GRUB",
            ),
            ("boot/grub/grub.cfg", "generated GRUB configuration (copy)"),
        ] {
            files.push(PlannedFile {
                location: "esp".into(),
                relative_path: path.into(),
                source: source.into(),
                size_bytes: None,
            });
        }
    }

    let loader_path = format!("\\EFI\\{HOST_BOOT_ESP_DIR}\\BOOTX64.EFI");
    let steps = vec![
        "Re-check elevation, UEFI, staging-volume encryption, and free space".into(),
        "Re-verify the full ISO against the pinned size and SHA-256".into(),
        "Back up firmware boot entries (and the BCD store on Windows) to .nousb/host-boot/<plan>/backup".into(),
        format!(
            "Copy the ISO to {}{} and verify the copy's SHA-256",
            facts.staging_volume_root.display(),
            staging_relative_dir
        ),
        format!("Mount the ESP (Windows: a free drive letter via mountvol) and create EFI/{HOST_BOOT_ESP_DIR}; refuse if it exists"),
        "Copy the ISO's signed shim/GRUB/MokManager to the ESP and write the generated grub.cfg".into(),
        format!("Create firmware entry \"{HOST_BOOT_ENTRY_LABEL}\" -> {loader_path}, outside the persistent boot order"),
        "Select that entry for the next boot only (UEFI BootNext / bcdedit {fwbootmgr} bootsequence)".into(),
        "Verify the persistent boot order is unchanged; on any failure, undo every completed step".into(),
        "You reboot. Firmware consumes the one-shot selector; later boots return to the current OS".into(),
        "Back in the current OS, run `nousb boot cleanup` to remove the entry and every file".into(),
    ];
    let recovery = vec![
        "If the installer does not start, simply reboot: the one-shot selector is already consumed and firmware returns to your current OS.".into(),
        "If a machine ever boots the installer repeatedly, choose your OS in the firmware boot menu (often F12/F11/Esc/F8) and run `nousb boot cleanup`.".into(),
        "Backups of the firmware entries and BCD are in .nousb/host-boot/<plan>/backup; `bcdedit /import` restores the BCD on Windows.".into(),
        "On BitLocker systems keep the recovery key at hand before any boot change.".into(),
    ];

    Ok(HostBootPlan {
        id: format!("host-boot-{token}"),
        profile_id: profile.id.clone(),
        profile_name: format!("{} {}", profile.name, profile.version),
        host_os: facts.os_name.clone(),
        backend: backend.into(),
        iso_path: iso_path.to_path_buf(),
        iso_filename: manifest.filename.clone(),
        iso_sha256: manifest.sha256,
        iso_size_bytes: manifest.size_bytes,
        recipe,
        ram_copy,
        staging_volume_root: facts.staging_volume_root.clone(),
        staging_relative_dir,
        grub_iso_path,
        grub_config,
        write_disk_info,
        files,
        entry_label: HOST_BOOT_ENTRY_LABEL.into(),
        loader_path,
        confirmation_phrase: arm_confirmation_phrase(&profile.id),
        blockers,
        warnings,
        steps,
        recovery,
        execution_enabled,
    })
}

/// Host-level preflight shared by planning and arming. Never waives a blocker.
fn host_preflight(
    facts: &HostBootFacts,
    family: LiveBootFamily,
    iso_size_bytes: u64,
    execution_enabled: bool,
) -> (Vec<String>, Vec<String>) {
    let mut blockers = Vec::new();
    let mut warnings = Vec::new();
    if !execution_enabled {
        blockers.push(
            "this build has no real boot backend; rebuild with --features real-windows-boot or real-linux-boot".into(),
        );
    }
    if !matches!(facts.os_name.as_str(), "windows" | "linux") {
        blockers.push(format!(
            "{} hosts are out of scope for real boot changes",
            facts.os_name
        ));
    }
    if facts.firmware != FirmwareMode::Uefi {
        blockers.push(
            "UEFI firmware was not detected; legacy BIOS one-shot boot is not supported".into(),
        );
    }
    if !facts.elevated {
        blockers.push(
            "not elevated: arming needs Administrator (Windows) or root (Linux); planning works without it".into(),
        );
    }
    match facts.staging_volume_encrypted {
        Some(true) => blockers.push(format!(
            "staging volume {} is encrypted; GRUB and the live initramfs cannot read BitLocker/LUKS volumes. Choose an unencrypted volume with --staging-root",
            facts.staging_volume_root.display()
        )),
        None => blockers.push(format!(
            "encryption state of staging volume {} is unknown; arming re-checks it with elevation and refuses if it stays unknown",
            facts.staging_volume_root.display()
        )),
        Some(false) => {}
    }
    let needed = iso_size_bytes.saturating_add(1024 * 1024 * 1024);
    match facts.staging_free_bytes {
        Some(free) if free < needed => blockers.push(format!(
            "staging volume has {} MiB free; the ISO copy needs {} MiB",
            free / (1024 * 1024),
            needed / (1024 * 1024)
        )),
        None => warnings.push("staging volume free space is unknown".into()),
        _ => {}
    }
    if let Some(fs_name) = facts.staging_filesystem.as_deref() {
        let fs_lower = fs_name.to_ascii_lowercase();
        if !matches!(
            fs_lower.as_str(),
            "ntfs" | "ext4" | "ext3" | "ext2" | "btrfs" | "xfs" | "vfat" | "fat32" | "exfat"
        ) {
            blockers.push(format!(
                "staging filesystem {fs_name} is not known to be readable by the official GRUB"
            ));
        }
        const FAT32_MAX_FILE_BYTES: u64 = 0xFFFF_FFFF;
        if matches!(fs_lower.as_str(), "vfat" | "fat32") && iso_size_bytes > FAT32_MAX_FILE_BYTES {
            let iso_gib = iso_size_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
            blockers.push(format!(
                "staging filesystem {fs_name} has a 4 GiB single-file limit; this ISO is {iso_gib:.1} GiB (choose another staging volume with --staging-root)"
            ));
        }
        if fs_lower == "ntfs" && family == LiveBootFamily::Dracut {
            blockers.push(
                "dracut live images cannot loop-mount an ISO from NTFS; stage it on an ext4/FAT/exFAT volume with --staging-root".into(),
            );
        }
        if fs_lower == "ntfs" && family == LiveBootFamily::Casper {
            warnings.push(
                "casper must mount NTFS from its initramfs to find the ISO; this is a physical-test item (see docs/PHYSICAL_TESTING.md)".into(),
            );
        }
    }
    if facts.secure_boot == SecureBootState::Enabled {
        warnings.push(
            "Secure Boot is enabled: only the ISO's own signed shim/GRUB/kernel are used. If firmware rejects them, it falls back to the normal OS".into(),
        );
    }

    (blockers, warnings)
}

fn placeholder_recipe(kernel_initrd_paths: &[String]) -> LiveBootRecipe {
    let kernel = kernel_initrd_paths
        .first()
        .cloned()
        .unwrap_or_else(|| "(read from the ISO once it is downloaded)".into());
    LiveBootRecipe {
        family: if kernel.starts_with("/casper/") {
            LiveBootFamily::Casper
        } else {
            LiveBootFamily::Dracut
        },
        kernel,
        initrds: kernel_initrd_paths.iter().skip(1).cloned().collect(),
        kernel_args: vec![],
        source_config: "profile metadata (ISO not yet available)".into(),
    }
}

fn read_recipe_from_iso(iso_path: &Path) -> Result<LiveBootRecipe, NoUsbError> {
    let mut errors = Vec::new();
    for config in ISO_GRUB_CONFIGS {
        match read_iso_text_file(iso_path, config, 256 * 1024) {
            Ok(Some(text)) => match derive_live_boot_recipe(&text, config) {
                Ok(recipe) => return Ok(recipe),
                Err(error) => errors.push(error.to_string()),
            },
            Ok(None) => {}
            Err(error) => errors.push(error.to_string()),
        }
    }
    Err(NoUsbError::Verification(format!(
        "no usable live-boot recipe in the ISO's GRUB configuration: {}",
        if errors.is_empty() {
            "no GRUB configuration found".into()
        } else {
            errors.join("; ")
        }
    )))
}

pub fn render_grub_config(
    title: &str,
    recipe: &LiveBootRecipe,
    grub_iso_path: &str,
    grub_marker_path: &str,
    ram_copy: bool,
) -> String {
    let mut ours = vec![format!("iso-scan/filename={grub_iso_path}")];
    if ram_copy {
        ours.push(
            match recipe.family {
                LiveBootFamily::Casper => "toram",
                LiveBootFamily::Dracut => "rd.live.ram=1",
            }
            .into(),
        );
    }
    // Arguments before `---` belong to the live system; insert ours there.
    let mut args = Vec::new();
    let mut inserted = false;
    for arg in &recipe.kernel_args {
        if arg == "---" && !inserted {
            args.extend(ours.iter().cloned());
            inserted = true;
        }
        args.push(arg.clone());
    }
    if !inserted {
        args.extend(ours);
    }
    let initrds = recipe
        .initrds
        .iter()
        .map(|path| format!("(loop){path}"))
        .collect::<Vec<_>>()
        .join(" ");
    let title = title.replace('"', "'");
    format!(
        "# Generated by NoUSB OS Switcher for exactly one boot. `nousb boot cleanup` removes it.\n\
set timeout=10\n\
set default=0\n\
\n\
menuentry \"{title} - live (NoUSB one-shot)\" {{\n\
\x20   search --no-floppy --set=nousb_root --file {grub_marker_path}\n\
\x20   loopback loop ($nousb_root){grub_iso_path}\n\
\x20   linux (loop){kernel} {args}\n\
\x20   initrd {initrds}\n\
}}\n\
\n\
menuentry \"Cancel and reboot to the installed OS\" {{\n\
\x20   reboot\n\
}}\n",
        kernel = recipe.kernel,
        args = args.join(" "),
    )
}

/// The ESP as mounted for this transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EspMount {
    pub path: PathBuf,
    /// True when the backend mounted it (Windows `mountvol`) and must unmount it afterwards.
    pub mounted_by_us: bool,
}

/// Platform operations the transaction needs. Real implementations live in the platform
/// crates behind `real-*-boot` features; [`FakeHostBootBackend`] backs the tests.
pub trait HostBootBackend {
    fn name(&self) -> &'static str;
    fn facts(&mut self, staging_root: &Path) -> Result<HostBootFacts, NoUsbError>;
    fn backup_boot_state(&mut self, dir: &Path) -> Result<Vec<PathBuf>, NoUsbError>;
    fn mount_esp(&mut self) -> Result<EspMount, NoUsbError>;
    fn unmount_esp(&mut self, mount: &EspMount) -> Result<(), NoUsbError>;
    fn esp_free_bytes(&mut self, mount: &EspMount) -> Result<Option<u64>, NoUsbError>;
    fn boot_order(&mut self) -> Result<Vec<String>, NoUsbError>;
    /// Creates a firmware entry outside the persistent boot order; returns its id.
    fn create_entry(
        &mut self,
        label: &str,
        loader: &str,
        mount: &EspMount,
    ) -> Result<String, NoUsbError>;
    fn arm_one_shot(&mut self, entry: &str) -> Result<(), NoUsbError>;
    fn pending_one_shot(&mut self) -> Result<Option<String>, NoUsbError>;
    fn clear_one_shot(&mut self) -> Result<(), NoUsbError>;
    fn delete_entry(&mut self, entry: &str) -> Result<(), NoUsbError>;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostBootPhase {
    Preparing,
    Armed,
    RolledBack,
    CleanedUp,
    Failed,
}

/// Persisted after every step so cleanup is idempotent and survives power loss.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostBootState {
    pub plan_id: String,
    pub profile_id: String,
    pub backend: String,
    pub phase: HostBootPhase,
    pub boot_order_before: Vec<String>,
    pub entry_id: Option<String>,
    pub armed: bool,
    pub esp_mount: Option<EspMount>,
    pub created_files: Vec<PathBuf>,
    /// Created directories, parents first; removed in reverse and only when empty.
    pub created_dirs: Vec<PathBuf>,
    /// ESP-relative paths, recorded so cleanup can find them after a later remount.
    pub esp_files: Vec<String>,
    pub esp_dirs: Vec<String>,
    pub backup_files: Vec<PathBuf>,
    pub events: Vec<String>,
    pub updated_at: u64,
}

impl HostBootState {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|error| {
            format!(
                "{{\"error\":{}}}",
                serde_json::Value::String(error.to_string())
            )
        })
    }

    pub fn needs_cleanup(&self) -> bool {
        matches!(
            self.phase,
            HostBootPhase::Preparing | HostBootPhase::Armed | HostBootPhase::Failed
        )
    }
}

pub fn host_boot_dir(base_dir: &Path) -> PathBuf {
    base_dir.join(".nousb").join("host-boot")
}

pub fn host_boot_state_path(base_dir: &Path) -> PathBuf {
    host_boot_dir(base_dir).join("state.json")
}

pub fn load_host_boot_state(base_dir: &Path) -> Result<Option<HostBootState>, NoUsbError> {
    let path = host_boot_state_path(base_dir);
    match fs::read_to_string(&path) {
        Ok(text) => serde_json::from_str(&text).map(Some).map_err(|error| {
            NoUsbError::InvalidInput(format!("{} is unreadable: {error}", path.display()))
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn save_state(base_dir: &Path, state: &mut HostBootState, event: &str) -> Result<(), NoUsbError> {
    state.updated_at = now_stamp();
    state.events.push(format!("{} {event}", state.updated_at));
    let dir = host_boot_dir(base_dir);
    fs::create_dir_all(&dir)?;
    let partial = dir.join("state.json.partial");
    {
        let mut file = fs::File::create(&partial)?;
        file.write_all(state.to_json().as_bytes())?;
        file.sync_all()?;
    }
    fs::rename(&partial, host_boot_state_path(base_dir))?;
    write_journal_entry(base_dir, &format!("host-boot {}: {event}", state.plan_id))?;
    Ok(())
}

/// Arms the one-shot boot. On any failure every completed step is undone before returning.
pub fn arm_host_one_shot(
    base_dir: &Path,
    plan: &HostBootPlan,
    backend: &mut dyn HostBootBackend,
    confirmation: &str,
) -> Result<HostBootState, NoUsbError> {
    arm_with_extractor(
        base_dir,
        plan,
        backend,
        confirmation,
        &|iso_file, target| super::extract_iso_file(&plan.iso_path, iso_file, target),
    )
}

/// Extracts one ISO file to a new target; `Ok(false)` when the ISO does not contain it.
type LoaderExtractor<'a> = &'a dyn Fn(&str, &Path) -> Result<bool, NoUsbError>;

fn arm_with_extractor(
    base_dir: &Path,
    plan: &HostBootPlan,
    backend: &mut dyn HostBootBackend,
    confirmation: &str,
    extract: LoaderExtractor<'_>,
) -> Result<HostBootState, NoUsbError> {
    if confirmation != plan.confirmation_phrase {
        return Err(NoUsbError::UnsafeExecution(format!(
            "typed confirmation must be exactly \"{}\"",
            plan.confirmation_phrase
        )));
    }
    if let Some(existing) = load_host_boot_state(base_dir)? {
        if existing.needs_cleanup() {
            return Err(NoUsbError::UnsafeExecution(format!(
                "{} is still {:?}; run `nousb boot cleanup` first",
                existing.plan_id, existing.phase
            )));
        }
    }
    if !plan.ready() {
        return Err(NoUsbError::UnsafeExecution(format!(
            "preflight blocked: {}",
            plan.blockers.join("; ")
        )));
    }
    // Re-check live facts with whatever elevation the caller now has.
    let facts = backend.facts(&plan.staging_volume_root)?;
    let (blockers, _) = host_preflight(
        &facts,
        plan.recipe.family,
        plan.iso_size_bytes,
        plan.execution_enabled,
    );
    if !blockers.is_empty() {
        return Err(NoUsbError::UnsafeExecution(format!(
            "preflight blocked: {}",
            blockers.join("; ")
        )));
    }

    let mut state = HostBootState {
        plan_id: plan.id.clone(),
        profile_id: plan.profile_id.clone(),
        backend: backend.name().into(),
        phase: HostBootPhase::Preparing,
        boot_order_before: vec![],
        entry_id: None,
        armed: false,
        esp_mount: None,
        created_files: vec![],
        created_dirs: vec![],
        esp_files: vec![],
        esp_dirs: vec![],
        backup_files: vec![],
        events: vec![],
        updated_at: now_stamp(),
    };
    save_state(base_dir, &mut state, "transaction started")?;

    match run_arm_steps(base_dir, plan, backend, &mut state, extract) {
        Ok(()) => Ok(state),
        Err(error) => {
            let undo = undo_transaction(base_dir, backend, &mut state);
            state.phase = match undo {
                Ok(()) => HostBootPhase::RolledBack,
                Err(_) => HostBootPhase::Failed,
            };
            let note = match &undo {
                Ok(()) => format!("failed and rolled back: {error}"),
                Err(undo_error) => {
                    format!("failed: {error}; rollback incomplete: {undo_error}")
                }
            };
            save_state(base_dir, &mut state, &note)?;
            Err(NoUsbError::UnsafeExecution(note))
        }
    }
}

fn run_arm_steps(
    base_dir: &Path,
    plan: &HostBootPlan,
    backend: &mut dyn HostBootBackend,
    state: &mut HostBootState,
    extract: LoaderExtractor<'_>,
) -> Result<(), NoUsbError> {
    verify_file(&plan.iso_path, plan.iso_size_bytes, &plan.iso_sha256)?;
    save_state(base_dir, state, "source ISO re-verified")?;

    let backup_dir = host_boot_dir(base_dir).join(&plan.id).join("backup");
    fs::create_dir_all(&backup_dir)?;
    state.backup_files = backend.backup_boot_state(&backup_dir)?;
    state.boot_order_before = backend.boot_order()?;
    save_state(base_dir, state, "boot state backed up")?;

    let mount = backend.mount_esp()?;
    state.esp_mount = Some(mount.clone());
    save_state(base_dir, state, &format!("ESP at {}", mount.path.display()))?;
    let needed: u64 = 64 * 1024 * 1024;
    if let Some(free) = backend.esp_free_bytes(&mount)? {
        if free < needed {
            return Err(NoUsbError::UnsafeExecution(format!(
                "ESP has {} MiB free; at least {} MiB is required",
                free / (1024 * 1024),
                needed / (1024 * 1024)
            )));
        }
    }
    let efi_dir = mount.path.join("EFI");
    if !efi_dir.is_dir() {
        return Err(NoUsbError::UnsafeExecution(format!(
            "{} has no EFI directory; this does not look like an EFI System Partition",
            mount.path.display()
        )));
    }
    let loader_dir_rel = format!("EFI/{HOST_BOOT_ESP_DIR}");
    let loader_dir = mount.path.join(relative_native(&loader_dir_rel));
    if loader_dir.exists() {
        return Err(NoUsbError::UnsafeExecution(format!(
            "{} already exists; refusing to overwrite (run `nousb boot cleanup` or inspect it)",
            loader_dir.display()
        )));
    }
    if plan.write_disk_info {
        for relative in [".disk/info", "boot/grub/grub.cfg"] {
            let target = mount.path.join(relative_native(relative));
            if target.exists() {
                return Err(NoUsbError::UnsafeExecution(format!(
                    "{} already exists on the ESP; refusing to overwrite it",
                    target.display()
                )));
            }
        }
    }

    // Unmount ESP right after checks so it does not stay mounted during the multi-GB copy.
    if mount.mounted_by_us {
        backend.unmount_esp(&mount)?;
    }
    state.esp_mount = None;
    save_state(base_dir, state, "ESP pre-checks passed")?;

    // Staging volume: NoUSB/<token>/<iso> plus the marker GRUB searches for.
    let staging_parent = plan.staging_volume_root.join(HOST_BOOT_STAGING_DIR);
    if !staging_parent.exists() {
        fs::create_dir(&staging_parent)?;
        state.created_dirs.push(staging_parent.clone());
    }
    let staging_dir = plan
        .staging_volume_root
        .join(relative_native(&plan.staging_relative_dir));
    fs::create_dir(&staging_dir)?;
    state.created_dirs.push(staging_dir.clone());
    save_state(base_dir, state, "staging directory created")?;

    let iso_copy = staging_dir.join(&plan.iso_filename);
    state.created_files.push(iso_copy.clone());
    save_state(base_dir, state, "copying ISO")?;
    copy_create_new(&plan.iso_path, &iso_copy)?;
    let copied = sha256_file(&iso_copy)?;
    if copied != plan.iso_sha256 {
        return Err(NoUsbError::Verification(format!(
            "ISO copy hash {copied} does not match pinned {}",
            plan.iso_sha256
        )));
    }
    let marker_name = plan
        .grub_config
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix("search --no-floppy --set=nousb_root --file ")
        })
        .and_then(|path| path.rsplit('/').next())
        .ok_or_else(|| NoUsbError::InvalidInput("plan has no GRUB marker".into()))?
        .to_string();
    let marker = staging_dir.join(marker_name);
    write_create_new(&marker, plan.id.as_bytes())?;
    state.created_files.push(marker);
    save_state(base_dir, state, "ISO copied and verified")?;

    let mount = backend.mount_esp()?;
    state.esp_mount = Some(mount.clone());
    save_state(
        base_dir,
        state,
        &format!("ESP mounted at {}", mount.path.display()),
    )?;

    let loader_dir = mount.path.join(relative_native(&loader_dir_rel));
    fs::create_dir(&loader_dir)?;
    state.esp_dirs.push(loader_dir_rel.clone());
    save_state(base_dir, state, "ESP loader directory created")?;

    for (iso_file, name, required) in ISO_LOADERS {
        let relative = format!("{loader_dir_rel}/{name}");
        let target = mount.path.join(relative_native(&relative));
        state.esp_files.push(relative.clone());
        save_state(base_dir, state, &format!("writing {relative}"))?;
        let written = extract(iso_file, &target)?;
        if !written {
            state.esp_files.retain(|path| path != &relative);
            if required {
                return Err(NoUsbError::Verification(format!(
                    "ISO has no {iso_file}; it cannot be booted through shim"
                )));
            }
        }
    }
    let mut generated = vec![(
        format!("{loader_dir_rel}/grub.cfg"),
        plan.grub_config.clone(),
    )];
    if plan.write_disk_info {
        for dir in [".disk", "boot", "boot/grub"] {
            let path = mount.path.join(relative_native(dir));
            if !path.exists() {
                fs::create_dir(&path)?;
                state.esp_dirs.push(dir.into());
            }
        }
        generated.push((
            ".disk/info".into(),
            format!("NoUSB one-shot {} {}\n", plan.profile_name, plan.id),
        ));
        generated.push(("boot/grub/grub.cfg".into(), plan.grub_config.clone()));
    }
    for (relative, contents) in generated {
        let target = mount.path.join(relative_native(&relative));
        if target.exists() {
            return Err(NoUsbError::UnsafeExecution(format!(
                "{} already exists on the ESP; refusing to overwrite it",
                target.display()
            )));
        }
        state.esp_files.push(relative.clone());
        save_state(base_dir, state, &format!("writing {relative}"))?;
        write_create_new(&target, contents.as_bytes())?;
    }
    save_state(base_dir, state, "loader chain staged on ESP")?;

    let entry = backend.create_entry(&plan.entry_label, &plan.loader_path, &mount)?;
    state.entry_id = Some(entry.clone());
    save_state(base_dir, state, &format!("firmware entry {entry} created"))?;

    backend.arm_one_shot(&entry)?;
    state.armed = true;
    save_state(
        base_dir,
        state,
        &format!("one-shot selector set to {entry}"),
    )?;

    let order_after = backend.boot_order()?;
    if order_after != state.boot_order_before {
        return Err(NoUsbError::UnsafeExecution(format!(
            "persistent boot order changed from {:?} to {:?}",
            state.boot_order_before, order_after
        )));
    }
    match backend.pending_one_shot()? {
        Some(pending) if pending == entry => {}
        other => {
            return Err(NoUsbError::UnsafeExecution(format!(
                "one-shot selector reads back as {other:?}, expected {entry}"
            )))
        }
    }

    // The ESP stays mounted only as long as needed; files persist on disk.
    if mount.mounted_by_us {
        backend.unmount_esp(&mount)?;
        state.esp_mount = Some(EspMount {
            path: mount.path,
            mounted_by_us: false,
        });
    }
    state.phase = HostBootPhase::Armed;
    save_state(base_dir, state, "armed: reboot to start the installer once")?;
    Ok(())
}

/// Removes everything the transaction created. Idempotent: missing items are skipped.
pub fn cleanup_host_one_shot(
    base_dir: &Path,
    backend: &mut dyn HostBootBackend,
    confirmation: &str,
) -> Result<HostBootState, NoUsbError> {
    if confirmation != CLEANUP_CONFIRMATION_PHRASE {
        return Err(NoUsbError::UnsafeExecution(format!(
            "typed confirmation must be exactly \"{CLEANUP_CONFIRMATION_PHRASE}\""
        )));
    }
    let mut state = load_host_boot_state(base_dir)?.ok_or_else(|| {
        NoUsbError::InvalidInput("no NoUSB host boot transaction is recorded".into())
    })?;
    if !state.needs_cleanup() {
        return Ok(state);
    }
    undo_transaction(base_dir, backend, &mut state)?;
    state.phase = HostBootPhase::CleanedUp;
    save_state(base_dir, &mut state, "cleaned up")?;
    Ok(state)
}

fn undo_transaction(
    base_dir: &Path,
    backend: &mut dyn HostBootBackend,
    state: &mut HostBootState,
) -> Result<(), NoUsbError> {
    let mut errors = Vec::new();
    if let Some(entry) = state.entry_id.clone() {
        match backend.pending_one_shot() {
            Ok(Some(pending)) if pending == entry => {
                if let Err(error) = backend.clear_one_shot() {
                    errors.push(format!("clear one-shot: {error}"));
                }
            }
            Ok(_) => {}
            Err(error) => errors.push(format!("read one-shot: {error}")),
        }
        state.armed = false;
        match backend.delete_entry(&entry) {
            Ok(()) => state.entry_id = None,
            Err(error) => errors.push(format!("delete entry {entry}: {error}")),
        }
        save_state(base_dir, state, "firmware entry removed")?;
    }

    let saved_esp_mount = state.esp_mount.clone();
    let has_esp_items = !state.esp_files.is_empty() || !state.esp_dirs.is_empty();

    if has_esp_items {
        match backend.mount_esp() {
            Ok(cleanup_mount) => {
                for relative in state.esp_files.iter().rev() {
                    let path = cleanup_mount.path.join(relative_native(relative));
                    if let Err(error) = remove_file_if_present(&path) {
                        errors.push(format!("remove {}: {error}", path.display()));
                    }
                }
                for relative in state.esp_dirs.iter().rev() {
                    let path = cleanup_mount.path.join(relative_native(relative));
                    if let Err(error) = remove_dir_if_empty(&path) {
                        errors.push(format!("remove {}: {error}", path.display()));
                    }
                }
                let mut unmount_ok = true;
                if cleanup_mount.mounted_by_us {
                    if let Err(error) = backend.unmount_esp(&cleanup_mount) {
                        errors.push(format!("unmount ESP: {error}"));
                        unmount_ok = false;
                    }
                }
                if let Some(ref saved) = saved_esp_mount {
                    if saved.mounted_by_us && saved.path != cleanup_mount.path {
                        if let Err(error) = backend.unmount_esp(saved) {
                            errors.push(format!(
                                "unmount saved ESP {}: {error}",
                                saved.path.display()
                            ));
                            unmount_ok = false;
                        }
                    }
                }
                if unmount_ok {
                    state.esp_mount = None;
                }
                if errors.is_empty() {
                    state.esp_files.clear();
                    state.esp_dirs.clear();
                }
            }
            Err(error) => {
                errors.push(format!("mount ESP for cleanup: {error}"));
                if let Some(ref saved) = saved_esp_mount {
                    if saved.mounted_by_us {
                        if let Err(unmount_error) = backend.unmount_esp(saved) {
                            errors.push(format!(
                                "unmount saved ESP {}: {unmount_error}",
                                saved.path.display()
                            ));
                        } else {
                            state.esp_mount = None;
                        }
                    }
                }
            }
        }
        save_state(base_dir, state, "ESP files removed")?;
    } else if let Some(ref saved) = saved_esp_mount {
        if saved.mounted_by_us {
            if let Err(error) = backend.unmount_esp(saved) {
                errors.push(format!("unmount ESP {}: {error}", saved.path.display()));
            } else {
                state.esp_mount = None;
            }
            save_state(base_dir, state, "ESP unmounted")?;
        }
    }

    for path in state.created_files.iter().rev() {
        if let Err(error) = remove_file_if_present(path) {
            errors.push(format!("remove {}: {error}", path.display()));
        }
    }
    for path in state.created_dirs.iter().rev() {
        if let Err(error) = remove_dir_if_empty(path) {
            errors.push(format!("remove {}: {error}", path.display()));
        }
    }
    if errors.is_empty() {
        state.created_files.clear();
        state.created_dirs.clear();
        Ok(())
    } else {
        Err(NoUsbError::Io(errors.join("; ")))
    }
}

fn verify_file(path: &Path, size_bytes: u64, sha256: &str) -> Result<(), NoUsbError> {
    let actual_size = fs::metadata(path)?.len();
    if actual_size != size_bytes {
        return Err(NoUsbError::Verification(format!(
            "{} is {actual_size} bytes; expected {size_bytes}",
            path.display()
        )));
    }
    let actual = sha256_file(path)?;
    if !actual.eq_ignore_ascii_case(sha256) {
        return Err(NoUsbError::Verification(format!(
            "{} has SHA-256 {actual}; expected {sha256}",
            path.display()
        )));
    }
    Ok(())
}

fn relative_native(relative: &str) -> PathBuf {
    relative
        .split('/')
        .filter(|part| !part.is_empty())
        .collect()
}

fn remove_file_if_present(path: &Path) -> std::io::Result<()> {
    match fs::remove_file(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

fn remove_dir_if_empty(path: &Path) -> std::io::Result<()> {
    match fs::read_dir(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
        Ok(mut entries) => {
            if entries.next().is_none() {
                fs::remove_dir(path)
            } else {
                Ok(())
            }
        }
    }
}

fn copy_create_new(source: &Path, destination: &Path) -> Result<(), NoUsbError> {
    let mut input = fs::File::open(source)?;
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)?;
    std::io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    Ok(())
}

fn write_create_new(path: &Path, contents: &[u8]) -> Result<(), NoUsbError> {
    let mut output = OpenOptions::new().create_new(true).write(true).open(path)?;
    output.write_all(contents)?;
    output.sync_all()?;
    Ok(())
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CommandOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Runs the platform boot tools (`bcdedit`, `mountvol`, `efibootmgr`, ...). Real backends use
/// [`SystemCommandRunner`]; tests use [`ScriptedCommandRunner`] so no tool ever runs.
pub trait CommandRunner {
    fn run(&mut self, program: &str, args: &[&str]) -> Result<CommandOutput, NoUsbError>;

    /// Runs and fails unless the tool reports success.
    fn run_checked(&mut self, program: &str, args: &[&str]) -> Result<String, NoUsbError> {
        let output = self.run(program, args)?;
        if output.success {
            Ok(output.stdout)
        } else {
            Err(NoUsbError::Io(format!(
                "{program} {} failed: {}{}",
                args.join(" "),
                output.stderr.trim(),
                output.stdout.trim()
            )))
        }
    }
}

pub struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(&mut self, program: &str, args: &[&str]) -> Result<CommandOutput, NoUsbError> {
        let output = std::process::Command::new(program)
            .args(args)
            .stdin(std::process::Stdio::null())
            .output()
            .map_err(|error| NoUsbError::Io(format!("cannot run {program}: {error}")))?;
        Ok(CommandOutput {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

type CommandHandler = Box<dyn FnMut(&str) -> CommandOutput>;

/// Answers each command line (`program arg arg`) from a handler and records every call.
pub struct ScriptedCommandRunner {
    pub calls: Vec<String>,
    handler: CommandHandler,
}

impl ScriptedCommandRunner {
    pub fn new(handler: impl FnMut(&str) -> CommandOutput + 'static) -> Self {
        Self {
            calls: Vec::new(),
            handler: Box::new(handler),
        }
    }

    pub fn ok(stdout: &str) -> CommandOutput {
        CommandOutput {
            success: true,
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }
}

impl CommandRunner for ScriptedCommandRunner {
    fn run(&mut self, program: &str, args: &[&str]) -> Result<CommandOutput, NoUsbError> {
        let line = std::iter::once(program)
            .chain(args.iter().copied())
            .collect::<Vec<_>>()
            .join(" ");
        self.calls.push(line.clone());
        Ok((self.handler)(&line))
    }
}

/// In-memory backend for tests and rehearsals: the "ESP" is a directory and firmware
/// variables are plain fields. Failures can be injected per operation.
#[derive(Clone, Debug)]
pub struct FakeHostBootBackend {
    pub facts: HostBootFacts,
    pub esp_dir: PathBuf,
    pub boot_order: Vec<String>,
    pub entries: Vec<(String, String)>,
    pub boot_next: Option<String>,
    pub fail_on: Option<String>,
    pub mounted: bool,
    pub mounted_paths: Vec<PathBuf>,
}

impl FakeHostBootBackend {
    pub fn new(facts: HostBootFacts, esp_dir: PathBuf) -> Self {
        Self {
            facts,
            esp_dir,
            boot_order: vec!["0000".into(), "0001".into()],
            entries: vec![
                ("0000".into(), "Current OS".into()),
                ("0001".into(), "Network".into()),
            ],
            boot_next: None,
            fail_on: None,
            mounted: false,
            mounted_paths: Vec::new(),
        }
    }

    fn check(&self, operation: &str) -> Result<(), NoUsbError> {
        if self.fail_on.as_deref() == Some(operation) {
            Err(NoUsbError::Io(format!("injected failure in {operation}")))
        } else {
            Ok(())
        }
    }
}

impl HostBootBackend for FakeHostBootBackend {
    fn name(&self) -> &'static str {
        "fake-host-boot"
    }

    fn facts(&mut self, _staging_root: &Path) -> Result<HostBootFacts, NoUsbError> {
        self.check("facts")?;
        Ok(self.facts.clone())
    }

    fn backup_boot_state(&mut self, dir: &Path) -> Result<Vec<PathBuf>, NoUsbError> {
        self.check("backup")?;
        let path = dir.join("firmware-entries.txt");
        fs::write(
            &path,
            format!("{:?}\n{:?}\n", self.boot_order, self.entries),
        )?;
        Ok(vec![path])
    }

    fn mount_esp(&mut self) -> Result<EspMount, NoUsbError> {
        self.check("mount")?;
        if !self.mounted_paths.contains(&self.esp_dir) {
            self.mounted_paths.push(self.esp_dir.clone());
        }
        self.mounted = !self.mounted_paths.is_empty();
        Ok(EspMount {
            path: self.esp_dir.clone(),
            mounted_by_us: true,
        })
    }

    fn unmount_esp(&mut self, mount: &EspMount) -> Result<(), NoUsbError> {
        self.check("unmount")?;
        if !mount.mounted_by_us {
            return Ok(());
        }
        if let Some(pos) = self.mounted_paths.iter().position(|p| p == &mount.path) {
            self.mounted_paths.remove(pos);
        }
        self.mounted = !self.mounted_paths.is_empty();
        Ok(())
    }

    fn esp_free_bytes(&mut self, _mount: &EspMount) -> Result<Option<u64>, NoUsbError> {
        Ok(Some(512 * 1024 * 1024))
    }

    fn boot_order(&mut self) -> Result<Vec<String>, NoUsbError> {
        Ok(self.boot_order.clone())
    }

    fn create_entry(
        &mut self,
        label: &str,
        _loader: &str,
        _mount: &EspMount,
    ) -> Result<String, NoUsbError> {
        self.check("create")?;
        let id = format!("{:04X}", self.entries.len());
        self.entries.push((id.clone(), label.into()));
        Ok(id)
    }

    fn arm_one_shot(&mut self, entry: &str) -> Result<(), NoUsbError> {
        self.check("arm")?;
        self.boot_next = Some(entry.into());
        Ok(())
    }

    fn pending_one_shot(&mut self) -> Result<Option<String>, NoUsbError> {
        Ok(self.boot_next.clone())
    }

    fn clear_one_shot(&mut self) -> Result<(), NoUsbError> {
        self.boot_next = None;
        Ok(())
    }

    fn delete_entry(&mut self, entry: &str) -> Result<(), NoUsbError> {
        self.check("delete")?;
        self.entries.retain(|(id, _)| id != entry);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UBUNTU_CFG: &str = "set timeout=30\nloadfont unicode\nmenuentry \"Try or Install Ubuntu\" {\n\tset gfxpayload=keep\n\tlinux\t/casper/vmlinuz  --- quiet splash\n\tinitrd\t/casper/initrd\n}\nmenuentry \"Ubuntu (safe graphics)\" {\n\tlinux /casper/vmlinuz nomodeset ---\n\tinitrd /casper/initrd\n}\n";
    const FEDORA_CFG: &str = "set default=\"1\"\nsearch --no-floppy --set=root -l 'Fedora-WS-Live-44-1-7'\nmenuentry 'Start Fedora-Workstation-Live 44' --class fedora {\n\tlinux ($root)/images/pxeboot/vmlinuz root=live:CDLABEL=Fedora-WS-Live-44-1-7 rd.live.image quiet rhgb\n\tinitrd ($root)/images/pxeboot/initrd.img\n}\nmenuentry 'Test this media & start' {\n\tlinux /images/pxeboot/vmlinuz root=live:CDLABEL=Fedora-WS-Live-44-1-7 rd.live.image rd.live.check quiet\n\tinitrd /images/pxeboot/initrd.img\n}\n";

    #[test]
    fn derives_casper_recipe_from_the_first_entry() {
        let recipe = derive_live_boot_recipe(UBUNTU_CFG, "/boot/grub/grub.cfg").unwrap();
        assert_eq!(recipe.family, LiveBootFamily::Casper);
        assert_eq!(recipe.kernel, "/casper/vmlinuz");
        assert_eq!(recipe.initrds, vec!["/casper/initrd"]);
        assert_eq!(recipe.kernel_args, vec!["---", "quiet", "splash"]);
    }

    #[test]
    fn derives_dracut_recipe_and_strips_root_prefix() {
        let recipe = derive_live_boot_recipe(FEDORA_CFG, "/EFI/BOOT/grub.cfg").unwrap();
        assert_eq!(recipe.family, LiveBootFamily::Dracut);
        assert_eq!(recipe.kernel, "/images/pxeboot/vmlinuz");
        assert_eq!(recipe.initrds, vec!["/images/pxeboot/initrd.img"]);
        assert!(recipe
            .kernel_args
            .contains(&"root=live:CDLABEL=Fedora-WS-Live-44-1-7".to_string()));
    }

    #[test]
    fn refuses_variables_unknown_families_and_traversal() {
        let variable = "menuentry x {\n linux /vmlinuz root=$foo\n initrd /initrd\n}\n";
        assert!(derive_live_boot_recipe(variable, "x").is_err());
        let unknown = "menuentry x {\n linux /vmlinuz quiet\n initrd /initrd\n}\n";
        assert!(derive_live_boot_recipe(unknown, "x").is_err());
        let traversal =
            "menuentry x {\n linux /casper/../../vmlinuz boot=casper\n initrd /initrd\n}\n";
        assert!(derive_live_boot_recipe(traversal, "x").is_err());
        assert!(derive_live_boot_recipe("set timeout=1\n", "x").is_err());
    }

    #[test]
    fn grub_config_inserts_iso_scan_before_the_separator() {
        let recipe = derive_live_boot_recipe(UBUNTU_CFG, "/boot/grub/grub.cfg").unwrap();
        let config = render_grub_config(
            "Ubuntu Desktop 24.04.4",
            &recipe,
            "/NoUSB/t/u.iso",
            "/NoUSB/t/m.marker",
            true,
        );
        assert!(config.contains(
            "linux (loop)/casper/vmlinuz iso-scan/filename=/NoUSB/t/u.iso toram --- quiet splash"
        ));
        assert!(config.contains("search --no-floppy --set=nousb_root --file /NoUSB/t/m.marker"));
        assert!(config.contains("loopback loop ($nousb_root)/NoUSB/t/u.iso"));
        assert!(config.contains("initrd (loop)/casper/initrd"));

        let fedora = derive_live_boot_recipe(FEDORA_CFG, "/EFI/BOOT/grub.cfg").unwrap();
        let config = render_grub_config("Fedora", &fedora, "/a.iso", "/m", false);
        assert!(config.contains("rd.live.image quiet rhgb iso-scan/filename=/a.iso\n"));
        assert!(!config.contains("rd.live.ram"));
    }

    fn facts(root: &Path) -> HostBootFacts {
        HostBootFacts {
            os_name: "linux".into(),
            elevated: true,
            firmware: FirmwareMode::Uefi,
            secure_boot: SecureBootState::Enabled,
            memory_total_mb: Some(4096),
            staging_volume_root: root.to_path_buf(),
            staging_grub_prefix: "/".into(),
            staging_filesystem: Some("ext4".into()),
            staging_volume_encrypted: Some(false),
            staging_free_bytes: Some(u64::MAX / 2),
        }
    }

    #[test]
    fn plan_reports_blockers_instead_of_waiving_them() {
        let dir = std::env::temp_dir().join(format!("nousb-hb-plan-{}", std::process::id()));
        let mut host = facts(&dir);
        host.elevated = false;
        host.firmware = FirmwareMode::Bios;
        host.staging_volume_encrypted = Some(true);
        let plan = plan_host_one_shot(
            "ubuntu-24.04-desktop",
            &dir.join("missing.iso"),
            &host,
            "fake",
            false,
        )
        .unwrap();
        assert!(!plan.ready());
        let text = plan.blockers.join("\n");
        for needle in [
            "verified ISO not found",
            "no real boot backend",
            "UEFI firmware was not detected",
            "not elevated",
            "is encrypted",
        ] {
            assert!(text.contains(needle), "missing blocker {needle}: {text}");
        }
        assert_eq!(
            plan.confirmation_phrase,
            "BOOT ONCE INTO ubuntu-24.04-desktop"
        );
        assert!(plan.write_disk_info);
        assert!(!plan.ram_copy);
        serde_json::from_str::<serde_json::Value>(&plan.to_json()).unwrap();
    }

    #[test]
    fn fat32_staging_blocks_large_iso() {
        let dir = std::env::temp_dir().join(format!("nousb-hb-fat32-{}", std::process::id()));
        let mut host = facts(&dir);
        host.staging_filesystem = Some("vfat".into());
        let plan = plan_host_one_shot(
            "ubuntu-24.04-desktop",
            &dir.join("missing.iso"),
            &host,
            "fake",
            true,
        )
        .unwrap();
        assert!(!plan.ready());
        assert!(plan
            .blockers
            .iter()
            .any(|blocker| blocker.contains("4 GiB single-file limit")));
        assert!(plan
            .blockers
            .iter()
            .any(|blocker| blocker.contains("this ISO is 6.2 GiB")));

        let (blockers, _) = host_preflight(
            &host,
            LiveBootFamily::Casper,
            (4.5 * 1024.0 * 1024.0 * 1024.0) as u64,
            true,
        );
        assert!(blockers.iter().any(|b| b.contains("this ISO is 4.5 GiB")));
    }

    #[test]
    fn arm_refuses_wrong_phrase_and_preflight_blockers() {
        let dir = std::env::temp_dir().join(format!("nousb-hb-arm-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let plan = plan_host_one_shot(
            "ubuntu-24.04-desktop",
            &dir.join("missing.iso"),
            &facts(&dir),
            "fake",
            true,
        )
        .unwrap();
        let mut backend = FakeHostBootBackend::new(facts(&dir), dir.join("esp"));
        let wrong = arm_host_one_shot(&dir, &plan, &mut backend, "yes").unwrap_err();
        assert!(wrong.to_string().contains("typed confirmation"));
        let blocked =
            arm_host_one_shot(&dir, &plan, &mut backend, &plan.confirmation_phrase).unwrap_err();
        assert!(blocked.to_string().contains("preflight blocked"));
        assert!(backend.entries.len() == 2 && backend.boot_next.is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    /// A plan for a small stand-in ISO, so the full transaction runs without a 6 GiB download.
    fn fixture_plan(dir: &Path) -> HostBootPlan {
        let iso = dir.join("source.iso");
        fs::write(&iso, b"stand-in iso bytes").unwrap();
        let mut plan = plan_host_one_shot(
            "ubuntu-24.04-desktop",
            &dir.join("missing.iso"),
            &facts(dir),
            "fake",
            true,
        )
        .unwrap();
        plan.iso_path = iso.clone();
        plan.iso_filename = "ubuntu.iso".into();
        plan.iso_size_bytes = fs::metadata(&iso).unwrap().len();
        plan.iso_sha256 = sha256_file(&iso).unwrap();
        plan.recipe = derive_live_boot_recipe(UBUNTU_CFG, "/boot/grub/grub.cfg").unwrap();
        plan.blockers.clear();
        plan
    }

    fn fake_extract(iso_file: &str, target: &Path) -> Result<bool, NoUsbError> {
        if iso_file.ends_with("mmx64.efi") {
            return Ok(false);
        }
        write_create_new(target, iso_file.as_bytes())?;
        Ok(true)
    }

    #[test]
    fn arm_then_cleanup_runs_the_whole_transaction() {
        let dir = std::env::temp_dir().join(format!("nousb-hb-e2e-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let esp = dir.join("esp");
        fs::create_dir_all(esp.join("EFI").join("Microsoft")).unwrap();
        let plan = fixture_plan(&dir);
        let mut backend = FakeHostBootBackend::new(facts(&dir), esp.clone());

        let state = arm_with_extractor(
            &dir,
            &plan,
            &mut backend,
            &plan.confirmation_phrase,
            &fake_extract,
        )
        .unwrap();
        assert_eq!(state.phase, HostBootPhase::Armed);
        let entry = state.entry_id.clone().unwrap();
        assert_eq!(backend.boot_next.as_deref(), Some(entry.as_str()));
        assert_eq!(backend.boot_order, vec!["0000", "0001"]);
        assert!(!backend.mounted);
        let loader = esp.join("EFI").join("NoUSB");
        assert!(loader.join("BOOTX64.EFI").exists());
        assert!(loader.join("grubx64.efi").exists());
        assert!(!loader.join("mmx64.efi").exists());
        let cfg = fs::read_to_string(loader.join("grub.cfg")).unwrap();
        assert!(cfg.contains("iso-scan/filename="));
        assert!(esp.join(".disk").join("info").exists());
        assert!(esp.join("boot").join("grub").join("grub.cfg").exists());
        let staged = dir.join(relative_native(&plan.staging_relative_dir));
        assert!(staged.join("ubuntu.iso").exists());
        assert_eq!(
            load_host_boot_state(&dir).unwrap().unwrap().phase,
            HostBootPhase::Armed
        );

        // A second arm is refused until cleanup.
        let again = arm_with_extractor(
            &dir,
            &plan,
            &mut backend,
            &plan.confirmation_phrase,
            &fake_extract,
        )
        .unwrap_err();
        assert!(again.to_string().contains("boot cleanup"));

        let cleaned =
            cleanup_host_one_shot(&dir, &mut backend, CLEANUP_CONFIRMATION_PHRASE).unwrap();
        assert_eq!(cleaned.phase, HostBootPhase::CleanedUp);
        assert!(backend.boot_next.is_none());
        assert_eq!(backend.entries.len(), 2);
        assert!(!loader.exists());
        assert!(!esp.join(".disk").exists());
        assert!(!esp.join("boot").exists());
        assert!(esp.join("EFI").join("Microsoft").exists());
        assert!(!dir.join("NoUSB").exists());
        assert!(dir.join("source.iso").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn failure_at_every_step_rolls_back_completely() {
        for failure in ["backup", "mount", "create", "arm"] {
            let dir = std::env::temp_dir()
                .join(format!("nousb-hb-fail-{failure}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            let esp = dir.join("esp");
            fs::create_dir_all(esp.join("EFI")).unwrap();
            let plan = fixture_plan(&dir);
            let mut backend = FakeHostBootBackend::new(facts(&dir), esp.clone());
            backend.fail_on = Some(failure.into());
            let error = arm_with_extractor(
                &dir,
                &plan,
                &mut backend,
                &plan.confirmation_phrase,
                &fake_extract,
            )
            .unwrap_err();
            assert!(
                error.to_string().contains("rolled back"),
                "{failure}: {error}"
            );
            let state = load_host_boot_state(&dir).unwrap().unwrap();
            assert_eq!(state.phase, HostBootPhase::RolledBack, "{failure}");
            assert!(backend.boot_next.is_none(), "{failure}");
            assert_eq!(backend.entries.len(), 2, "{failure}");
            assert!(
                !backend.mounted,
                "{failure}: ESP was not unmounted on rollback"
            );
            assert!(!esp.join("EFI").join("NoUSB").exists(), "{failure}");
            assert!(!dir.join("NoUSB").exists(), "{failure}");
            let _ = fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn existing_esp_directory_is_never_overwritten() {
        let dir = std::env::temp_dir().join(format!("nousb-hb-exists-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let esp = dir.join("esp");
        fs::create_dir_all(esp.join("EFI").join("NoUSB")).unwrap();
        fs::write(esp.join("EFI").join("NoUSB").join("keep.txt"), "user file").unwrap();
        let plan = fixture_plan(&dir);
        let mut backend = FakeHostBootBackend::new(facts(&dir), esp.clone());
        let error = arm_with_extractor(
            &dir,
            &plan,
            &mut backend,
            &plan.confirmation_phrase,
            &fake_extract,
        )
        .unwrap_err();
        assert!(error.to_string().contains("refusing to overwrite"));
        assert_eq!(
            fs::read_to_string(esp.join("EFI").join("NoUSB").join("keep.txt")).unwrap(),
            "user file"
        );
        assert!(backend.boot_next.is_none());
        assert!(
            !backend.mounted,
            "ESP was not unmounted when loader dir already existed"
        );
        assert!(
            !dir.join("NoUSB").exists(),
            "staging directory should not be created if ESP check fails fast"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn undo_removes_entry_selector_and_files_idempotently() {
        let dir = std::env::temp_dir().join(format!("nousb-hb-undo-{}", std::process::id()));
        let esp = dir.join("esp");
        fs::create_dir_all(esp.join("EFI").join("NoUSB")).unwrap();
        fs::write(esp.join("EFI").join("NoUSB").join("grub.cfg"), "x").unwrap();
        let staged = dir.join("NoUSB");
        fs::create_dir_all(&staged).unwrap();
        fs::write(staged.join("u.iso"), "iso").unwrap();
        let mut backend = FakeHostBootBackend::new(facts(&dir), esp.clone());
        let entry = backend
            .create_entry(
                HOST_BOOT_ENTRY_LABEL,
                "\\EFI\\NoUSB\\BOOTX64.EFI",
                &EspMount {
                    path: esp.clone(),
                    mounted_by_us: true,
                },
            )
            .unwrap();
        backend.arm_one_shot(&entry).unwrap();
        let mut state = HostBootState {
            plan_id: "p".into(),
            profile_id: "ubuntu-24.04-desktop".into(),
            backend: "fake".into(),
            phase: HostBootPhase::Armed,
            boot_order_before: backend.boot_order.clone(),
            entry_id: Some(entry),
            armed: true,
            esp_mount: None,
            created_files: vec![staged.join("u.iso")],
            created_dirs: vec![staged.clone()],
            esp_files: vec!["EFI/NoUSB/grub.cfg".into()],
            esp_dirs: vec!["EFI/NoUSB".into()],
            backup_files: vec![],
            events: vec![],
            updated_at: 0,
        };
        save_state(&dir, &mut state, "test armed").unwrap();
        assert!(cleanup_host_one_shot(&dir, &mut backend, "cleanup").is_err());
        let cleaned =
            cleanup_host_one_shot(&dir, &mut backend, CLEANUP_CONFIRMATION_PHRASE).unwrap();
        assert_eq!(cleaned.phase, HostBootPhase::CleanedUp);
        assert!(backend.boot_next.is_none());
        assert_eq!(backend.entries.len(), 2);
        assert!(!esp.join("EFI").join("NoUSB").exists());
        assert!(esp.join("EFI").exists());
        assert!(!staged.exists());
        assert_eq!(backend.boot_order, vec!["0000", "0001"]);
        // Second run is a no-op.
        cleanup_host_one_shot(&dir, &mut backend, CLEANUP_CONFIRMATION_PHRASE).unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn existing_disk_info_and_grub_cfg_fail_fast_before_staging() {
        for (rel_dir, file_name) in [(".disk", "info"), ("boot/grub", "grub.cfg")] {
            let dir = std::env::temp_dir().join(format!(
                "nousb-hb-collision-{}-{}-{}",
                rel_dir.replace('/', "-"),
                file_name,
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&dir);
            let esp = dir.join("esp");
            let target_dir = esp.join(relative_native(rel_dir));
            fs::create_dir_all(&target_dir).unwrap();
            fs::create_dir_all(esp.join("EFI")).unwrap();
            let target_file = target_dir.join(file_name);
            fs::write(&target_file, "existing file content").unwrap();

            let plan = fixture_plan(&dir);
            assert!(plan.write_disk_info);
            let mut backend = FakeHostBootBackend::new(facts(&dir), esp.clone());
            let error = arm_with_extractor(
                &dir,
                &plan,
                &mut backend,
                &plan.confirmation_phrase,
                &fake_extract,
            )
            .unwrap_err();

            assert!(
                error.to_string().contains("already exists on the ESP"),
                "expected collision error, got: {error}"
            );
            assert_eq!(
                fs::read_to_string(&target_file).unwrap(),
                "existing file content",
                "existing file was overwritten"
            );
            assert!(
                !backend.mounted,
                "ESP was not unmounted when collision occurred"
            );
            assert!(
                !dir.join("NoUSB").exists(),
                "staging directory should not be created if ESP check fails fast"
            );
            let _ = fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn cleanup_after_crash_unmounts_saved_mount_path_in_fresh_backend() {
        let dir = std::env::temp_dir().join(format!("nousb-hb-crash-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let esp_x = dir.join("esp-x");
        let esp_y = dir.join("esp-y");
        fs::create_dir_all(esp_x.join("EFI").join("NoUSB")).unwrap();
        fs::write(esp_x.join("EFI").join("NoUSB").join("grub.cfg"), "grub").unwrap();
        fs::create_dir_all(esp_y.join("EFI").join("NoUSB")).unwrap();
        fs::write(esp_y.join("EFI").join("NoUSB").join("grub.cfg"), "grub").unwrap();

        // Process 1 crashed while ESP was mounted at esp_x
        let mut state = HostBootState {
            plan_id: "crash-test".into(),
            profile_id: "ubuntu-24.04-desktop".into(),
            backend: "fake".into(),
            phase: HostBootPhase::Preparing,
            boot_order_before: vec!["0000".into(), "0001".into()],
            entry_id: None,
            armed: false,
            esp_mount: Some(EspMount {
                path: esp_x.clone(),
                mounted_by_us: true,
            }),
            created_files: vec![],
            created_dirs: vec![],
            esp_files: vec!["EFI/NoUSB/grub.cfg".into()],
            esp_dirs: vec!["EFI/NoUSB".into()],
            backup_files: vec![],
            events: vec![],
            updated_at: 0,
        };
        save_state(&dir, &mut state, "process 1 crashed").unwrap();

        // Process 2 restarts with a fresh backend; esp_x was left mounted by the crashed process
        let mut backend2 = FakeHostBootBackend::new(facts(&dir), esp_y.clone());
        backend2.mounted_paths = vec![esp_x.clone()];
        backend2.mounted = true;

        let cleaned =
            cleanup_host_one_shot(&dir, &mut backend2, CLEANUP_CONFIRMATION_PHRASE).unwrap();
        assert_eq!(cleaned.phase, HostBootPhase::CleanedUp);
        assert!(
            backend2.mounted_paths.is_empty(),
            "both the new mount and the saved mount from before the crash should be unmounted: {:?}",
            backend2.mounted_paths
        );
        assert!(!backend2.mounted);
        assert_eq!(load_host_boot_state(&dir).unwrap().unwrap().esp_mount, None);

        // Also test crash when esp_files is empty (e.g. process crashed before extracting loaders)
        let mut state_empty = HostBootState {
            plan_id: "crash-empty".into(),
            profile_id: "ubuntu-24.04-desktop".into(),
            backend: "fake".into(),
            phase: HostBootPhase::Preparing,
            boot_order_before: vec!["0000".into(), "0001".into()],
            entry_id: None,
            armed: false,
            esp_mount: Some(EspMount {
                path: esp_x.clone(),
                mounted_by_us: true,
            }),
            created_files: vec![],
            created_dirs: vec![],
            esp_files: vec![],
            esp_dirs: vec![],
            backup_files: vec![],
            events: vec![],
            updated_at: 0,
        };
        save_state(&dir, &mut state_empty, "crashed before files staged").unwrap();

        let mut backend3 = FakeHostBootBackend::new(facts(&dir), esp_y.clone());
        backend3.mounted_paths = vec![esp_x.clone()];
        backend3.mounted = true;

        let cleaned =
            cleanup_host_one_shot(&dir, &mut backend3, CLEANUP_CONFIRMATION_PHRASE).unwrap();
        assert_eq!(cleaned.phase, HostBootPhase::CleanedUp);
        assert!(
            backend3.mounted_paths.is_empty(),
            "saved mount should be unmounted directly without calling mount_esp: {:?}",
            backend3.mounted_paths
        );
        assert!(!backend3.mounted);
        assert_eq!(load_host_boot_state(&dir).unwrap().unwrap().esp_mount, None);

        let _ = fs::remove_dir_all(&dir);
    }
}
