use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use iso9660_simple::{ISODirectoryEntry, Read as IsoRead, ISO9660};
use reqwest::blocking::{Client, Response};
use reqwest::header::{ACCEPT_RANGES, CONTENT_LENGTH, RANGE};
use reqwest::redirect::Policy;
use reqwest::StatusCode;
use sha2::{Digest, Sha256};

mod boot_hints;
mod host_boot;
mod journal;
mod provenance;
mod qemu;
mod recovery;
pub use boot_hints::{
    parse_efi_boot_order, parse_efi_load_option, BootEnvironmentHints, EfiBootTarget,
    EfiLoadOption, EFI_GLOBAL_VARIABLE_GUID,
};
pub use host_boot::{
    arm_confirmation_phrase, arm_host_one_shot, cleanup_host_one_shot, derive_live_boot_recipe,
    host_boot_dir, host_boot_state_path, load_host_boot_state, plan_host_one_shot,
    render_grub_config, CommandOutput, CommandRunner, EspMount, FakeHostBootBackend,
    HostBootBackend, HostBootFacts, HostBootPhase, HostBootPlan, HostBootState, LiveBootFamily,
    LiveBootRecipe, PlannedFile, ScriptedCommandRunner, SystemCommandRunner,
    CLEANUP_CONFIRMATION_PHRASE, HOST_BOOT_ENTRY_LABEL, HOST_BOOT_ESP_DIR, HOST_BOOT_STAGING_DIR,
};
pub use journal::{
    journal_database_path, journal_execution_report, migrate_saved_reports, open_journal,
    record_execution_report, write_journal_entry, JournalMigration,
};
pub use provenance::{
    checksum_document_lists, fetch_https_bytes, pinned_signing_key, verify_cleartext_signature,
    verify_detached_signature, verify_profile_signature, ChecksumSignatureFormat, PinnedSigningKey,
    SignatureVerification, PINNED_SIGNING_KEYS,
};
pub use qemu::{
    acquire_qemu_windows_runtime, qemu_runtime_cache_path, qemu_windows_runtime_manifest,
    QemuRuntimeDownload, QemuRuntimeManifest,
};
pub use recovery::{
    assess_recovery, load_execution_report, parse_execution_report, resume_simulated_report,
    RecoveryAction, RecoveryAssessment,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FirmwareMode {
    Uefi,
    Bios,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecureBootState {
    Enabled,
    Disabled,
    Unsupported,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EncryptionState {
    Enabled(String),
    Disabled,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartitionInfo {
    pub name: String,
    pub mount_point: Option<String>,
    pub filesystem: Option<String>,
    pub size_bytes: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiskInventory {
    pub disks: Vec<String>,
    pub partitions: Vec<PartitionInfo>,
    pub available_space_gb: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootEntry {
    pub id: String,
    pub label: String,
    pub is_default: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemInventory {
    pub os_name: String,
    pub arch: String,
    pub memory_total_mb: Option<u64>,
    pub firmware: FirmwareMode,
    pub secure_boot: SecureBootState,
    pub encryption: EncryptionState,
    pub disk_inventory: DiskInventory,
    pub boot_entries: Vec<BootEntry>,
    pub boot_hints: BootEnvironmentHints,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StagingStrategy {
    ExtractedEfiInstaller,
    IsoLoopback,
    KernelInitrd,
    WindowsMountedIsoSetup,
    MacosStartosinstall,
    ManualInstructions,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlatformCapability {
    OneTimeBoot,
    BootEntryBackup,
    RecoveryPack,
    Snapshot,
    EncryptionStatus,
    SecureBootDetection,
    InstallerVerification,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeliveryReadiness {
    DesignCandidate,
    RequiresHostCapability,
    Unsupported,
    OutOfScope,
}

impl DeliveryReadiness {
    pub fn as_str(&self) -> &'static str {
        match self {
            DeliveryReadiness::DesignCandidate => "design_candidate",
            DeliveryReadiness::RequiresHostCapability => "requires_host_capability",
            DeliveryReadiness::Unsupported => "unsupported",
            DeliveryReadiness::OutOfScope => "out_of_scope",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PayloadResidency {
    FullLiveMediaInRam,
    BootEnvironmentInRam,
    PersistentStaging,
    FirmwareManaged,
}

impl PayloadResidency {
    pub fn as_str(&self) -> &'static str {
        match self {
            PayloadResidency::FullLiveMediaInRam => "full_live_media_in_ram",
            PayloadResidency::BootEnvironmentInRam => "boot_environment_in_ram",
            PayloadResidency::PersistentStaging => "persistent_staging",
            PayloadResidency::FirmwareManaged => "firmware_managed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeliveryRoute {
    pub id: String,
    pub name: String,
    pub readiness: DeliveryReadiness,
    pub payload_residency: PayloadResidency,
    pub requires_persistent_staging: bool,
    pub requirements: Vec<String>,
    pub limitations: Vec<String>,
    pub reference_urls: Vec<String>,
}

impl DeliveryRoute {
    pub fn to_json(&self) -> String {
        format!(
            "{{{},{},\"readiness\":\"{}\",\"payload_residency\":\"{}\",\"requires_persistent_staging\":{},\"requirements\":{},\"limitations\":{},\"reference_urls\":{}}}",
            json_pair("id", &self.id),
            json_pair("name", &self.name),
            self.readiness.as_str(),
            self.payload_residency.as_str(),
            self.requires_persistent_staging,
            json_string_array(&self.requirements),
            json_string_array(&self.limitations),
            json_string_array(&self.reference_urls)
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeliveryAssessment {
    pub host_os: String,
    pub profile_id: String,
    pub recommended_route: Option<String>,
    pub safe_default_execution_enabled: bool,
    pub universal_no_usb_guarantee: bool,
    pub summary: String,
    pub routes: Vec<DeliveryRoute>,
}

impl DeliveryAssessment {
    pub fn preview(&self) -> String {
        let mut output = format!(
            "Delivery assessment\nHost: {}\nProfile: {}\nExecution enabled: {}\nUniversal no-USB guarantee: {}\n",
            self.host_os,
            self.profile_id,
            self.safe_default_execution_enabled,
            self.universal_no_usb_guarantee
        );
        match &self.recommended_route {
            Some(route) => output.push_str(&format!("Recommended design route: {route}\n")),
            None => {
                output.push_str("Recommended design route: none until capability checks pass\n")
            }
        }
        output.push_str(&format!("Summary: {}\nRoutes:\n", self.summary));
        for route in &self.routes {
            output.push_str(&format!(
                "- {} [{}]: {}\n  payload: {}; persistent staging: {}\n",
                route.id,
                route.readiness.as_str(),
                route.name,
                route.payload_residency.as_str(),
                route.requires_persistent_staging
            ));
            for limitation in &route.limitations {
                output.push_str(&format!("  limitation: {limitation}\n"));
            }
        }
        output
    }

    pub fn to_json(&self) -> String {
        let routes: Vec<String> = self.routes.iter().map(DeliveryRoute::to_json).collect();
        format!(
            "{{{},{},\"recommended_route\":{},\"safe_default_execution_enabled\":{},\"universal_no_usb_guarantee\":{},{},\"routes\":[{}]}}",
            json_pair("host_os", &self.host_os),
            json_pair("profile_id", &self.profile_id),
            json_optional_value(self.recommended_route.as_deref()),
            self.safe_default_execution_enabled,
            self.universal_no_usb_guarantee,
            json_pair("summary", &self.summary),
            routes.join(",")
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallerProfile {
    pub schema_version: String,
    pub id: String,
    pub name: String,
    pub vendor: String,
    pub version: String,
    pub architecture: String,
    pub source_url: String,
    pub checksum_url: String,
    pub sha256: String,
    pub artifact_filename: Option<String>,
    pub artifact_size_bytes: Option<u64>,
    pub signature_url: Option<String>,
    /// Id of the pinned vendor key that signs the checksum document (see `provenance`).
    pub signing_key: Option<String>,
    pub homepage: String,
    pub license_notes: String,
    pub supported_platforms: Vec<String>,
    pub supported_staging_strategies: Vec<StagingStrategy>,
    pub required_free_space_gb: u32,
    pub extraction_rules: Vec<String>,
    pub kernel_initrd_paths: Vec<String>,
    pub bootloader_paths: Vec<String>,
    pub secure_boot_notes: String,
    pub known_limitations: Vec<String>,
    pub post_boot_instructions: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactManifest {
    pub profile_id: String,
    pub filename: String,
    pub source_url: String,
    pub checksum_url: String,
    pub signature_url: Option<String>,
    pub sha256: String,
    pub size_bytes: u64,
}

impl ArtifactManifest {
    pub fn to_json(&self) -> String {
        format!(
            "{{{},{},{},{},\"signature_url\":{},{},\"size_bytes\":{}}}",
            json_pair("profile_id", &self.profile_id),
            json_pair("filename", &self.filename),
            json_pair("source_url", &self.source_url),
            json_pair("checksum_url", &self.checksum_url),
            json_optional_value(self.signature_url.as_deref()),
            json_pair("sha256", &self.sha256),
            self.size_bytes
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactProbe {
    pub manifest: ArtifactManifest,
    pub final_url: String,
    pub content_length: Option<u64>,
    pub accepts_ranges: bool,
}

impl ArtifactProbe {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"manifest\":{}, {},\"content_length\":{},\"accepts_ranges\":{}}}",
            self.manifest.to_json(),
            json_pair("final_url", &self.final_url),
            self.content_length
                .map(|value| value.to_string())
                .unwrap_or_else(|| "null".into()),
            self.accepts_ranges
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactDownload {
    pub manifest: ArtifactManifest,
    pub path: PathBuf,
    pub resumed_from_bytes: u64,
    pub downloaded_bytes: u64,
    pub verified: bool,
    pub already_present: bool,
}

impl ArtifactDownload {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"manifest\":{},{},\"resumed_from_bytes\":{},\"downloaded_bytes\":{},\"verified\":{},\"already_present\":{}}}",
            self.manifest.to_json(),
            json_pair("path", &self.path.display().to_string()),
            self.resumed_from_bytes,
            self.downloaded_bytes,
            self.verified,
            self.already_present
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagingAsset {
    pub source_path: String,
    pub size_bytes: u64,
    pub output_path: Option<PathBuf>,
    pub sha256: Option<String>,
}

impl StagingAsset {
    pub fn to_json(&self) -> String {
        format!(
            "{{{},\"size_bytes\":{},\"output_path\":{},\"sha256\":{}}}",
            json_pair("source_path", &self.source_path),
            self.size_bytes,
            json_optional_value(
                self.output_path
                    .as_ref()
                    .map(|path| path.display().to_string())
                    .as_deref()
            ),
            json_optional_value(self.sha256.as_deref())
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagingPreview {
    pub profile_id: String,
    pub artifact_path: PathBuf,
    pub artifact_verified: bool,
    pub assets: Vec<StagingAsset>,
    pub execution_enabled: bool,
}

impl StagingPreview {
    pub fn to_json(&self) -> String {
        let assets: Vec<String> = self.assets.iter().map(StagingAsset::to_json).collect();
        format!(
            "{{{},{},\"artifact_verified\":{},\"assets\":[{}],\"execution_enabled\":{}}}",
            json_pair("profile_id", &self.profile_id),
            json_pair("artifact_path", &self.artifact_path.display().to_string()),
            self.artifact_verified,
            assets.join(","),
            self.execution_enabled
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagingBundle {
    pub profile_id: String,
    pub path: PathBuf,
    pub artifact_path: PathBuf,
    pub artifact_sha256: String,
    pub assets: Vec<StagingAsset>,
    pub execution_enabled: bool,
}

impl StagingBundle {
    pub fn to_json(&self) -> String {
        let assets: Vec<String> = self.assets.iter().map(StagingAsset::to_json).collect();
        format!(
            "{{{},{},{},{},\"assets\":[{}],\"execution_enabled\":{}}}",
            json_pair("profile_id", &self.profile_id),
            json_pair("path", &self.path.display().to_string()),
            json_pair("artifact_path", &self.artifact_path.display().to_string()),
            json_pair("artifact_sha256", &self.artifact_sha256),
            assets.join(","),
            self.execution_enabled
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OneShotBootBackend {
    UefiBootNext,
    WindowsBcdBootSequence,
    LinuxSystemdBootOneShot,
    LinuxGrubReboot,
}

impl OneShotBootBackend {
    pub fn id(&self) -> &'static str {
        match self {
            Self::UefiBootNext => "uefi-bootnext",
            Self::WindowsBcdBootSequence => "windows-bcd-bootsequence",
            Self::LinuxSystemdBootOneShot => "linux-systemd-boot-oneshot",
            Self::LinuxGrubReboot => "linux-grub-reboot",
        }
    }

    pub fn parse(value: &str) -> Result<Self, NoUsbError> {
        match value {
            "uefi-bootnext" => Ok(Self::UefiBootNext),
            "windows-bcd-bootsequence" => Ok(Self::WindowsBcdBootSequence),
            "linux-systemd-boot-oneshot" => Ok(Self::LinuxSystemdBootOneShot),
            "linux-grub-reboot" => Ok(Self::LinuxGrubReboot),
            _ => Err(NoUsbError::InvalidInput(format!(
                "unknown one-shot backend {value}; expected uefi-bootnext, windows-bcd-bootsequence, linux-systemd-boot-oneshot, or linux-grub-reboot"
            ))),
        }
    }

    fn reference_url(&self) -> &'static str {
        match self {
            Self::UefiBootNext => "https://uefi.org/specs/UEFI/2.11/03_Boot_Manager.html",
            Self::WindowsBcdBootSequence => {
                "https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--bootsequence"
            }
            Self::LinuxSystemdBootOneShot => {
                "https://www.freedesktop.org/software/systemd/man/latest/bootctl.html"
            }
            Self::LinuxGrubReboot => "https://www.gnu.org/software/grub/manual/grub/grub.html",
        }
    }
}

impl fmt::Display for OneShotBootBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmRehearsalScenario {
    pub id: String,
    pub failure_after: Option<String>,
    pub events: Vec<String>,
    pub recovered: bool,
    pub original_default_preserved: bool,
    pub boot_order_preserved: bool,
    pub one_shot_cleared: bool,
    pub temporary_entry_removed: bool,
    pub staged_assets_removed: bool,
    pub installer_attempted: bool,
    pub ram_payload_observed: bool,
    pub fallback_observed: bool,
    pub invariants_hold: bool,
}

impl VmRehearsalScenario {
    pub fn to_json(&self) -> String {
        format!(
            "{{{},\"failure_after\":{},\"events\":{},\"recovered\":{},\"original_default_preserved\":{},\"boot_order_preserved\":{},\"one_shot_cleared\":{},\"temporary_entry_removed\":{},\"staged_assets_removed\":{},\"installer_attempted\":{},\"ram_payload_observed\":{},\"fallback_observed\":{},\"invariants_hold\":{}}}",
            json_pair("id", &self.id),
            json_optional_value(self.failure_after.as_deref()),
            json_string_array(&self.events),
            self.recovered,
            self.original_default_preserved,
            self.boot_order_preserved,
            self.one_shot_cleared,
            self.temporary_entry_removed,
            self.staged_assets_removed,
            self.installer_attempted,
            self.ram_payload_observed,
            self.fallback_observed,
            self.invariants_hold
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmRehearsalReport {
    pub id: String,
    pub backend: OneShotBootBackend,
    pub profile_id: String,
    pub scenarios: Vec<VmRehearsalScenario>,
    pub all_invariants_hold: bool,
    pub real_vm_executed: bool,
    pub host_boot_changes: bool,
    pub reference_urls: Vec<String>,
}

impl VmRehearsalReport {
    pub fn to_json(&self) -> String {
        let scenarios = self
            .scenarios
            .iter()
            .map(VmRehearsalScenario::to_json)
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{{},{},{},\"scenarios\":[{}],\"all_invariants_hold\":{},\"real_vm_executed\":{},\"host_boot_changes\":{},\"reference_urls\":{}}}",
            json_pair("id", &self.id),
            json_pair("backend", self.backend.id()),
            json_pair("profile_id", &self.profile_id),
            scenarios,
            self.all_invariants_hold,
            self.real_vm_executed,
            self.host_boot_changes,
            json_string_array(&self.reference_urls)
        )
    }

    pub fn preview(&self) -> String {
        let mut output = String::new();
        output.push_str("VM one-shot boot rehearsal\n");
        output.push_str(&format!("Backend: {}\n", self.backend));
        output.push_str(&format!("Profile: {}\n", self.profile_id));
        output.push_str(&format!("Scenarios: {}\n", self.scenarios.len()));
        output.push_str(&format!(
            "All recovery invariants hold: {}\n",
            self.all_invariants_hold
        ));
        output.push_str("Real VM executed: false\nHost boot changes: false\n");
        for scenario in &self.scenarios {
            output.push_str(&format!(
                "- {}: invariants={} fallback={} ram={}\n",
                scenario.id,
                scenario.invariants_hold,
                scenario.fallback_observed,
                scenario.ram_payload_observed
            ));
        }
        output
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            RiskLevel::Info => "info",
            RiskLevel::Low => "low",
            RiskLevel::Medium => "medium",
            RiskLevel::High => "high",
            RiskLevel::Critical => "critical",
        };
        f.write_str(value)
    }
}

impl RiskLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::Info => "info",
            RiskLevel::Low => "low",
            RiskLevel::Medium => "medium",
            RiskLevel::High => "high",
            RiskLevel::Critical => "critical",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfirmationRequirement {
    None,
    SimpleYes,
    TypePhrase(String),
    TypeTargetLabel(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RollbackAction {
    None,
    RemoveStagedFiles,
    RestoreBootBackup,
    Manual(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StepState {
    Pending,
    Running,
    Completed,
    Failed,
    RolledBack,
    ManualInterventionRequired,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationStep {
    pub id: String,
    pub title: String,
    pub description: String,
    pub risk: RiskLevel,
    pub modifies: Vec<String>,
    pub rollback: RollbackAction,
    pub state: StepState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BootPlanPreference {
    OneTimeBoot,
    TemporaryBootEntryWithFallback,
    ExistingBootManagerOneShot,
    ManualInstructionsOnly,
}

impl BootPlanPreference {
    pub fn as_str(&self) -> &'static str {
        match self {
            BootPlanPreference::OneTimeBoot => "one_time_boot",
            BootPlanPreference::TemporaryBootEntryWithFallback => {
                "temporary_boot_entry_with_fallback"
            }
            BootPlanPreference::ExistingBootManagerOneShot => "existing_boot_manager_one_shot",
            BootPlanPreference::ManualInstructionsOnly => "manual_instructions_only",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootPlan {
    pub preference_order: Vec<BootPlanPreference>,
    pub selected_preference: BootPlanPreference,
    pub keep_current_os_default: bool,
    pub allow_permanent_boot_order_change: bool,
    pub fallback_description: String,
    pub backup_requirements: Vec<String>,
    pub manual_instructions: Vec<String>,
}

impl BootPlan {
    pub fn safe_default(kind: &OperationKind) -> Self {
        let selected_preference = match kind {
            OperationKind::BootOnce => BootPlanPreference::OneTimeBoot,
            OperationKind::DualBoot
            | OperationKind::ReplaceOs
            | OperationKind::ReinstallCurrentOs => {
                BootPlanPreference::TemporaryBootEntryWithFallback
            }
            OperationKind::RecoveryPack => BootPlanPreference::ManualInstructionsOnly,
        };

        Self {
            preference_order: vec![
                BootPlanPreference::OneTimeBoot,
                BootPlanPreference::TemporaryBootEntryWithFallback,
                BootPlanPreference::ExistingBootManagerOneShot,
                BootPlanPreference::ManualInstructionsOnly,
            ],
            selected_preference,
            keep_current_os_default: true,
            allow_permanent_boot_order_change: false,
            fallback_description:
                "Keep the current OS as the default boot target; if staged boot fails, firmware should return to the existing OS path."
                    .into(),
            backup_requirements: vec![
                "Back up existing boot entries before editing boot metadata.".into(),
                "Back up bootloader or BCD configuration before any real adapter executes.".into(),
                "Back up touched EFI System Partition files before modification.".into(),
            ],
            manual_instructions: vec![
                "Use firmware boot menu to return to the current OS if automated one-time boot is unavailable.".into(),
                "Do not make installer media the permanent default in the safe default build.".into(),
            ],
        }
    }

    pub fn to_json(&self) -> String {
        let preference_order: Vec<String> = self
            .preference_order
            .iter()
            .map(|preference| preference.as_str().to_string())
            .collect();
        format!(
            "{{\"preference_order\":{},\"selected_preference\":\"{}\",\"keep_current_os_default\":{},\"allow_permanent_boot_order_change\":{}, {},\"backup_requirements\":{},\"manual_instructions\":{}}}",
            json_string_array(&preference_order),
            self.selected_preference.as_str(),
            self.keep_current_os_default,
            self.allow_permanent_boot_order_change,
            json_pair("fallback_description", &self.fallback_description),
            json_string_array(&self.backup_requirements),
            json_string_array(&self.manual_instructions)
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OperationKind {
    BootOnce,
    DualBoot,
    ReplaceOs,
    ReinstallCurrentOs,
    RecoveryPack,
}

impl fmt::Display for OperationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            OperationKind::BootOnce => "boot-once",
            OperationKind::DualBoot => "dual-boot",
            OperationKind::ReplaceOs => "replace-os",
            OperationKind::ReinstallCurrentOs => "reinstall-current-os",
            OperationKind::RecoveryPack => "recovery-pack",
        };
        f.write_str(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationPlan {
    pub id: String,
    pub kind: OperationKind,
    pub profile_id: Option<String>,
    pub risk: RiskLevel,
    pub required_privileges: Vec<String>,
    pub confirmation: ConfirmationRequirement,
    pub warnings: Vec<String>,
    pub boot_plan: Option<BootPlan>,
    pub steps: Vec<OperationStep>,
}

impl OperationPlan {
    pub fn preview(&self) -> String {
        let mut output = String::new();
        output.push_str(&format!("Plan: {}\nRisk: {}\n", self.id, self.risk));
        if !self.required_privileges.is_empty() {
            output.push_str(&format!(
                "Privileges: {}\n",
                self.required_privileges.join(", ")
            ));
        }
        if !self.warnings.is_empty() {
            output.push_str("Warnings:\n");
            for warning in &self.warnings {
                output.push_str(&format!("- {warning}\n"));
            }
        }
        if let Some(boot_plan) = &self.boot_plan {
            output.push_str("Boot safety:\n");
            output.push_str(&format!(
                "- selected: {}\n- keep current OS default: {}\n- permanent boot order change allowed: {}\n",
                boot_plan.selected_preference.as_str(),
                boot_plan.keep_current_os_default,
                boot_plan.allow_permanent_boot_order_change
            ));
        }
        output.push_str("Steps:\n");
        for step in &self.steps {
            output.push_str(&format!("- [{}] {}: {}\n", step.risk, step.id, step.title));
            if !step.modifies.is_empty() {
                output.push_str(&format!("  modifies: {}\n", step.modifies.join(", ")));
            }
        }
        output
    }

    pub fn to_json(&self) -> String {
        let mut output = String::new();
        output.push('{');
        output.push_str(&json_pair("id", &self.id));
        output.push_str(&format!(",\"kind\":\"{}\"", self.kind));
        match &self.profile_id {
            Some(profile_id) => {
                output.push_str(&format!(",{}", json_pair("profile_id", profile_id)))
            }
            None => output.push_str(",\"profile_id\":null"),
        }
        output.push_str(&format!(",\"risk\":\"{}\"", self.risk.as_str()));
        output.push_str(",\"required_privileges\":");
        output.push_str(&json_string_array(&self.required_privileges));
        output.push_str(",\"confirmation\":");
        output.push_str(&self.confirmation.to_json());
        output.push_str(",\"warnings\":");
        output.push_str(&json_string_array(&self.warnings));
        output.push_str(",\"boot_plan\":");
        match &self.boot_plan {
            Some(boot_plan) => output.push_str(&boot_plan.to_json()),
            None => output.push_str("null"),
        }
        output.push_str(",\"steps\":[");
        for (index, step) in self.steps.iter().enumerate() {
            if index > 0 {
                output.push(',');
            }
            output.push_str(&step.to_json());
        }
        output.push_str("]}");
        output
    }
}

impl ConfirmationRequirement {
    pub fn permits_yes_flag(&self, risk: RiskLevel) -> bool {
        matches!(
            self,
            ConfirmationRequirement::None | ConfirmationRequirement::SimpleYes
        ) && risk <= RiskLevel::Low
    }

    pub fn to_json(&self) -> String {
        match self {
            ConfirmationRequirement::None => "{\"type\":\"none\"}".into(),
            ConfirmationRequirement::SimpleYes => "{\"type\":\"simple_yes\"}".into(),
            ConfirmationRequirement::TypePhrase(phrase) => {
                format!(
                    "{{\"type\":\"type_phrase\",{}}}",
                    json_pair("phrase", phrase)
                )
            }
            ConfirmationRequirement::TypeTargetLabel(label) => {
                format!(
                    "{{\"type\":\"type_target_label\",{}}}",
                    json_pair("label", label)
                )
            }
        }
    }
}

impl OperationStep {
    pub fn to_json(&self) -> String {
        format!(
            "{{{},{},{},\"risk\":\"{}\",\"modifies\":{},\"rollback\":{},\"state\":\"{}\"}}",
            json_pair("id", &self.id),
            json_pair("title", &self.title),
            json_pair("description", &self.description),
            self.risk.as_str(),
            json_string_array(&self.modifies),
            self.rollback.to_json(),
            self.state.as_str()
        )
    }
}

impl StepState {
    pub fn as_str(&self) -> &'static str {
        match self {
            StepState::Pending => "pending",
            StepState::Running => "running",
            StepState::Completed => "completed",
            StepState::Failed => "failed",
            StepState::RolledBack => "rolled_back",
            StepState::ManualInterventionRequired => "manual_intervention_required",
        }
    }
}

impl RollbackAction {
    pub fn to_json(&self) -> String {
        match self {
            RollbackAction::None => "{\"type\":\"none\"}".into(),
            RollbackAction::RemoveStagedFiles => "{\"type\":\"remove_staged_files\"}".into(),
            RollbackAction::RestoreBootBackup => "{\"type\":\"restore_boot_backup\"}".into(),
            RollbackAction::Manual(note) => {
                format!("{{\"type\":\"manual\",{}}}", json_pair("note", note))
            }
        }
    }
}

impl InstallerProfile {
    pub fn to_json(&self) -> String {
        let strategies: Vec<String> = self
            .supported_staging_strategies
            .iter()
            .map(|strategy| strategy.as_str().to_string())
            .collect();
        format!(
            "{{{},{},{},{},{},{},{},{},{},\"artifact_filename\":{},\"artifact_size_bytes\":{},\"signature_url\":{},\"signing_key\":{}, {},{},\"supported_platforms\":{},\"supported_staging_strategies\":{},\"required_free_space_gb\":{},\"extraction_rules\":{},\"kernel_initrd_paths\":{},\"bootloader_paths\":{}, {},\"known_limitations\":{}, {}}}",
            json_pair("schema_version", &self.schema_version),
            json_pair("id", &self.id),
            json_pair("name", &self.name),
            json_pair("vendor", &self.vendor),
            json_pair("version", &self.version),
            json_pair("architecture", &self.architecture),
            json_pair("source_url", &self.source_url),
            json_pair("checksum_url", &self.checksum_url),
            json_pair("sha256", &self.sha256),
            json_optional_value(self.artifact_filename.as_deref()),
            self.artifact_size_bytes
                .map(|value| value.to_string())
                .unwrap_or_else(|| "null".into()),
            json_optional_value(self.signature_url.as_deref()),
            json_optional_value(self.signing_key.as_deref()),
            json_pair("homepage", &self.homepage),
            json_pair("license_notes", &self.license_notes),
            json_string_array(&self.supported_platforms),
            json_string_array(&strategies),
            self.required_free_space_gb,
            json_string_array(&self.extraction_rules),
            json_string_array(&self.kernel_initrd_paths),
            json_string_array(&self.bootloader_paths),
            json_pair("secure_boot_notes", &self.secure_boot_notes),
            json_string_array(&self.known_limitations),
            json_pair("post_boot_instructions", &self.post_boot_instructions)
        )
    }
}

impl StagingStrategy {
    pub fn as_str(&self) -> &'static str {
        match self {
            StagingStrategy::ExtractedEfiInstaller => "extracted_efi_installer",
            StagingStrategy::IsoLoopback => "iso_loopback",
            StagingStrategy::KernelInitrd => "kernel_initrd",
            StagingStrategy::WindowsMountedIsoSetup => "windows_mounted_iso_setup",
            StagingStrategy::MacosStartosinstall => "macos_startosinstall",
            StagingStrategy::ManualInstructions => "manual_instructions",
        }
    }

    pub fn from_profile_value(value: &str) -> Result<Self, NoUsbError> {
        match value {
            "extracted_efi_installer" => Ok(StagingStrategy::ExtractedEfiInstaller),
            "iso_loopback" => Ok(StagingStrategy::IsoLoopback),
            "kernel_initrd" => Ok(StagingStrategy::KernelInitrd),
            "windows_mounted_iso_setup" => Ok(StagingStrategy::WindowsMountedIsoSetup),
            "macos_startosinstall" => Ok(StagingStrategy::MacosStartosinstall),
            "manual_instructions" => Ok(StagingStrategy::ManualInstructions),
            _ => Err(NoUsbError::ProfileParse(format!(
                "unknown staging strategy: {value}"
            ))),
        }
    }
}

impl SystemInventory {
    pub fn to_json(&self, adapter: &str) -> String {
        let partitions: Vec<String> = self
            .disk_inventory
            .partitions
            .iter()
            .map(|partition| {
                format!(
                    "{{{},{},\"filesystem\":{},\"size_bytes\":{}}}",
                    json_pair("name", &partition.name),
                    json_optional_pair("mount_point", partition.mount_point.as_deref()),
                    json_optional_value(partition.filesystem.as_deref()),
                    partition
                        .size_bytes
                        .map(|size| size.to_string())
                        .unwrap_or_else(|| "null".into())
                )
            })
            .collect();
        let boot_entries: Vec<String> = self
            .boot_entries
            .iter()
            .map(|entry| {
                format!(
                    "{{{},{},\"is_default\":{}}}",
                    json_pair("id", &entry.id),
                    json_pair("label", &entry.label),
                    entry.is_default
                )
            })
            .collect();
        format!(
            "{{{},{},{},\"memory_total_mb\":{},{},{},{},\"disk_inventory\":{{\"disks\":{},\"available_space_gb\":{},\"partitions\":[{}]}},\"boot_entries\":[{}],\"boot_hints\":{},\"warnings\":{}}}",
            json_pair("adapter", adapter),
            json_pair("os_name", &self.os_name),
            json_pair("arch", &self.arch),
            self.memory_total_mb
                .map(|value| value.to_string())
                .unwrap_or_else(|| "null".into()),
            json_pair("firmware", &format!("{:?}", self.firmware)),
            json_pair("secure_boot", &format!("{:?}", self.secure_boot)),
            json_pair("encryption", &format!("{:?}", self.encryption)),
            json_string_array(&self.disk_inventory.disks),
            self.disk_inventory
                .available_space_gb
                .map(|value| value.to_string())
                .unwrap_or_else(|| "null".into()),
            partitions.join(","),
            boot_entries.join(","),
            self.boot_hints.to_json(),
            json_string_array(&self.warnings)
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionOutcome {
    pub plan_id: String,
    pub executed: bool,
    pub message: String,
}

impl ExecutionOutcome {
    pub fn to_json(&self) -> String {
        format!(
            "{{{},\"executed\":{}, {}}}",
            json_pair("plan_id", &self.plan_id),
            self.executed,
            json_pair("message", &self.message)
        )
    }
}

pub trait PlatformAdapter {
    fn inspect(&self) -> Result<SystemInventory, NoUsbError>;
    fn name(&self) -> &'static str;
}

pub trait OperationExecutor {
    fn execute(&self, plan: &OperationPlan) -> Result<ExecutionReport, NoUsbError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimulationConfig {
    pub interrupt_after_completed_steps: Option<usize>,
    pub fail_step_id: Option<String>,
}

impl SimulationConfig {
    pub fn complete() -> Self {
        Self {
            interrupt_after_completed_steps: None,
            fail_step_id: None,
        }
    }

    pub fn interrupt_after(completed_steps: usize) -> Self {
        Self {
            interrupt_after_completed_steps: Some(completed_steps),
            fail_step_id: None,
        }
    }

    pub fn fail_step(step_id: impl Into<String>) -> Self {
        Self {
            interrupt_after_completed_steps: None,
            fail_step_id: Some(step_id.into()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecutionStatus {
    Completed,
    Interrupted,
    Failed,
    RolledBack,
}

impl ExecutionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ExecutionStatus::Completed => "completed",
            ExecutionStatus::Interrupted => "interrupted",
            ExecutionStatus::Failed => "failed",
            ExecutionStatus::RolledBack => "rolled_back",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionReport {
    pub plan_id: String,
    pub status: ExecutionStatus,
    pub steps: Vec<OperationStep>,
    pub journal: Vec<String>,
    pub recovery_required: bool,
}

impl ExecutionReport {
    pub fn preview(&self) -> String {
        let mut output = String::new();
        output.push_str(&format!(
            "Execution report: {}\nStatus: {}\nRecovery required: {}\n",
            self.plan_id,
            self.status.as_str(),
            self.recovery_required
        ));
        output.push_str("Steps:\n");
        for step in &self.steps {
            output.push_str(&format!("- {}: {}\n", step.id, step.state.as_str()));
        }
        if !self.journal.is_empty() {
            output.push_str("Journal:\n");
            for entry in &self.journal {
                output.push_str(&format!("- {entry}\n"));
            }
        }
        output
    }

    pub fn to_json(&self) -> String {
        let steps: Vec<String> = self.steps.iter().map(|step| step.to_json()).collect();
        format!(
            "{{{},\"status\":\"{}\",\"steps\":[{}],\"journal\":{},\"recovery_required\":{}}}",
            json_pair("plan_id", &self.plan_id),
            self.status.as_str(),
            steps.join(","),
            json_string_array(&self.journal),
            self.recovery_required
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SavedExecutionReportSummary {
    pub plan_id: String,
    pub status: String,
    pub recovery_required: bool,
    pub path: PathBuf,
}

impl SavedExecutionReportSummary {
    pub fn to_json(&self) -> String {
        format!(
            "{{{},{},\"recovery_required\":{}, {}}}",
            json_pair("plan_id", &self.plan_id),
            json_pair("status", &self.status),
            self.recovery_required,
            json_pair("path", &self.path.display().to_string())
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiagnosticBundle {
    pub path: PathBuf,
    pub files: Vec<PathBuf>,
}

impl DiagnosticBundle {
    pub fn to_json(&self) -> String {
        let files: Vec<String> = self
            .files
            .iter()
            .map(|path| path.display().to_string())
            .collect();
        format!(
            "{{{},\"files\":{}}}",
            json_pair("path", &self.path.display().to_string()),
            json_string_array(&files)
        )
    }
}

pub struct SimulatedExecutor {
    config: SimulationConfig,
}

impl SimulatedExecutor {
    pub fn new(config: SimulationConfig) -> Self {
        Self { config }
    }
}

impl OperationExecutor for SimulatedExecutor {
    fn execute(&self, plan: &OperationPlan) -> Result<ExecutionReport, NoUsbError> {
        let mut steps = plan.steps.clone();
        let mut journal = vec![format!("simulation started for {}", plan.id)];
        let mut completed = 0usize;

        for step in &mut steps {
            if step.state == StepState::ManualInterventionRequired {
                journal.push(format!(
                    "step {} requires manual intervention before execution",
                    step.id
                ));
                return Ok(ExecutionReport {
                    plan_id: plan.id.clone(),
                    status: ExecutionStatus::Interrupted,
                    steps,
                    journal,
                    recovery_required: true,
                });
            }

            step.state = StepState::Running;
            journal.push(format!("step {} running", step.id));

            if self.config.fail_step_id.as_deref() == Some(step.id.as_str()) {
                step.state = StepState::Failed;
                journal.push(format!("step {} failed by simulation", step.id));
                return Ok(ExecutionReport {
                    plan_id: plan.id.clone(),
                    status: ExecutionStatus::Failed,
                    steps,
                    journal,
                    recovery_required: true,
                });
            }

            step.state = StepState::Completed;
            completed += 1;
            journal.push(format!("step {} completed", step.id));

            if self.config.interrupt_after_completed_steps == Some(completed) {
                journal.push(format!(
                    "simulation interrupted after {completed} completed steps"
                ));
                return Ok(ExecutionReport {
                    plan_id: plan.id.clone(),
                    status: ExecutionStatus::Interrupted,
                    steps,
                    journal,
                    recovery_required: true,
                });
            }
        }

        journal.push("simulation completed".into());
        Ok(ExecutionReport {
            plan_id: plan.id.clone(),
            status: ExecutionStatus::Completed,
            steps,
            journal,
            recovery_required: false,
        })
    }
}

pub fn rollback_simulated_report(report: &ExecutionReport) -> ExecutionReport {
    let mut steps = report.steps.clone();
    let mut journal = report.journal.clone();
    journal.push(format!("rollback started for {}", report.plan_id));

    for step in steps.iter_mut().rev() {
        match step.state {
            StepState::Completed => match &step.rollback {
                RollbackAction::None => {
                    journal.push(format!("step {} has no rollback action", step.id));
                }
                _ => {
                    step.state = StepState::RolledBack;
                    journal.push(format!("step {} rolled back", step.id));
                }
            },
            StepState::Running | StepState::Failed => {
                step.state = StepState::ManualInterventionRequired;
                journal.push(format!(
                    "step {} needs manual intervention before rollback can continue",
                    step.id
                ));
            }
            _ => {}
        }
    }

    let recovery_required = steps
        .iter()
        .any(|step| step.state == StepState::ManualInterventionRequired);

    ExecutionReport {
        plan_id: report.plan_id.clone(),
        status: ExecutionStatus::RolledBack,
        steps,
        journal,
        recovery_required,
    }
}

pub fn save_execution_report(
    base_dir: &Path,
    report: &ExecutionReport,
) -> Result<PathBuf, NoUsbError> {
    let dir = execution_reports_dir(base_dir);
    fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.json", safe_filename(&report.plan_id)));
    fs::write(&path, report.to_json())?;
    record_execution_report(&mut open_journal(base_dir)?, report)?;
    write_journal_entry(
        base_dir,
        &format!(
            "saved execution report {} status={}",
            report.plan_id,
            report.status.as_str()
        ),
    )?;
    Ok(path)
}

pub fn load_execution_report_json(base_dir: &Path, plan_id: &str) -> Result<String, NoUsbError> {
    let path = execution_reports_dir(base_dir).join(format!("{}.json", safe_filename(plan_id)));
    if !path.exists() {
        return Err(NoUsbError::InvalidInput(format!(
            "no saved execution report for {plan_id}"
        )));
    }
    Ok(fs::read_to_string(path)?)
}

pub fn list_saved_execution_reports(
    base_dir: &Path,
) -> Result<Vec<SavedExecutionReportSummary>, NoUsbError> {
    let dir = execution_reports_dir(base_dir);
    if !dir.exists() {
        return Ok(vec![]);
    }

    let mut reports = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let content = fs::read_to_string(&path)?;
        let plan_id = json_field(&content, "plan_id").unwrap_or_else(|| {
            path.file_stem()
                .and_then(|value| value.to_str())
                .unwrap_or("unknown")
                .to_string()
        });
        let status = json_field(&content, "status").unwrap_or_else(|| "unknown".into());
        let recovery_required = json_bool_field(&content, "recovery_required").unwrap_or(false);
        reports.push(SavedExecutionReportSummary {
            plan_id,
            status,
            recovery_required,
            path,
        });
    }
    reports.sort_by(|left, right| left.plan_id.cmp(&right.plan_id));
    Ok(reports)
}

fn execution_reports_dir(base_dir: &Path) -> PathBuf {
    base_dir.join(".nousb").join("reports")
}

pub fn export_diagnostic_bundle(
    base_dir: &Path,
    inventory: &SystemInventory,
) -> Result<DiagnosticBundle, NoUsbError> {
    let bundle_dir = base_dir
        .join(".nousb")
        .join("diagnostics")
        .join(format!("bundle-{}", now_stamp()));
    fs::create_dir_all(&bundle_dir)?;

    let mut files = Vec::new();
    write_diagnostic_file(
        &bundle_dir,
        &mut files,
        "README.txt",
        "NoUSB diagnostic bundle. Secrets are redacted with [REDACTED]. This bundle contains project-local logs, saved reports, catalog metadata, and safe host inventory only.\n",
    )?;
    write_diagnostic_file(
        &bundle_dir,
        &mut files,
        "system-inventory.json",
        &inventory.to_json("diagnostic-export"),
    )?;

    let catalog_json = format!(
        "[{}]",
        built_in_profiles()
            .iter()
            .map(|profile| profile.to_json())
            .collect::<Vec<_>>()
            .join(",")
    );
    write_diagnostic_file(&bundle_dir, &mut files, "catalog.json", &catalog_json)?;

    let reports = list_saved_execution_reports(base_dir)?;
    let report_summary = format!(
        "[{}]",
        reports
            .iter()
            .map(|report| report.to_json())
            .collect::<Vec<_>>()
            .join(",")
    );
    write_diagnostic_file(
        &bundle_dir,
        &mut files,
        "execution-report-index.json",
        &report_summary,
    )?;

    for report in reports {
        let content = fs::read_to_string(&report.path)?;
        write_diagnostic_file(
            &bundle_dir.join("reports"),
            &mut files,
            &format!("{}.json", safe_filename(&report.plan_id)),
            &content,
        )?;
    }

    let log_path = base_dir
        .join(".nousb")
        .join("journal")
        .join("operations.log");
    if log_path.exists() {
        let content = fs::read_to_string(log_path)?;
        write_diagnostic_file(&bundle_dir, &mut files, "operations.log", &content)?;
    }

    write_journal_entry(
        base_dir,
        &format!("exported diagnostic bundle {}", bundle_dir.display()),
    )?;

    Ok(DiagnosticBundle {
        path: bundle_dir,
        files,
    })
}

fn write_diagnostic_file(
    base_dir: &Path,
    files: &mut Vec<PathBuf>,
    name: &str,
    content: &str,
) -> Result<(), NoUsbError> {
    fs::create_dir_all(base_dir)?;
    let path = base_dir.join(name);
    fs::write(&path, redact_secrets(content))?;
    files.push(path);
    Ok(())
}

pub fn redact_secrets(content: &str) -> String {
    let mut redacted_lines = Vec::new();
    for line in content.lines() {
        redacted_lines.push(redact_secret_line(line));
    }
    redacted_lines.join("\n")
}

fn redact_secret_line(line: &str) -> String {
    let lower = line.to_ascii_lowercase();
    let secret_markers = [
        "password",
        "passphrase",
        "recovery_key",
        "recovery-key",
        "bitlocker",
        "filevault",
        "luks_header",
        "token",
        "secret",
        "api_key",
        "apikey",
        "private_key",
    ];
    if !secret_markers.iter().any(|marker| lower.contains(marker)) {
        return line.to_string();
    }

    if let Some((key, _)) = line.split_once('=') {
        format!("{}=[REDACTED]", key.trim_end())
    } else if let Some((key, _)) = line.split_once(':') {
        format!("{}: [REDACTED]", key.trim_end())
    } else {
        "[REDACTED]".into()
    }
}

#[derive(Clone, Debug)]
pub struct FakePlatformAdapter {
    name: &'static str,
    inventory: SystemInventory,
    capabilities: Vec<PlatformCapability>,
}

impl FakePlatformAdapter {
    pub fn windows_uefi_bitlocker() -> Self {
        Self {
            name: "fake-windows-uefi-bitlocker",
            inventory: SystemInventory {
                os_name: "windows".into(),
                arch: "x86_64".into(),
                memory_total_mb: Some(32 * 1024),
                firmware: FirmwareMode::Uefi,
                secure_boot: SecureBootState::Enabled,
                encryption: EncryptionState::Enabled("BitLocker".into()),
                disk_inventory: DiskInventory {
                    disks: vec!["Disk0 GPT 512GB".into()],
                    partitions: vec![
                        PartitionInfo {
                            name: "EFI System Partition".into(),
                            mount_point: Some("ESP".into()),
                            filesystem: Some("FAT32".into()),
                            size_bytes: Some(272 * 1024 * 1024),
                        },
                        PartitionInfo {
                            name: "Windows".into(),
                            mount_point: Some("C:\\".into()),
                            filesystem: Some("NTFS".into()),
                            size_bytes: Some(400 * 1024 * 1024 * 1024),
                        },
                    ],
                    available_space_gb: Some(64),
                },
                boot_entries: vec![BootEntry {
                    id: "{bootmgr}".into(),
                    label: "Windows Boot Manager".into(),
                    is_default: true,
                }],
                boot_hints: BootEnvironmentHints {
                    esp_present: Some(true),
                    esp_location: Some("disk 0 partition 1".into()),
                    esp_size_bytes: Some(272 * 1024 * 1024),
                    recovery_partition_present: Some(true),
                    boot_managers: vec!["Windows Boot Manager".into()],
                    firmware_boot_current: Some("Boot0000".into()),
                    firmware_boot_order: Some(vec!["Boot0000".into(), "Boot0001".into()]),
                    firmware_boot_next: None,
                    network_boot_entries: Some(1),
                    http_boot_entries: Some(0),
                    unknowns: vec![],
                },
                warnings: vec![
                    "BitLocker recovery key backup must be confirmed before boot changes.".into(),
                ],
            },
            capabilities: vec![
                PlatformCapability::OneTimeBoot,
                PlatformCapability::BootEntryBackup,
                PlatformCapability::RecoveryPack,
                PlatformCapability::EncryptionStatus,
                PlatformCapability::SecureBootDetection,
                PlatformCapability::InstallerVerification,
            ],
        }
    }

    pub fn linux_grub_luks_btrfs_low_space() -> Self {
        Self {
            name: "fake-linux-grub-luks-btrfs-low-space",
            inventory: SystemInventory {
                os_name: "linux".into(),
                arch: "x86_64".into(),
                memory_total_mb: Some(8 * 1024),
                firmware: FirmwareMode::Uefi,
                secure_boot: SecureBootState::Disabled,
                encryption: EncryptionState::Enabled("LUKS".into()),
                disk_inventory: DiskInventory {
                    disks: vec!["nvme0n1 GPT 256GB".into()],
                    partitions: vec![
                        PartitionInfo {
                            name: "EFI System Partition".into(),
                            mount_point: Some("/boot/efi".into()),
                            filesystem: Some("vfat".into()),
                            size_bytes: Some(512 * 1024 * 1024),
                        },
                        PartitionInfo {
                            name: "root".into(),
                            mount_point: Some("/".into()),
                            filesystem: Some("btrfs".into()),
                            size_bytes: Some(180 * 1024 * 1024 * 1024),
                        },
                    ],
                    available_space_gb: Some(3),
                },
                boot_entries: vec![BootEntry {
                    id: "0001".into(),
                    label: "GRUB".into(),
                    is_default: true,
                }],
                boot_hints: BootEnvironmentHints {
                    esp_present: Some(true),
                    esp_location: Some("/boot/efi".into()),
                    boot_managers: vec!["grub".into(), "shim".into()],
                    firmware_boot_current: Some("Boot0001".into()),
                    firmware_boot_order: Some(vec!["Boot0001".into()]),
                    network_boot_entries: Some(0),
                    http_boot_entries: Some(0),
                    ..Default::default()
                },
                warnings: vec![
                    "LUKS header backup should be completed manually before boot work.".into(),
                    "Btrfs snapshot may be available before risky operations.".into(),
                ],
            },
            capabilities: vec![
                PlatformCapability::OneTimeBoot,
                PlatformCapability::BootEntryBackup,
                PlatformCapability::RecoveryPack,
                PlatformCapability::Snapshot,
                PlatformCapability::EncryptionStatus,
                PlatformCapability::InstallerVerification,
            ],
        }
    }

    pub fn macos_apple_silicon_filevault() -> Self {
        Self {
            name: "fake-macos-apple-silicon-filevault",
            inventory: SystemInventory {
                os_name: "macos".into(),
                arch: "aarch64".into(),
                memory_total_mb: Some(16 * 1024),
                firmware: FirmwareMode::Uefi,
                secure_boot: SecureBootState::Enabled,
                encryption: EncryptionState::Enabled("FileVault".into()),
                disk_inventory: DiskInventory {
                    disks: vec!["APFS container 1TB".into()],
                    partitions: vec![PartitionInfo {
                        name: "Macintosh HD".into(),
                        mount_point: Some("/".into()),
                        filesystem: Some("apfs".into()),
                        size_bytes: Some(900 * 1024 * 1024 * 1024),
                    }],
                    available_space_gb: Some(120),
                },
                boot_entries: vec![BootEntry {
                    id: "apple-default".into(),
                    label: "macOS".into(),
                    is_default: true,
                }],
                boot_hints: BootEnvironmentHints::default(),
                warnings: vec![
                    "Apple Silicon boot policy must not be bypassed.".into(),
                    "Use only Apple-supported installer mechanisms.".into(),
                ],
            },
            capabilities: vec![
                PlatformCapability::RecoveryPack,
                PlatformCapability::Snapshot,
                PlatformCapability::EncryptionStatus,
                PlatformCapability::SecureBootDetection,
            ],
        }
    }

    pub fn capabilities(&self) -> &[PlatformCapability] {
        &self.capabilities
    }
}

impl PlatformAdapter for FakePlatformAdapter {
    fn inspect(&self) -> Result<SystemInventory, NoUsbError> {
        Ok(self.inventory.clone())
    }

    fn name(&self) -> &'static str {
        self.name
    }
}

pub fn execute_plan_safe(plan: &OperationPlan, yes: bool) -> Result<ExecutionOutcome, NoUsbError> {
    if yes && !plan.confirmation.permits_yes_flag(plan.risk) {
        return Err(NoUsbError::UnsafeExecution(format!(
            "--yes cannot approve {} risk plan {}; typed confirmation is required",
            plan.risk, plan.id
        )));
    }

    Err(NoUsbError::UnsafeExecution(format!(
        "execution of {} is disabled in the default non-destructive build",
        plan.id
    )))
}

#[derive(Debug)]
pub enum NoUsbError {
    Io(String),
    Network(String),
    Verification(String),
    ArtifactUnavailable(String),
    UnknownProfile(String),
    ProfileParse(String),
    UnsafeExecution(String),
    InvalidInput(String),
}

impl fmt::Display for NoUsbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NoUsbError::Io(value) => write!(f, "I/O error: {value}"),
            NoUsbError::Network(value) => write!(f, "network error: {value}"),
            NoUsbError::Verification(value) => write!(f, "verification error: {value}"),
            NoUsbError::ArtifactUnavailable(value) => {
                write!(f, "artifact unavailable: {value}")
            }
            NoUsbError::UnknownProfile(value) => write!(f, "unknown installer profile: {value}"),
            NoUsbError::ProfileParse(value) => write!(f, "profile parse error: {value}"),
            NoUsbError::UnsafeExecution(value) => write!(f, "unsafe execution blocked: {value}"),
            NoUsbError::InvalidInput(value) => write!(f, "invalid input: {value}"),
        }
    }
}

impl std::error::Error for NoUsbError {}

impl From<io::Error> for NoUsbError {
    fn from(value: io::Error) -> Self {
        NoUsbError::Io(value.to_string())
    }
}

pub fn built_in_profiles() -> Vec<InstallerProfile> {
    match embedded_profiles() {
        Ok(profiles) => profiles,
        Err(error) => vec![InstallerProfile {
            schema_version: "1".into(),
            id: "profile-catalog-error".into(),
            name: "Profile catalog failed to load".into(),
            vendor: "NoUSB".into(),
            version: "error".into(),
            architecture: "unknown".into(),
            source_url: "about:blank".into(),
            checksum_url: "about:blank".into(),
            sha256: "unavailable".into(),
            artifact_filename: None,
            artifact_size_bytes: None,
            signature_url: None,
            signing_key: None,
            homepage: "about:blank".into(),
            license_notes: "Catalog parsing failed.".into(),
            supported_platforms: vec![],
            supported_staging_strategies: vec![StagingStrategy::ManualInstructions],
            required_free_space_gb: 1,
            extraction_rules: vec![],
            kernel_initrd_paths: vec![],
            bootloader_paths: vec![],
            secure_boot_notes: "Catalog parsing failed; do not use this placeholder.".into(),
            known_limitations: vec![error.to_string()],
            post_boot_instructions: "Fix the embedded profile catalog before use.".into(),
        }],
    }
}

pub fn embedded_profiles() -> Result<Vec<InstallerProfile>, NoUsbError> {
    let sources = [
        include_str!("../../nousb-installer-profiles/profiles/ubuntu-24.04-desktop.toml"),
        include_str!("../../nousb-installer-profiles/profiles/ubuntu-24.04-server.toml"),
        include_str!("../../nousb-installer-profiles/profiles/fedora-44-workstation.toml"),
        include_str!("../../nousb-installer-profiles/profiles/windows-11.toml"),
    ];
    sources
        .iter()
        .map(|source| parse_installer_profile(source))
        .collect()
}

pub fn parse_installer_profile(source: &str) -> Result<InstallerProfile, NoUsbError> {
    let fields = ProfileFields::parse(source)?;
    let artifact_size_bytes = fields
        .optional("artifact_size_bytes")
        .map(|value| {
            value.parse::<u64>().map_err(|error| {
                NoUsbError::ProfileParse(format!("artifact_size_bytes is invalid: {error}"))
            })
        })
        .transpose()?
        .filter(|value| *value > 0);
    let profile = InstallerProfile {
        schema_version: fields.required("schema_version")?,
        id: fields.required("id")?,
        name: fields.required("name")?,
        vendor: fields.required("vendor")?,
        version: fields.required("version")?,
        architecture: fields.required("architecture")?,
        source_url: fields.required("source_url")?,
        checksum_url: fields.required("checksum_url")?,
        sha256: fields.required("sha256")?,
        artifact_filename: fields.optional("artifact_filename"),
        artifact_size_bytes,
        signature_url: fields.optional("signature_url"),
        signing_key: fields.optional("signing_key"),
        homepage: fields.required("homepage")?,
        license_notes: fields.required("license_notes")?,
        supported_platforms: fields.array("supported_platforms")?,
        supported_staging_strategies: fields
            .array("supported_staging_strategies")?
            .iter()
            .map(|value| StagingStrategy::from_profile_value(value))
            .collect::<Result<Vec<_>, _>>()?,
        required_free_space_gb: fields.required("required_free_space_gb")?.parse().map_err(
            |error| NoUsbError::ProfileParse(format!("required_free_space_gb is invalid: {error}")),
        )?,
        extraction_rules: fields.array("extraction_rules")?,
        kernel_initrd_paths: fields.array("kernel_initrd_paths")?,
        bootloader_paths: fields.array("bootloader_paths")?,
        secure_boot_notes: fields.required("secure_boot_notes")?,
        known_limitations: fields.array("known_limitations")?,
        post_boot_instructions: fields.required("post_boot_instructions")?,
    };
    validate_profile(&profile)?;
    Ok(profile)
}

pub fn validate_profile(profile: &InstallerProfile) -> Result<(), NoUsbError> {
    if let Some(key) = profile.signing_key.as_deref() {
        pinned_signing_key(key)?;
    }
    if profile.schema_version != "1" {
        return Err(NoUsbError::ProfileParse(format!(
            "{} uses unsupported schema_version {}",
            profile.id, profile.schema_version
        )));
    }
    if profile.id.trim().is_empty() {
        return Err(NoUsbError::ProfileParse("profile id is required".into()));
    }
    if profile.required_free_space_gb == 0 {
        return Err(NoUsbError::ProfileParse(format!(
            "{} must require nonzero free space",
            profile.id
        )));
    }
    if profile.supported_platforms.is_empty() {
        return Err(NoUsbError::ProfileParse(format!(
            "{} must declare supported platforms",
            profile.id
        )));
    }
    if profile.supported_staging_strategies.is_empty() {
        return Err(NoUsbError::ProfileParse(format!(
            "{} must declare staging strategies",
            profile.id
        )));
    }
    if profile.sha256.trim().is_empty() {
        return Err(NoUsbError::ProfileParse(format!(
            "{} must declare sha256 metadata",
            profile.id
        )));
    }
    Ok(())
}

pub fn find_profile(id: &str) -> Result<InstallerProfile, NoUsbError> {
    built_in_profiles()
        .into_iter()
        .find(|profile| profile.id == id)
        .ok_or_else(|| NoUsbError::UnknownProfile(id.into()))
}

pub fn artifact_manifest(profile_id: &str) -> Result<ArtifactManifest, NoUsbError> {
    let profile = find_profile(profile_id)?;
    let filename = profile.artifact_filename.clone().ok_or_else(|| {
        NoUsbError::ArtifactUnavailable(format!(
            "{} has no stable vendor artifact URL; use {} to obtain vendor-mediated media",
            profile.id, profile.source_url
        ))
    })?;
    let size_bytes = profile.artifact_size_bytes.ok_or_else(|| {
        NoUsbError::ArtifactUnavailable(format!("{} has no pinned artifact size", profile.id))
    })?;
    if !is_safe_filename(&filename) {
        return Err(NoUsbError::ProfileParse(format!(
            "{} has unsafe artifact filename {filename}",
            profile.id
        )));
    }
    if !is_https_url(&profile.source_url) || !is_https_url(&profile.checksum_url) {
        return Err(NoUsbError::ProfileParse(format!(
            "{} artifact and checksum URLs must use HTTPS",
            profile.id
        )));
    }
    if profile.sha256.len() != 64
        || !profile
            .sha256
            .chars()
            .all(|value| value.is_ascii_hexdigit())
    {
        return Err(NoUsbError::ArtifactUnavailable(format!(
            "{} does not have a pinned SHA-256 digest",
            profile.id
        )));
    }
    if size_bytes == 0 {
        return Err(NoUsbError::ArtifactUnavailable(format!(
            "{} does not have a nonzero pinned artifact size",
            profile.id
        )));
    }
    Ok(ArtifactManifest {
        profile_id: profile.id,
        filename,
        source_url: profile.source_url,
        checksum_url: profile.checksum_url,
        signature_url: profile.signature_url,
        sha256: profile.sha256.to_ascii_lowercase(),
        size_bytes,
    })
}

pub fn artifact_cache_path(base_dir: &Path, profile_id: &str) -> Result<PathBuf, NoUsbError> {
    let manifest = artifact_manifest(profile_id)?;
    Ok(base_dir
        .join(".nousb")
        .join("artifacts")
        .join(&manifest.profile_id)
        .join(&manifest.filename))
}

pub fn probe_artifact(profile_id: &str) -> Result<ArtifactProbe, NoUsbError> {
    let manifest = artifact_manifest(profile_id)?;
    let response = http_client()?
        .head(&manifest.source_url)
        .send()
        .map_err(|error| NoUsbError::Network(error.to_string()))?;
    validate_https_response(&response)?;
    if !response.status().is_success() {
        return Err(NoUsbError::Network(format!(
            "{} returned HTTP {}",
            manifest.source_url,
            response.status()
        )));
    }
    let content_length = response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    if let Some(actual) = content_length {
        if actual != manifest.size_bytes {
            return Err(NoUsbError::Verification(format!(
                "vendor reports {actual} bytes for {}, expected {}",
                manifest.filename, manifest.size_bytes
            )));
        }
    }
    let accepts_ranges = response
        .headers()
        .get(ACCEPT_RANGES)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("bytes"));
    Ok(ArtifactProbe {
        final_url: response.url().to_string(),
        manifest,
        content_length,
        accepts_ranges,
    })
}

pub fn download_artifact(
    base_dir: &Path,
    profile_id: &str,
) -> Result<ArtifactDownload, NoUsbError> {
    let manifest = artifact_manifest(profile_id)?;
    let artifact_dir = base_dir
        .join(".nousb")
        .join("artifacts")
        .join(&manifest.profile_id);
    fs::create_dir_all(&artifact_dir)?;
    let final_path = artifact_dir.join(&manifest.filename);
    if final_path.exists() {
        let actual = sha256_file(&final_path)?;
        if actual == manifest.sha256 {
            return Ok(ArtifactDownload {
                downloaded_bytes: manifest.size_bytes,
                manifest,
                path: final_path,
                resumed_from_bytes: 0,
                verified: true,
                already_present: true,
            });
        }
        return Err(NoUsbError::Verification(format!(
            "cached artifact {} exists but has SHA-256 {actual}; it was not overwritten",
            final_path.display()
        )));
    }

    let lock_path = artifact_dir.join("download.lock");
    let _lock = DownloadLock::acquire(lock_path)?;
    let partial_path = artifact_dir.join(format!("{}.part", manifest.filename));
    let resumed_from_bytes = fs::metadata(&partial_path)
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    if resumed_from_bytes > manifest.size_bytes {
        return Err(NoUsbError::Verification(format!(
            "partial download is {resumed_from_bytes} bytes, larger than expected {} bytes; move it aside and retry",
            manifest.size_bytes
        )));
    }

    if resumed_from_bytes == manifest.size_bytes {
        return finalize_download(manifest, partial_path, final_path, resumed_from_bytes, 0);
    }

    let client = http_client()?;
    let mut request = client.get(&manifest.source_url);
    if resumed_from_bytes > 0 {
        request = request.header(RANGE, format!("bytes={resumed_from_bytes}-"));
    }
    let mut response = request
        .send()
        .map_err(|error| NoUsbError::Network(error.to_string()))?;
    validate_https_response(&response)?;
    let expected_status = if resumed_from_bytes > 0 {
        StatusCode::PARTIAL_CONTENT
    } else {
        StatusCode::OK
    };
    if response.status() != expected_status {
        return Err(NoUsbError::Network(format!(
            "{} returned HTTP {}; expected {}. Existing partial data was kept unchanged",
            manifest.source_url,
            response.status(),
            expected_status
        )));
    }

    let expected_remaining = manifest.size_bytes - resumed_from_bytes;
    if let Some(content_length) = response.content_length() {
        if content_length != expected_remaining {
            return Err(NoUsbError::Verification(format!(
                "server offered {content_length} bytes, expected {expected_remaining} remaining bytes"
            )));
        }
    }

    let mut output = if resumed_from_bytes > 0 {
        OpenOptions::new().append(true).open(&partial_path)?
    } else {
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&partial_path)?
    };
    let downloaded_bytes = io::copy(&mut response, &mut output)?;
    output.sync_all()?;
    finalize_download(
        manifest,
        partial_path,
        final_path,
        resumed_from_bytes,
        downloaded_bytes,
    )
}

pub fn inspect_staging_artifact(
    profile_id: &str,
    artifact_path: &Path,
) -> Result<StagingPreview, NoUsbError> {
    let manifest = artifact_manifest(profile_id)?;
    verify_artifact_against_manifest(artifact_path, &manifest)?;
    let profile = find_profile(profile_id)?;
    inspect_staging_profile(&profile, artifact_path)
}

fn inspect_staging_profile(
    profile: &InstallerProfile,
    artifact_path: &Path,
) -> Result<StagingPreview, NoUsbError> {
    let mut iso = open_iso(artifact_path)?;
    let mut declared_paths = profile.kernel_initrd_paths.clone();
    declared_paths.extend(profile.bootloader_paths.clone());
    if declared_paths.is_empty() {
        return Err(NoUsbError::ArtifactUnavailable(format!(
            "{} does not declare extractable staging assets",
            profile.id
        )));
    }
    let mut assets = Vec::new();
    for source_path in declared_paths {
        let entry = find_iso_entry(&mut iso, &source_path).ok_or_else(|| {
            NoUsbError::Verification(format!(
                "verified artifact does not contain declared path {source_path}"
            ))
        })?;
        if !entry.is_file() {
            return Err(NoUsbError::Verification(format!(
                "declared staging path {source_path} is not a file"
            )));
        }
        assets.push(StagingAsset {
            source_path,
            size_bytes: u64::from(entry.file_size()),
            output_path: None,
            sha256: None,
        });
    }
    Ok(StagingPreview {
        profile_id: profile.id.clone(),
        artifact_path: artifact_path.to_path_buf(),
        artifact_verified: true,
        assets,
        execution_enabled: false,
    })
}

pub fn create_staging_bundle(
    base_dir: &Path,
    profile_id: &str,
    artifact_path: &Path,
) -> Result<StagingBundle, NoUsbError> {
    let preview = inspect_staging_artifact(profile_id, artifact_path)?;
    let manifest = artifact_manifest(profile_id)?;
    create_staging_bundle_from_preview(base_dir, preview, &manifest.sha256)
}

fn create_staging_bundle_from_preview(
    base_dir: &Path,
    preview: StagingPreview,
    artifact_sha256: &str,
) -> Result<StagingBundle, NoUsbError> {
    let profile_id = preview.profile_id.clone();
    let artifact_path = preview.artifact_path.clone();
    let bundle_name = format!(
        "{}-{}-{}",
        safe_filename(&profile_id),
        now_stamp(),
        std::process::id()
    );
    let staging_root = base_dir
        .join(".nousb")
        .join("staging")
        .join(safe_filename(&profile_id));
    fs::create_dir_all(&staging_root)?;
    let partial_path = staging_root.join(format!("{bundle_name}.partial"));
    let final_path = staging_root.join(&bundle_name);
    fs::create_dir(&partial_path)?;

    let mut iso = open_iso(&artifact_path)?;
    let mut assets = Vec::new();
    for asset in preview.assets {
        let entry = find_iso_entry(&mut iso, &asset.source_path).ok_or_else(|| {
            NoUsbError::Verification(format!(
                "verified artifact no longer exposes {}",
                asset.source_path
            ))
        })?;
        let relative_path = safe_iso_relative_path(&asset.source_path)?;
        let output_path = partial_path.join("assets").join(&relative_path);
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)?;
        }
        extract_iso_entry(&mut iso, &entry, &output_path)?;
        let extracted_sha256 = sha256_file(&output_path)?;
        assets.push(StagingAsset {
            source_path: asset.source_path,
            size_bytes: asset.size_bytes,
            output_path: Some(final_path.join("assets").join(relative_path)),
            sha256: Some(extracted_sha256),
        });
    }

    let bundle = StagingBundle {
        profile_id,
        path: final_path.clone(),
        artifact_path,
        artifact_sha256: artifact_sha256.into(),
        assets,
        execution_enabled: false,
    };
    fs::write(partial_path.join("bundle.json"), bundle.to_json())?;
    fs::write(
        partial_path.join("README.txt"),
        "Verified NoUSB staging bundle. This directory contains extracted installer boot assets only. It does not modify or select any boot entry, and execution is disabled.\n",
    )?;
    fs::rename(&partial_path, &final_path)?;
    Ok(bundle)
}

const VM_REHEARSAL_STEPS: [&str; 8] = [
    "capture-boot-backup",
    "stage-verified-assets",
    "register-temporary-entry",
    "select-one-shot-entry",
    "transfer-to-installer",
    "verify-payload-in-ram",
    "reboot-to-original-default",
    "cleanup-temporary-state",
];

#[derive(Clone)]
struct VmBootState {
    original_default: String,
    default_entry: String,
    original_boot_order: Vec<String>,
    boot_order: Vec<String>,
    active_entry: String,
    backup_captured: bool,
    staged_assets: bool,
    temporary_entry: bool,
    one_shot_entry: Option<String>,
    installer_attempted: bool,
    ram_payload_observed: bool,
    fallback_observed: bool,
}

impl VmBootState {
    fn clean() -> Self {
        Self {
            original_default: "current-os".into(),
            default_entry: "current-os".into(),
            original_boot_order: vec!["current-os".into(), "firmware-recovery".into()],
            boot_order: vec!["current-os".into(), "firmware-recovery".into()],
            active_entry: "current-os".into(),
            backup_captured: false,
            staged_assets: false,
            temporary_entry: false,
            one_shot_entry: None,
            installer_attempted: false,
            ram_payload_observed: false,
            fallback_observed: false,
        }
    }
}

pub fn rehearse_vm_one_shot(
    backend: OneShotBootBackend,
    profile_id: &str,
) -> Result<VmRehearsalReport, NoUsbError> {
    let _profile = find_profile(profile_id)?;
    let mut failure_points = vec![None];
    failure_points.extend(
        VM_REHEARSAL_STEPS
            .iter()
            .map(|step| Some((*step).to_string())),
    );
    let mut scenarios = Vec::new();
    for failure_after in failure_points {
        scenarios.push(run_vm_rehearsal_scenario(backend, failure_after)?);
    }
    let all_invariants_hold = scenarios.iter().all(|scenario| scenario.invariants_hold);
    Ok(VmRehearsalReport {
        id: format!(
            "vm-rehearsal-{}-{}-{}-{}",
            backend.id(),
            safe_filename(profile_id),
            now_stamp(),
            std::process::id()
        ),
        backend,
        profile_id: profile_id.into(),
        scenarios,
        all_invariants_hold,
        real_vm_executed: false,
        host_boot_changes: false,
        reference_urls: vec![
            backend.reference_url().into(),
            "https://uefi.org/specs/UEFI/2.11/03_Boot_Manager.html".into(),
            "https://www.qemu.org/docs/master/system/invocation.html".into(),
            "https://manpages.ubuntu.com/manpages/noble/man7/casper.7.html".into(),
        ],
    })
}

pub fn save_vm_rehearsal(
    base_dir: &Path,
    report: &VmRehearsalReport,
) -> Result<PathBuf, NoUsbError> {
    let directory = base_dir.join(".nousb").join("vm-rehearsals");
    fs::create_dir_all(&directory)?;
    let path = directory.join(format!("{}.json", safe_filename(&report.id)));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)?;
    file.write_all(report.to_json().as_bytes())?;
    file.sync_all()?;
    Ok(path)
}

fn run_vm_rehearsal_scenario(
    backend: OneShotBootBackend,
    failure_after: Option<String>,
) -> Result<VmRehearsalScenario, NoUsbError> {
    let mut state = VmBootState::clean();
    let mut events = Vec::new();
    let mut recovered = false;
    for step in VM_REHEARSAL_STEPS {
        apply_vm_rehearsal_step(&mut state, backend, step, &mut events)?;
        if failure_after.as_deref() == Some(step) {
            events.push(format!("interruption-injected-after:{step}"));
            recover_vm_rehearsal_state(&mut state, &mut events);
            recovered = true;
            break;
        }
    }

    let original_default_preserved = state.default_entry == state.original_default;
    let boot_order_preserved = state.boot_order == state.original_boot_order;
    let one_shot_cleared = state.one_shot_entry.is_none();
    let temporary_entry_removed = !state.temporary_entry;
    let staged_assets_removed = !state.staged_assets;
    let fallback_sufficient = !state.installer_attempted || state.fallback_observed;
    let invariants_hold = state.backup_captured
        && original_default_preserved
        && boot_order_preserved
        && one_shot_cleared
        && temporary_entry_removed
        && staged_assets_removed
        && state.active_entry == state.original_default
        && fallback_sufficient;
    let id = failure_after
        .as_deref()
        .map(|step| format!("interrupt-after-{step}"))
        .unwrap_or_else(|| "complete-one-shot-cycle".into());

    Ok(VmRehearsalScenario {
        id,
        failure_after,
        events,
        recovered,
        original_default_preserved,
        boot_order_preserved,
        one_shot_cleared,
        temporary_entry_removed,
        staged_assets_removed,
        installer_attempted: state.installer_attempted,
        ram_payload_observed: state.ram_payload_observed,
        fallback_observed: state.fallback_observed,
        invariants_hold,
    })
}

fn apply_vm_rehearsal_step(
    state: &mut VmBootState,
    backend: OneShotBootBackend,
    step: &str,
    events: &mut Vec<String>,
) -> Result<(), NoUsbError> {
    match step {
        "capture-boot-backup" => {
            state.backup_captured = true;
            events.push("boot-state-backup-captured".into());
        }
        "stage-verified-assets" if state.backup_captured => {
            state.staged_assets = true;
            events.push("verified-assets-staged-on-vm-disk".into());
        }
        "register-temporary-entry" if state.staged_assets => {
            state.temporary_entry = true;
            events.push("temporary-nousb-entry-registered".into());
        }
        "select-one-shot-entry" if state.temporary_entry => {
            state.one_shot_entry = Some("nousb-installer".into());
            events.push(format!(
                "{}:one-shot-selector-set",
                backend_one_shot_selector(backend)
            ));
        }
        "transfer-to-installer" if state.one_shot_entry.is_some() => {
            state.one_shot_entry = None;
            state.active_entry = "nousb-installer".into();
            state.installer_attempted = true;
            events.push("firmware-consumed-one-shot-before-transfer".into());
            events.push("control-transferred-to-staged-installer".into());
        }
        "verify-payload-in-ram" if state.active_entry == "nousb-installer" => {
            state.ram_payload_observed = true;
            events.push("installer-reported-live-payload-in-ram".into());
        }
        "reboot-to-original-default" if state.installer_attempted => {
            state.active_entry = state.original_default.clone();
            state.fallback_observed = true;
            events.push("second-boot-returned-to-original-default".into());
        }
        "cleanup-temporary-state" if state.active_entry == state.original_default => {
            state.temporary_entry = false;
            state.staged_assets = false;
            events.push("temporary-entry-and-staged-assets-removed".into());
        }
        _ => {
            return Err(NoUsbError::Verification(format!(
                "VM rehearsal precondition failed at step {step}"
            )))
        }
    }
    Ok(())
}

fn recover_vm_rehearsal_state(state: &mut VmBootState, events: &mut Vec<String>) {
    if state.one_shot_entry.take().is_some() {
        events.push("recovery-cleared-pending-one-shot-selector".into());
    }
    state.default_entry = state.original_default.clone();
    state.boot_order = state.original_boot_order.clone();
    state.active_entry = state.original_default.clone();
    state.fallback_observed = true;
    state.temporary_entry = false;
    state.staged_assets = false;
    events.push("recovery-restored-original-default-and-order".into());
    events.push("recovery-removed-temporary-entry-and-assets".into());
}

fn backend_one_shot_selector(backend: OneShotBootBackend) -> &'static str {
    match backend {
        OneShotBootBackend::UefiBootNext => "UEFI BootNext",
        OneShotBootBackend::WindowsBcdBootSequence => "BCD bootsequence",
        OneShotBootBackend::LinuxSystemdBootOneShot => "LoaderEntryOneShot",
        OneShotBootBackend::LinuxGrubReboot => "GRUB next_entry",
    }
}

fn is_safe_filename(value: &str) -> bool {
    if value.is_empty() || value == "." || value == ".." {
        return false;
    }
    let mut components = Path::new(value).components();
    matches!(
        (components.next(), components.next()),
        (Some(std::path::Component::Normal(_)), None)
    )
}

fn is_https_url(value: &str) -> bool {
    value.starts_with("https://") && !value.chars().any(char::is_whitespace)
}

fn http_client() -> Result<Client, NoUsbError> {
    Client::builder()
        .redirect(Policy::limited(5))
        .user_agent(concat!("NoUSB/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|error| NoUsbError::Network(error.to_string()))
}

fn validate_https_response(response: &Response) -> Result<(), NoUsbError> {
    if response.url().scheme() != "https" {
        return Err(NoUsbError::Network(format!(
            "refused HTTPS downgrade redirect to {}",
            response.url()
        )));
    }
    Ok(())
}

pub fn sha256_file(path: &Path) -> Result<String, NoUsbError> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

pub fn verify_artifact(
    profile_id: &str,
    artifact_path: &Path,
) -> Result<ArtifactManifest, NoUsbError> {
    let manifest = artifact_manifest(profile_id)?;
    verify_artifact_against_manifest(artifact_path, &manifest)?;
    Ok(manifest)
}

fn verify_artifact_against_manifest(
    artifact_path: &Path,
    manifest: &ArtifactManifest,
) -> Result<(), NoUsbError> {
    let metadata = fs::metadata(artifact_path)?;
    if !metadata.is_file() {
        return Err(NoUsbError::Verification(format!(
            "artifact path {} is not a regular file",
            artifact_path.display()
        )));
    }
    if metadata.len() != manifest.size_bytes {
        return Err(NoUsbError::Verification(format!(
            "artifact {} is {} bytes; expected {} bytes",
            artifact_path.display(),
            metadata.len(),
            manifest.size_bytes
        )));
    }
    let actual = sha256_file(artifact_path)?;
    if !actual.eq_ignore_ascii_case(&manifest.sha256) {
        return Err(NoUsbError::Verification(format!(
            "artifact {} has SHA-256 {actual}; expected {}",
            artifact_path.display(),
            manifest.sha256
        )));
    }
    Ok(())
}

struct DownloadLock {
    path: PathBuf,
}

impl DownloadLock {
    fn acquire(path: PathBuf) -> Result<Self, NoUsbError> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .map_err(|error| {
                NoUsbError::Io(format!(
                    "cannot acquire download lock {}: {error}",
                    path.display()
                ))
            })?;
        writeln!(file, "pid={}", std::process::id())?;
        file.sync_all()?;
        Ok(Self { path })
    }
}

impl Drop for DownloadLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn finalize_download(
    manifest: ArtifactManifest,
    partial_path: PathBuf,
    final_path: PathBuf,
    resumed_from_bytes: u64,
    downloaded_bytes: u64,
) -> Result<ArtifactDownload, NoUsbError> {
    let actual_size = fs::metadata(&partial_path)?.len();
    if actual_size != manifest.size_bytes {
        return Err(NoUsbError::Verification(format!(
            "downloaded artifact is {actual_size} bytes; expected {}. Partial data was retained",
            manifest.size_bytes
        )));
    }
    let actual_sha256 = sha256_file(&partial_path)?;
    if !actual_sha256.eq_ignore_ascii_case(&manifest.sha256) {
        return Err(NoUsbError::Verification(format!(
            "downloaded artifact has SHA-256 {actual_sha256}; expected {}. Partial data was retained",
            manifest.sha256
        )));
    }
    if final_path.exists() {
        return Err(NoUsbError::Verification(format!(
            "refused to overwrite existing artifact {}",
            final_path.display()
        )));
    }
    fs::rename(&partial_path, &final_path)?;
    Ok(ArtifactDownload {
        manifest,
        path: final_path,
        resumed_from_bytes,
        downloaded_bytes,
        verified: true,
        already_present: false,
    })
}

struct FileDevice(File);

impl IsoRead for FileDevice {
    fn read(&mut self, position: usize, buffer: &mut [u8]) -> Option<()> {
        let position = u64::try_from(position).ok()?;
        self.0.seek(SeekFrom::Start(position)).ok()?;
        self.0.read_exact(buffer).ok()
    }
}

fn open_iso(path: &Path) -> Result<ISO9660, NoUsbError> {
    let file = File::open(path)?;
    ISO9660::from_device(FileDevice(file)).ok_or_else(|| {
        NoUsbError::Verification(format!(
            "{} is not a readable ISO9660 artifact",
            path.display()
        ))
    })
}

/// Reads a small text file from an ISO; `Ok(None)` when the ISO has no such file.
pub(crate) fn read_iso_text_file(
    iso_path: &Path,
    value: &str,
    max_bytes: u64,
) -> Result<Option<String>, NoUsbError> {
    let mut iso = open_iso(iso_path)?;
    let Some(entry) = find_iso_entry(&mut iso, value) else {
        return Ok(None);
    };
    if !entry.is_file() || u64::from(entry.file_size()) > max_bytes {
        return Err(NoUsbError::Verification(format!(
            "{value} in {} is not a small regular file",
            iso_path.display()
        )));
    }
    let mut buffer = vec![0_u8; entry.file_size() as usize];
    let read = iso
        .read_file(&entry, 0, &mut buffer)
        .ok_or_else(|| NoUsbError::Verification(format!("could not read {value} from the ISO")))?;
    buffer.truncate(read);
    Ok(Some(String::from_utf8_lossy(&buffer).into_owned()))
}

/// Extracts one ISO file to a new path; `Ok(false)` when the ISO has no such file.
pub(crate) fn extract_iso_file(
    iso_path: &Path,
    value: &str,
    output_path: &Path,
) -> Result<bool, NoUsbError> {
    let mut iso = open_iso(iso_path)?;
    match find_iso_entry(&mut iso, value) {
        Some(entry) if entry.is_file() => {
            extract_iso_entry(&mut iso, &entry, output_path)?;
            Ok(true)
        }
        Some(_) => Err(NoUsbError::Verification(format!(
            "{value} in the ISO is not a file"
        ))),
        None => Ok(false),
    }
}

fn safe_iso_relative_path(value: &str) -> Result<PathBuf, NoUsbError> {
    if value.contains('\\') || value.contains(':') {
        return Err(NoUsbError::Verification(format!("unsafe ISO path {value}")));
    }
    let trimmed = value.trim_start_matches('/');
    if trimmed.is_empty() || trimmed.contains("//") {
        return Err(NoUsbError::Verification(format!("unsafe ISO path {value}")));
    }
    let mut path = PathBuf::new();
    for component in trimmed.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(NoUsbError::Verification(format!("unsafe ISO path {value}")));
        }
        path.push(component);
    }
    Ok(path)
}

fn iso_names_equal(entry_name: &str, requested: &str) -> bool {
    entry_name
        .split(';')
        .next()
        .unwrap_or(entry_name)
        .trim_end_matches('.')
        .eq_ignore_ascii_case(requested)
}

fn find_iso_entry(iso: &mut ISO9660, value: &str) -> Option<ISODirectoryEntry> {
    let relative_path = safe_iso_relative_path(value).ok()?;
    let components = relative_path
        .iter()
        .map(|component| component.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    let mut directory_lba = iso.root().lba.get() as usize;
    let mut directory_size = iso.root().data_length.get() as usize;
    for (index, component) in components.iter().enumerate() {
        // ISO9660 pads each directory sector with zeroes. `iso9660_simple` stops an
        // iterator at that padding, so inspect every sector in a multi-sector
        // directory instead of assuming all records occupy the first sector.
        let sector_count = directory_size.saturating_add(2047) / 2048;
        let mut matching_entry = None;
        for sector_index in 0..sector_count.max(1) {
            let directory = iso.read_directory(directory_lba.saturating_add(sector_index));
            if let Some(entry) = (&directory).find(|entry| iso_names_equal(&entry.name, component))
            {
                matching_entry = Some(entry);
                break;
            }
        }
        let entry = matching_entry?;
        if index + 1 == components.len() {
            return Some(entry);
        }
        if !entry.is_folder() {
            return None;
        }
        directory_lba = entry.lsb_position() as usize;
        directory_size = entry.file_size() as usize;
    }
    None
}

fn extract_iso_entry(
    iso: &mut ISO9660,
    entry: &ISODirectoryEntry,
    output_path: &Path,
) -> Result<(), NoUsbError> {
    let expected_size = u64::from(entry.file_size());
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(output_path)?;
    let mut offset = 0_u64;
    while offset < expected_size {
        let remaining = expected_size - offset;
        let chunk_size = usize::try_from(remaining.min(1024 * 1024)).map_err(|_| {
            NoUsbError::Verification("ISO asset is too large for this platform".into())
        })?;
        let mut buffer = vec![0_u8; chunk_size];
        let iso_offset = usize::try_from(offset).map_err(|_| {
            NoUsbError::Verification("ISO asset offset is too large for this platform".into())
        })?;
        let read = iso
            .read_file(entry, iso_offset, &mut buffer)
            .ok_or_else(|| {
                NoUsbError::Verification(format!("could not extract ISO entry {}", entry.name))
            })?;
        if read != chunk_size {
            return Err(NoUsbError::Verification(format!(
                "short read while extracting ISO entry {}",
                entry.name
            )));
        }
        output.write_all(&buffer)?;
        offset += u64::try_from(read)
            .map_err(|_| NoUsbError::Verification("ISO asset read size is invalid".into()))?;
    }
    output.sync_all()?;
    if fs::metadata(output_path)?.len() != expected_size {
        return Err(NoUsbError::Verification(format!(
            "extracted ISO entry {} has an unexpected size",
            entry.name
        )));
    }
    Ok(())
}

pub fn plan_operation(
    kind: OperationKind,
    profile_id: Option<&str>,
) -> Result<OperationPlan, NoUsbError> {
    let profile = match profile_id {
        Some(id) => Some(find_profile(id)?),
        None => None,
    };
    let id = format!("plan-{}-{}", kind, unique_plan_stamp());
    let mut steps = vec![
        OperationStep {
            id: "inspect-system".into(),
            title: "Inspect current system".into(),
            description: "Collect firmware, encryption, disk, boot, and space metadata.".into(),
            risk: RiskLevel::Info,
            modifies: vec![],
            rollback: RollbackAction::None,
            state: StepState::Pending,
        },
        OperationStep {
            id: "create-recovery-pack".into(),
            title: "Create recovery pack".into(),
            description: "Write local metadata, boot inventory, and manual recovery notes.".into(),
            risk: RiskLevel::Low,
            modifies: vec!["./recovery-packs".into()],
            rollback: RollbackAction::RemoveStagedFiles,
            state: StepState::Pending,
        },
        OperationStep {
            id: "verify-installer".into(),
            title: "Verify installer artifact".into(),
            description: "Require SHA256 or stronger verification before execution.".into(),
            risk: RiskLevel::Medium,
            modifies: vec![],
            rollback: RollbackAction::None,
            state: StepState::Pending,
        },
    ];

    let (risk, confirmation, mut warnings) = match kind {
        OperationKind::BootOnce => (
            RiskLevel::Medium,
            ConfirmationRequirement::SimpleYes,
            vec!["Default boot target remains the current OS; real boot edits are disabled in this build.".into()],
        ),
        OperationKind::DualBoot => (
            RiskLevel::High,
            ConfirmationRequirement::TypePhrase("I understand dual-boot risk".into()),
            vec!["Partition changes are not performed by the default build.".into()],
        ),
        OperationKind::ReplaceOs => (
            RiskLevel::Critical,
            ConfirmationRequirement::TypePhrase("I have a verified full backup".into()),
            vec![
                "Replacing the current OS can destroy user data.".into(),
                "The default build will not wipe or repartition disks.".into(),
            ],
        ),
        OperationKind::ReinstallCurrentOs => (
            RiskLevel::High,
            ConfirmationRequirement::TypePhrase("I have reviewed reinstall risk".into()),
            vec!["Official installer flow must perform the final reinstall or upgrade.".into()],
        ),
        OperationKind::RecoveryPack => (RiskLevel::Low, ConfirmationRequirement::None, vec![]),
    };

    if let Some(profile) = &profile {
        warnings.push(format!(
            "Profile {} requires at least {} GB free space.",
            profile.id, profile.required_free_space_gb
        ));
    }

    steps.push(OperationStep {
        id: "stage-installer-dry-run".into(),
        title: "Preview installer staging".into(),
        description: "Show the staging strategy without modifying boot configuration.".into(),
        risk,
        modifies: vec!["no boot changes in default build".into()],
        rollback: RollbackAction::Manual(
            "Remove staged files if created by a future real adapter.".into(),
        ),
        state: StepState::Pending,
    });

    Ok(OperationPlan {
        id,
        boot_plan: Some(BootPlan::safe_default(&kind)),
        kind,
        profile_id: profile.map(|p| p.id),
        risk,
        required_privileges: vec![
            "administrator/root required only for real execution adapters".into(),
        ],
        confirmation,
        warnings,
        steps,
    })
}

pub fn plan_operation_for_inventory(
    kind: OperationKind,
    profile_id: Option<&str>,
    inventory: &SystemInventory,
) -> Result<OperationPlan, NoUsbError> {
    let profile = match profile_id {
        Some(id) => Some(find_profile(id)?),
        None => None,
    };
    let mut plan = plan_operation(kind, profile_id)?;

    for warning in &inventory.warnings {
        plan.warnings.push(format!("Preflight: {warning}"));
    }

    if let Some(profile) = &profile {
        match inventory.disk_inventory.available_space_gb {
            Some(available) if available < profile.required_free_space_gb => {
                plan.risk = plan.risk.max(RiskLevel::High);
                plan.warnings.push(format!(
                    "Preflight: only {available} GB free; profile {} requires {} GB.",
                    profile.id, profile.required_free_space_gb
                ));
                plan.steps.push(OperationStep {
                    id: "resolve-low-disk-space".into(),
                    title: "Resolve low disk space".into(),
                    description: "Free space or choose another staging location before proceeding."
                        .into(),
                    risk: RiskLevel::High,
                    modifies: vec![],
                    rollback: RollbackAction::Manual(
                        "No changes were made; free disk space and re-run planning.".into(),
                    ),
                    state: StepState::ManualInterventionRequired,
                });
            }
            None => plan
                .warnings
                .push("Preflight: available disk space could not be determined.".into()),
            _ => {}
        }
    }

    match &inventory.encryption {
        EncryptionState::Enabled(name) => {
            plan.warnings.push(format!(
                "Preflight: {name} encryption is enabled; recovery key/header backup confirmation is required before real boot changes."
            ));
        }
        EncryptionState::Unknown => plan
            .warnings
            .push("Preflight: encryption state is unknown.".into()),
        EncryptionState::Disabled => {}
    }

    if inventory.secure_boot == SecureBootState::Enabled {
        plan.warnings.push(
            "Preflight: Secure Boot is enabled; use only official signed boot assets and stop if firmware rejects them."
                .into(),
        );
    }

    Ok(plan)
}

pub fn assess_delivery(
    inventory: &SystemInventory,
    profile_id: &str,
) -> Result<DeliveryAssessment, NoUsbError> {
    const UEFI_SPEC: &str = "https://uefi.org/specifications";
    const DELL_BIOSCONNECT: &str =
        "https://www.dell.com/support/kbdoc/en-us/000177771/using-biosconnect-to-recover-supportassist-os-recovery-partition";
    const UBUNTU_CASPER: &str = "https://manpages.ubuntu.com/manpages/noble/man7/casper.7.html";
    const GRUB_LOOPBACK: &str =
        "https://www.gnu.org/software/grub/manual/grub/html_node/Loopback-booting.html";
    const WINDOWS_BOOTSEQUENCE: &str =
        "https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--bootsequence";
    const WINDOWS_WINPE: &str =
        "https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/winpe-mount-and-customize";
    const IPXE_WIMBOOT: &str = "https://ipxe.org/wimboot";

    let profile = find_profile(profile_id)?;
    if inventory.os_name == "macos" {
        return Ok(DeliveryAssessment {
            host_os: inventory.os_name.clone(),
            profile_id: profile.id,
            recommended_route: None,
            safe_default_execution_enabled: false,
            universal_no_usb_guarantee: false,
            summary: "macOS hosts are intentionally excluded from the current objective.".into(),
            routes: vec![DeliveryRoute {
                id: "macos-excluded".into(),
                name: "macOS host delivery".into(),
                readiness: DeliveryReadiness::OutOfScope,
                payload_residency: PayloadResidency::PersistentStaging,
                requires_persistent_staging: true,
                requirements: vec![],
                limitations: vec!["No macOS boot-policy or installer work is in scope.".into()],
                reference_urls: vec![],
            }],
        });
    }

    let architecture_matches = profile.architecture == inventory.arch;
    let uefi_known = inventory.firmware == FirmwareMode::Uefi;
    let uefi_unavailable = inventory.firmware == FirmwareMode::Bios;
    let enough_staging_space = inventory
        .disk_inventory
        .available_space_gb
        .map(|available| available >= profile.required_free_space_gb);
    let minimum_ram_mb = u64::from(profile.required_free_space_gb + 2) * 1024;
    let enough_ram = inventory
        .memory_total_mb
        .map(|available| available >= minimum_ram_mb);
    let mut routes = Vec::new();

    if profile
        .supported_staging_strategies
        .contains(&StagingStrategy::KernelInitrd)
    {
        let readiness = if !architecture_matches || uefi_unavailable {
            DeliveryReadiness::Unsupported
        } else if !uefi_known || enough_staging_space != Some(true) || enough_ram != Some(true) {
            DeliveryReadiness::RequiresHostCapability
        } else {
            DeliveryReadiness::DesignCandidate
        };
        let mut limitations = vec![
            "RAM is volatile across reboot, so firmware must first load signed boot assets from disk or the network.".into(),
            "The full-media RAM option needs more memory than the installer image plus runtime headroom.".into(),
        ];
        if let Some(available) = inventory.disk_inventory.available_space_gb {
            if available < profile.required_free_space_gb {
                limitations.push(format!(
                    "Only {available} GB is reported free; the profile requires {} GB for staging.",
                    profile.required_free_space_gb
                ));
            }
        }
        if let Some(available) = inventory.memory_total_mb {
            if available < minimum_ram_mb {
                limitations.push(format!(
                    "Only {available} MB of RAM is reported; this conservative profile check requires at least {minimum_ram_mb} MB."
                ));
            }
        }
        routes.push(DeliveryRoute {
            id: "host-staged-ram-boot".into(),
            name: "Host-staged signed kernel/initrd, then copy live media to RAM".into(),
            readiness,
            payload_residency: PayloadResidency::FullLiveMediaInRam,
            requires_persistent_staging: true,
            requirements: vec![
                "Verified official installer image and signed boot assets.".into(),
                "Feature-gated Windows or Linux one-shot boot adapter with a boot backup.".into(),
                "Installer-specific RAM-copy support such as Ubuntu casper toram.".into(),
            ],
            limitations,
            reference_urls: vec![UBUNTU_CASPER.into(), WINDOWS_BOOTSEQUENCE.into()],
        });
    }

    if inventory.os_name == "linux"
        && profile
            .supported_staging_strategies
            .contains(&StagingStrategy::IsoLoopback)
    {
        let readiness = if !architecture_matches {
            DeliveryReadiness::Unsupported
        } else if enough_staging_space != Some(true) {
            DeliveryReadiness::RequiresHostCapability
        } else {
            DeliveryReadiness::DesignCandidate
        };
        routes.push(DeliveryRoute {
            id: "linux-grub-loopback".into(),
            name: "Linux GRUB loopback boot from a verified ISO".into(),
            readiness,
            payload_residency: PayloadResidency::PersistentStaging,
            requires_persistent_staging: true,
            requirements: vec![
                "GRUB must be able to read the filesystem containing the ISO.".into(),
                "The target distribution initramfs must be able to locate its live root.".into(),
                "A temporary or one-shot entry must preserve the existing default.".into(),
            ],
            limitations: vec![
                "GRUB loopback support alone does not guarantee that the installer can find its root filesystem.".into(),
            ],
            reference_urls: vec![GRUB_LOOPBACK.into()],
        });
    }

    if inventory.os_name == "windows"
        && profile
            .supported_staging_strategies
            .contains(&StagingStrategy::WindowsMountedIsoSetup)
    {
        routes.push(DeliveryRoute {
            id: "windows-mounted-setup".into(),
            name: "Microsoft-supported setup from a verified mounted ISO".into(),
            readiness: if architecture_matches && enough_staging_space == Some(true) {
                DeliveryReadiness::DesignCandidate
            } else {
                DeliveryReadiness::RequiresHostCapability
            },
            payload_residency: PayloadResidency::PersistentStaging,
            requires_persistent_staging: true,
            requirements: vec![
                "Official Microsoft media and supported Windows Setup flow.".into(),
                "A full backup and typed confirmation for reinstall or replacement.".into(),
            ],
            limitations: vec![
                "This is not a firmware-independent RAM boot and is limited to supported Windows Setup scenarios.".into(),
            ],
            reference_urls: vec![WINDOWS_WINPE.into(), WINDOWS_BOOTSEQUENCE.into()],
        });
    }

    if profile.id == "windows-11" {
        routes.push(DeliveryRoute {
            id: "winpe-network-ramdisk".into(),
            name: "Network-fetched WinPE RAM disk with a separate install source".into(),
            readiness: if architecture_matches && !uefi_unavailable {
                DeliveryReadiness::RequiresHostCapability
            } else {
                DeliveryReadiness::Unsupported
            },
            payload_residency: PayloadResidency::BootEnvironmentInRam,
            requires_persistent_staging: false,
            requirements: vec![
                "UEFI HTTP Boot/PXE or a safely staged iPXE-compatible boot chain.".into(),
                "A trusted HTTPS or local network source for WinPE and Windows installation files.".into(),
                "Network drivers compatible with firmware and WinPE.".into(),
            ],
            limitations: vec![
                "WinPE can run from RAM, but the Windows install payload must remain reachable from disk or the network.".into(),
                "The current catalog does not yet contain a signed WinPE artifact manifest.".into(),
            ],
            reference_urls: vec![WINDOWS_WINPE.into(), IPXE_WIMBOOT.into()],
        });
    }

    routes.push(DeliveryRoute {
        id: "uefi-http-boot".into(),
        name: "Firmware-native UEFI HTTP Boot".into(),
        readiness: if uefi_unavailable || !architecture_matches {
            DeliveryReadiness::Unsupported
        } else {
            DeliveryReadiness::RequiresHostCapability
        },
        payload_residency: PayloadResidency::BootEnvironmentInRam,
        requires_persistent_staging: false,
        requirements: vec![
            "Firmware implementation with enabled UEFI HTTP Boot and a supported network device.".into(),
            "Trusted boot URI, signed boot assets, and installer-specific network boot artifacts.".into(),
        ],
        limitations: vec![
            "UEFI support does not imply HTTP Boot support; many PCs expose no usable HTTP Boot path.".into(),
            "Wi-Fi support in preboot firmware is vendor and model dependent.".into(),
        ],
        reference_urls: vec![UEFI_SPEC.into()],
    });

    routes.push(DeliveryRoute {
        id: "dell-biosconnect-reference".into(),
        name: "Dell BIOSConnect comparison".into(),
        readiness: DeliveryReadiness::Unsupported,
        payload_residency: PayloadResidency::FirmwareManaged,
        requires_persistent_staging: false,
        requirements: vec!["Supported Dell firmware and Dell recovery service.".into()],
        limitations: vec![
            "BIOSConnect is vendor firmware, not an application-installable cross-vendor feature.".into(),
            "It restores supported Dell Windows recovery environments and does not boot arbitrary OS profiles.".into(),
        ],
        reference_urls: vec![DELL_BIOSCONNECT.into()],
    });

    let recommended_route = [
        "host-staged-ram-boot",
        "windows-mounted-setup",
        "linux-grub-loopback",
    ]
    .iter()
    .find(|candidate| {
        routes.iter().any(|route| {
            route.id == **candidate && route.readiness == DeliveryReadiness::DesignCandidate
        })
    })
    .map(|value| (*value).to_string());

    Ok(DeliveryAssessment {
        host_os: inventory.os_name.clone(),
        profile_id: profile.id,
        recommended_route,
        safe_default_execution_enabled: false,
        universal_no_usb_guarantee: false,
        summary: "A cross-vendor no-USB workflow must use either firmware network boot or persistent one-shot staging; the installer may move into RAM only after boot begins.".into(),
        routes,
    })
}

pub fn create_recovery_pack(
    base_dir: &Path,
    inventory: &SystemInventory,
) -> Result<PathBuf, NoUsbError> {
    let dir = base_dir
        .join("recovery-packs")
        .join(format!("pack-{}", now_stamp()));
    fs::create_dir_all(&dir)?;
    let mut file = File::create(dir.join("RECOVERY.md"))?;
    writeln!(file, "# NoUSB Recovery Pack")?;
    writeln!(file)?;
    writeln!(
        file,
        "This pack contains metadata only. It is not a full user-data backup."
    )?;
    writeln!(file)?;
    writeln!(file, "## System")?;
    writeln!(file, "- OS: {}", inventory.os_name)?;
    writeln!(file, "- Architecture: {}", inventory.arch)?;
    writeln!(file, "- Firmware: {:?}", inventory.firmware)?;
    writeln!(file, "- Secure Boot: {:?}", inventory.secure_boot)?;
    writeln!(file, "- Encryption: {:?}", inventory.encryption)?;
    writeln!(file)?;
    writeln!(file, "## Manual Recovery")?;
    writeln!(
        file,
        "1. Reboot and choose the original OS entry from firmware boot menu."
    )?;
    writeln!(file, "2. If boot metadata was changed by a future real adapter, restore the recorded boot backup.")?;
    writeln!(
        file,
        "3. Use vendor recovery media if the original OS no longer boots."
    )?;
    Ok(dir)
}

pub fn verify_sha256_with_system_tool(path: &Path, expected: &str) -> Result<bool, NoUsbError> {
    if expected.len() != 64 || !expected.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(NoUsbError::InvalidInput(
            "expected SHA256 must be 64 hex characters".into(),
        ));
    }
    let actual = sha256_file(path)?;
    Ok(actual.eq_ignore_ascii_case(expected))
}

pub struct HostPlatform;

impl PlatformAdapter for HostPlatform {
    fn inspect(&self) -> Result<SystemInventory, NoUsbError> {
        let os_name = std::env::consts::OS.to_string();
        let arch = std::env::consts::ARCH.to_string();
        let firmware = if Path::new("/sys/firmware/efi").exists() {
            FirmwareMode::Uefi
        } else {
            FirmwareMode::Unknown
        };
        let secure_boot = if Path::new("/sys/firmware/efi/efivars").exists() {
            SecureBootState::Unknown
        } else {
            SecureBootState::Unsupported
        };
        // Generic inspection cannot tell; platform adapters refine this read-only.
        let encryption = EncryptionState::Unknown;
        let mut warnings =
            vec!["Default build performs inspection only and will not edit boot settings.".into()];
        if os_name == "macos" {
            warnings.push("Apple Silicon boot policy must not be bypassed.".into());
        }
        Ok(SystemInventory {
            os_name,
            arch,
            memory_total_mb: None,
            firmware,
            secure_boot,
            encryption,
            disk_inventory: DiskInventory {
                disks: vec!["host disk inventory requires privileged platform adapter".into()],
                partitions: vec![],
                available_space_gb: None,
            },
            boot_entries: vec![],
            boot_hints: BootEnvironmentHints {
                unknowns: vec![
                    "ESP, boot managers, and firmware boot entries need a platform adapter".into(),
                ],
                ..Default::default()
            },
            warnings,
        })
    }

    fn name(&self) -> &'static str {
        "host-safe"
    }
}

pub fn read_to_bytes(path: &Path) -> Result<Vec<u8>, NoUsbError> {
    let mut file = File::open(path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn now_stamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or(0)
}

/// Seconds plus nanoseconds, so plans created within the same second never share an id
/// (a shared id would make one saved report overwrite another).
fn unique_plan_stamp() -> String {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}-{:09}", elapsed.as_secs(), elapsed.subsec_nanos())
}

#[derive(Debug)]
struct ProfileFields {
    values: Vec<(String, ProfileValue)>,
}

#[derive(Debug)]
enum ProfileValue {
    String(String),
    Array(Vec<String>),
}

impl ProfileFields {
    fn parse(source: &str) -> Result<Self, NoUsbError> {
        let mut values = Vec::new();
        for (index, raw_line) in source.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((raw_key, raw_value)) = line.split_once('=') else {
                return Err(NoUsbError::ProfileParse(format!(
                    "line {} is missing '='",
                    index + 1
                )));
            };
            let key = raw_key.trim().to_string();
            let value = parse_profile_value(raw_value.trim()).map_err(|error| {
                NoUsbError::ProfileParse(format!("line {} for key {key}: {error}", index + 1))
            })?;
            values.push((key, value));
        }
        Ok(Self { values })
    }

    fn required(&self, key: &str) -> Result<String, NoUsbError> {
        match self.value(key) {
            Some(ProfileValue::String(value)) => Ok(value.clone()),
            Some(ProfileValue::Array(_)) => Err(NoUsbError::ProfileParse(format!(
                "{key} must be a string value"
            ))),
            None => Err(NoUsbError::ProfileParse(format!(
                "missing required field {key}"
            ))),
        }
    }

    fn optional(&self, key: &str) -> Option<String> {
        match self.value(key) {
            Some(ProfileValue::String(value)) if !value.is_empty() => Some(value.clone()),
            _ => None,
        }
    }

    fn array(&self, key: &str) -> Result<Vec<String>, NoUsbError> {
        match self.value(key) {
            Some(ProfileValue::Array(value)) => Ok(value.clone()),
            Some(ProfileValue::String(_)) => Err(NoUsbError::ProfileParse(format!(
                "{key} must be an array value"
            ))),
            None => Err(NoUsbError::ProfileParse(format!(
                "missing required field {key}"
            ))),
        }
    }

    fn value(&self, key: &str) -> Option<&ProfileValue> {
        self.values
            .iter()
            .find_map(|(candidate, value)| (candidate == key).then_some(value))
    }
}

fn parse_profile_value(source: &str) -> Result<ProfileValue, String> {
    if source.starts_with('"') {
        parse_quoted_string(source).map(ProfileValue::String)
    } else if source.starts_with('[') {
        parse_string_array(source).map(ProfileValue::Array)
    } else {
        Ok(ProfileValue::String(source.to_string()))
    }
}

fn parse_quoted_string(source: &str) -> Result<String, String> {
    let trimmed = source.trim();
    if !trimmed.starts_with('"') || !trimmed.ends_with('"') {
        return Err("quoted string must start and end with double quotes".into());
    }
    Ok(unescape_profile_string(&trimmed[1..trimmed.len() - 1]))
}

fn parse_string_array(source: &str) -> Result<Vec<String>, String> {
    let trimmed = source.trim();
    if !trimmed.starts_with('[') || !trimmed.ends_with(']') {
        return Err("array must start with '[' and end with ']'".into());
    }
    let inner = trimmed[1..trimmed.len() - 1].trim();
    if inner.is_empty() {
        return Ok(vec![]);
    }

    let mut values = Vec::new();
    let mut current = String::new();
    let mut in_string = false;
    let mut escaped = false;

    for character in inner.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            continue;
        }
        match character {
            '\\' if in_string => escaped = true,
            '"' => {
                in_string = !in_string;
                current.push(character);
            }
            ',' if !in_string => {
                values.push(parse_quoted_string(current.trim())?);
                current.clear();
            }
            _ => current.push(character),
        }
    }

    if in_string {
        return Err("unterminated string in array".into());
    }
    if !current.trim().is_empty() {
        values.push(parse_quoted_string(current.trim())?);
    }
    Ok(values)
}

fn unescape_profile_string(source: &str) -> String {
    let mut output = String::new();
    let mut escaped = false;
    for character in source.chars() {
        if escaped {
            match character {
                'n' => output.push('\n'),
                'r' => output.push('\r'),
                't' => output.push('\t'),
                '"' => output.push('"'),
                '\\' => output.push('\\'),
                other => output.push(other),
            }
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else {
            output.push(character);
        }
    }
    output
}

fn json_pair(key: &str, value: &str) -> String {
    format!("\"{}\":\"{}\"", escape_json(key), escape_json(value))
}

fn json_optional_pair(key: &str, value: Option<&str>) -> String {
    match value {
        Some(value) => json_pair(key, value),
        None => format!("\"{}\":null", escape_json(key)),
    }
}

fn json_optional_value(value: Option<&str>) -> String {
    match value {
        Some(value) => format!("\"{}\"", escape_json(value)),
        None => "null".into(),
    }
}

fn json_string_array(values: &[String]) -> String {
    let values: Vec<String> = values
        .iter()
        .map(|value| format!("\"{}\"", escape_json(value)))
        .collect();
    format!("[{}]", values.join(","))
}

fn json_field(source: &str, key: &str) -> Option<String> {
    let marker = format!("\"{}\":\"", escape_json(key));
    let start = source.find(&marker)? + marker.len();
    let mut output = String::new();
    let mut escaped = false;
    for character in source[start..].chars() {
        if escaped {
            match character {
                'n' => output.push('\n'),
                'r' => output.push('\r'),
                't' => output.push('\t'),
                '"' => output.push('"'),
                '\\' => output.push('\\'),
                other => output.push(other),
            }
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '"' {
            return Some(output);
        } else {
            output.push(character);
        }
    }
    None
}

fn json_bool_field(source: &str, key: &str) -> Option<bool> {
    let marker = format!("\"{}\":", escape_json(key));
    let start = source.find(&marker)? + marker.len();
    let remaining = source[start..].trim_start();
    if remaining.starts_with("true") {
        Some(true)
    } else if remaining.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

fn safe_filename(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

/// Escapes `value` for the inside of a JSON string literal. serde_json does the escaping, so
/// every crate's hand-assembled JSON stays valid for quotes, backslashes, and control characters.
pub fn escape_json(value: &str) -> String {
    let quoted = serde_json::Value::String(value.to_owned()).to_string();
    quoted[1..quoted.len() - 1].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replace_os_is_critical_and_typed() {
        let plan = plan_operation(OperationKind::ReplaceOs, Some("ubuntu-24.04-desktop")).unwrap();
        assert_eq!(plan.risk, RiskLevel::Critical);
        assert!(matches!(
            plan.confirmation,
            ConfirmationRequirement::TypePhrase(_)
        ));
    }

    #[test]
    fn unknown_profile_fails() {
        let result = plan_operation(OperationKind::BootOnce, Some("missing"));
        assert!(matches!(result, Err(NoUsbError::UnknownProfile(_))));
    }

    #[test]
    fn profile_catalog_has_safe_defaults() {
        let profiles = built_in_profiles();
        assert!(profiles
            .iter()
            .any(|profile| profile.id == "ubuntu-24.04-desktop"));
        assert!(profiles
            .iter()
            .all(|profile| profile.required_free_space_gb > 0));
    }

    #[test]
    fn embedded_profiles_parse_and_validate() {
        let profiles = embedded_profiles().unwrap();
        assert_eq!(profiles.len(), 4);
        assert!(profiles.iter().all(|profile| profile.schema_version == "1"));
        assert!(profiles
            .iter()
            .any(|profile| profile.supported_platforms.contains(&"linux_uefi".into())));
    }

    #[test]
    fn profile_validation_rejects_empty_platforms() {
        let source = r#"
schema_version = "1"
id = "bad"
name = "Bad"
vendor = "NoUSB"
version = "0"
architecture = "x86_64"
source_url = "https://example.invalid"
checksum_url = "https://example.invalid/SHA256SUMS"
sha256 = "placeholder"
signature_url = ""
homepage = "https://example.invalid"
license_notes = "None"
supported_platforms = []
supported_staging_strategies = ["manual_instructions"]
required_free_space_gb = 1
extraction_rules = []
kernel_initrd_paths = []
bootloader_paths = []
secure_boot_notes = "None"
known_limitations = []
post_boot_instructions = "None"
"#;
        let result = parse_installer_profile(source);
        assert!(matches!(result, Err(NoUsbError::ProfileParse(_))));
    }

    #[test]
    fn plan_json_contains_core_fields() {
        let plan = plan_operation(OperationKind::BootOnce, Some("ubuntu-24.04-desktop")).unwrap();
        let json = plan.to_json();
        assert!(json.contains("\"kind\":\"boot-once\""));
        assert!(json.contains("\"risk\":\"medium\""));
        assert!(json.contains("\"boot_plan\""));
        assert!(json.contains("\"steps\""));
    }

    #[test]
    fn boot_once_plan_prefers_one_time_boot() {
        let plan = plan_operation(OperationKind::BootOnce, Some("ubuntu-24.04-desktop")).unwrap();
        let boot_plan = plan.boot_plan.unwrap();
        assert_eq!(
            boot_plan.selected_preference,
            BootPlanPreference::OneTimeBoot
        );
        assert!(boot_plan.keep_current_os_default);
        assert!(!boot_plan.allow_permanent_boot_order_change);
    }

    #[test]
    fn replace_os_plan_still_disallows_permanent_boot_change_by_default() {
        let plan = plan_operation(OperationKind::ReplaceOs, Some("ubuntu-24.04-desktop")).unwrap();
        let boot_plan = plan.boot_plan.unwrap();
        assert_eq!(
            boot_plan.selected_preference,
            BootPlanPreference::TemporaryBootEntryWithFallback
        );
        assert!(boot_plan.keep_current_os_default);
        assert!(!boot_plan.allow_permanent_boot_order_change);
    }

    #[test]
    fn yes_flag_cannot_approve_critical_plan() {
        let plan = plan_operation(OperationKind::ReplaceOs, Some("ubuntu-24.04-desktop")).unwrap();
        let result = execute_plan_safe(&plan, true);
        assert!(matches!(result, Err(NoUsbError::UnsafeExecution(_))));
    }

    #[test]
    fn fake_windows_bitlocker_adds_preflight_warnings() {
        let adapter = FakePlatformAdapter::windows_uefi_bitlocker();
        let inventory = adapter.inspect().unwrap();
        let plan = plan_operation_for_inventory(
            OperationKind::BootOnce,
            Some("ubuntu-24.04-desktop"),
            &inventory,
        )
        .unwrap();

        assert_eq!(inventory.secure_boot, SecureBootState::Enabled);
        assert!(adapter
            .capabilities()
            .contains(&PlatformCapability::BootEntryBackup));
        assert!(plan
            .warnings
            .iter()
            .any(|warning| warning.contains("BitLocker")));
        assert!(plan
            .warnings
            .iter()
            .any(|warning| warning.contains("Secure Boot")));
    }

    #[test]
    fn windows_to_ubuntu_assessment_recommends_staged_ram_design() {
        let inventory = FakePlatformAdapter::windows_uefi_bitlocker()
            .inspect()
            .unwrap();
        let assessment = assess_delivery(&inventory, "ubuntu-24.04-desktop").unwrap();

        assert_eq!(
            assessment.recommended_route.as_deref(),
            Some("host-staged-ram-boot")
        );
        assert!(!assessment.safe_default_execution_enabled);
        assert!(!assessment.universal_no_usb_guarantee);
        assert!(assessment.routes.iter().any(|route| {
            route.id == "host-staged-ram-boot"
                && route.readiness == DeliveryReadiness::DesignCandidate
                && route.requires_persistent_staging
        }));
    }

    #[test]
    fn macos_delivery_is_explicitly_out_of_scope() {
        let inventory = FakePlatformAdapter::macos_apple_silicon_filevault()
            .inspect()
            .unwrap();
        let assessment = assess_delivery(&inventory, "ubuntu-24.04-desktop").unwrap();

        assert!(assessment.recommended_route.is_none());
        assert_eq!(assessment.routes.len(), 1);
        assert_eq!(
            assessment.routes[0].readiness,
            DeliveryReadiness::OutOfScope
        );
    }

    #[test]
    fn fake_linux_low_space_requires_manual_intervention() {
        let inventory = FakePlatformAdapter::linux_grub_luks_btrfs_low_space()
            .inspect()
            .unwrap();
        let plan = plan_operation_for_inventory(
            OperationKind::BootOnce,
            Some("ubuntu-24.04-desktop"),
            &inventory,
        )
        .unwrap();

        assert_eq!(plan.risk, RiskLevel::High);
        assert!(plan
            .steps
            .iter()
            .any(|step| step.id == "resolve-low-disk-space"
                && step.state == StepState::ManualInterventionRequired));
        assert!(plan.warnings.iter().any(|warning| warning.contains("LUKS")));
    }

    #[test]
    fn fake_macos_apple_silicon_warns_about_policy() {
        let inventory = FakePlatformAdapter::macos_apple_silicon_filevault()
            .inspect()
            .unwrap();
        let plan = plan_operation_for_inventory(
            OperationKind::ReinstallCurrentOs,
            Some("windows-11"),
            &inventory,
        )
        .unwrap();

        assert_eq!(inventory.arch, "aarch64");
        assert!(plan
            .warnings
            .iter()
            .any(|warning| warning.contains("Apple Silicon boot policy")));
        assert!(plan
            .warnings
            .iter()
            .any(|warning| warning.contains("FileVault")));
    }

    #[test]
    fn simulated_executor_can_complete_safe_plan() {
        let plan = plan_operation(OperationKind::BootOnce, Some("ubuntu-24.04-desktop")).unwrap();
        let report = SimulatedExecutor::new(SimulationConfig::complete())
            .execute(&plan)
            .unwrap();

        assert_eq!(report.status, ExecutionStatus::Completed);
        assert!(!report.recovery_required);
        assert!(report
            .steps
            .iter()
            .all(|step| step.state == StepState::Completed));
    }

    #[test]
    fn simulated_executor_can_interrupt_after_completed_step() {
        let plan = plan_operation(OperationKind::BootOnce, Some("ubuntu-24.04-desktop")).unwrap();
        let report = SimulatedExecutor::new(SimulationConfig::interrupt_after(2))
            .execute(&plan)
            .unwrap();

        assert_eq!(report.status, ExecutionStatus::Interrupted);
        assert!(report.recovery_required);
        assert_eq!(report.steps[0].state, StepState::Completed);
        assert_eq!(report.steps[1].state, StepState::Completed);
        assert_eq!(report.steps[2].state, StepState::Pending);
    }

    #[test]
    fn simulated_executor_failure_marks_step_failed() {
        let plan = plan_operation(OperationKind::BootOnce, Some("ubuntu-24.04-desktop")).unwrap();
        let report = SimulatedExecutor::new(SimulationConfig::fail_step("verify-installer"))
            .execute(&plan)
            .unwrap();

        assert_eq!(report.status, ExecutionStatus::Failed);
        assert!(report.recovery_required);
        assert!(report
            .steps
            .iter()
            .any(|step| step.id == "verify-installer" && step.state == StepState::Failed));
    }

    #[test]
    fn simulated_rollback_rolls_back_completed_steps_with_actions() {
        let plan = plan_operation(OperationKind::BootOnce, Some("ubuntu-24.04-desktop")).unwrap();
        let interrupted = SimulatedExecutor::new(SimulationConfig::interrupt_after(2))
            .execute(&plan)
            .unwrap();
        let rolled_back = rollback_simulated_report(&interrupted);

        assert_eq!(rolled_back.status, ExecutionStatus::RolledBack);
        assert!(rolled_back
            .steps
            .iter()
            .any(|step| step.id == "create-recovery-pack" && step.state == StepState::RolledBack));
        assert!(rolled_back
            .steps
            .iter()
            .any(|step| step.id == "inspect-system" && step.state == StepState::Completed));
    }

    #[test]
    fn execution_reports_can_be_saved_listed_and_loaded() {
        let base_dir = std::env::temp_dir().join(format!("nousb-test-{}", now_stamp()));
        let plan = plan_operation(OperationKind::BootOnce, Some("ubuntu-24.04-desktop")).unwrap();
        let report = SimulatedExecutor::new(SimulationConfig::interrupt_after(1))
            .execute(&plan)
            .unwrap();

        let path = save_execution_report(&base_dir, &report).unwrap();
        assert!(path.exists());

        let summaries = list_saved_execution_reports(&base_dir).unwrap();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].plan_id, report.plan_id);
        assert_eq!(summaries[0].status, "interrupted");
        assert!(summaries[0].recovery_required);

        let loaded = load_execution_report_json(&base_dir, &report.plan_id).unwrap();
        assert!(loaded.contains("\"status\":\"interrupted\""));

        let _ = fs::remove_dir_all(base_dir);
    }

    #[test]
    fn diagnostic_bundle_redacts_secret_like_lines() {
        let redacted =
            redact_secrets("password=hunter2\nsafe=value\nBitLocker recovery_key: 12345");
        assert!(redacted.contains("password=[REDACTED]"));
        assert!(redacted.contains("safe=value"));
        assert!(redacted.contains("BitLocker recovery_key: [REDACTED]"));
        assert!(!redacted.contains("hunter2"));
        assert!(!redacted.contains("12345"));
    }

    #[test]
    fn diagnostic_bundle_exports_project_local_artifacts() {
        let base_dir = std::env::temp_dir().join(format!("nousb-diag-test-{}", now_stamp()));
        let plan = plan_operation(OperationKind::BootOnce, Some("ubuntu-24.04-desktop")).unwrap();
        let report = SimulatedExecutor::new(SimulationConfig::interrupt_after(1))
            .execute(&plan)
            .unwrap();
        save_execution_report(&base_dir, &report).unwrap();
        write_journal_entry(&base_dir, "token=super-secret").unwrap();

        let inventory = FakePlatformAdapter::windows_uefi_bitlocker()
            .inspect()
            .unwrap();
        let bundle = export_diagnostic_bundle(&base_dir, &inventory).unwrap();
        assert!(bundle.path.exists());
        assert!(bundle
            .files
            .iter()
            .any(|path| path.ends_with("system-inventory.json")));
        assert!(bundle
            .files
            .iter()
            .any(|path| path.ends_with("execution-report-index.json")));

        let log = fs::read_to_string(bundle.path.join("operations.log")).unwrap();
        assert!(log.contains("token=[REDACTED]"));
        assert!(!log.contains("super-secret"));

        let _ = fs::remove_dir_all(base_dir);
    }

    #[test]
    fn artifact_manifests_pin_current_vendor_images() {
        let ubuntu = artifact_manifest("ubuntu-24.04-desktop").unwrap();
        assert_eq!(ubuntu.filename, "ubuntu-24.04.4-desktop-amd64.iso");
        assert_eq!(ubuntu.size_bytes, 6_655_619_072);

        let ubuntu_server = artifact_manifest("ubuntu-24.04-server").unwrap();
        assert_eq!(
            ubuntu_server.filename,
            "ubuntu-24.04.4-live-server-amd64.iso"
        );
        assert_eq!(
            ubuntu_server.sha256,
            "e907d92eeec9df64163a7e454cbc8d7755e8ddc7ed42f99dbc80c40f1a138433"
        );
        assert_eq!(ubuntu_server.size_bytes, 3_405_469_696);
        assert_eq!(
            ubuntu.sha256,
            "3a4c9877b483ab46d7c3fbe165a0db275e1ae3cfe56a5657e5a47c2f99a99d1e"
        );

        let fedora = artifact_manifest("fedora-44-workstation").unwrap();
        assert_eq!(fedora.size_bytes, 2_851_612_672);
        assert_eq!(
            fedora.sha256,
            "1620295f6a00c27c3208f0c00b8ece4eab1ec69b9002152d97488bf26a426ddf"
        );
    }

    #[test]
    fn vendor_mediated_windows_image_is_not_downloadable() {
        assert!(matches!(
            artifact_manifest("windows-11"),
            Err(NoUsbError::ArtifactUnavailable(_))
        ));
    }

    #[test]
    fn sha256_verification_is_cross_platform() {
        let base_dir = std::env::temp_dir().join(format!(
            "nousb-sha-test-{}-{}",
            std::process::id(),
            now_stamp()
        ));
        fs::create_dir_all(&base_dir).unwrap();
        let path = base_dir.join("fixture.bin");
        fs::write(&path, b"abc").unwrap();

        assert_eq!(
            sha256_file(&path).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(verify_sha256_with_system_tool(
            &path,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )
        .unwrap());

        let _ = fs::remove_dir_all(base_dir);
    }

    #[test]
    fn verified_partial_is_atomically_finalized() {
        let base_dir = std::env::temp_dir().join(format!(
            "nousb-finalize-test-{}-{}",
            std::process::id(),
            now_stamp()
        ));
        fs::create_dir_all(&base_dir).unwrap();
        let partial_path = base_dir.join("fixture.iso.part");
        let final_path = base_dir.join("fixture.iso");
        fs::write(&partial_path, b"abc").unwrap();
        let manifest = ArtifactManifest {
            profile_id: "fixture".into(),
            filename: "fixture.iso".into(),
            source_url: "https://example.invalid/fixture.iso".into(),
            checksum_url: "https://example.invalid/SHA256SUMS".into(),
            signature_url: None,
            sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into(),
            size_bytes: 3,
        };

        let result =
            finalize_download(manifest, partial_path.clone(), final_path.clone(), 1, 2).unwrap();
        assert!(result.verified);
        assert_eq!(result.resumed_from_bytes, 1);
        assert!(!partial_path.exists());
        assert_eq!(fs::read(&final_path).unwrap(), b"abc");

        let _ = fs::remove_dir_all(base_dir);
    }

    #[test]
    fn staging_paths_reject_traversal_and_windows_separators() {
        assert!(safe_iso_relative_path("/casper/vmlinuz").is_ok());
        assert!(safe_iso_relative_path("../bootx64.efi").is_err());
        assert!(safe_iso_relative_path("EFI/../bootx64.efi").is_err());
        assert!(safe_iso_relative_path("EFI\\BOOT\\BOOTX64.EFI").is_err());
        assert!(safe_iso_relative_path("C:/bootx64.efi").is_err());
    }

    #[test]
    fn iso_names_accept_versioned_extensionless_files_with_trailing_dot() {
        assert!(iso_names_equal("VMLINUZ.;1", "vmlinuz"));
        assert!(iso_names_equal("INITRD.;1", "initrd"));
        assert!(iso_names_equal("BOOTX64.EFI;1", "bootx64.efi"));
        assert!(!iso_names_equal("VMLINUZ.OLD;1", "vmlinuz"));
    }

    #[test]
    fn vm_rehearsal_matrix_preserves_default_and_recovers_every_interruption() {
        let backends = [
            OneShotBootBackend::UefiBootNext,
            OneShotBootBackend::WindowsBcdBootSequence,
            OneShotBootBackend::LinuxSystemdBootOneShot,
            OneShotBootBackend::LinuxGrubReboot,
        ];
        for backend in backends {
            let report = rehearse_vm_one_shot(backend, "ubuntu-24.04-desktop").unwrap();
            assert_eq!(report.scenarios.len(), VM_REHEARSAL_STEPS.len() + 1);
            assert!(report.all_invariants_hold);
            assert!(!report.real_vm_executed);
            assert!(!report.host_boot_changes);
            assert!(report.scenarios.iter().all(|scenario| {
                scenario.invariants_hold
                    && scenario.original_default_preserved
                    && scenario.boot_order_preserved
                    && scenario.one_shot_cleared
                    && scenario.temporary_entry_removed
                    && scenario.staged_assets_removed
            }));
            let completed = &report.scenarios[0];
            assert!(completed.installer_attempted);
            assert!(completed.ram_payload_observed);
            assert!(completed.fallback_observed);
        }
    }

    #[test]
    fn vm_rehearsal_uses_backend_specific_one_shot_selectors() {
        let cases = [
            (OneShotBootBackend::UefiBootNext, "UEFI BootNext"),
            (
                OneShotBootBackend::WindowsBcdBootSequence,
                "BCD bootsequence",
            ),
            (
                OneShotBootBackend::LinuxSystemdBootOneShot,
                "LoaderEntryOneShot",
            ),
            (OneShotBootBackend::LinuxGrubReboot, "GRUB next_entry"),
        ];
        for (backend, selector) in cases {
            let report = rehearse_vm_one_shot(backend, "ubuntu-24.04-desktop").unwrap();
            assert!(report.scenarios[0]
                .events
                .iter()
                .any(|event| event.contains(selector)));
        }
    }

    #[test]
    fn vm_rehearsal_report_is_saved_project_locally() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        let base_dir =
            std::env::temp_dir().join(format!("nousb-vm-report-{}-{unique}", std::process::id()));
        let report = rehearse_vm_one_shot(
            OneShotBootBackend::WindowsBcdBootSequence,
            "ubuntu-24.04-desktop",
        )
        .unwrap();
        let path = save_vm_rehearsal(&base_dir, &report).unwrap();
        let contents = fs::read_to_string(&path).unwrap();

        assert!(path.starts_with(base_dir.join(".nousb/vm-rehearsals")));
        assert!(contents.contains("\"all_invariants_hold\":true"));
        assert!(contents.contains("\"real_vm_executed\":false"));
        assert!(contents.contains("\"host_boot_changes\":false"));

        let _ = fs::remove_dir_all(base_dir);
    }

    #[test]
    fn synthetic_iso_is_verified_inspected_and_staged_end_to_end() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        let base_dir =
            std::env::temp_dir().join(format!("nousb-iso-fixture-{}-{unique}", std::process::id()));
        fs::create_dir_all(&base_dir).unwrap();
        let artifact_path = base_dir.join("fixture.iso");
        write_synthetic_iso(&artifact_path);

        let digest = sha256_file(&artifact_path).unwrap();
        let manifest = ArtifactManifest {
            profile_id: "fixture-linux".into(),
            filename: "fixture.iso".into(),
            source_url: "https://example.invalid/fixture.iso".into(),
            checksum_url: "https://example.invalid/SHA256SUMS".into(),
            signature_url: None,
            sha256: digest.clone(),
            size_bytes: fs::metadata(&artifact_path).unwrap().len(),
        };
        verify_artifact_against_manifest(&artifact_path, &manifest).unwrap();

        let mut profile = find_profile("ubuntu-24.04-desktop").unwrap();
        profile.id = "fixture-linux".into();
        profile.kernel_initrd_paths = vec!["/casper/vmlinuz".into(), "/casper/initrd".into()];
        profile.bootloader_paths.clear();
        let preview = inspect_staging_profile(&profile, &artifact_path).unwrap();
        assert!(preview.artifact_verified);
        assert_eq!(preview.assets.len(), 2);
        assert!(!preview.execution_enabled);

        let bundle = create_staging_bundle_from_preview(&base_dir, preview, &digest).unwrap();
        assert!(bundle.path.join("bundle.json").exists());
        assert!(bundle.path.join("README.txt").exists());
        assert_eq!(
            fs::read(bundle.path.join("assets/casper/vmlinuz")).unwrap(),
            b"synthetic-linux-kernel"
        );
        assert_eq!(
            fs::read(bundle.path.join("assets/casper/initrd")).unwrap(),
            b"synthetic-initrd"
        );
        assert!(bundle.assets.iter().all(|asset| asset.sha256.is_some()));
        assert!(!bundle.execution_enabled);

        let mut wrong_manifest = manifest;
        wrong_manifest.size_bytes += 1;
        assert!(matches!(
            verify_artifact_against_manifest(&artifact_path, &wrong_manifest),
            Err(NoUsbError::Verification(_))
        ));

        let _ = fs::remove_dir_all(base_dir);
    }

    fn write_synthetic_iso(path: &Path) {
        const SECTOR_SIZE: usize = 2048;
        const SECTOR_COUNT: usize = 24;
        const ROOT_SECTOR: u32 = 20;
        const CASPER_SECTOR: u32 = 21;
        const KERNEL_SECTOR: u32 = 22;
        const INITRD_SECTOR: u32 = 23;

        let kernel = b"synthetic-linux-kernel";
        let initrd = b"synthetic-initrd";
        let mut image = vec![0_u8; SECTOR_SIZE * SECTOR_COUNT];

        let pvd = 16 * SECTOR_SIZE;
        image[pvd] = 1;
        image[pvd + 1..pvd + 6].copy_from_slice(b"CD001");
        image[pvd + 6] = 1;
        write_both_endian_u32(&mut image[pvd + 80..pvd + 88], SECTOR_COUNT as u32);
        write_both_endian_u16(&mut image[pvd + 120..pvd + 124], 1);
        write_both_endian_u16(&mut image[pvd + 124..pvd + 128], 1);
        write_both_endian_u16(&mut image[pvd + 128..pvd + 132], SECTOR_SIZE as u16);
        let root_record = iso_directory_record(ROOT_SECTOR, SECTOR_SIZE as u32, true, &[0]);
        image[pvd + 156..pvd + 190].copy_from_slice(&root_record);
        image[pvd + 881] = 1;

        let terminator = 17 * SECTOR_SIZE;
        image[terminator] = 255;
        image[terminator + 1..terminator + 6].copy_from_slice(b"CD001");
        image[terminator + 6] = 1;

        let root_offset = ROOT_SECTOR as usize * SECTOR_SIZE;
        let mut cursor = root_offset;
        cursor = write_iso_record(
            &mut image,
            cursor,
            iso_directory_record(ROOT_SECTOR, SECTOR_SIZE as u32, true, &[0]),
        );
        cursor = write_iso_record(
            &mut image,
            cursor,
            iso_directory_record(ROOT_SECTOR, SECTOR_SIZE as u32, true, &[1]),
        );
        let _ = write_iso_record(
            &mut image,
            cursor,
            iso_directory_record(CASPER_SECTOR, SECTOR_SIZE as u32, true, b"CASPER"),
        );

        let casper_offset = CASPER_SECTOR as usize * SECTOR_SIZE;
        let mut cursor = casper_offset;
        cursor = write_iso_record(
            &mut image,
            cursor,
            iso_directory_record(CASPER_SECTOR, SECTOR_SIZE as u32, true, &[0]),
        );
        cursor = write_iso_record(
            &mut image,
            cursor,
            iso_directory_record(ROOT_SECTOR, SECTOR_SIZE as u32, true, &[1]),
        );
        cursor = write_iso_record(
            &mut image,
            cursor,
            iso_directory_record(KERNEL_SECTOR, kernel.len() as u32, false, b"VMLINUZ;1"),
        );
        let _ = write_iso_record(
            &mut image,
            cursor,
            iso_directory_record(INITRD_SECTOR, initrd.len() as u32, false, b"INITRD;1"),
        );

        let kernel_offset = KERNEL_SECTOR as usize * SECTOR_SIZE;
        image[kernel_offset..kernel_offset + kernel.len()].copy_from_slice(kernel);
        let initrd_offset = INITRD_SECTOR as usize * SECTOR_SIZE;
        image[initrd_offset..initrd_offset + initrd.len()].copy_from_slice(initrd);
        fs::write(path, image).unwrap();
    }

    fn iso_directory_record(lba: u32, size: u32, is_directory: bool, name: &[u8]) -> Vec<u8> {
        let padding = usize::from(name.len().is_multiple_of(2));
        let length = 33 + name.len() + padding;
        let mut record = vec![0_u8; length];
        record[0] = length as u8;
        write_both_endian_u32(&mut record[2..10], lba);
        write_both_endian_u32(&mut record[10..18], size);
        record[18..25].copy_from_slice(&[126, 1, 1, 0, 0, 0, 0]);
        record[25] = if is_directory { 2 } else { 0 };
        write_both_endian_u16(&mut record[28..32], 1);
        record[32] = name.len() as u8;
        record[33..33 + name.len()].copy_from_slice(name);
        record
    }

    fn write_iso_record(image: &mut [u8], offset: usize, record: Vec<u8>) -> usize {
        let end = offset + record.len();
        image[offset..end].copy_from_slice(&record);
        end
    }

    fn write_both_endian_u16(target: &mut [u8], value: u16) {
        target[..2].copy_from_slice(&value.to_le_bytes());
        target[2..4].copy_from_slice(&value.to_be_bytes());
    }

    fn write_both_endian_u32(target: &mut [u8], value: u32) {
        target[..4].copy_from_slice(&value.to_le_bytes());
        target[4..8].copy_from_slice(&value.to_be_bytes());
    }
}
