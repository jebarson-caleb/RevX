//! Recovery from persisted execution reports: parse what `save_execution_report` wrote,
//! decide whether an operation should be resumed, rolled back, or handed to a human, and
//! resume simulated operations. Nothing here touches host boot state.

use std::path::Path;

use serde::Deserialize;

use super::{
    journal_execution_report, json_pair, json_string_array, load_execution_report_json,
    ExecutionReport, ExecutionStatus, NoUsbError, OperationStep, RiskLevel, RollbackAction,
    StepState,
};

#[derive(Deserialize)]
struct StoredReport {
    plan_id: String,
    status: StoredStatus,
    steps: Vec<StoredStep>,
    journal: Vec<String>,
    recovery_required: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum StoredStatus {
    Completed,
    Interrupted,
    Failed,
    RolledBack,
}

#[derive(Deserialize)]
struct StoredStep {
    id: String,
    title: String,
    description: String,
    risk: StoredRisk,
    modifies: Vec<String>,
    rollback: StoredRollback,
    state: StoredState,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum StoredRisk {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum StoredState {
    Pending,
    Running,
    Completed,
    Failed,
    RolledBack,
    ManualInterventionRequired,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum StoredRollback {
    None,
    RemoveStagedFiles,
    RestoreBootBackup,
    Manual { note: String },
}

impl From<StoredReport> for ExecutionReport {
    fn from(stored: StoredReport) -> Self {
        ExecutionReport {
            plan_id: stored.plan_id,
            status: match stored.status {
                StoredStatus::Completed => ExecutionStatus::Completed,
                StoredStatus::Interrupted => ExecutionStatus::Interrupted,
                StoredStatus::Failed => ExecutionStatus::Failed,
                StoredStatus::RolledBack => ExecutionStatus::RolledBack,
            },
            steps: stored.steps.into_iter().map(OperationStep::from).collect(),
            journal: stored.journal,
            recovery_required: stored.recovery_required,
        }
    }
}

impl From<StoredStep> for OperationStep {
    fn from(stored: StoredStep) -> Self {
        OperationStep {
            id: stored.id,
            title: stored.title,
            description: stored.description,
            risk: match stored.risk {
                StoredRisk::Info => RiskLevel::Info,
                StoredRisk::Low => RiskLevel::Low,
                StoredRisk::Medium => RiskLevel::Medium,
                StoredRisk::High => RiskLevel::High,
                StoredRisk::Critical => RiskLevel::Critical,
            },
            modifies: stored.modifies,
            rollback: match stored.rollback {
                StoredRollback::None => RollbackAction::None,
                StoredRollback::RemoveStagedFiles => RollbackAction::RemoveStagedFiles,
                StoredRollback::RestoreBootBackup => RollbackAction::RestoreBootBackup,
                StoredRollback::Manual { note } => RollbackAction::Manual(note),
            },
            state: match stored.state {
                StoredState::Pending => StepState::Pending,
                StoredState::Running => StepState::Running,
                StoredState::Completed => StepState::Completed,
                StoredState::Failed => StepState::Failed,
                StoredState::RolledBack => StepState::RolledBack,
                StoredState::ManualInterventionRequired => StepState::ManualInterventionRequired,
            },
        }
    }
}

/// Parses a report in the format written by [`ExecutionReport::to_json`].
pub fn parse_execution_report(json: &str) -> Result<ExecutionReport, NoUsbError> {
    serde_json::from_str::<StoredReport>(json)
        .map(ExecutionReport::from)
        .map_err(|error| NoUsbError::InvalidInput(format!("unreadable execution report: {error}")))
}

pub fn load_execution_report(
    base_dir: &Path,
    plan_id: &str,
) -> Result<ExecutionReport, NoUsbError> {
    match load_execution_report_json(base_dir, plan_id) {
        Ok(json) => parse_execution_report(&json),
        // A report whose JSON file is gone may still be in the operation journal.
        Err(missing) => journal_execution_report(base_dir, plan_id)?.ok_or(missing),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryAction {
    NothingToDo,
    Resume,
    Rollback,
    ManualIntervention,
}

impl RecoveryAction {
    pub fn as_str(self) -> &'static str {
        match self {
            RecoveryAction::NothingToDo => "nothing_to_do",
            RecoveryAction::Resume => "resume",
            RecoveryAction::Rollback => "rollback",
            RecoveryAction::ManualIntervention => "manual_intervention",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryAssessment {
    pub plan_id: String,
    pub status: ExecutionStatus,
    pub completed_steps: Vec<String>,
    pub interrupted_steps: Vec<String>,
    pub pending_steps: Vec<String>,
    pub failed_steps: Vec<String>,
    pub manual_steps: Vec<String>,
    pub recommended: RecoveryAction,
    pub reasons: Vec<String>,
}

impl RecoveryAssessment {
    pub fn preview(&self) -> String {
        let list = |steps: &[String]| {
            if steps.is_empty() {
                "none".to_string()
            } else {
                steps.join(", ")
            }
        };
        let mut output = format!(
            "Recovery assessment: {}\nStatus: {}\nCompleted: {}\nInterrupted while running: {}\nPending: {}\nFailed: {}\nManual intervention: {}\nRecommended: {}\n",
            self.plan_id,
            self.status.as_str(),
            list(&self.completed_steps),
            list(&self.interrupted_steps),
            list(&self.pending_steps),
            list(&self.failed_steps),
            list(&self.manual_steps),
            self.recommended.as_str(),
        );
        for reason in &self.reasons {
            output.push_str(&format!("- {reason}\n"));
        }
        output
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{{},\"status\":\"{}\",\"completed_steps\":{},\"interrupted_steps\":{},\"pending_steps\":{},\"failed_steps\":{},\"manual_steps\":{},\"recommended\":\"{}\",\"reasons\":{}}}",
            json_pair("plan_id", &self.plan_id),
            self.status.as_str(),
            json_string_array(&self.completed_steps),
            json_string_array(&self.interrupted_steps),
            json_string_array(&self.pending_steps),
            json_string_array(&self.failed_steps),
            json_string_array(&self.manual_steps),
            self.recommended.as_str(),
            json_string_array(&self.reasons),
        )
    }
}

/// Decides how a saved operation should continue. Failures and manual holds are never resumed
/// automatically; only cleanly interrupted operations may continue forward.
pub fn assess_recovery(report: &ExecutionReport) -> RecoveryAssessment {
    let ids = |state: StepState| -> Vec<String> {
        report
            .steps
            .iter()
            .filter(|step| step.state == state)
            .map(|step| step.id.clone())
            .collect()
    };
    let completed_steps = ids(StepState::Completed);
    let interrupted_steps = ids(StepState::Running);
    let pending_steps = ids(StepState::Pending);
    let failed_steps = ids(StepState::Failed);
    let manual_steps = ids(StepState::ManualInterventionRequired);
    let mut reasons = Vec::new();

    let recommended = if !manual_steps.is_empty() {
        reasons.push(format!(
            "steps {} need a human before anything else runs; use the recovery pack",
            manual_steps.join(", ")
        ));
        RecoveryAction::ManualIntervention
    } else if !failed_steps.is_empty() {
        reasons.push(format!(
            "steps {} failed; roll back completed steps instead of continuing",
            failed_steps.join(", ")
        ));
        RecoveryAction::Rollback
    } else if report.status == ExecutionStatus::RolledBack {
        reasons.push("the operation was already rolled back".into());
        RecoveryAction::NothingToDo
    } else if interrupted_steps.is_empty() && pending_steps.is_empty() {
        reasons.push("every step completed".into());
        RecoveryAction::NothingToDo
    } else {
        if !interrupted_steps.is_empty() {
            reasons.push(format!(
                "steps {} were running at interruption and will be re-run from the start",
                interrupted_steps.join(", ")
            ));
        }
        reasons.push(format!(
            "{} completed step(s) are kept; {} step(s) remain",
            completed_steps.len(),
            interrupted_steps.len() + pending_steps.len()
        ));
        RecoveryAction::Resume
    };

    RecoveryAssessment {
        plan_id: report.plan_id.clone(),
        status: report.status.clone(),
        completed_steps,
        interrupted_steps,
        pending_steps,
        failed_steps,
        manual_steps,
        recommended,
        reasons,
    }
}

/// Continues a simulated operation from its first unfinished step. Refuses anything the
/// assessment does not recommend resuming.
pub fn resume_simulated_report(report: &ExecutionReport) -> Result<ExecutionReport, NoUsbError> {
    let assessment = assess_recovery(report);
    if assessment.recommended != RecoveryAction::Resume {
        return Err(NoUsbError::UnsafeExecution(format!(
            "{} cannot be resumed; recommended action is {} ({})",
            report.plan_id,
            assessment.recommended.as_str(),
            assessment.reasons.join("; ")
        )));
    }
    let mut steps = report.steps.clone();
    let mut journal = report.journal.clone();
    journal.push(format!("resume started for {}", report.plan_id));
    for step in &mut steps {
        match step.state {
            StepState::Running => {
                journal.push(format!(
                    "step {} was running at interruption; re-running",
                    step.id
                ));
            }
            StepState::Pending => journal.push(format!("step {} running", step.id)),
            _ => continue,
        }
        step.state = StepState::Completed;
        journal.push(format!("step {} completed", step.id));
    }
    journal.push("simulation resumed to completion".into());
    Ok(ExecutionReport {
        plan_id: report.plan_id.clone(),
        status: ExecutionStatus::Completed,
        steps,
        journal,
        recovery_required: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        plan_operation, rollback_simulated_report, OperationExecutor, OperationKind,
        SimulatedExecutor, SimulationConfig,
    };

    fn simulate(config: SimulationConfig) -> ExecutionReport {
        let plan = plan_operation(OperationKind::BootOnce, Some("ubuntu-24.04-desktop")).unwrap();
        SimulatedExecutor::new(config).execute(&plan).unwrap()
    }

    #[test]
    fn saved_reports_round_trip_through_the_parser() {
        for report in [
            simulate(SimulationConfig::complete()),
            simulate(SimulationConfig::interrupt_after(2)),
            rollback_simulated_report(&simulate(SimulationConfig::interrupt_after(2))),
        ] {
            assert_eq!(parse_execution_report(&report.to_json()).unwrap(), report);
        }
        let mut manual = simulate(SimulationConfig::complete());
        manual.steps[0].rollback = RollbackAction::Manual("restore \"BCD\" export".into());
        assert_eq!(parse_execution_report(&manual.to_json()).unwrap(), manual);
        assert!(parse_execution_report("{\"plan_id\":1}").is_err());
    }

    #[test]
    fn hand_assembled_json_stays_valid_with_hostile_strings() {
        use crate::{escape_json, PlatformAdapter};
        let hostile = "tab\there\u{1}bell\u{7} \"quoted\" back\\slash\nline";
        let mut inventory = crate::HostPlatform.inspect().unwrap();
        inventory.warnings.push(hostile.into());
        let parsed: serde_json::Value = serde_json::from_str(&inventory.to_json(hostile)).unwrap();
        assert_eq!(parsed["adapter"], hostile);

        let mut report = simulate(SimulationConfig::interrupt_after(1));
        report.journal.push(hostile.into());
        serde_json::from_str::<serde_json::Value>(&report.to_json()).unwrap();
        assert_eq!(parse_execution_report(&report.to_json()).unwrap(), report);
        assert_eq!(escape_json("a\u{1}\"b"), "a\\u0001\\\"b");
    }

    #[test]
    fn interrupted_operations_resume_and_keep_completed_steps() {
        let interrupted = simulate(SimulationConfig::interrupt_after(2));
        let assessment = assess_recovery(&interrupted);
        assert_eq!(assessment.recommended, RecoveryAction::Resume);
        assert_eq!(assessment.completed_steps.len(), 2);

        let resumed = resume_simulated_report(&interrupted).unwrap();
        assert_eq!(resumed.status, ExecutionStatus::Completed);
        assert!(!resumed.recovery_required);
        assert!(resumed
            .steps
            .iter()
            .all(|step| step.state == StepState::Completed));
        assert!(resumed
            .journal
            .iter()
            .any(|entry| entry.starts_with("resume started")));
    }

    #[test]
    fn running_steps_are_rerun_on_resume() {
        let mut interrupted = simulate(SimulationConfig::interrupt_after(1));
        interrupted.steps[1].state = StepState::Running;
        let assessment = assess_recovery(&interrupted);
        assert_eq!(
            assessment.interrupted_steps,
            vec![interrupted.steps[1].id.clone()]
        );
        let resumed = resume_simulated_report(&interrupted).unwrap();
        assert!(resumed
            .journal
            .iter()
            .any(|entry| entry.contains("was running at interruption")));
    }

    #[test]
    fn failures_manual_holds_and_finished_operations_are_never_resumed() {
        let plan = plan_operation(OperationKind::BootOnce, Some("ubuntu-24.04-desktop")).unwrap();
        let failed = simulate(SimulationConfig::fail_step(plan.steps[1].id.clone()));
        assert_eq!(
            assess_recovery(&failed).recommended,
            RecoveryAction::Rollback
        );
        assert!(resume_simulated_report(&failed).is_err());

        let rolled_back = rollback_simulated_report(&failed);
        assert_eq!(
            assess_recovery(&rolled_back).recommended,
            RecoveryAction::ManualIntervention
        );
        assert!(resume_simulated_report(&rolled_back).is_err());

        let completed = simulate(SimulationConfig::complete());
        assert_eq!(
            assess_recovery(&completed).recommended,
            RecoveryAction::NothingToDo
        );
        assert!(resume_simulated_report(&completed).is_err());

        let clean_rollback =
            rollback_simulated_report(&simulate(SimulationConfig::interrupt_after(2)));
        assert_eq!(
            assess_recovery(&clean_rollback).recommended,
            RecoveryAction::NothingToDo
        );
    }
}
