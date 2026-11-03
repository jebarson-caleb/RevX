//! The operation journal: an embedded SQLite database under `.nousb/journal`, plus an
//! append-only plain-text log that survives even if the database cannot be opened.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use rusqlite::{params, Connection};

use super::{
    escape_json, list_saved_execution_reports, now_stamp, parse_execution_report, ExecutionReport,
    NoUsbError,
};

/// Bumped whenever `MIGRATIONS` gains an entry; stored in SQLite's `user_version`.
const SCHEMA_VERSION: i64 = 2;

const MIGRATIONS: [&str; 2] = [
    // 1: the original shell-out schema, kept so existing journals open unchanged.
    "CREATE TABLE IF NOT EXISTS operations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at INTEGER NOT NULL,
        message TEXT NOT NULL
    );",
    // 2: execution reports and their steps, so recovery no longer depends on loose JSON files.
    "CREATE TABLE IF NOT EXISTS reports (
        plan_id TEXT PRIMARY KEY,
        status TEXT NOT NULL,
        recovery_required INTEGER NOT NULL,
        saved_at INTEGER NOT NULL,
        report_json TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS steps (
        plan_id TEXT NOT NULL REFERENCES reports(plan_id) ON DELETE CASCADE,
        position INTEGER NOT NULL,
        step_id TEXT NOT NULL,
        state TEXT NOT NULL,
        risk TEXT NOT NULL,
        PRIMARY KEY (plan_id, position)
    );",
];

pub fn journal_directory(base_dir: &Path) -> PathBuf {
    base_dir.join(".nousb").join("journal")
}

pub fn journal_database_path(base_dir: &Path) -> PathBuf {
    journal_directory(base_dir).join("operation_journal.sqlite3")
}

fn sqlite_error(error: rusqlite::Error) -> NoUsbError {
    NoUsbError::Io(format!("operation journal: {error}"))
}

/// Opens the journal and applies any pending migrations inside one transaction.
pub fn open_journal(base_dir: &Path) -> Result<Connection, NoUsbError> {
    fs::create_dir_all(journal_directory(base_dir))?;
    let mut connection = Connection::open(journal_database_path(base_dir)).map_err(sqlite_error)?;
    connection
        .busy_timeout(std::time::Duration::from_secs(5))
        .map_err(sqlite_error)?;
    connection
        .pragma_update(None, "foreign_keys", true)
        .map_err(sqlite_error)?;
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(sqlite_error)?;
    if version > SCHEMA_VERSION {
        return Err(NoUsbError::Io(format!(
            "operation journal schema {version} is newer than this build supports ({SCHEMA_VERSION})"
        )));
    }
    if version < SCHEMA_VERSION {
        let transaction = connection.transaction().map_err(sqlite_error)?;
        for migration in &MIGRATIONS[usize::try_from(version).unwrap_or(0)..] {
            transaction.execute_batch(migration).map_err(sqlite_error)?;
        }
        transaction
            .pragma_update(None, "user_version", SCHEMA_VERSION)
            .map_err(sqlite_error)?;
        transaction.commit().map_err(sqlite_error)?;
    }
    Ok(connection)
}

/// Records one journal message. The plain-text log is always appended; the database is the
/// primary record and its path is returned when the insert succeeds.
pub fn write_journal_entry(base_dir: &Path, entry: &str) -> Result<PathBuf, NoUsbError> {
    let log_path = journal_directory(base_dir).join("operations.log");
    fs::create_dir_all(journal_directory(base_dir))?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;
    writeln!(file, "{} {entry}", now_stamp())?;

    let inserted = open_journal(base_dir).and_then(|connection| {
        connection
            .execute(
                "INSERT INTO operations (created_at, message) VALUES (?1, ?2)",
                params![now_stamp() as i64, entry],
            )
            .map_err(sqlite_error)
    });
    match inserted {
        Ok(_) => Ok(journal_database_path(base_dir)),
        Err(_) => Ok(log_path),
    }
}

/// Inserts or replaces a report and its steps.
pub fn record_execution_report(
    connection: &mut Connection,
    report: &ExecutionReport,
) -> Result<(), NoUsbError> {
    let transaction = connection.transaction().map_err(sqlite_error)?;
    transaction
        .execute(
            "INSERT INTO reports (plan_id, status, recovery_required, saved_at, report_json)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(plan_id) DO UPDATE SET status = excluded.status,
                 recovery_required = excluded.recovery_required,
                 saved_at = excluded.saved_at,
                 report_json = excluded.report_json",
            params![
                report.plan_id,
                report.status.as_str(),
                report.recovery_required,
                now_stamp() as i64,
                report.to_json(),
            ],
        )
        .map_err(sqlite_error)?;
    transaction
        .execute(
            "DELETE FROM steps WHERE plan_id = ?1",
            params![report.plan_id],
        )
        .map_err(sqlite_error)?;
    for (position, step) in report.steps.iter().enumerate() {
        transaction
            .execute(
                "INSERT INTO steps (plan_id, position, step_id, state, risk) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    report.plan_id,
                    position as i64,
                    step.id,
                    step.state.as_str(),
                    step.risk.as_str(),
                ],
            )
            .map_err(sqlite_error)?;
    }
    transaction.commit().map_err(sqlite_error)
}

/// Reads a report back from the journal.
pub fn journal_execution_report(
    base_dir: &Path,
    plan_id: &str,
) -> Result<Option<ExecutionReport>, NoUsbError> {
    let connection = open_journal(base_dir)?;
    let mut statement = connection
        .prepare("SELECT report_json FROM reports WHERE plan_id = ?1")
        .map_err(sqlite_error)?;
    let mut rows = statement.query(params![plan_id]).map_err(sqlite_error)?;
    match rows.next().map_err(sqlite_error)? {
        Some(row) => {
            let json: String = row.get(0).map_err(sqlite_error)?;
            parse_execution_report(&json).map(Some)
        }
        None => Ok(None),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalMigration {
    pub database: PathBuf,
    pub schema_version: i64,
    pub imported_reports: usize,
    pub skipped: Vec<String>,
}

impl JournalMigration {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"database\":\"{}\",\"schema_version\":{},\"imported_reports\":{},\"skipped\":[{}]}}",
            escape_json(&self.database.display().to_string()),
            self.schema_version,
            self.imported_reports,
            self.skipped
                .iter()
                .map(|item| format!("\"{}\"", escape_json(item)))
                .collect::<Vec<_>>()
                .join(","),
        )
    }
}

/// Imports every saved JSON report into the journal. Safe to repeat: rows are upserted.
pub fn migrate_saved_reports(base_dir: &Path) -> Result<JournalMigration, NoUsbError> {
    let mut connection = open_journal(base_dir)?;
    let mut imported_reports = 0;
    let mut skipped = Vec::new();
    for summary in list_saved_execution_reports(base_dir)? {
        let parsed = fs::read_to_string(&summary.path)
            .map_err(NoUsbError::from)
            .and_then(|json| parse_execution_report(&json));
        match parsed {
            Ok(report) => {
                record_execution_report(&mut connection, &report)?;
                imported_reports += 1;
            }
            Err(error) => skipped.push(format!("{}: {error}", summary.path.display())),
        }
    }
    Ok(JournalMigration {
        database: journal_database_path(base_dir),
        schema_version: SCHEMA_VERSION,
        imported_reports,
        skipped,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        plan_operation, save_execution_report, OperationExecutor, OperationKind, SimulatedExecutor,
        SimulationConfig,
    };

    fn temp_base(label: &str) -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "nousb-journal-{label}-{}-{}",
            std::process::id(),
            now_stamp()
        ));
        fs::create_dir_all(&base).unwrap();
        base
    }

    #[test]
    fn entries_are_parameterized_and_reports_round_trip() {
        let base = temp_base("entries");
        let path = write_journal_entry(&base, "quote ' and \"; DROP TABLE operations; --").unwrap();
        assert_eq!(path, journal_database_path(&base));
        let connection = open_journal(&base).unwrap();
        let message: String = connection
            .query_row("SELECT message FROM operations", [], |row| row.get(0))
            .unwrap();
        assert!(message.contains("DROP TABLE"));
        drop(connection);

        let plan = plan_operation(OperationKind::BootOnce, Some("ubuntu-24.04-desktop")).unwrap();
        let report = SimulatedExecutor::new(SimulationConfig::interrupt_after(2))
            .execute(&plan)
            .unwrap();
        save_execution_report(&base, &report).unwrap();
        assert_eq!(
            journal_execution_report(&base, &report.plan_id).unwrap(),
            Some(report.clone())
        );
        let steps: i64 = open_journal(&base)
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM steps WHERE plan_id = ?1",
                params![report.plan_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(steps as usize, report.steps.len());
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn back_to_back_plans_never_share_a_report_id() {
        let ids: std::collections::HashSet<String> = (0..50)
            .map(|_| {
                plan_operation(OperationKind::BootOnce, Some("ubuntu-24.04-desktop"))
                    .unwrap()
                    .id
            })
            .collect();
        assert_eq!(ids.len(), 50);
    }

    #[test]
    fn legacy_journals_and_json_reports_migrate_idempotently() {
        let base = temp_base("migrate");
        fs::create_dir_all(journal_directory(&base)).unwrap();
        {
            // A journal created by the old sqlite3 shell-out: schema 0 with only `operations`.
            let legacy = Connection::open(journal_database_path(&base)).unwrap();
            legacy.execute_batch(MIGRATIONS[0]).unwrap();
            legacy
                .execute(
                    "INSERT INTO operations (created_at, message) VALUES (1, 'legacy')",
                    [],
                )
                .unwrap();
        }
        let reports = base.join(".nousb").join("reports");
        fs::create_dir_all(&reports).unwrap();
        let plan = plan_operation(OperationKind::BootOnce, Some("ubuntu-24.04-desktop")).unwrap();
        let report = SimulatedExecutor::new(SimulationConfig::complete())
            .execute(&plan)
            .unwrap();
        fs::write(reports.join("good.json"), report.to_json()).unwrap();
        fs::write(reports.join("broken.json"), "{\"plan_id\":\"broken\"}").unwrap();

        for _ in 0..2 {
            let migration = migrate_saved_reports(&base).unwrap();
            assert_eq!(migration.schema_version, SCHEMA_VERSION);
            assert_eq!(migration.imported_reports, 1);
            assert_eq!(migration.skipped.len(), 1);
        }
        let connection = open_journal(&base).unwrap();
        let legacy: i64 = connection
            .query_row("SELECT COUNT(*) FROM operations", [], |row| row.get(0))
            .unwrap();
        assert_eq!(legacy, 1);
        let rows: i64 = connection
            .query_row("SELECT COUNT(*) FROM reports", [], |row| row.get(0))
            .unwrap();
        assert_eq!(rows, 1);
        drop(connection);
        let _ = fs::remove_dir_all(base);
    }
}
