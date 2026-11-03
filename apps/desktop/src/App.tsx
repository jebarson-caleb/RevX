import React, { useCallback, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  bridge,
  CLEANUP_PHRASE,
  isLive,
  type HostBootPlan,
  type HostBootState,
  type Inventory,
  type Profile,
  type SavedReport,
  type SignatureVerification,
  type VmEvidence,
} from "./bridge";
import "./style.css";

const views = ["overview", "boot once", "delivery", "vm evidence", "catalog", "planner", "reports", "diagnostics"] as const;
type View = (typeof views)[number];

const commands = [
  "cargo run -p nousb -- tui",
  "cargo run -p nousb -- system inspect",
  "cargo run -p nousb -- vm doctor",
  "cargo run -p nousb -- vm qemu bootstrap-runtime \"ASSEMBLE PROJECT-LOCAL QEMU RUNTIME\"",
  "cargo run -p nousb -- vm qemu rehearse-current-os-one-shot \"RUN DISPOSABLE CURRENT OS UEFI ONE-SHOT MATRIX\"",
  "cargo run -p nousb -- vm qemu rehearse-current-os-one-shot \"RUN DISPOSABLE CURRENT OS UEFI ONE-SHOT MATRIX\" linux-grub-reboot",
  "cargo run -p nousb -- vm qemu rehearse-secure-boot \"RUN DISPOSABLE SECURE BOOT REHEARSAL\"",
  "cargo run -p nousb -- image verify-signature ubuntu-24.04-server",
  "cargo run -p nousb -- --interrupt-after 2 simulate boot-once ubuntu-24.04-desktop",
  "cargo run -p nousb -- reports recover <plan-id>",
  "cargo run -p nousb -- journal migrate",
];

/** Loads one bridge call, keeping the error so the view can say why it shows preview text. */
function useBridge<T>(load: () => Promise<T>, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const refresh = useCallback(() => {
    load()
      .then((value) => {
        setData(value);
        setError(null);
      })
      .catch((reason: unknown) => setError(String(reason instanceof Error ? reason.message : reason)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  useEffect(refresh, [refresh]);
  return { data, error, refresh };
}

function App() {
  const [view, setView] = useState<View>("overview");
  const live = isLive();

  return (
    <main>
      <header>
        <div>
          <p className="eyebrow">NoUSB OS Switcher</p>
          <h1>Safe installer staging, preflight planning, and recovery rehearsal</h1>
        </div>
        <div className="statusbar" aria-label="Safety status">
          <span className="pill">Boot changes need a real-boot build + typed phrase</span>
          <span className="pill">{live ? "Live: desktop bridge" : "Preview: static data"}</span>
          <span className="pill">Diagnostics redacted</span>
        </div>
      </header>

      <div className="layout">
        <nav aria-label="Views">
          {views.map((item, index) => (
            <button
              className="navbutton"
              key={item}
              aria-selected={view === item}
              onClick={() => setView(item)}
            >
              <span>{label(item)}</span>
              <span>{index + 1}</span>
            </button>
          ))}
        </nav>

        <div className="content">
          {view === "overview" && <Overview />}
          {view === "boot once" && <BootOnce />}
          {view === "delivery" && <Delivery />}
          {view === "vm evidence" && <Evidence />}
          {view === "catalog" && <Catalog />}
          {view === "planner" && <Planner />}
          {view === "reports" && <Reports />}
          {view === "diagnostics" && <Diagnostics />}
        </div>
      </div>
    </main>
  );
}

function Overview() {
  const { data, error } = useBridge<Inventory>(bridge.inventory);
  if (!data) {
    return (
      <section>
        <SectionHead title="System Summary" detail={error ?? "Inspecting the host read-only..."} />
        <div className="grid">
          <Panel title="Guided TUI" text="Run nousb tui for profile selection, feasibility checks, verified acquisition, staging, and plan previews." />
          <Panel title="Read-only inspection" text="Firmware, Secure Boot, encryption, ESP, boot managers, and firmware boot entries; unknowns stay explicit." />
          <Panel title="Local State" text="Verified images, staging bundles, reports, the SQLite journal, and disposable VM evidence stay under .nousb/." />
        </div>
      </section>
    );
  }
  const hints = data.boot_hints;
  return (
    <section>
      <SectionHead title="System Summary" detail={`Collected read-only by ${data.adapter}.`} />
      <table>
        <tbody>
          <Row name="OS" value={data.os_name} />
          <Row name="Firmware" value={data.firmware} />
          <Row name="Secure Boot" value={data.secure_boot} />
          <Row name="Encryption" value={data.encryption} />
          <Row name="Memory" value={data.memory_total_mb === null ? "unknown" : `${data.memory_total_mb} MiB`} />
          <Row name="ESP" value={tri(hints.esp_present) + (hints.esp_location ? ` (${hints.esp_location})` : "")} />
          <Row name="Boot managers" value={hints.boot_managers.join(", ") || "unknown"} />
          <Row name="Firmware BootOrder" value={hints.firmware_boot_order?.join(", ") ?? "unknown"} />
          <Row
            name="Network boot entries"
            value={hints.network_boot_entries === null ? "unknown" : `${hints.network_boot_entries} (HTTP: ${hints.http_boot_entries})`}
          />
        </tbody>
      </table>
      {hints.unknowns.length > 0 && (
        <ul className="steps">
          {hints.unknowns.map((unknown) => (
            <li key={unknown}><strong>unknown</strong><span>{unknown}</span></li>
          ))}
        </ul>
      )}
    </section>
  );
}

function BootOnce() {
  const [profile, setProfile] = useState("ubuntu-24.04-desktop");
  const [stagingRoot, setStagingRoot] = useState("");
  const [phrase, setPhrase] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const root = stagingRoot.trim() || undefined;
  const plan = useBridge<HostBootPlan>(() => bridge.hostBootPlan(profile, root), [profile, root]);
  const status = useBridge<HostBootState | null>(bridge.hostBootStatus);
  const run = (action: Promise<HostBootState>, done: string) => {
    setMessage("Working...");
    action
      .then((state) => {
        setMessage(`${done} (${state.phase})`);
        setPhrase("");
        status.refresh();
        plan.refresh();
      })
      .catch((reason: unknown) => setMessage(String(reason)));
  };
  const data = plan.data;
  const pending = status.data && ["preparing", "armed", "failed"].includes(status.data.phase);
  return (
    <section>
      <SectionHead
        title="Boot Once Into an Installer"
        detail={message ?? plan.error ?? "One firmware boot into a verified official live installer; every later boot returns to this OS."}
        risk={data ? (data.blockers.length === 0 ? "ready" : `${data.blockers.length} blocker(s)`) : undefined}
      />
      <ProfilePicker value={profile} onChange={setProfile} />
      <p>
        <label>
          Staging volume root{" "}
          <input value={stagingRoot} placeholder="default: system volume" onChange={(event) => setStagingRoot(event.target.value)} />
        </label>
      </p>
      {status.data && (
        <table>
          <tbody>
            <Row name="Recorded transaction" value={status.data.plan_id} />
            <Row name="Phase" value={status.data.phase} />
            <Row name="Firmware entry" value={status.data.entry_id ?? "none"} />
          </tbody>
        </table>
      )}
      {data && (
        <>
          <ul className="steps">
            {data.blockers.map((item) => (
              <li key={item}><strong>blocker</strong><span>{item}</span></li>
            ))}
            {data.warnings.map((item) => (
              <li key={item}><strong>warning</strong><span>{item}</span></li>
            ))}
          </ul>
          <h3>Steps</h3>
          <ol>{data.steps.map((step) => <li key={step}>{step}</li>)}</ol>
          <h3>Files created (all removed by cleanup)</h3>
          <ul>{data.files.map((file) => <li key={file.location + file.relative_path}>[{file.location}] {file.relative_path}</li>)}</ul>
          <h3>Generated GRUB configuration</h3>
          <pre>{data.grub_config}</pre>
          <h3>If anything goes wrong</h3>
          <ul>{data.recovery.map((line) => <li key={line}>{line}</li>)}</ul>
          <p>
            <label>
              Type <code>{pending ? CLEANUP_PHRASE : data.confirmation_phrase}</code> to confirm{" "}
              <input value={phrase} onChange={(event) => setPhrase(event.target.value)} />
            </label>
          </p>
          {pending ? (
            <button className="copy" disabled={!isLive() || phrase !== CLEANUP_PHRASE} onClick={() => run(bridge.hostBootCleanup(phrase), "Cleanup finished")}>
              Clean up
            </button>
          ) : (
            <button
              className="copy"
              disabled={!isLive() || !data.execution_enabled || data.blockers.length > 0 || phrase !== data.confirmation_phrase}
              onClick={() => run(bridge.hostBootArm(profile, phrase, root), "Armed: restart to boot the installer once")}
            >
              Arm one-shot boot
            </button>
          )}
        </>
      )}
    </section>
  );
}

function Delivery() {
  const [profile, setProfile] = useState("ubuntu-24.04-server");
  const { data, error } = useBridge<Record<string, unknown>>(() => bridge.delivery(profile), [profile]);
  return (
    <section>
      <SectionHead title="No-USB Delivery" detail="Feasibility for this host before planning or execution." />
      <ProfilePicker value={profile} onChange={setProfile} />
      {data ? <pre>{JSON.stringify(data, null, 2)}</pre> : (
        <div className="grid">
          <Panel title="Recommended design" text="Acquire the pinned official ISO, extract only declared Ubuntu boot assets, then copy live media to RAM after boot begins." />
          <Panel title="Firmware alternative" text="UEFI HTTP Boot avoids disk staging only when the firmware and preboot network device support it." />
          <Panel title="Bridge" text={error ?? "Loading..."} />
        </div>
      )}
    </section>
  );
}

function Evidence() {
  const { data, error } = useBridge<VmEvidence[]>(bridge.vmEvidence);
  return (
    <section>
      <SectionHead title="Disposable VM Evidence" detail="Real QEMU runs, kept separate from host boot execution." />
      {data && data.length > 0 ? (
        <table>
          <thead><tr><th>Run</th><th>Key results</th></tr></thead>
          <tbody>
            {data.map((item) => (
              <tr key={item.run}>
                <td>{item.run}</td>
                <td>{keyResults(item.report)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <div className="grid">
          <Panel title="UEFI BootNext matrix" text="A disposable current OS arms BootNext with efibootmgr; the official installer chain runs exactly once and firmware falls back to the unchanged default after power loss at every step." />
          <Panel title="GRUB next_entry matrix" text="The same six-scenario power-loss matrix passes with grub-reboot semantics on the current OS's own GRUB." />
          <Panel title="Full installer in RAM" text="The pinned 3.2 GiB Server ISO continues from RAM after its EFI and HTTP sources are removed." />
          <Panel title="Bridge" text={error ?? "No saved VM evidence in this project yet."} />
        </div>
      )}
    </section>
  );
}

function Catalog() {
  const { data, error } = useBridge<Profile[]>(bridge.catalog);
  const [signatures, setSignatures] = useState<Record<string, string>>({});
  const verify = (profile: string) => {
    setSignatures((current) => ({ ...current, [profile]: "checking..." }));
    bridge
      .verifySignature(profile)
      .then((result: SignatureVerification) =>
        setSignatures((current) => ({
          ...current,
          [profile]: result.verified ? `vendor-signed (${result.key_id})` : "NOT verified",
        })),
      )
      .catch((reason: unknown) => setSignatures((current) => ({ ...current, [profile]: String(reason) })));
  };
  return (
    <section>
      <SectionHead title="Installer Catalog" detail={error ?? "Versioned TOML profiles embedded in the workspace."} />
      <table>
        <thead>
          <tr><th>Profile</th><th>Vendor</th><th>Strategies</th><th>Signature chain</th></tr>
        </thead>
        <tbody>
          {(data ?? previewProfiles).map((profile) => (
            <tr key={profile.id}>
              <td>{profile.id}</td>
              <td>{profile.vendor}</td>
              <td>{profile.supported_staging_strategies.join(", ")}</td>
              <td>
                {profile.signing_key ? (
                  signatures[profile.id] ?? (
                    <button className="copy" disabled={!isLive()} onClick={() => verify(profile.id)}>Verify</button>
                  )
                ) : "no pinned vendor key (fails closed)"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

function Planner() {
  const [profile, setProfile] = useState("ubuntu-24.04-desktop");
  const { data, error } = useBridge<Record<string, unknown>>(() => bridge.planPreview("boot-once", profile), [profile]);
  const steps = (data?.steps as Array<{ id: string; title: string; risk: string }> | undefined) ?? [];
  return (
    <section>
      <SectionHead title="Plan Preview" detail={error ?? "Boot-once plan for this host; execution stays blocked."} risk={data ? String(data.risk) : undefined} />
      <ProfilePicker value={profile} onChange={setProfile} />
      <ul className="steps">
        {steps.map((step) => (
          <li key={step.id}><strong>{step.risk}</strong><span>{step.title}</span></li>
        ))}
      </ul>
    </section>
  );
}

function Reports() {
  const { data, error, refresh } = useBridge<SavedReport[]>(bridge.reports);
  const [message, setMessage] = useState<string | null>(null);
  const act = (planId: string, action: "resume" | "rollback") =>
    bridge
      .recover(planId, action)
      .then(() => {
        setMessage(`${action} completed for ${planId}`);
        refresh();
      })
      .catch((reason: unknown) => setMessage(String(reason)));
  const simulate = () =>
    bridge
      .simulate("boot-once", "ubuntu-24.04-desktop", 2)
      .then(() => {
        setMessage("Saved an interrupted boot-once simulation.");
        refresh();
      })
      .catch((reason: unknown) => setMessage(String(reason)));
  return (
    <section>
      <SectionHead title="Execution Reports" detail={message ?? error ?? "Saved simulations with their recovery recommendation."} />
      <button className="copy" disabled={!isLive()} onClick={simulate}>Simulate an interrupted boot-once</button>
      <table>
        <thead><tr><th>Plan</th><th>Status</th><th>Recommended</th><th>Action</th></tr></thead>
        <tbody>
          {(data ?? []).map((report) => (
            <tr key={report.summary.plan_id}>
              <td>{report.summary.plan_id}</td>
              <td>{report.summary.status}</td>
              <td title={report.recovery?.reasons.join("\n")}>{report.recovery?.recommended ?? "unreadable"}</td>
              <td>
                {report.recovery?.recommended === "resume" && (
                  <button className="copy" onClick={() => act(report.summary.plan_id, "resume")}>Resume</button>
                )}
                {(report.recovery?.recommended === "resume" || report.recovery?.recommended === "rollback") && (
                  <button className="copy" onClick={() => act(report.summary.plan_id, "rollback")}>Roll back</button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

function Diagnostics() {
  return (
    <section>
      <SectionHead title="Diagnostics" detail="Project-local bundle export with secret-like line redaction, and the CLI equivalents of every view." />
      <div className="commands">
        {commands.map((command) => (
          <div className="command-row" key={command}>
            <pre>{command}</pre>
            <button className="copy" onClick={() => navigator.clipboard?.writeText(command)}>Copy</button>
          </div>
        ))}
      </div>
    </section>
  );
}

const previewProfiles: Profile[] = [
  { id: "ubuntu-24.04-desktop", name: "Ubuntu Desktop", vendor: "Canonical", version: "24.04.4 LTS", supported_staging_strategies: ["iso_loopback", "kernel_initrd"], signing_key: "ubuntu-cdimage-2012" },
  { id: "ubuntu-24.04-server", name: "Ubuntu Server", vendor: "Canonical", version: "24.04.4 LTS", supported_staging_strategies: ["iso_loopback", "kernel_initrd"], signing_key: "ubuntu-cdimage-2012" },
  { id: "fedora-44-workstation", name: "Fedora Workstation", vendor: "Fedora Project", version: "44", supported_staging_strategies: ["iso_loopback"], signing_key: "fedora-44" },
  { id: "windows-11", name: "Windows 11", vendor: "Microsoft", version: "11", supported_staging_strategies: ["windows_mounted_iso_setup"], signing_key: null },
];

function ProfilePicker({ value, onChange }: { value: string; onChange: (value: string) => void }) {
  return (
    <p>
      <label>
        Profile{" "}
        <select value={value} onChange={(event) => onChange(event.target.value)}>
          {previewProfiles.map((profile) => (
            <option key={profile.id} value={profile.id}>{profile.id}</option>
          ))}
        </select>
      </label>
    </p>
  );
}

function keyResults(report: Record<string, unknown>): string {
  const keys = [
    "backend",
    "one_shot_selection_proven",
    "power_loss_matrix_complete",
    "full_installer_payload_in_ram",
    "secure_boot_enabled",
    "signed_chain_accepted",
    "unsigned_loader_rejected",
    "host_boot_changes",
  ];
  return keys
    .filter((key) => key in report)
    .map((key) => `${key}=${String(report[key])}`)
    .join("  ");
}

function tri(value: boolean | null): string {
  return value === null ? "unknown" : value ? "yes" : "no";
}

function Row({ name, value }: { name: string; value: string }) {
  return (
    <tr>
      <th>{name}</th>
      <td>{value}</td>
    </tr>
  );
}

function SectionHead({ title, detail, risk }: { title: string; detail: string; risk?: string }) {
  return (
    <div className="section-head">
      <div>
        <h2>{title}</h2>
        <p className="muted">{detail}</p>
      </div>
      {risk ? <span className="risk high">{risk}</span> : null}
    </div>
  );
}

function Panel({ title, text }: { title: string; text: string }) {
  return (
    <div className="panel">
      <h3>{title}</h3>
      <p>{text}</p>
    </div>
  );
}

function label(value: string) {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

createRoot(document.getElementById("root")!).render(<App />);
