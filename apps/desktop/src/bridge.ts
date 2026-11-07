// Command bridge to the Tauri backend (apps/desktop/src-tauri). In the default build every command is
// read-only or simulation-only and returns the same JSON as the matching `nousb --json` command.
// Outside Tauri (a plain browser opening the Vite build) the bridge reports itself offline and
// the UI falls back to the static preview fixture.

import { invoke } from "@tauri-apps/api/core";

export const isLive = (): boolean =>
  typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  if (!isLive()) {
    throw new Error("Not running inside the NoUSB desktop shell; showing preview data.");
  }
  const json = await invoke<string>(command, args);
  return JSON.parse(json) as T;
}

export interface Profile {
  id: string;
  name: string;
  vendor: string;
  version: string;
  supported_staging_strategies: string[];
  signing_key: string | null;
}

export interface BootHints {
  esp_present: boolean | null;
  esp_location: string | null;
  boot_managers: string[];
  firmware_boot_order: string[] | null;
  network_boot_entries: number | null;
  http_boot_entries: number | null;
  unknowns: string[];
}

export interface Inventory {
  adapter: string;
  os_name: string;
  firmware: string;
  secure_boot: string;
  encryption: string;
  memory_total_mb: number | null;
  boot_hints: BootHints;
  warnings: string[];
}

export interface RecoveryAssessment {
  plan_id: string;
  status: string;
  recommended: "nothing_to_do" | "resume" | "rollback" | "manual_intervention";
  reasons: string[];
}

export interface SavedReport {
  summary: { plan_id: string; status: string; recovery_required: boolean };
  recovery: RecoveryAssessment | null;
}

export interface SignatureVerification {
  profile_id: string;
  key_id: string;
  key_fingerprint: string;
  verified: boolean;
  pinned_sha256: string;
}

export interface VmEvidence {
  run: string;
  report: Record<string, unknown>;
}

export interface HostBootPlan {
  id: string;
  profile_id: string;
  profile_name: string;
  backend: string;
  recipe: { family: string; kernel: string; source_config: string };
  ram_copy: boolean;
  staging_volume_root: string;
  grub_config: string;
  files: Array<{ location: string; relative_path: string; source: string }>;
  confirmation_phrase: string;
  blockers: string[];
  warnings: string[];
  steps: string[];
  recovery: string[];
  execution_enabled: boolean;
}

export interface HostBootState {
  plan_id: string;
  profile_id: string;
  phase: "preparing" | "armed" | "rolled_back" | "cleaned_up" | "failed";
  entry_id: string | null;
  events: string[];
}

export const CLEANUP_PHRASE = "CLEAN UP NOUSB BOOT";

export const bridge = {
  hostBootPlan: (profile: string, stagingRoot?: string) =>
    call<HostBootPlan>("host_boot_plan", { profile, stagingRoot }),
  hostBootStatus: () => call<HostBootState | null>("host_boot_status"),
  hostBootArm: (profile: string, confirmation: string, stagingRoot?: string) =>
    call<HostBootState>("host_boot_arm", { profile, confirmation, stagingRoot }),
  hostBootCleanup: (confirmation: string) =>
    call<HostBootState>("host_boot_cleanup", { confirmation }),
  inventory: () => call<Inventory>("inventory"),
  catalog: () => call<Profile[]>("catalog"),
  delivery: (profile: string) => call<Record<string, unknown>>("delivery", { profile }),
  planPreview: (kind: string, profile: string) =>
    call<Record<string, unknown>>("plan_preview", { kind, profile }),
  simulate: (kind: string, profile: string, interruptAfter?: number) =>
    call<Record<string, unknown>>("simulate", { kind, profile, interruptAfter }),
  reports: () => call<SavedReport[]>("reports"),
  recover: (planId: string, action: "resume" | "rollback") =>
    call<Record<string, unknown>>("recover", { planId, action }),
  verifySignature: (profile: string) =>
    call<SignatureVerification>("verify_signature", { profile }),
  vmEvidence: () => call<VmEvidence[]>("vm_evidence"),
};
