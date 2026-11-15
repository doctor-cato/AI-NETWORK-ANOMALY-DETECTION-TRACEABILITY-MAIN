import { render } from "svelte/server";
import { describe, expect, it } from "vitest";
import ForensicTimelinePanel from "./ForensicTimelinePanel.svelte";
import SecurityDryRunPanel from "./SecurityDryRunPanel.svelte";
import type { SecurityResponseSimulationResponse } from "../types";

const sampleSimulation: SecurityResponseSimulationResponse = {
  simulation_id: "sim_test123",
  created_at_utc: "2026-11-15T15:00:00Z",
  analysis_id: "csvrun_abc",
  source_csv_path: "data/demo/demo_flows.csv",
  source_csv_sha256: "a".repeat(64),
  model_key: "random_forest",
  model_type: "Random Forest",
  run_id: "rf-run-1",
  model_sha256: "b".repeat(64),
  preprocessor_sha256: "c".repeat(64),
  triggered_by: "desktop_operator",
  provenance_verification: "server_verified_analysis",
  execution_mode: "DRY_RUN_SIMULATION",
  action_status: "SIMULATED",
  recommendation_status: "RECOMMENDED",
  execution_status: "NOT_EXECUTED",
  executed: false,
  os_firewall_touched: false,
  real_key_rotated: false,
  overall_recommendation: "ISOLATE_RECOMMENDED",
  overall_severity: "CRITICAL",
  total_flows: 2,
  evaluated_flows: 1,
  ood_abstained_flows: 1,
  action_counts: {
    NO_ACTION: 0,
    MONITOR: 0,
    INVESTIGATE: 1,
    ISOLATE_RECOMMENDED: 1,
  },
  key_rotation_simulation: {
    decision: "SIMULATED_ROTATION_RECOMMENDED",
    recommended: true,
    would_rotate: true,
    simulation_status: "SIMULATED",
    executed: false,
    key_material_generated: false,
    real_key_modified: false,
    keyring_status: "DEFERRED_PRODUCTION_KEYRING",
    active_key_id: "key_v1_init",
    active_key_version: 1,
    simulated_next_version: 2,
    cooldown_seconds: 1.0,
    cooldown_remaining_seconds: 0.0,
    trigger_metrics: { isolate_recommended_flows: 1 },
    reason: "Simulated adaptive key rotation evaluation without real key mutation.",
  },
  policy_summary: "Dry-run simulated 2 flows (1 evaluated, 1 ABSTAINED_OOD).",
  security_notice: "Adaptive rotation & security response (#27) runs in DRY-RUN mode; keyring DEFERRED.",
  deferred_capabilities: [
    "production_aes256_gcm_keyring",
    "automatic_real_key_rotation",
    "os_firewall_command_execution",
  ],
  provenance: { executed: false },
  recommendations: [
    {
      row_id: 10,
      row_index: 0,
      predicted_class: "Attack",
      is_ood_flagged: false,
      risk_score: 97.5,
      risk_level: "CRITICAL",
      action: "ISOLATE_RECOMMENDED",
      severity: "CRITICAL",
      action_status: "RECOMMENDED",
      simulation_status: "SIMULATED",
      executed: false,
      execution_status: "NOT_EXECUTED",
      containment_allowed: true,
      reason: "Attack predicted with CRITICAL risk.",
      src_ip: "10.0.0.5",
      dst_ip: "192.168.1.9",
      src_port: 51000,
      dst_port: 443,
      flow_start_ms: 1700000000000,
      provenance: {
        model_key: "random_forest",
        source_id: "source:nf-v3-canonical",
        provenance_verified: true,
      },
    },
    {
      row_id: 20,
      row_index: 1,
      predicted_class: "ABSTAINED_OOD",
      is_ood_flagged: true,
      risk_score: null,
      risk_level: "ABSTAINED_OOD",
      action: "INVESTIGATE",
      severity: "MEDIUM",
      action_status: "RECOMMENDED",
      simulation_status: "SIMULATED",
      executed: false,
      execution_status: "NOT_EXECUTED",
      containment_allowed: false,
      reason: "ABSTAINED_OOD guard enforced.",
      src_ip: "10.0.0.6",
      dst_ip: "192.168.1.10",
      src_port: 51001,
      dst_port: 80,
      flow_start_ms: 1700000001000,
      provenance: {
        model_key: "random_forest",
        source_id: "source:nf-v3-canonical",
        provenance_verified: true,
      },
    },
  ],
};

describe("Issue #27 SecurityDryRunPanel and Tab 4 ForensicTimelinePanel UI rendering", () => {
  it("renders dry-run recommendations, OOD guard, key rotation simulation, and executed=false markers", () => {
    const out = render(SecurityDryRunPanel, {
      props: {
        simulation: sampleSimulation,
        history: [
          {
            ...sampleSimulation,
          },
        ],
        exportInfo: null,
        simulating: false,
        canSimulate: true,
        onRunSimulation: () => {},
        onRefreshHistory: () => {},
        onExportSimulation: () => {},
      },
    });
    expect(out.body).toContain("SIMULATED / RECOMMENDED ONLY");
    expect(out.body).toContain("EXECUTED: FALSE");
    expect(out.body).toContain("ISOLATE_RECOMMENDED");
    expect(out.body).toContain("SIMULATED_ROTATION_RECOMMENDED");
    expect(out.body).toContain("DEFERRED_PRODUCTION_KEYRING");
    expect(out.body).toContain("sim_test123");
    expect(out.body).toContain("ABSTAINED_OOD");
  });

  it("renders Tab 4 ForensicTimelinePanel with deferred keyring and dry-run explanation", () => {
    const out = render(ForensicTimelinePanel, {
      props: {
        timeline: [],
        behavioral: null,
        securityNotice: sampleSimulation.security_notice,
        simulation: sampleSimulation,
        simulationHistory: [],
        simulationExportInfo: null,
        simulating: false,
        canSimulate: true,
        onRunSimulation: () => {},
        onRefreshHistory: () => {},
        onExportSimulation: () => {},
      },
    });
    expect(out.body).toContain("AES-256-GCM keyring production");
    expect(out.body).toContain("DEFERRED");
    expect(out.body).toContain("Adaptive Security Response Simulation");
  });

  it("shows bounded sample truncation notice when recommendations_truncated is true", () => {
    const truncatedSim: SecurityResponseSimulationResponse = {
      ...sampleSimulation,
      total_flows: 9000,
      evaluated_flows: 8999,
      ood_abstained_flows: 1,
      provenance: {
        ...sampleSimulation.provenance,
        recommendations_truncated: true,
        recommendations_stored_count: 2000,
        recommendations_total_count: 9000,
      },
      recommendations: [sampleSimulation.recommendations[0]],
    };
    const out = render(SecurityDryRunPanel, {
      props: {
        simulation: truncatedSim,
        history: [],
        exportInfo: null,
        simulating: false,
        canSimulate: true,
        onRunSimulation: () => {},
        onRefreshHistory: () => {},
        onExportSimulation: () => {},
      },
    });
    expect(out.body).toContain("Hiển thị 1/9000");
    expect(out.body).toContain("Tất cả (1/9000)");
    expect(out.body).toContain("action_counts");
  });
});
