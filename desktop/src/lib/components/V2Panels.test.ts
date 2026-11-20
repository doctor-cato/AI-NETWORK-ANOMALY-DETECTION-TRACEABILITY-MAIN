import { render } from "svelte/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  fetchBehavioralCorrelation,
  fetchBehavioralSimilarity,
  fetchBehavioralVectors,
  fetchCryptoStatus,
  fetchLiveAlerts,
  fetchLiveStatus,
  fetchTraceTimeline,
  getModelBenchmarkReport,
} from "../api";
import type { ModelBenchmarkReportResponse, ModelStatusItem } from "../types";
import AttackTimelinePanel from "./AttackTimelinePanel.svelte";
import BehavioralAnalysisPanel from "./BehavioralAnalysisPanel.svelte";
import CryptographyDashboardPanel from "./CryptographyDashboardPanel.svelte";
import LiveMonitoringPanel from "./LiveMonitoringPanel.svelte";
import ModelComparisonPanel from "./ModelComparisonPanel.svelte";

afterEach(() => {
  vi.restoreAllMocks();
});

describe("V2 Dynamic Desktop Panels — No Hardcoded Fake Data", () => {
  it("LiveMonitoringPanel defaults to LOADING without hardcoded fake alerts or metrics", () => {
    const out = render(LiveMonitoringPanel, { props: { initialDemoMode: false } });
    expect(out.body).toContain("STATE: LOADING");
    expect(out.body).toContain("COLLECTOR STOPPED");
    expect(out.body).not.toContain("alert-98ab42c1ef01");
    expect(out.body).not.toContain("12,450");
    expect(out.body).not.toContain("LIVE STREAMING ACTIVE");
  });

  it("LiveMonitoringPanel renders DEMO state only when explicitly enabled", () => {
    const out = render(LiveMonitoringPanel, { props: { initialDemoMode: true } });
    expect(out.body).toContain("STATE: DEMO");
    expect(out.body).toContain("DEMO MODE ACTIVE");
    expect(out.body).toContain("demo-alert-01");
    expect(out.body).toContain("Medium (Risk >= 30)");
    expect(out.body).not.toContain("Risk >= 45");
  });

  it("BehavioralAnalysisPanel defaults to LOADING without hardcoded 16D vector or fake SHA-256", () => {
    const out = render(BehavioralAnalysisPanel, { props: { initialDemoMode: false } });
    expect(out.body).toContain("STATE: LOADING");
    expect(out.body).toContain("NO VECTOR LOADED");
    expect(out.body).not.toContain("81879b0e707bfc4e4fbe7b646dc06698");
    expect(out.body).not.toContain("0.412");
  });

  it("BehavioralAnalysisPanel renders DEMO mode when explicitly enabled", () => {
    const out = render(BehavioralAnalysisPanel, { props: { initialDemoMode: true } });
    expect(out.body).toContain("STATE: DEMO");
    expect(out.body).toContain("DEMO MODE ACTIVE");
    expect(out.body).toContain("log_duration");
  });

  it("AttackTimelinePanel defaults to LOADING without hardcoded APT-Campaign-01 or empty SHA-256", () => {
    const out = render(AttackTimelinePanel, { props: { initialDemoMode: false } });
    expect(out.body).toContain("STATE: LOADING");
    expect(out.body).not.toContain("e3b0c44298fc1c149afbf4c8996fb924");
    expect(out.body).not.toContain("Apache Struts2");
  });

  it("AttackTimelinePanel distinguishes observed vs inferred stages in DEMO mode", () => {
    const out = render(AttackTimelinePanel, { props: { initialDemoMode: true } });
    expect(out.body).toContain("STATE: DEMO");
    expect(out.body).toContain("OBSERVED TELEMETRY");
    expect(out.body).toContain("INFERRED RELATIONSHIP");
  });

  it("CryptographyDashboardPanel defaults to LOADING without hardcoded key IDs or 25.24 us benchmark", () => {
    const out = render(CryptographyDashboardPanel, { props: { initialDemoMode: false } });
    expect(out.body).toContain("STATE: LOADING");
    expect(out.body).not.toContain("key-gen-20261117-v3");
    expect(out.body).not.toContain("25.24");
    expect(out.body).not.toContain("39,623");
  });

  it("CryptographyDashboardPanel renders DEMO mode only when explicitly enabled", () => {
    const out = render(CryptographyDashboardPanel, { props: { initialDemoMode: true } });
    expect(out.body).toContain("STATE: DEMO");
    expect(out.body).toContain("demo-rot-01");
  });
});

describe("V2 Backend API Client State Contracts (CONNECTED / DISCONNECTED / EMPTY / ERROR)", () => {
  it("parses CONNECTED, DISCONNECTED, and EMPTY responses from live and behavioral endpoints", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            mode: "STOPPED",
            running: false,
            data_status: "DISCONNECTED",
            bound_port: null,
            started_at_utc: null,
            collector: {},
            pipeline: {},
            metrics: {},
            inference: { ai_ready: false, ready_count: 0 },
          }),
          { status: 200 },
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            data_status: "EMPTY",
            total: 0,
            items: [],
          }),
          { status: 200 },
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            vector_a: "v1",
            vector_b: "v2",
            dimensions: 16,
            cosine_similarity: 0.912,
            euclidean_distance: 0.41,
            manhattan_distance: 1.05,
            interpretation: "SIMILAR",
            comparable: true,
            data_status: "CONNECTED",
          }),
          { status: 200 },
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            data_status: "CONNECTED",
            match_threshold: 0.85,
            total_vectors_evaluated: 2,
            clusters: [
              {
                cluster_id: "cluster-1",
                member_vector_ids: ["v1", "v2"],
                average_similarity: 0.95,
                ip_addresses_observed: ["192.0.2.10"],
              },
            ],
          }),
          { status: 200 },
        ),
      );
    vi.stubGlobal("fetch", fetchMock);

    const liveStatus = await fetchLiveStatus();
    expect(liveStatus.data_status).toBe("DISCONNECTED");
    expect(liveStatus.running).toBe(false);

    const vecList = await fetchBehavioralVectors();
    expect(vecList.data_status).toBe("EMPTY");
    expect(vecList.items).toEqual([]);

    const sim = await fetchBehavioralSimilarity("v1", "v2");
    expect(sim.cosine_similarity).toBe(0.912);
    expect(sim.manhattan_distance).toBe(1.05);

    const corr = await fetchBehavioralCorrelation();
    expect(corr.clusters).toHaveLength(1);
    expect(corr.clusters[0].ip_addresses_observed).toContain("192.0.2.10");
  });

  it("propagates HTTP errors from trace/crypto endpoints instead of returning fake success", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ detail: "Backend unavailable" }), { status: 503 }),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            active_key_id: "k-general-1",
            algorithm: "AES-256-GCM",
            rotation_interval_minutes: 30,
            adaptive_risk_threshold: 85,
            cooldown_seconds: 60,
            total_rotations: 1,
            total_records_encrypted: 4,
            recent_rotations: [],
            storage_protection_status: { master_key_protection: "WINDOWS_DPAPI" },
            data_status: "CONNECTED",
          }),
          { status: 200 },
        ),
      );
    vi.stubGlobal("fetch", fetchMock);

    await expect(fetchTraceTimeline()).rejects.toThrow("Backend unavailable");
    const crypto = await fetchCryptoStatus();
    expect(crypto.data_status).toBe("CONNECTED");
    expect(crypto.storage_protection_status?.master_key_protection).toBe("WINDOWS_DPAPI");
  });

  it("fetchLiveAlerts decodes live alert rows including deduplicated occurrence counts", async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          data_status: "CONNECTED",
          total: 1,
          items: [
            {
              alert_id: "alert-loopback-01",
              entity_id: "host:192.0.2.10",
              risk_score: 84.0,
              risk_level: "HIGH",
              trigger_reason: "Ensemble Attack Consensus; High outbound asymmetry",
              status: "NEW",
              occurrence_count: 2,
              last_seen_utc: "2026-11-18T05:44:32Z",
            },
          ],
        }),
        { status: 200 },
      ),
    );
    vi.stubGlobal("fetch", fetchMock);

    const resp = await fetchLiveAlerts(50);
    expect(resp.data_status).toBe("CONNECTED");
    expect(resp.total).toBe(1);
    expect(resp.items[0].alert_id).toBe("alert-loopback-01");
    expect(resp.items[0].risk_score).toBe(84.0);
    expect(resp.items[0].occurrence_count).toBe(2);
  });

  it("LiveMonitoringPanel paginates 2,000 alerts at 100 rows per page (#140 AC3)", () => {
    const bulkAlerts = Array.from({ length: 2000 }, (_, idx) => ({
      alert_id: `alert-bulk-${idx}`,
      entity_id: `host:10.0.${Math.floor(idx / 250)}.${(idx % 250) + 1}`,
      risk_score: idx % 2 === 0 ? 88.0 : 52.0,
      risk_level: idx % 2 === 0 ? "CRITICAL" : "MEDIUM",
      trigger_reason: "High flow burst",
      status: "NEW",
      last_seen_utc: "2026-11-18T06:00:00Z",
      source: "LIVE",
    }));

    const t0 = performance.now();
    const out = render(LiveMonitoringPanel, {
      props: { initialDemoMode: false, initialAlerts: bulkAlerts, pageSize: 100 },
    });
    const renderMs = performance.now() - t0;

    expect(out.body).toContain("STATE: CONNECTED");
    expect(out.body).toContain("Showing 1–100 of 2000 (Page 1/20)");
    expect(out.body).toContain("alert-bulk-0");
    expect(out.body).toContain("alert-bulk-99");
    expect(out.body).not.toContain("alert-bulk-100\"");
    expect(out.body).not.toContain("alert-bulk-1999");
    expect(renderMs).toBeLessThan(2000);
  });

  it("AttackTimelinePanel renders multi-stage replay correlation with observed vs inferred tags (#142 AC1)", () => {
    const replayStages = [
      {
        stage_order: 1,
        stage_name: "RECONNAISSANCE",
        description: "SYN port sweep across /24 subnet",
        timestamp: "2026-11-18T10:00:01Z",
        entity: "host:10.10.1.5 -> host:10.10.2.20",
        tactic_id: "TA0043",
        is_observed: true,
        confidence: 0.96,
        evidence_ids: ["ev-recon-1"],
      },
      {
        stage_order: 2,
        stage_name: "CREDENTIAL_ACCESS",
        description: "SSH/LDAP brute-force authentication burst",
        timestamp: "2026-11-18T10:02:15Z",
        entity: "host:10.10.1.5 -> host:10.10.2.20",
        tactic_id: "TA0006",
        is_observed: true,
        confidence: 0.91,
        evidence_ids: ["ev-cred-2"],
      },
      {
        stage_order: 3,
        stage_name: "LATERAL_MOVEMENT",
        description: "Behavioral pivot inferred across pivoted source IP",
        timestamp: "2026-11-18T10:05:40Z",
        entity: "host:10.10.2.20 -> host:10.10.3.50",
        tactic_id: "TA0008",
        is_observed: false,
        confidence: 0.78,
        evidence_ids: [],
      },
      {
        stage_order: 4,
        stage_name: "EXFILTRATION",
        description: "Outbound high-asymmetry transfer",
        timestamp: "2026-11-18T10:09:10Z",
        entity: "host:10.10.3.50 -> host:198.51.100.8",
        tactic_id: "TA0010",
        is_observed: true,
        confidence: 0.94,
        evidence_ids: ["ev-exfil-4"],
      },
    ];

    const out = render(AttackTimelinePanel, {
      props: {
        initialDemoMode: false,
        initialCampaign: "REPLAY-CAMPAIGN-4PHASE",
        initialStages: replayStages,
      },
    });

    expect(out.body).toContain("STATE: CONNECTED");
    expect(out.body).toContain("RECONNAISSANCE");
    expect(out.body).toContain("CREDENTIAL_ACCESS");
    expect(out.body).toContain("LATERAL_MOVEMENT");
    expect(out.body).toContain("EXFILTRATION");
    expect(out.body).toContain("OBSERVED TELEMETRY");
    expect(out.body).toContain("INFERRED RELATIONSHIP");
    expect(out.body).toContain("ev-exfil-4");
  });

  it("LiveMonitoringPanel renders Dropped events counter and applies warning class when > 0", () => {
    const outZero = render(LiveMonitoringPanel, {
      props: { initialDemoMode: false },
    });
    expect(outZero.body).toMatch(/Dropped events:\s*<code[^>]*>0<\/code>/);
    expect(outZero.body).not.toContain("dropped-warning");

    const outDropped = render(LiveMonitoringPanel, {
      props: {
        initialDemoMode: false,
        initialLiveStatus: {
          mode: "LIVE",
          running: true,
          data_status: "CONNECTED",
          bound_port: 2055,
          started_at_utc: "2026-11-19T10:00:00Z",
          collector: {
            flows_decoded: 120,
            events_dropped: 3,
          },
          pipeline: {
            total_dropped: 2,
          },
          metrics: {
            events_processed: 115,
          },
          inference: {
            ready_count: 4,
            inference_mode: "RESEARCH_ONLY",
          },
        },
      },
    });
    expect(outDropped.body).toMatch(/Dropped events:\s*<code[^>]*>5<\/code>/);
    expect(outDropped.body).toContain("dropped-warning");
  });

  it("getModelBenchmarkReport decodes CONNECTED and EMPTY responses from backend", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            data_status: "CONNECTED",
            generated_at_utc: "2026-11-19T10:00:00Z",
            dataset_provenance: "AIT-NDS-v2",
            evaluation_partition: "test",
            models: [
              {
                model_key: "random_forest",
                display_name: "Random Forest",
                model_type: "RandomForest",
                deployment_tier: "RESEARCH_ONLY",
                decision_threshold: 0.5,
                threshold_source: "manifest.threshold",
                in_domain: {
                  dataset: "AIT-NDS-v2-test",
                  f1: 0.9912,
                  precision: 0.995,
                  recall: 0.9875,
                  fpr: 0.0012,
                  roc_auc: 0.9991,
                  pr_auc: 0.9985,
                  sample_count: 988805,
                },
                cross_source: [],
                top_features: [
                  {
                    feature: "bytes_per_sec_out",
                    importance: 0.2412,
                    method: "tree_feature_importances",
                  },
                ],
              },
            ],
            limitations: ["Domain shift degrades cross-source recall."],
            sources_loaded: ["model_comparison_report.json"],
          }),
          { status: 200 },
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            data_status: "EMPTY",
            models: [],
            limitations: [],
            sources_loaded: [],
          }),
          { status: 200 },
        ),
      );
    vi.stubGlobal("fetch", fetchMock);

    const connected = await getModelBenchmarkReport();
    expect(connected.data_status).toBe("CONNECTED");
    expect(connected.models).toHaveLength(1);
    expect(connected.models[0].in_domain?.roc_auc).toBe(0.9991);

    const empty = await getModelBenchmarkReport();
    expect(empty.data_status).toBe("EMPTY");
    expect(empty.models).toEqual([]);
  });

  it("ModelComparisonPanel renders Official Benchmark table with ROC-AUC, PR-AUC, CTU/UWF, Top Features, and EMPTY fallback", () => {
    const mockModels: ModelStatusItem[] = [
      {
        model_key: "random_forest",
        display_name: "Random Forest",
        model_type: "RandomForest",
        ready: true,
        status: "READY",
        artifact_path: null,
        manifest_path: null,
        artifact_sha256: null,
        run_id: "run-rf",
        decision_threshold: 0.5,
        score_semantics: "attack_probability",
        reason: null,
      },
    ];

    const mockReport: ModelBenchmarkReportResponse = {
      data_status: "CONNECTED",
      generated_at_utc: "2026-11-19T10:00:00Z",
      dataset_provenance: "AIT-NDS-v2 (test) + CTU-SME-11 + UWF-ZeekData24",
      evaluation_partition: "test",
      sources_loaded: [
        "model_comparison_report.json",
        "ctu_cross_source_eval.json",
        "uwf_zeekdata24_cross_source_eval.json",
      ],
      limitations: [
        "All 4 models remain RESEARCH_ONLY under cross-source domain shift.",
      ],
      models: [
        {
          model_key: "random_forest",
          display_name: "Random Forest",
          model_type: "RandomForest",
          deployment_tier: "RESEARCH_ONLY",
          decision_threshold: 0.5,
          threshold_source: "manifest.threshold",
          in_domain: {
            dataset: "AIT-NDS-v2-test",
            f1: 0.9912,
            precision: 0.995,
            recall: 0.9875,
            fpr: 0.0012,
            roc_auc: 0.9991,
            pr_auc: 0.9985,
            sample_count: 988805,
          },
          cross_source: [
            { dataset: "CTU-Echo", f1: 0.421, fpr: 0.032, roc_auc: 0.7123 },
            { dataset: "CTU-Win7AD", f1: 0.318, fpr: 0.041, roc_auc: 0.6542 },
            { dataset: "UWF-ZeekData24", f1: 0.289, fpr: 0.055, roc_auc: 0.6104 },
          ],
          top_features: [
            {
              feature: "bytes_per_sec_out",
              importance: 0.2412,
              method: "tree_feature_importances",
            },
            {
              feature: "duration_ms",
              importance: 0.1834,
              method: "validation_permutation_importance",
            },
          ],
        },
      ],
    };

    const out = render(ModelComparisonPanel, {
      props: {
        models: mockModels,
        selectedModel: "random_forest",
        analysesByModel: {},
        evaluationsByModel: {},
        benchmarkReport: mockReport,
        canRunComparison: false,
        hasLabelsPath: false,
        busy: false,
        onSelectModel: () => {},
        onRunAllComparison: () => {},
        onEvaluateAllAnalyzed: () => {},
      },
    });

    expect(out.body).toContain(
      "Báo cáo Benchmark Chính thức (AIT-NDS-v2 Test &amp; Cross-Source CTU/UWF)",
    );
    expect(out.body).toContain("RESEARCH_ONLY");
    expect(out.body).toContain("0.9991");
    expect(out.body).toContain("0.9985");
    expect(out.body).toContain("99.12%");
    expect(out.body).toContain("0.12%");
    expect(out.body).toContain("CTU-Echo:");
    expect(out.body).toContain("CTU-Win7AD:");
    expect(out.body).toContain("UWF-ZeekData24:");
    expect(out.body).toContain("bytes_per_sec_out");
    expect(out.body).toContain("tree_feature_importances");
    expect(out.body).toContain("validation_permutation_importance");
    expect(out.body).not.toContain("SHAP");
    expect(out.body).toContain(
      "All 4 models remain RESEARCH_ONLY under cross-source domain shift.",
    );

    const outEmpty = render(ModelComparisonPanel, {
      props: {
        models: mockModels,
        selectedModel: "random_forest",
        analysesByModel: {},
        evaluationsByModel: {},
        benchmarkReport: {
          data_status: "EMPTY",
          models: [],
          limitations: [],
          sources_loaded: [],
        },
        canRunComparison: false,
        hasLabelsPath: false,
        busy: false,
        onSelectModel: () => {},
        onRunAllComparison: () => {},
        onEvaluateAllAnalyzed: () => {},
      },
    });
    expect(outEmpty.body).toContain("So sánh 4 Mô hình Trên Cùng Batch CSV");
    expect(outEmpty.body).toContain("Chưa có dữ liệu Báo cáo Benchmark Chính thức");
  });

  it("LiveMonitoringPanel renders Stage-2 predicted_attack_category and confidence badge on live alerts", () => {
    const out = render(LiveMonitoringPanel, {
      props: {
        initialDemoMode: false,
        initialAlerts: [
          {
            alert_id: "alert-stage2-01",
            entity_id: "host:10.0.0.15",
            risk_score: 91.5,
            risk_level: "CRITICAL",
            trigger_reason: "Ensemble Attack Consensus",
            status: "NEW",
            last_seen_utc: "2026-11-19T12:00:00Z",
            source: "LIVE_ALERT_MANAGER",
            predicted_attack_category: "DDoS_or_DoS",
            attack_category_confidence: 0.92,
          },
        ],
      },
    });

    expect(out.body).toContain("STATE: CONNECTED");
    expect(out.body).toContain("alert-stage2-01");
    expect(out.body).toContain("DDoS_or_DoS");
    expect(out.body).toContain("(92%)");
  });

  it("BehavioralAnalysisPanel in CONNECTED state renders entity-baseline-card when baseline_profile is returned", () => {
    const out = render(BehavioralAnalysisPanel, {
      props: {
        initialDemoMode: false,
        initialSelectedDetail: {
          vector_id: "vec-001",
          entity_id: "host:10.0.0.42",
          window_start: "2026-11-19T12:00:00Z",
          window_end: "2026-11-19T12:01:00Z",
          dimensions: 16,
          features: Array(16).fill(0.1),
          feature_names: null,
          feature_name_status: "OK",
          is_encrypted_at_rest: true,
          key_id: "key-beh-1",
          created_at: "2026-11-19T12:01:00Z",
          data_status: "CONNECTED",
          baseline_profile: {
            entity_key: "host:10.0.0.42",
            has_baseline: true,
            deviation_score: 0.1234,
            cosine_similarity: 0.8766,
            sample_count: 12,
            window_size: 50,
          },
        },
      },
    });

    expect(out.body).toContain("STATE: CONNECTED");
    expect(out.body).toContain('data-testid="entity-baseline-card"');
    expect(out.body).toContain("host:10.0.0.42");
    expect(out.body).toContain("ACTIVE (12/50 prior vectors)");
    expect(out.body).toContain("0.8766");
    expect(out.body).toContain("0.1234");
  });
});
