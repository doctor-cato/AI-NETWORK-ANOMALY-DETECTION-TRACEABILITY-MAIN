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
} from "../api";
import AttackTimelinePanel from "./AttackTimelinePanel.svelte";
import BehavioralAnalysisPanel from "./BehavioralAnalysisPanel.svelte";
import CryptographyDashboardPanel from "./CryptographyDashboardPanel.svelte";
import LiveMonitoringPanel from "./LiveMonitoringPanel.svelte";

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
});
