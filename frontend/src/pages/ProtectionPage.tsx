import { useCallback, useEffect, useState } from "react";
import { Activity, Globe2, ShieldAlert, ShieldCheck } from "lucide-react";
import type { ProtectionResponse } from "../types";
import { Metric } from "../components/Metric";
import { formatTime } from "../utils";

export function ProtectionPage({ refreshSignal }: { refreshSignal: number }) {
  const [days, setDays] = useState(1);
  const [summary, setSummary] = useState<ProtectionResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const loadProtection = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const response = await fetch(`/api/protection?days=${days}`);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      setSummary((await response.json()) as ProtectionResponse);
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : String(loadError));
    } finally {
      setLoading(false);
    }
  }, [days]);

  useEffect(() => {
    loadProtection();
  }, [loadProtection]);
  useEffect(() => {
    if (refreshSignal > 0) loadProtection();
  }, [loadProtection, refreshSignal]);

  const maxRequests = Math.max(
    1,
    ...(summary?.timeline || []).map((item) => item.processedRequests),
  );
  return (
    <section className="protectionView">
      <div className="protectionControls">
        <div className="segmented" role="group" aria-label="Protection time range">
          {[1, 3, 7].map((value) => (
            <button
              type="button"
              className={days === value ? "active" : ""}
              key={value}
              onClick={() => setDays(value)}
            >
              {value === 1 ? "24h" : `${value}d`}
            </button>
          ))}
        </div>
      </div>
      <div className="protectionSummary">
        <Metric
          icon={<Activity />}
          label="Processed Requests"
          value={summary?.totals?.processedRequests || 0}
        />
        <Metric
          icon={<ShieldAlert />}
          label="HTTP Blocked"
          value={summary?.totals?.httpBlockedRequests || 0}
        />
        <Metric
          icon={<ShieldCheck />}
          label="Block Rate"
          value={`${summary?.totals?.blockRate || 0}%`}
        />
        <Metric
          icon={<Globe2 />}
          label="Active Hostnames"
          value={summary?.totals?.activeHostnames || 0}
        />
      </div>
      {error && <div className="warning">protection: {error}</div>}
      {!error && loading && !summary && (
        <div className="modalLoading">Reading proxy access logs...</div>
      )}
      {summary?.warning && <div className="warning">{summary.warning}</div>}
      {summary?.timedOut && (
        <div className="warning">
          Log scan stopped at the configured investigation timeout; increase
          INVESTIGATION_TIMEOUT_MS for a complete result.
        </div>
      )}
      <div className="protectionGrid">
        <section className="protectionTrend">
          <header>
            <div>
              <h3>Request activity</h3>
              <p>
                {summary?.parsedRequests || 0} parsed access-log entries ·{" "}
                {summary?.availableFiles || 0} readable source
                {summary?.availableFiles === 1 ? "" : "s"}
              </p>
            </div>
            <span>403 / 429 / 444 are counted as HTTP-blocked</span>
          </header>
          <div className="protectionBars" aria-label="Processed request volume by hour">
            {(summary?.timeline || []).map((item) => (
              <div
                className="protectionBucket"
                key={item.timestamp}
                title={`${formatTime(item.timestamp)} · ${item.processedRequests} requests · ${item.httpBlockedRequests} blocked`}
              >
                <i
                  style={{
                    height: `${Math.max(4, (item.processedRequests / maxRequests) * 100)}%`,
                  }}
                />
                {item.httpBlockedRequests > 0 && (
                  <b
                    style={{
                      height: `${Math.max(4, (item.httpBlockedRequests / maxRequests) * 100)}%`,
                    }}
                  />
                )}
              </div>
            ))}
            {!summary?.timeline?.length && (
              <p className="protectionEmpty">No timestamped access-log entries in this period.</p>
            )}
          </div>
          <footer>
            <span>Teal: processed requests</span>
            <span>Amber: HTTP 403 / 429 / 444</span>
          </footer>
        </section>
        <section className="protectionHosts">
          <header>
            <div>
              <h3>Top protected hostnames</h3>
              <p>Sorted by HTTP-blocked requests</p>
            </div>
          </header>
          <div className="protectionTableWrap">
            <table>
              <thead>
                <tr>
                  <th>Hostname</th>
                  <th>Requests</th>
                  <th>Blocked</th>
                  <th>Rate</th>
                </tr>
              </thead>
              <tbody>
                {(summary?.hosts || []).map((item) => (
                  <tr key={item.hostname}>
                    <td>
                      <strong>{item.hostname}</strong>
                    </td>
                    <td>{item.processedRequests}</td>
                    <td>{item.httpBlockedRequests}</td>
                    <td>
                      <span className={item.httpBlockedRequests ? "blockRate hot" : "blockRate"}>
                        {item.blockRate}%
                      </span>
                    </td>
                  </tr>
                ))}
                {summary && !summary.hosts?.length && (
                  <tr>
                    <td colSpan={4} className="protectionEmpty">
                      No supported access-log entries found.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </section>
  );
}
