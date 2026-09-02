import { Crosshair, RefreshCcw, Search, ShieldAlert } from "lucide-react";
import { JSX, useCallback, useEffect, useState } from "react";

import {
  buildActiveBanTitle,
  clampLineLimit,
  formatBanRemaining,
  formatBanSince,
  formatCtiScore,
  formatRelativeTime,
} from "../utils";

import type { InvestigationLogResponse, InvestigationLogSource, ReputationIp } from "../types";
import "../styles/components/DetailBlocks.scss";

export function CtiReputationBlock({
  reputation,
  warning,
  onRefresh,
  loading,
}: {
  reputation?: ReputationIp | null;
  warning?: string;
  onRefresh: () => void;
  loading: boolean;
}) {
  if (!reputation && !warning) return null;
  const status = reputation?.status || "error";

  const label =
    (
      {
        false_positive: "false positive",
        malicious: "malicious",
        suspicious: "suspicious",
        unknown: "unknown",
        not_configured: "not configured",
        error: "error",
      } as Record<string, string>
    )[status] || status;

  return (
    <div className={`ctiBlock cti-${status}`}>
      <div className="ctiHeader">
        <div>
          <h4>
            <ShieldAlert size={15} /> CrowdSec CTI reputation
          </h4>
          <p>{warning || reputation?.summary || "No CrowdSec CTI data available."}</p>
        </div>
        <span>{label}</span>
      </div>
      {warning ? (
        <div className="warning">cti: {warning}</div>
      ) : reputation ? (
        <>
          <div className="ctiGrid">
            <div>
              <span>Maliciousness</span>
              <strong>{formatCtiScore(reputation.maliciousness, "percent")}</strong>
            </div>
            <div>
              <span>Background noise</span>
              <strong>{formatCtiScore(reputation.backgroundNoise, "ten")}</strong>
            </div>
            <div>
              <span>Cache</span>
              <strong>
                {reputation.cached ? `cached ${formatRelativeTime(reputation.cachedAt)}` : "fresh"}
              </strong>
            </div>
          </div>
          {reputation.behaviors && reputation.behaviors.length > 0 && (
            <div className="ctiTags">
              {reputation.behaviors.map((behavior: string) => (
                <span key={behavior}>{behavior}</span>
              ))}
            </div>
          )}
          <div className="ctiActions">
            {reputation.configured && reputation.webUrl && (
              <a href={reputation.webUrl} target="_blank" rel="noreferrer">
                Open CrowdSec CTI
              </a>
            )}
            <button type="button" onClick={onRefresh} disabled={loading}>
              <RefreshCcw size={14} /> Refresh CTI
            </button>
          </div>
        </>
      ) : null}
    </div>
  );
}

export function IpLookupBlock({ ip }: { ip: string }) {
  const [reputation, setReputation] = useState<ReputationIp | null>(null);

  const [stats, setStats] = useState<Record<string, unknown> | null>(null);

  const [loading, setLoading] = useState(false);

  const [error, setError] = useState("");

  const loadStats = useCallback(async () => {
    try {
      const response = await fetch("/api/reputation/stats");
      if (response.ok) setStats(await response.json());
    } catch {
      setStats(null);
    }
  }, []);

  const load = useCallback(
    async (refresh = false) => {
      setLoading(true);
      setError("");
      try {
        const response = await fetch(
          `/api/reputation/ip/${encodeURIComponent(ip)}${refresh ? "?refresh=1" : ""}`,
        );

        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || `HTTP ${response.status}`);
        setReputation(payload);
        setStats(payload.stats || null);
      } catch (loadError) {
        setError(loadError instanceof Error ? loadError.message : String(loadError));
      } finally {
        setLoading(false);
      }
    },
    [ip],
  );
  useEffect(() => {
    setReputation(null);
    setError("");
    loadStats();
  }, [ip, loadStats]);

  return (
    <div className="lookupBlock">
      <div className="lookupHeader">
        <div>
          <h4>
            <ShieldAlert size={15} /> IP lookup
          </h4>
          <p>External reputation checks only run when selected.</p>
        </div>
        {stats && <span>{stats.networkRequests as number} CTI requests this month</span>}
      </div>
      <div className="lookupActions">
        <button type="button" onClick={() => load()} disabled={loading}>
          <ShieldAlert size={14} /> CrowdSec CTI
        </button>
        <a
          href={`https://www.abuseipdb.com/check/${encodeURIComponent(ip)}`}
          target="_blank"
          rel="noreferrer"
        >
          <ShieldAlert size={14} /> AbuseIPDB
        </a>
        <a
          href={`https://www.shodan.io/host/${encodeURIComponent(ip)}`}
          target="_blank"
          rel="noreferrer"
        >
          <Crosshair size={14} /> Shodan.io
        </a>
      </div>
      {(reputation || error) && (
        <CtiReputationBlock
          reputation={reputation}
          warning={error}
          onRefresh={() => load(true)}
          loading={loading}
        />
      )}
    </div>
  );
}

export function InvestigationBlock({ ip, days }: { ip: string; days: number }) {
  const [investigation, setInvestigation] = useState<InvestigationLogResponse | null>(null);

  const [loading, setLoading] = useState(false);

  const [error, setError] = useState("");

  const [lineLimit, setLineLimit] = useState(50);

  const load = async () => {
    setLoading(true);
    setError("");
    try {
      const response = await fetch(
        `/api/investigation/ip/${encodeURIComponent(ip)}?${new URLSearchParams({ days: String(days), maxLines: String(clampLineLimit(lineLimit)) })}`,
      );

      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || `HTTP ${response.status}`);
      setInvestigation(payload);
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : String(loadError));
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => {
    setInvestigation(null);
    setError("");
  }, [ip, days]);

  return (
    <div className="investigationBlock">
      <div className="investigationHeader">
        <div>
          <h4>
            <Search size={15} /> Investigation
          </h4>
          <p>Checks configured host logs for this IP in the selected {days}d window.</p>
        </div>
        <div className="investigationRunControls">
          <label>
            <span>Lines</span>
            <input
              type="number"
              min="1"
              max="200"
              value={lineLimit}
              onChange={(event) => setLineLimit(Number(event.target.value))}
              onBlur={() => setLineLimit(clampLineLimit(lineLimit))}
            />
          </label>
          <button type="button" onClick={load} disabled={loading}>
            <RefreshCcw size={14} /> Run
          </button>
        </div>
      </div>
      {error && <div className="warning">investigation: {error}</div>}
      {!investigation && !error && (
        <p className="investigationHint">Compare CrowdSec context with mounted host logs.</p>
      )}
      {investigation && (
        <>
          <div className="investigationGrid">
            <div>
              <span>Hits</span>
              <strong>{investigation.totalHits}</strong>
            </div>
            <div>
              <span>'403 (Forbidden)'</span>
              <strong>{investigation.totalForbidden}</strong>
            </div>
            <div title={buildActiveBanTitle(investigation.activeBans?.items || [])}>
              <span>Active Bans</span>
              <strong>{investigation.activeBans?.count || 0}</strong>
            </div>
            <div>
              <span>Ban since</span>
              <strong>{String(formatBanSince(investigation.activeBans?.since || ""))}</strong>
            </div>
            <div>
              <span>Remaining</span>
              <strong>
                {String(formatBanRemaining(investigation.activeBans?.remaining || ""))}
              </strong>
            </div>
            <div>
              <span>Files</span>
              <strong>
                {investigation.scannedFiles}/{investigation.availableFiles}
              </strong>
            </div>
          </div>
          <div className="investigationSources">
            {investigation.sources?.map((source: InvestigationLogSource): JSX.Element => (
              <details key={source.path} open={(source.hits || 0) > 0}>
                <summary>
                  <strong>{source.name}</strong>
                  <span>
                    {source.hits} hits · {source.forbidden} '403 (Forbidden)'
                  </span>
                </summary>
                <pre>
                  {source.sampledLines?.join("\n") || "No matching sample lines in this window."}
                </pre>
              </details>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

export function InvestigationLogModal({
  ip,
  days,
  source,
  activeBans,
  onClose,
}: {
  ip: string;
  days: number;
  source: InvestigationLogSource;
  activeBans?: Array<{ ip?: string; value?: string; since?: string }>;
  onClose: () => void;
}) {
  const [search, setSearch] = useState("");

  const [lines, setLines] = useState<Array<Record<string, unknown>>>([]);

  const [loading, setLoading] = useState(true);

  const [error, setError] = useState("");

  const banSince = activeBans?.find((b) => (b.ip || b.value) === ip)?.since
    ? activeBans?.find((b) => (b.ip || b.value) === ip)?.since || ""
    : "";

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const response = await fetch(
        `/api/investigation/ip/${encodeURIComponent(ip)}/log-lines?${new URLSearchParams({ days: String(days), path: source.path, offset: String(0), limit: String(200), filter: "all", sort: "newest", search })}`,
      );

      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || `HTTP ${response.status}`);
      setLines(payload.lines || []);
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : String(loadError));
    } finally {
      setLoading(false);
    }
  }, [days, ip, search, source.path]);
  useEffect(() => {
    load();
  }, [load]);
  useEffect(() => {
    const close = (event: KeyboardEvent) => event.key === "Escape" && onClose();
    window.addEventListener("keydown", close);

    return () => window.removeEventListener("keydown", close);
  }, [onClose]);

  return (
    <div className="modalBackdrop" role="presentation" onClick={onClose}>
      <section
        className="ipModal investigationLogModal"
        role="dialog"
        aria-modal="true"
        onClick={(event: React.MouseEvent) => event.stopPropagation()}
      >
        <header className="modalHeader">
          <div>
            <h3>{source.name}</h3>
            <p>
              {ip} · {days}d window · {banSince ? `ban since: ${banSince}` : "matching lines"}
            </p>
          </div>
          <button type="button" onClick={onClose} aria-label="Close">
            ×
          </button>
        </header>
        <form className="logLineControls" onSubmit={(event) => event.preventDefault()}>
          <label>
            <span>Search</span>
            <input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="path, router, origin..."
            />
          </label>
          <button type="submit">Apply</button>
        </form>
        {error && <div className="warning">log-lines: {error}</div>}
        <div className="logLineList">
          {lines.map((item, index) => (
            <div
              className={(item.forbidden as boolean) ? "logLineRow forbidden" : "logLineRow"}
              key={`${item.timestamp as string}-${index}`}
            >
              <span>{(item.forbidden as boolean) ? "403" : "OK"}</span>
              <code>{item.line as string}</code>
            </div>
          ))}
          {!loading && !lines.length && <p>No log lines match the current filters.</p>}
        </div>
      </section>
    </div>
  );
}
