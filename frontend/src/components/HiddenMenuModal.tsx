import { Activity, Copy, Crosshair, Timer, X } from "lucide-react";
import React, { useCallback, useEffect, useState } from "react";


import type { AccessLogSummary, LapiCredentialsStatus, UpdateStatus } from "../types";
import { formatRelativeTime } from "../utils";
import { HiddenMenuList } from "./HiddenMenuList";
import { Metric } from "./Metric";

export function HiddenMenuModal({ onClose }: { onClose: () => void }) {
  const [summary, setSummary] = useState<AccessLogSummary | null>(null);

  const [lapiStatus, setLapiStatus] = useState<LapiCredentialsStatus | null>(null);

  const [investigationSources, setInvestigationSources] = useState<Record<string, unknown> | null>(
    null,
  );

  const [updateStatus, setUpdateStatus] = useState<UpdateStatus | null>(null);

  const [pathCopied, setPathCopied] = useState(false);

  const [error, setError] = useState("");

  const loadSummary = useCallback(async () => {
    setError("");
    try {
      const responses = await Promise.all([
        fetch("/api/access-log/summary?days=7"),
        fetch("/api/lapi/credentials/status"),
        fetch("/api/investigation/sources"),
        fetch("/api/system/update-status"),
      ]);

      const failed = responses.find((response) => !response.ok);
      if (failed) throw new Error(`HTTP ${failed.status}`);
      const payloads = await Promise.all(responses.map((response) => response.json()));
      setSummary(payloads[0] as AccessLogSummary);
      setLapiStatus(payloads[1] as LapiCredentialsStatus);
      setInvestigationSources(payloads[2]);
      setUpdateStatus(payloads[3] as UpdateStatus);
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : String(loadError));
    }
  }, []);
  useEffect(() => {
    loadSummary();
  }, [loadSummary]);
  useEffect(() => {
    const close = (event: KeyboardEvent) => event.key === "Escape" && onClose();
    window.addEventListener("keydown", close);

    return () => window.removeEventListener("keydown", close);
  }, [onClose]);
  const copyPath = async () => {
    try {
      await navigator.clipboard.writeText(lapiStatus?.file || "");
      setPathCopied(true);
      window.setTimeout(() => setPathCopied(false), 1400);
    } catch {
      setPathCopied(false);
    }
  };

  return (
    <div className="modalBackdrop" role="presentation" onClick={onClose}>
      <section
        className="hiddenMenuModal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="hidden-menu-title"
        onClick={(event) => event.stopPropagation()}
      >
        <header className="modalHeader">
          <div>
            <h3 id="hidden-menu-title">π</h3>
            <p>Demo visit log</p>
          </div>
          <button type="button" onClick={onClose} title="Close" aria-label="Close">
            <X size={18} />
          </button>
        </header>
        {error && <div className="warning">access-log: {error}</div>}
        {!error && !summary && <div className="modalLoading">Loading access log...</div>}
        {summary && (
          <div className="hiddenMenuContent">
            <div className="hiddenMenuStats">
              <Metric icon={<Activity />} label="24h visits" value={summary["24hVisits"] || 0} />
              <Metric icon={<Crosshair />} label="Unique IPs" value={summary.uniqueIps || 0} />
              <Metric icon={<Timer />} label="Retention" value={`${summary.retention}`} />
            </div>
            {summary.enabled === false && <div className="warning">Access log is disabled.</div>}
            <HiddenMenuList title="Top IPs" items={summary.topIps || []} />
            <HiddenMenuList title="Top countries" items={summary.topCountries || []} />
            <div className="hiddenRecent">
              <h4>Recent visits</h4>
              {(summary.recent || []).slice(0, 12).map((visit: Record<string, unknown>) => (
                <div className="hiddenRecentRow" key={`${visit.ts}-${visit.ip}-${visit.path}`}>
                  <time>{formatRelativeTime(visit.ts as string | number | Date | undefined)}</time>
                  <strong title={visit.ip as string}>{visit.ip as string}</strong>
                  <span>{(visit.country as string) || "??"}</span>
                  <em title={visit.userAgent as string}>{visit.path as string}</em>
                </div>
              ))}
              {!summary.recent?.length && <p>No visits logged yet.</p>}
            </div>
            {lapiStatus && (
              <div className="hiddenRecent lapiCredentials">
                <h4>LAPI credentials</h4>
                <p>
                  {lapiStatus.watcherConfigured
                    ? "Watcher credentials configured"
                    : "Watcher credentials not configured"}{" "}
                  ·{" "}
                  {lapiStatus.decisionsConfigured ? "Decisions key configured" : "No Decisions key"}
                </p>
                <div className="lapiCredentialsPath">
                  <code title={lapiStatus.file}>{lapiStatus.file}</code>
                  <button type="button" onClick={copyPath} title="Copy container path">
                    <Copy size={14} /> {pathCopied ? "Copied" : "Copy path"}
                  </button>
                </div>
              </div>
            )}
            {investigationSources && (
              <div className="hiddenRecent investigationSources">
                <h4>Investigation log paths</h4>
                <p>
                  {(investigationSources.sources as unknown[]).length} readable source
                  {(investigationSources.sources as unknown[]).length === 1 ? "" : "s"} · Auto
                  detect{" "}
                  {(investigationSources.autoDetectEnabled as boolean) ? "enabled" : "disabled"}
                </p>
                {((investigationSources.sources as unknown[]) || []).map((source: unknown) => {
                  const s = source as Record<string, unknown>;

                  return (
                    <div
                      className="investigationSourcePath"
                      key={`${s.location as string}-${s.path as string}`}
                    >
                      <span>{s.location as string}</span>
                      <code title={s.path as string}>{s.path as string}</code>
                    </div>
                  );
                })}
                {!(investigationSources.sources as unknown[]).length && (
                  <p>
                    No readable log sources. Configured:{" "}
                    {((investigationSources.configuredPaths as string[]) || []).join(", ") ||
                      "none"}
                  </p>
                )}
              </div>
            )}
            {updateStatus && (
              <div className="hiddenRecent updateStatus">
                <h4>Container image · GitHub dev</h4>
                <p className={`updateState ${updateStatus.state}`}>
                  {updateStatus.state === "current"
                    ? "Current"
                    : updateStatus.state === "update_available"
                      ? "Update available"
                      : "Check unavailable"}
                </p>
                <p>{updateStatus.message}</p>
                {updateStatus.image && <code title={updateStatus.image}>{updateStatus.image}</code>}
              </div>
            )}
          </div>
        )}
      </section>
    </div>
  );
}
