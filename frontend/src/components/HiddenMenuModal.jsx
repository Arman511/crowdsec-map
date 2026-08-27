import { useCallback, useEffect, useState } from "react";
import { Activity, Copy, Crosshair, Timer, X } from "lucide-react";
import { HiddenMenuList } from "./HiddenMenuList";
import { Metric } from "./Metric";
import { formatRelativeTime } from "../utils";

export function HiddenMenuModal({ onClose }) {
  const [summary, setSummary] = useState(null);
  const [lapiStatus, setLapiStatus] = useState(null);
  const [investigationSources, setInvestigationSources] = useState(null);
  const [updateStatus, setUpdateStatus] = useState(null);
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
      const payloads = await Promise.all(
        responses.map((response) => response.json()),
      );
      setSummary(payloads[0]);
      setLapiStatus(payloads[1]);
      setInvestigationSources(payloads[2]);
      setUpdateStatus(payloads[3]);
    } catch (loadError) {
      setError(loadError.message);
    }
  }, []);
  useEffect(() => {
    loadSummary();
  }, [loadSummary]);
  useEffect(() => {
    const close = (event) => event.key === "Escape" && onClose();
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
          <button
            type="button"
            onClick={onClose}
            title="Close"
            aria-label="Close"
          >
            <X size={18} />
          </button>
        </header>
        {error && <div className="warning">access-log: {error}</div>}
        {!error && !summary && (
          <div className="modalLoading">Loading access log...</div>
        )}
        {summary && (
          <div className="hiddenMenuContent">
            <div className="hiddenMenuStats">
              <Metric
                icon={<Activity />}
                label="24h visits"
                value={summary.visits24h || 0}
              />
              <Metric
                icon={<Crosshair />}
                label="Unique IPs"
                value={summary.uniqueIps || 0}
              />
              <Metric
                icon={<Timer />}
                label="Retention"
                value={`${summary.retentionDays}d`}
              />
            </div>
            {!summary.enabled && (
              <div className="warning">Access log is disabled.</div>
            )}
            <HiddenMenuList title="Top IPs" items={summary.topIps || []} />
            <HiddenMenuList
              title="Top countries"
              items={summary.topCountries || []}
            />
            <div className="hiddenRecent">
              <h4>Recent visits</h4>
              {(summary.recent || []).slice(0, 12).map((visit) => (
                <div
                  className="hiddenRecentRow"
                  key={`${visit.ts}-${visit.ip}-${visit.path}`}
                >
                  <time>{formatRelativeTime(visit.ts)}</time>
                  <strong title={visit.ip}>{visit.ip}</strong>
                  <span>{visit.country || "??"}</span>
                  <em title={visit.userAgent}>{visit.path}</em>
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
                  {lapiStatus.decisionsConfigured
                    ? "Decisions key configured"
                    : "No Decisions key"}
                </p>
                <div className="lapiCredentialsPath">
                  <code title={lapiStatus.file}>{lapiStatus.file}</code>
                  <button
                    type="button"
                    onClick={copyPath}
                    title="Copy container path"
                  >
                    <Copy size={14} /> {pathCopied ? "Copied" : "Copy path"}
                  </button>
                </div>
              </div>
            )}
            {investigationSources && (
              <div className="hiddenRecent investigationSources">
                <h4>Investigation log paths</h4>
                <p>
                  {investigationSources.sources.length} readable source
                  {investigationSources.sources.length === 1 ? "" : "s"} · Auto
                  detect{" "}
                  {investigationSources.autoDetectEnabled
                    ? "enabled"
                    : "disabled"}
                </p>
                {investigationSources.sources.map((source) => (
                  <div
                    className="investigationSourcePath"
                    key={`${source.location}-${source.path}`}
                  >
                    <span>{source.location}</span>
                    <code title={source.path}>{source.path}</code>
                  </div>
                ))}
                {!investigationSources.sources.length && (
                  <p>
                    No readable log sources. Configured:{" "}
                    {investigationSources.configuredPaths.join(", ") || "none"}
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
                {updateStatus.image && (
                  <code title={updateStatus.image}>{updateStatus.image}</code>
                )}
              </div>
            )}
          </div>
        )}
      </section>
    </div>
  );
}
