import { useCallback, useEffect, useState } from "react";

import { Activity, BarChart3, Copy, RefreshCcw, Timer, X } from "lucide-react";

import type { HistoryIpResponse } from "../types";
import { formatRelativeTime } from "../utils";
import { InvestigationBlock, IpLookupBlock } from "./DetailBlocks";
import { Metric } from "./Metric";

export function IpDetailModal({
  ip,
  days,
  onClose,
}: {
  ip: string;
  days: number;
  onClose: () => void;
}) {
  const [detail, setDetail] = useState<HistoryIpResponse | null>(null);
  const [offset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);
  const [commandCopied, setCommandCopied] = useState(false);
  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const response = await fetch(
        `/api/history/ip/${encodeURIComponent(ip)}?${new URLSearchParams({ days: String(days), offset: String(offset), limit: "20" })}`,
      );
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      setDetail((await response.json()) as HistoryIpResponse);
    } catch (loadError) {
      if (loadError instanceof Error) {
        setError(loadError.message);
      } else {
        setError(String(loadError));
      }
    } finally {
      setLoading(false);
    }
  }, [days, ip, offset]);
  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    const close = (event: KeyboardEvent) => event.key === "Escape" && onClose();
    window.addEventListener("keydown", close);
    return () => window.removeEventListener("keydown", close);
  }, [onClose]);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(detail?.cscli || "");
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1400);
    } catch {
      setCopied(false);
    }
  };

  const copyCommand = async () => {
    try {
      await navigator.clipboard.writeText(detail?.cscliCommand || "");
      setCommandCopied(true);
      window.setTimeout(() => setCommandCopied(false), 1400);
    } catch {
      setCommandCopied(false);
    }
  };

  return (
    <div className="modalBackdrop" role="presentation" onClick={onClose}>
      <section
        className="ipModal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="ip-detail-title"
        onClick={(event) => event.stopPropagation()}
      >
        <header className="modalHeader">
          <div>
            <h3 id="ip-detail-title">{ip}</h3>
            <p>{days}d history window · CrowdSec raw details</p>
          </div>
          <button type="button" onClick={onClose} aria-label="Close">
            <X size={18} />
          </button>
        </header>
        {error && <div className="warning">{error}</div>}
        {loading && <div className="modalLoading">Loading IP details...</div>}
        {detail && !loading && (
          <>
            <div className="ipSummaryGrid">
              <Metric icon={<Activity />} label="Log Events" value={detail.alerts || 0} />
              <Metric icon={<BarChart3 />} label="Recorded Alerts" value={detail.events || 0} />
              <Metric
                icon={<Timer />}
                label="Days seen"
                value={`${detail.daysSeen || 0}/${detail.days}`}
              />
            </div>
            <div className="ipMetaGrid">
              <div>
                <span>ASN</span>
                <strong>{detail.topAsName}</strong>
              </div>
              <div>
                <span>Top scenario</span>
                <strong>{detail.topScenario}</strong>
              </div>
              <div>
                <span>Country</span>
                <strong>{detail.topCountry}</strong>
              </div>
              <div>
                <span>Last seen</span>
                <strong>{formatRelativeTime(detail.lastSeen)}</strong>
              </div>
            </div>
            <IpLookupBlock ip={ip} />
            <InvestigationBlock ip={ip} days={days} />
            <div className="recentEvents">
              <h4>Recent alerts</h4>
              <div className="eventList">
                {detail.recentEvents?.map((event) => (
                  <div
                    className="eventRow"
                    key={`${event.seenAt}-${event.scenario}-${event.count}`}
                  >
                    <time>{formatRelativeTime(event.seenAt)}</time>
                    <strong>{event.count}</strong>
                    <span>{event.scenario}</span>
                    <em>{event.country}</em>
                  </div>
                ))}
              </div>
            </div>
            <div className="rawBlock">
              <div className="rawHeader">
                <div>
                  <h4>cscli raw details</h4>
                  <p>{detail.note}</p>
                </div>
                <div className="rawActions">
                  <button
                    type="button"
                    onClick={load}
                    disabled={loading}
                    title="Refresh IP details"
                  >
                    <RefreshCcw size={15} className={loading ? "spin" : ""} />
                  </button>
                  <button type="button" onClick={copy} disabled={!detail.cscli}>
                    <Copy size={15} /> {copied ? "Copied" : "Copy"}
                  </button>
                </div>
              </div>
              {detail.cscliWarning && <div className="warning">cscli: {detail.cscliWarning}</div>}
              <div className="rawCommand">
                <code>{detail.cscliCommand || "cscli command unavailable"}</code>
                <button
                  type="button"
                  onClick={copyCommand}
                  disabled={!detail.cscliCommand}
                  title="Copy cscli command"
                >
                  <Copy size={14} /> {commandCopied ? "Copied" : "Copy command"}
                </button>
              </div>
              <pre>{detail.cscli || "No cscli output for this IP."}</pre>
            </div>
          </>
        )}
      </section>
    </div>
  );
}
