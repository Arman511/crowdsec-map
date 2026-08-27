import { useCallback, useEffect, useState } from "react";
import { Activity, BarChart3, Timer, X } from "lucide-react";
import { getHistoryGroupLabel } from "../utils";
import { Metric } from "./Metric";

export function GroupDetailModal({ group, days, onClose, onSelectIp }) {
  const [detail, setDetail] = useState(null);
  const [offset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const response = await fetch(
        `/api/history/group?${new URLSearchParams({ days, groupBy: group.groupBy, label: group.label, offset, limit: 50 })}`,
      );
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      setDetail(await response.json());
    } catch (loadError) {
      setError(loadError.message);
    } finally {
      setLoading(false);
    }
  }, [days, group, offset]);

  useEffect(() => {
    load();
  }, [load]);
  useEffect(() => {
    const close = (event) => event.key === "Escape" && onClose();
    window.addEventListener("keydown", close);
    return () => window.removeEventListener("keydown", close);
  }, [onClose]);

  const max = Math.max(...(detail?.items || []).map((item) => item.alerts), 1);

  return (
    <div className="modalBackdrop" role="presentation" onClick={onClose}>
      <section
        className="ipModal groupModal"
        role="dialog"
        aria-modal="true"
        onClick={(event) => event.stopPropagation()}
      >
        <header className="modalHeader">
          <div>
            <h3>{group.label}</h3>
            <p>
              {getHistoryGroupLabel(group.groupBy)} · {days}d window · select an
              IP for cscli details
            </p>
          </div>
          <button type="button" onClick={onClose} aria-label="Close">
            <X size={18} />
          </button>
        </header>
        {error && <div className="warning">{error}</div>}
        {loading && <div className="modalLoading">Loading group IPs...</div>}
        {detail && !loading && (
          <>
            <div className="ipSummaryGrid">
              <Metric
                icon={<BarChart3 />}
                label="IPs"
                value={detail.items.length}
              />
              <Metric
                icon={<Activity />}
                label="Recorded Alerts"
                value={detail.matchedEvents || 0}
              />
              <Metric
                icon={<Timer />}
                label="Window"
                value={`${detail.days}d`}
              />
            </div>
            <div className="groupIpList">
              {detail.items.map((item) => (
                <button
                  type="button"
                  className="groupIpRow"
                  key={item.ip}
                  onClick={() => onSelectIp(item.ip)}
                >
                  <span>
                    <strong>{item.ip}</strong>
                    <i
                      style={{
                        width: `${Math.max(4, (item.alerts / max) * 100)}%`,
                      }}
                    />
                  </span>
                  <em>{item.alerts} log events</em>
                  <small>
                    {item.daysSeen}/{detail.days} days
                  </small>
                  <small>{item.topScenario}</small>
                  <small>{item.topCountry}</small>
                </button>
              ))}
            </div>
          </>
        )}
      </section>
    </div>
  );
}
