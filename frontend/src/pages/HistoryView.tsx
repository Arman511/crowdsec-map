import { Activity, BarChart3, RefreshCcw, Timer } from "lucide-react";
import { useCallback, useEffect, useState } from "react";

import { GroupDetailModal } from "../components/GroupDetailModal";
import { IpDetailModal } from "../components/IpDetailModal";
import { Metric } from "../components/Metric";
import { HISTORY_DAYS_OPTIONS, HISTORY_GROUP_OPTIONS } from "../constants";
import { formatRelativeTime, getHistoryGroupLabel, isIpv4 } from "../utils";

import type { HistoryItem, HistoryResponse } from "../types";
import "../styles/pages/HistoryView.scss";

export function HistoryView() {
  const [days, setDays] = useState(90);

  const [groupBy, setGroupBy] = useState("cidr24");

  const [history, setHistory] = useState<HistoryResponse | null>(null);

  const [offset, setOffset] = useState(0);

  const [selectedIp, setSelectedIp] = useState("");

  const [selectedGroup, setSelectedGroup] = useState<HistoryItem | null>(null);

  const [loading, setLoading] = useState(true);

  const [error, setError] = useState("");

  const loadHistory = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const response = await fetch(
        `/api/history?${new URLSearchParams({ days: String(days), groupBy, offset: String(offset), limit: "50" })}`,
      );
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      setHistory((await response.json()) as HistoryResponse);
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : String(loadError));
    } finally {
      setLoading(false);
    }
  }, [days, groupBy, offset]);
  useEffect(() => {
    loadHistory();
  }, [loadHistory]);
  const maxAlerts = Math.max(...(history?.items || []).map((item) => item.alerts), 1);

  return (
    <section className="historyView">
      <div className="historyControls">
        <div className="segmented" role="group" aria-label="History time range">
          {HISTORY_DAYS_OPTIONS.map((value) => (
            <button
              type="button"
              className={days === value ? "active" : ""}
              key={value}
              onClick={() => {
                setOffset(0);
                setDays(value);
              }}
            >
              {value}d
            </button>
          ))}
        </div>
        <div className="segmented wide" role="group" aria-label="History grouping">
          {HISTORY_GROUP_OPTIONS.map(([value, label]) => (
            <button
              type="button"
              className={groupBy === value ? "active" : ""}
              key={value}
              onClick={() => {
                setOffset(0);
                setGroupBy(value);
              }}
            >
              {label}
            </button>
          ))}
        </div>
        <button
          type="button"
          className="historyRefresh"
          onClick={loadHistory}
          disabled={loading}
          title="Refresh history"
        >
          <RefreshCcw size={16} className={loading ? "spin" : ""} />
        </button>
      </div>
      <div className="historySummary">
        <Metric icon={<BarChart3 />} label="Groups" value={history?.total || 0} />
        <Metric icon={<Activity />} label="Recorded Alerts" value={history?.matchedEvents || 0} />
        <Metric icon={<Timer />} label="Window" value={`${history?.days || days}d`} />
      </div>
      <p className="historySourceNote">
        Recorded locally by CrowdSec Map. This archive can include alerts that CrowdSec no longer
        retains.
      </p>
      <div className="historyTableWrap">
        {error && <div className="warning">{error}</div>}
        {!error && history?.items?.length === 0 && (
          <div className="historyEmpty">
            <strong>No history yet</strong>
            <span>History starts filling when live data is refreshed.</span>
          </div>
        )}
        {history?.items && history.items.length > 0 && (
          <table className="historyTable">
            <thead>
              <tr>
                {[
                  getHistoryGroupLabel(groupBy),
                  "Days",
                  "Log events",
                  "IPs",
                  "Last seen",
                  "Top scenario",
                  "Country",
                ].map((label) => (
                  <th key={label}>{label}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {history.items.map((item: HistoryItem) => {
                const isIpRow = groupBy === "ip" && isIpv4(item.label);

                return (
                  <tr
                    className="clickableRow"
                    key={item.label}
                    onClick={() => (isIpRow ? setSelectedIp(item.label) : setSelectedGroup(item))}
                  >
                    <td>
                      <strong title={item.label}>{item.label}</strong>
                      <div className="historyBar">
                        <i
                          style={{
                            width: `${Math.max(4, (item.alerts / maxAlerts) * 100)}%`,
                          }}
                        />
                      </div>
                    </td>
                    <td>
                      {item.daysSeen}/{history.days}
                    </td>
                    <td>{item.alerts}</td>
                    <td>{item.ipCount}</td>
                    <td title={item.lastSeen}>{formatRelativeTime(item.lastSeen)}</td>
                    <td title={item.topScenario}>{item.topScenario}</td>
                    <td>{item.topCountry}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
      <footer className="decisionsPager">
        <span>{history?.total || 0} groups · 50 per page</span>
        <div>
          <button
            type="button"
            disabled={offset === 0 || loading}
            onClick={() => setOffset((value) => Math.max(0, value - 50))}
          >
            Previous
          </button>
          <strong>
            {history?.total
              ? `${offset + 1}–${Math.min(offset + (history.limit || 50), history.total)} of ${history.total}`
              : "0 groups"}
          </strong>
          <button
            type="button"
            disabled={history?.nextOffset == null || loading}
            onClick={() => history?.nextOffset != null && setOffset(history.nextOffset)}
          >
            Next
          </button>
        </div>
      </footer>
      {selectedIp && (
        <IpDetailModal days={days} ip={selectedIp} onClose={() => setSelectedIp("")} />
      )}
      {selectedGroup && (
        <GroupDetailModal
          days={days}
          group={selectedGroup}
          groupBy={groupBy}
          onClose={() => setSelectedGroup(null)}
          onSelectIp={(ip) => {
            setSelectedGroup(null);
            setSelectedIp(ip);
          }}
        />
      )}
    </section>
  );
}
