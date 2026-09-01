import {
  useEffect,
  useMemo,
  useState,
} from "react";
import type { RankItem, ActiveBan, Alert } from "../types";
import { EMPTY_RANK_ITEMS, METRIC_PAGE_SIZE } from "../constants";
import { formatRelativeTime, groupCounts } from "../utils";
import { Search, X } from "lucide-react";

export function MetricDrilldownModal({
  data,
  initialMode,
  onClose,
  onSelectIp,
}: {
  data: any;
  initialMode: string;
  onClose: () => void;
  onSelectIp: (ip: string) => void;
}) {
  const [mode, setMode] = useState(initialMode);
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(0);
  const [alertFilter, setAlertFilter] = useState<{ field: string; value: string } | null>(null);
  const alerts = data?.alerts || EMPTY_RANK_ITEMS;
  const bans = data?.activeBans || EMPTY_RANK_ITEMS;
  const grouped = useMemo(
    () => ({
      countries: groupCounts(alerts, "country"),
      scenarios: groupCounts(alerts, "scenario"),
    }),
    [alerts],
  );
  const rows = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (mode === "bans")
      return bans.filter((item: any) =>
        [item.ip, item.country, item.scenario, item.duration].some((value: any) =>
          String(value || "")
            .toLowerCase()
            .includes(needle),
        ),
      );
    if (mode === "countries" || mode === "scenarios")
      return grouped[mode].filter((item: any) => item.label.toLowerCase().includes(needle));
    return alerts.filter(
      (item: any) =>
        (!alertFilter || String(item[alertFilter.field] || "unknown") === alertFilter.value) &&
        [item.ip, item.country, item.scenario, item.createdAt].some((value: any) =>
          String(value || "")
            .toLowerCase()
            .includes(needle),
        ),
    );
  }, [alertFilter, alerts, bans, grouped, mode, query]);
  const pageCount = Math.max(1, Math.ceil(rows.length / METRIC_PAGE_SIZE));
  const visibleRows = rows.slice(page * METRIC_PAGE_SIZE, (page + 1) * METRIC_PAGE_SIZE);
  useEffect(() => setPage(0), [mode, query, alertFilter]);
  useEffect(() => {
    const close = (event: KeyboardEvent) => event.key === "Escape" && onClose();
    window.addEventListener("keydown", close);
    return () => window.removeEventListener("keydown", close);
  }, [onClose]);
  const openGroup = (field: string, value: string) => {
    setAlertFilter({ field, value });
    setMode("alerts");
    setQuery("");
  };
  return (
    <div className="modalBackdrop" role="presentation" onClick={onClose}>
      <section
        className="ipModal metricModal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="metric-detail-title"
        onClick={(event) => event.stopPropagation()}
      >
        <header className="modalHeader">
          <div>
            <h3 id="metric-detail-title">Live security details</h3>
            <p>
              {rows.length} matching entries · {data?.source || "unknown"}
            </p>
          </div>
          <button type="button" onClick={onClose} title="Close" aria-label="Close">
            <X size={18} />
          </button>
        </header>
        <div className="metricModalToolbar">
          <div className="segmented wide" role="group" aria-label="Metric detail mode">
            {[
              ["bans", "Active Bans"],
              ["alerts", "Current Alerts"],
              ["countries", "Countries"],
              ["scenarios", "Scenarios"],
            ].map(([value, label]) => (
              <button
                type="button"
                className={mode === value ? "active" : ""}
                key={value}
                onClick={() => {
                  setMode(value);
                  setAlertFilter(null);
                }}
              >
                {label}
              </button>
            ))}
          </div>
          <label className="metricSearch">
            <Search size={16} />
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search IP, country or scenario"
            />
          </label>
        </div>
        {alertFilter && (
          <button type="button" className="filterChip" onClick={() => setAlertFilter(null)}>
            {alertFilter.value} <X size={13} />
          </button>
        )}
        <div className="metricResultList">
          {visibleRows.map((item: any, index: number) =>
            mode === "countries" || mode === "scenarios" ? (
              <button
                type="button"
                className="metricResultRow groupResult"
                key={item.label}
                onClick={() => openGroup(mode === "countries" ? "country" : "scenario", item.label)}
              >
                <strong>{item.label || "unknown"}</strong>
                <span>{item.count} log events</span>
              </button>
            ) : (
              <button
                type="button"
                className="metricResultRow"
                key={`${item.id || item.ip || item.value}-${index}`}
                onClick={() => item.ip && onSelectIp(item.ip)}
                disabled={!item.ip}
              >
                <time>{formatRelativeTime(item.createdAt)}</time>
                <strong>{item.ip || "No IP"}</strong>
                <span>{item.country || "??"}</span>
                <span title={item.scenario}>{item.scenario || "unknown"}</span>
                <em>{mode === "bans" ? item.duration || "active" : `${item.count || 1} events`}</em>
              </button>
            ),
          )}
          {visibleRows.length === 0 && <p className="metricEmpty">No matching entries.</p>}
        </div>
        <footer className="metricPager">
          <button type="button" disabled={page === 0} onClick={() => setPage((value) => value - 1)}>
            Previous
          </button>
          <span>
            Page {page + 1} / {pageCount}
          </span>
          <button
            type="button"
            disabled={page + 1 >= pageCount}
            onClick={() => setPage((value) => value + 1)}
          >
            Next
          </button>
        </footer>
      </section>
    </div>
  );
}
