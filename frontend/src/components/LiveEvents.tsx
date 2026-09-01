import { useEffect, useMemo } from "react";
import { ArrowUpRight, Filter, Search, X } from "lucide-react";
import type { Alert, ActiveBan } from "../types";
import {
  buildTrendBuckets,
  formatRelativeTime,
  formatTime,
  groupEventSources,
  readableScenario,
} from "../utils";

export function LiveFilterBar({
  filters,
  setFilters,
  options,
  resultCount,
  totalCount,
}: {
  filters: Record<string, string>;
  setFilters: (
    f: Record<string, string> | ((prev: Record<string, string>) => Record<string, string>),
  ) => void;
  options: Record<string, any>;
  resultCount: number;
  totalCount: number;
}) {
  const update = (field: string, value: string) =>
    setFilters((prev) => ({ ...prev, [field]: value }));
  const activeCount = Object.values(filters).filter((value) => value && value !== "all").length;
  return (
    <section className="liveFilterBar" aria-label="Live attack filters">
      <label className="filterSearch">
        <Search size={16} />
        <input
          value={filters.query}
          onChange={(event) => update("query", event.target.value)}
          placeholder="Search IP, ASN, country or scenario"
        />
      </label>
      <label>
        <span>Scenario</span>
        <select
          value={filters.scenario}
          onChange={(event) => update("scenario", event.target.value)}
        >
          <option value="all">All scenarios</option>
          {options.scenarios.map((value: string) => (
            <option key={value}>{value}</option>
          ))}
        </select>
      </label>
      <label>
        <span>Country</span>
        <select value={filters.country} onChange={(event) => update("country", event.target.value)}>
          <option value="all">All countries</option>
          {options.countries.map((value: string) => (
            <option key={value}>{value}</option>
          ))}
        </select>
      </label>
      <label>
        <span>Time range</span>
        <select value={filters.age} onChange={(event) => update("age", event.target.value)}>
          <option value="all">All current alerts</option>
          <option value="15m">Last 15 minutes</option>
          <option value="1h">Last hour</option>
          <option value="24h">Last 24 hours</option>
        </select>
      </label>
      <div className="filterResult">
        <Filter size={15} />
        <strong>{resultCount}</strong>
        <span>of {totalCount}</span>
      </div>
      <button
        type="button"
        className="clearFilters"
        disabled={!activeCount}
        onClick={() => setFilters({ query: "", country: "all", scenario: "all", age: "all" })}
      >
        Clear {activeCount ? `(${activeCount})` : ""}
      </button>
    </section>
  );
}

interface TrendBucket {
  key: number;
  label: string;
  dateLabel?: string;
  count: number;
  attacks: Alert[];
}

export function ActivityTrend({
  attacks,
  onSelectBucket,
}: {
  attacks: Alert[];
  onSelectBucket: (bucket: TrendBucket) => void;
}) {
  const buckets = useMemo(() => buildTrendBuckets(attacks, 24), [attacks]);
  const max = Math.max(1, ...buckets.map((item) => item.count));
  return (
    <section className="activityTrend" aria-label="Attack activity over time">
      <header>
        <div>
          <h3>Attack activity</h3>
          <p>Filtered event volume over the current alert window</p>
        </div>
        <strong>
          {attacks.reduce((sum, item) => sum + (Number(item.count) || 1), 0)} attempts
        </strong>
      </header>
      <div className="trendBars">
        {buckets.map((item) => {
          const tooltip = `${item.dateLabel ? `${item.dateLabel} · ` : ""}${item.label} · ${item.count} attempts`;
          return (
            <button
              type="button"
              className="trendBucket"
              key={item.key}
              data-tooltip={tooltip}
              aria-label={`${tooltip} · open details`}
              disabled={!item.attacks.length}
              onClick={() => onSelectBucket(item)}
            >
              <i style={{ height: `${Math.max(5, (item.count / max) * 100)}%` }} />
            </button>
          );
        })}
      </div>
    </section>
  );
}

export function EventTable({
  attacks,
  activeBans,
  selectedEvent,
  onSelectEvent,
}: {
  attacks: Alert[];
  activeBans: ActiveBan[];
  selectedEvent?: Alert;
  onSelectEvent: (e: Alert) => void;
}) {
  const banned = useMemo(
    () => new Set(activeBans.map((item) => item.ip || item.value).filter(Boolean)),
    [activeBans],
  );
  const rows = attacks.slice(0, 12);
  return (
    <section className="eventTablePanel">
      <header>
        <div>
          <h3>Recent security events</h3>
          <p>Click an event to investigate its source IP.</p>
        </div>
        <span>{attacks.length} matching</span>
      </header>
      <div className="eventTableScroll">
        <table className="eventTable">
          <thead>
            <tr>
              <th>Time</th>
              <th>Source IP</th>
              <th>Country</th>
              <th>Scenario</th>
              <th>ASN / provider</th>
              <th>Attempts</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((item, index) => {
              const isBanned = banned.has(item.ip) || item.decisionType === "ban";
              const selected = selectedEvent === item;
              return (
                <tr
                  className={selected ? "selected" : ""}
                  aria-selected={selected}
                  key={`${item.id || item.ip}-${index}`}
                  onClick={() => item.ip && onSelectEvent(item)}
                  tabIndex={0}
                  onKeyDown={(event) => event.key === "Enter" && item.ip && onSelectEvent(item)}
                >
                  <td>{formatTime(item.createdAt)}</td>
                  <td>
                    <strong>{item.ip || "unknown"}</strong>
                  </td>
                  <td>{item.country || "Unknown"}</td>
                  <td title={item.scenario}>{readableScenario(item.scenario)}</td>
                  <td>{item.asn || item.asName || "-"}</td>
                  <td>{item.count || 1}</td>
                  <td>
                    <span className={`eventStatus ${isBanned ? "blocked" : "observed"}`}>
                      {isBanned ? "Blocked" : "Observed"}
                    </span>
                  </td>
                </tr>
              );
            })}
            {!rows.length && (
              <tr>
                <td colSpan={7} className="eventTableEmpty">
                  No events match the current filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export function EventDetailDrawer({
  event,
  activeBans,
  onClose,
  onInvestigate,
}: {
  event: Alert;
  activeBans: ActiveBan[];
  onClose: () => void;
  onInvestigate: (detail: any) => void;
}) {
  const ban = activeBans.find((item) => (item.ip || item.value) === event.ip);
  const blocked = Boolean(ban || event.decisionType === "ban");
  useEffect(() => {
    const closeOnEscape = (keyboardEvent: KeyboardEvent) =>
      keyboardEvent.key === "Escape" && onClose();
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [onClose]);
  return (
    <aside className="eventDrawer" aria-label={`Event details for ${event.ip}`}>
      <header>
        <div>
          <span>Selected event</span>
          <h3>{event.ip}</h3>
          <p>
            {event.country || "Unknown location"}
            {event.city ? ` · ${event.city}` : ""}
          </p>
        </div>
        <button type="button" onClick={onClose} aria-label="Close event details">
          <X size={18} />
        </button>
      </header>
      <div className="eventDrawerStatus">
        <span className={`eventStatus ${blocked ? "blocked" : "observed"}`}>
          {blocked ? "Blocked" : "Observed"}
        </span>
        <time>{formatRelativeTime(event.createdAt)}</time>
      </div>
      <dl>
        <div>
          <dt>Scenario</dt>
          <dd>{readableScenario(event.scenario)}</dd>
        </div>
        <div>
          <dt>Attempts</dt>
          <dd>{event.count || 1}</dd>
        </div>
        <div>
          <dt>Country</dt>
          <dd>{event.country || "Unknown"}</dd>
        </div>
        <div>
          <dt>ASN / provider</dt>
          <dd>{event.asn || event.asName || "Not available"}</dd>
        </div>
        <div>
          <dt>Decision</dt>
          <dd>{ban?.type || event.decisionType || "observe"}</dd>
        </div>
        <div>
          <dt>Detected</dt>
          <dd>{new Date(event.createdAt).toLocaleString()}</dd>
        </div>
      </dl>
      <button type="button" className="investigateEvent" onClick={() => onInvestigate(event.ip)}>
        Investigate IP <ArrowUpRight size={16} />
      </button>
    </aside>
  );
}

export function EventCollectionDrawer({
  detail,
  activeBans,
  onClose,
  onInvestigate,
}: {
  detail: any;
  activeBans: ActiveBan[];
  onClose: () => void;
  onInvestigate: (d: any) => void;
}) {
  const banned = useMemo(
    () => new Set(activeBans.map((item) => item.ip || item.value).filter(Boolean)),
    [activeBans],
  );
  const sources = useMemo(() => groupEventSources(detail.attacks), [detail.attacks]);
  useEffect(() => {
    const closeOnEscape = (event: KeyboardEvent) => event.key === "Escape" && onClose();
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [onClose]);
  return (
    <aside className="eventDrawer collectionDrawer" aria-label={detail.title}>
      <header>
        <div>
          <span>Event drill-down</span>
          <h3>{detail.title}</h3>
          <p>{detail.subtitle}</p>
        </div>
        <button type="button" onClick={onClose} aria-label="Close event details">
          <X size={18} />
        </button>
      </header>
      <div className="collectionSummary">
        <span>
          <strong>{sources.length}</strong> source IPs
        </span>
        <span>
          <strong>
            {
              new Set(detail.attacks.map((item: Alert) => item.asn || item.asName).filter(Boolean))
                .size
            }
          </strong>{" "}
          ASNs
        </span>
        <span>
          <strong>
            {new Set(detail.attacks.map((item: Alert) => item.scenario).filter(Boolean)).size}
          </strong>{" "}
          scenarios
        </span>
      </div>
      <div className="collectionSources">
        {sources.map((source) => (
          <article key={source.ip}>
            <div>
              <strong>{source.ip}</strong>
              <span>
                {source.country || "Unknown"} · {source.asn || "ASN unavailable"}
              </span>
              <small>{source.scenarios.join(" · ")}</small>
            </div>
            <div>
              <span className={`eventStatus ${banned.has(source.ip) ? "blocked" : "observed"}`}>
                {banned.has(source.ip) ? "Blocked" : `${source.attempts} attempts`}
              </span>
              <button type="button" onClick={() => onInvestigate(source.ip)}>
                Investigate IP <ArrowUpRight size={14} />
              </button>
            </div>
          </article>
        ))}
      </div>
    </aside>
  );
}
