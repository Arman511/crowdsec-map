import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { Activity, AlertTriangle, ArrowUpRight, BarChart3, ChevronDown, ChevronUp, Copy, Crosshair, Filter, Globe2, Map as MapIcon, Maximize2, Moon, RefreshCcw, Search, ShieldAlert, ShieldCheck, Sun, Timer, UserRoundSearch, X } from "lucide-react";
import { geoEqualEarth, geoPath } from "d3-geo";
import { feature } from "topojson-client";
import world from "world-atlas/countries-110m.json";
import packageInfo from "../package.json";
import "./styles.css";
import {
  EMPTY_RANK_ITEMS,
  HISTORY_DAYS_OPTIONS,
  HISTORY_GROUP_OPTIONS,
  HOME,
  MAX_MAP_POINTS,
  MAX_SIGNAL_PATHS,
  MAX_TIMELINE_COLUMNS,
  MAX_TIMELINE_ROWS,
  METRIC_PAGE_SIZE,
  RANK_MODES,
  RANK_MODE_STORAGE_PREFIX,
  REFRESH_STORAGE_KEY,
  SOURCE_OPTIONS,
  REFRESH_OPTIONS,
  THEME_STORAGE_KEY,
  TIMELINE_GAP,
  TIMELINE_MIN_CARD_WIDTH,
  TIMELINE_ROWS_STORAGE_KEY
} from "./constants";
import {
  buildActiveBanTitle,
  buildAnomaly,
  buildFilterOptions,
  buildRankings,
  buildTrendBuckets,
  buildZoraxyTimestampWarning,
  clampLineLimit,
  compactMapAttacks,
  compactTimelineAttacks,
  createArcPath,
  filterAttacks,
  formatBanRemaining,
  formatBanSince,
  formatBanSinceExact,
  formatCtiScore,
  formatRefreshInterval,
  formatRelativeTime,
  formatTime,
  getAgeClass,
  getAttackMarkerRadii,
  getHistoryGroupLabel,
  getSignalDuration,
  groupCounts,
  groupEventSources,
  isIpv4,
  readStoredRankMode,
  readStoredRefreshSeconds,
  readStoredTheme,
  readStoredTimelineRows,
  readableScenario
} from "./utils";
import { AgeLegend } from "./components/AgeLegend";
import { DecisionBlockedIpSummary } from "./components/DecisionBlockedIpSummary";
import { DecisionRanks } from "./components/DecisionRanks";
import { HiddenMenuList } from "./components/HiddenMenuList";
import { Metric } from "./components/Metric";

const countries = feature(world, world.objects.countries).features;
const APP_VERSION = `v${packageInfo.version}`;

function App() {
  const [source, setSource] = useState("auto");
  const [refreshSeconds, setRefreshSeconds] = useState(readStoredRefreshSeconds);
  const [theme, setTheme] = useState(readStoredTheme);
  const [view, setView] = useState("live");
  const [hiddenMenuOpen, setHiddenMenuOpen] = useState(false);
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [metricMode, setMetricMode] = useState("");
  const [selectedIp, setSelectedIp] = useState("");
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [eventDrilldown, setEventDrilldown] = useState(null);
  const [mapExpanded, setMapExpanded] = useState(false);
  const [viewRefreshSignals, setViewRefreshSignals] = useState({ protection: 0, decisions: 0 });
  const [selectedMapGroup, setSelectedMapGroup] = useState(null);
  const [filters, setFilters] = useState({ query: "", country: "all", scenario: "all", age: "all" });
  const requestControllerRef = useRef(null);

  const loadData = useCallback(async () => {
    requestControllerRef.current?.abort();
    const controller = new AbortController();
    requestControllerRef.current = controller;
    setLoading(true);
    setError("");
    try {
      const response = await fetch(`/api/attacks?source=${encodeURIComponent(source)}`, { signal: controller.signal });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      setData(await response.json());
    } catch (loadError) {
      if (loadError.name === "AbortError") return;
      setError(loadError.message);
    } finally {
      if (requestControllerRef.current === controller) setLoading(false);
    }
  }, [source]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  useEffect(() => {
    window.localStorage.setItem(REFRESH_STORAGE_KEY, String(refreshSeconds));
  }, [refreshSeconds]);

  useEffect(() => {
    window.localStorage.setItem(THEME_STORAGE_KEY, theme);
  }, [theme]);

  useEffect(() => {
    const interval = window.setInterval(loadData, refreshSeconds * 1000);
    return () => window.clearInterval(interval);
  }, [refreshSeconds, loadData]);

  const attacks = data?.alerts || EMPTY_RANK_ITEMS;
  const totals = data?.totals || {};
  const filterOptions = useMemo(() => buildFilterOptions(attacks), [attacks]);
  const filteredAttacks = useMemo(() => filterAttacks(attacks, filters), [attacks, filters]);

  useEffect(() => {
    if (selectedEvent && !filteredAttacks.includes(selectedEvent)) setSelectedEvent(null);
  }, [filteredAttacks, selectedEvent]);

  const refreshCurrentView = useCallback(() => {
    if (view === "protection" || view === "decisions") {
      setViewRefreshSignals((current) => ({ ...current, [view]: current[view] + 1 }));
      return;
    }
    loadData();
  }, [loadData, view]);

  return (
    <main className={`appShell theme${theme === "light" ? "Light" : "Dark"}`}>
      <Sidebar data={data} totals={totals} attacks={filteredAttacks} onOpenMetric={setMetricMode} />
      <section className={`mapStage mapStage--${view}`}>
        <Toolbar
          view={view}
          setView={setView}
          theme={theme}
          setTheme={setTheme}
          source={source}
          setSource={setSource}
          refreshSeconds={refreshSeconds}
          setRefreshSeconds={setRefreshSeconds}
          data={data}
          loading={loading}
          onRefresh={refreshCurrentView}
          onOpenHiddenMenu={() => setHiddenMenuOpen(true)}
        />
        {view === "live" ? (
          <>
            <LiveFilterBar filters={filters} setFilters={setFilters} options={filterOptions} resultCount={filteredAttacks.length} totalCount={attacks.length} />
            <div className="liveMapStack">
              <WorldMap attacks={filteredAttacks} initialLoading={loading && !data} onExpand={() => { setSelectedMapGroup(null); setMapExpanded(true); }} />
              <ActivityTrend attacks={filteredAttacks} onSelectBucket={(bucket) => setEventDrilldown({ title: `Attack activity · ${bucket.label}`, subtitle: `${bucket.count} attempts in this time segment`, attacks: bucket.attacks })} />
              <AgeLegend />
            </div>
            <EventTable attacks={filteredAttacks} activeBans={data?.activeBans || []} selectedEvent={selectedEvent} onSelectEvent={setSelectedEvent} />
            {selectedEvent && <EventDetailDrawer event={selectedEvent} activeBans={data?.activeBans || []} onClose={() => setSelectedEvent(null)} onInvestigate={(ip) => { setSelectedEvent(null); setSelectedIp(ip); }} />}
            {eventDrilldown && <EventCollectionDrawer detail={eventDrilldown} activeBans={data?.activeBans || []} onClose={() => setEventDrilldown(null)} onInvestigate={(ip) => { setEventDrilldown(null); setSelectedIp(ip); }} />}
            {mapExpanded && <ExpandedMapModal attacks={filteredAttacks} error={error || data?.warning} selectedGroup={selectedMapGroup} onSelectGroup={setSelectedMapGroup} onClose={() => { setMapExpanded(false); setSelectedMapGroup(null); }} onInspect={(detail) => { setMapExpanded(false); setSelectedMapGroup(null); setEventDrilldown(detail); }} onInvestigate={(ip) => { setMapExpanded(false); setSelectedMapGroup(null); setSelectedIp(ip); }} />}
          </>
        ) : view === "history" ? (
          <HistoryView />
        ) : view === "protection" ? (
          <ProtectionView refreshSignal={viewRefreshSignals.protection} />
        ) : (
          <DecisionsView onSelectIp={setSelectedIp} refreshSeconds={refreshSeconds} refreshSignal={viewRefreshSignals.decisions} />
        )}
        {hiddenMenuOpen && <HiddenMenuModal onClose={() => setHiddenMenuOpen(false)} />}
      </section>
      {metricMode && (
        <MetricDrilldownModal
          data={data}
          initialMode={metricMode}
          onClose={() => setMetricMode("")}
          onSelectIp={(ip) => {
            setMetricMode("");
            setSelectedIp(ip);
          }}
        />
      )}
      {selectedIp && <IpDetailModal ip={selectedIp} days={7} onClose={() => setSelectedIp("")} />}
    </main>
  );
}

function Sidebar({ data, totals, attacks, onOpenMetric }) {
  const rankings = useMemo(() => buildRankings(data?.alerts || [], data?.activeBans || []), [data?.alerts, data?.activeBans]);
  const uniqueAttackers = useMemo(() => new Set((data?.alerts || []).map((item) => item.ip).filter(Boolean)).size, [data?.alerts]);
  const anomaly = useMemo(() => buildAnomaly(attacks), [attacks]);

  return (
    <aside className="sidebar">
      <div className="brand">
        <span className="brandMark"><ShieldAlert size={22} /></span>
        <div>
          <h1>CrowdSec Map</h1>
          <p>Live attacks <small>{APP_VERSION}</small></p>
        </div>
      </div>

      <div className="metricGrid">
        <Metric icon={<Activity />} label="Current Alerts" value={totals.alerts || 0} onClick={() => onOpenMetric("alerts")} />
        <Metric icon={<UserRoundSearch />} label="Unique Attackers" value={uniqueAttackers} onClick={() => onOpenMetric("alerts")} />
        <Metric icon={<Globe2 />} label="Countries" value={totals.countries || 0} onClick={() => onOpenMetric("countries")} />
        <Metric icon={<ShieldAlert />} label="Active Bans" value={totals.activeBans || 0} onClick={() => onOpenMetric("bans")} />
      </div>

      <Panel rankings={rankings} initialMode="countries" storageKey="top" />
      <Panel rankings={rankings} initialMode="ips" storageKey="bottom" wide />

      <div className="anomalyCard">
        <AlertTriangle size={17} />
        <div><strong>{anomaly ? "Activity concentration" : "No anomaly detected"}</strong><p>{anomaly || "Attack distribution is currently stable."}</p></div>
      </div>

    </aside>
  );
}

function LiveFilterBar({ filters, setFilters, options, resultCount, totalCount }) {
  const update = (field, value) => setFilters((current) => ({ ...current, [field]: value }));
  const activeCount = Object.values(filters).filter((value) => value && value !== "all").length;
  return (
    <section className="liveFilterBar" aria-label="Live attack filters">
      <label className="filterSearch"><Search size={16} /><input value={filters.query} onChange={(event) => update("query", event.target.value)} placeholder="Search IP, ASN, country or scenario" /></label>
      <label><span>Scenario</span><select value={filters.scenario} onChange={(event) => update("scenario", event.target.value)}><option value="all">All scenarios</option>{options.scenarios.map((value) => <option key={value}>{value}</option>)}</select></label>
      <label><span>Country</span><select value={filters.country} onChange={(event) => update("country", event.target.value)}><option value="all">All countries</option>{options.countries.map((value) => <option key={value}>{value}</option>)}</select></label>
      <label><span>Time range</span><select value={filters.age} onChange={(event) => update("age", event.target.value)}><option value="all">All current alerts</option><option value="15m">Last 15 minutes</option><option value="1h">Last hour</option><option value="24h">Last 24 hours</option></select></label>
      <div className="filterResult"><Filter size={15} /><strong>{resultCount}</strong><span>of {totalCount}</span></div>
      <button type="button" className="clearFilters" disabled={!activeCount} onClick={() => setFilters({ query: "", country: "all", scenario: "all", age: "all" })}>Clear {activeCount ? `(${activeCount})` : ""}</button>
    </section>
  );
}

function ActivityTrend({ attacks, onSelectBucket }) {
  const buckets = useMemo(() => buildTrendBuckets(attacks, 24), [attacks]);
  const max = Math.max(1, ...buckets.map((item) => item.count));
  return (
    <section className="activityTrend" aria-label="Attack activity over time">
      <header><div><h3>Attack activity</h3><p>Filtered event volume over the current alert window</p></div><strong>{attacks.reduce((sum, item) => sum + (Number(item.count) || 1), 0)} attempts</strong></header>
      <div className="trendBars">{buckets.map((item) => { const tooltip = `${item.dateLabel ? `${item.dateLabel} · ` : ""}${item.label} · ${item.count} attempts`; return <button type="button" className="trendBucket" key={item.key} data-tooltip={tooltip} aria-label={`${tooltip} · open details`} disabled={!item.attacks.length} onClick={() => onSelectBucket(item)}><i style={{ height: `${Math.max(5, (item.count / max) * 100)}%` }} /></button>; })}</div>
    </section>
  );
}

function EventTable({ attacks, activeBans, selectedEvent, onSelectEvent }) {
  const banned = useMemo(() => new Set(activeBans.map((item) => item.ip || item.value).filter(Boolean)), [activeBans]);
  const rows = attacks.slice(0, 12);
  return (
    <section className="eventTablePanel">
      <header><div><h3>Recent security events</h3><p>Click an event to investigate its source IP.</p></div><span>{attacks.length} matching</span></header>
      <div className="eventTableScroll"><table className="eventTable"><thead><tr><th>Time</th><th>Source IP</th><th>Country</th><th>Scenario</th><th>ASN / provider</th><th>Attempts</th><th>Status</th></tr></thead><tbody>
        {rows.map((item, index) => { const isBanned = banned.has(item.ip) || item.decisionType === "ban"; const selected = selectedEvent === item; return <tr className={selected ? "selected" : ""} aria-selected={selected} key={`${item.id || item.ip}-${index}`} onClick={() => item.ip && onSelectEvent(item)} tabIndex={0} onKeyDown={(event) => event.key === "Enter" && item.ip && onSelectEvent(item)}><td>{formatTime(item.createdAt)}</td><td><strong>{item.ip || "unknown"}</strong></td><td>{item.country || "Unknown"}</td><td title={item.scenario}>{readableScenario(item.scenario)}</td><td>{item.asn || item.asName || "—"}</td><td>{item.count || 1}</td><td><span className={`eventStatus ${isBanned ? "blocked" : "observed"}`}>{isBanned ? "Blocked" : "Observed"}</span></td></tr>; })}
        {!rows.length && <tr><td colSpan="7" className="eventTableEmpty">No events match the current filters.</td></tr>}
      </tbody></table></div>
    </section>
  );
}

function EventDetailDrawer({ event, activeBans, onClose, onInvestigate }) {
  const ban = activeBans.find((item) => (item.ip || item.value) === event.ip);
  const blocked = Boolean(ban || event.decisionType === "ban");
  useEffect(() => {
    const closeOnEscape = (keyboardEvent) => keyboardEvent.key === "Escape" && onClose();
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [onClose]);
  return (
    <aside className="eventDrawer" aria-label={`Event details for ${event.ip}`}>
      <header><div><span>Selected event</span><h3>{event.ip}</h3><p>{event.country || "Unknown location"}{event.city ? ` · ${event.city}` : ""}</p></div><button type="button" onClick={onClose} aria-label="Close event details"><X size={18} /></button></header>
      <div className="eventDrawerStatus"><span className={`eventStatus ${blocked ? "blocked" : "observed"}`}>{blocked ? "Blocked" : "Observed"}</span><time>{formatRelativeTime(event.createdAt)}</time></div>
      <dl><div><dt>Scenario</dt><dd>{readableScenario(event.scenario)}</dd></div><div><dt>Attempts</dt><dd>{event.count || 1}</dd></div><div><dt>Country</dt><dd>{event.country || "Unknown"}</dd></div><div><dt>ASN / provider</dt><dd>{event.asn || event.asName || "Not available"}</dd></div><div><dt>Decision</dt><dd>{ban?.type || event.decisionType || "observe"}</dd></div><div><dt>Detected</dt><dd>{new Date(event.createdAt).toLocaleString()}</dd></div></dl>
      <button type="button" className="investigateEvent" onClick={() => onInvestigate(event.ip)}>Investigate IP <ArrowUpRight size={16} /></button>
    </aside>
  );
}

function EventCollectionDrawer({ detail, activeBans, onClose, onInvestigate }) {
  const banned = useMemo(() => new Set(activeBans.map((item) => item.ip || item.value).filter(Boolean)), [activeBans]);
  const sources = useMemo(() => groupEventSources(detail.attacks), [detail.attacks]);
  useEffect(() => {
    const closeOnEscape = (event) => event.key === "Escape" && onClose();
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [onClose]);
  return (
    <aside className="eventDrawer collectionDrawer" aria-label={detail.title}>
      <header><div><span>Event drill-down</span><h3>{detail.title}</h3><p>{detail.subtitle}</p></div><button type="button" onClick={onClose} aria-label="Close event details"><X size={18} /></button></header>
      <div className="collectionSummary"><span><strong>{sources.length}</strong> source IPs</span><span><strong>{new Set(detail.attacks.map((item) => item.asn || item.asName).filter(Boolean)).size}</strong> ASNs</span><span><strong>{new Set(detail.attacks.map((item) => item.scenario).filter(Boolean)).size}</strong> scenarios</span></div>
      <div className="collectionSources">
        {sources.map((source) => <article key={source.ip}><div><strong>{source.ip}</strong><span>{source.country || "Unknown"} · {source.asn || "ASN unavailable"}</span><small>{source.scenarios.join(" · ")}</small></div><div><span className={`eventStatus ${banned.has(source.ip) ? "blocked" : "observed"}`}>{banned.has(source.ip) ? "Blocked" : `${source.attempts} attempts`}</span><button type="button" onClick={() => onInvestigate(source.ip)}>Investigate IP <ArrowUpRight size={14} /></button></div></article>)}
      </div>
    </aside>
  );
}

function MetricDrilldownModal({ data, initialMode, onClose, onSelectIp }) {
  const [mode, setMode] = useState(initialMode);
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(0);
  const [alertFilter, setAlertFilter] = useState(null);
  const alerts = data?.alerts || EMPTY_RANK_ITEMS;
  const bans = data?.activeBans || EMPTY_RANK_ITEMS;
  const grouped = useMemo(() => ({ countries: groupCounts(alerts, "country"), scenarios: groupCounts(alerts, "scenario") }), [alerts]);
  const rows = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (mode === "bans") {
      return bans.filter((item) => [item.ip, item.country, item.scenario, item.duration].some((value) => String(value || "").toLowerCase().includes(needle)));
    }
    if (mode === "countries" || mode === "scenarios") {
      return grouped[mode].filter((item) => item.label.toLowerCase().includes(needle));
    }
    return alerts.filter((item) => {
      if (alertFilter && String(item[alertFilter.field] || "unknown") !== alertFilter.value) return false;
      return [item.ip, item.country, item.scenario, item.createdAt].some((value) => String(value || "").toLowerCase().includes(needle));
    });
  }, [alertFilter, alerts, bans, grouped, mode, query]);
  const pageCount = Math.max(1, Math.ceil(rows.length / METRIC_PAGE_SIZE));
  const visibleRows = rows.slice(page * METRIC_PAGE_SIZE, (page + 1) * METRIC_PAGE_SIZE);

  useEffect(() => {
    setPage(0);
  }, [mode, query, alertFilter]);

  useEffect(() => {
    const closeOnEscape = (event) => event.key === "Escape" && onClose();
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [onClose]);

  const openGroup = (field, value) => {
    setAlertFilter({ field, value });
    setMode("alerts");
    setQuery("");
  };

  return (
    <div className="modalBackdrop" role="presentation" onClick={onClose}>
      <section className="ipModal metricModal" role="dialog" aria-modal="true" aria-labelledby="metric-detail-title" onClick={(event) => event.stopPropagation()}>
        <header className="modalHeader">
          <div><h3 id="metric-detail-title">Live security details</h3><p>{rows.length} matching entries · {data?.source || "unknown"}</p></div>
          <button type="button" onClick={onClose} title="Close" aria-label="Close"><X size={18} /></button>
        </header>
        <div className="metricModalToolbar">
          <div className="segmented wide" role="group" aria-label="Metric detail mode">
            {[['bans', 'Active Bans'], ['alerts', 'Current Alerts'], ['countries', 'Countries'], ['scenarios', 'Scenarios']].map(([value, label]) => (
              <button type="button" className={mode === value ? "active" : ""} key={value} onClick={() => { setMode(value); setAlertFilter(null); }}>{label}</button>
            ))}
          </div>
          <label className="metricSearch"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search IP, country or scenario" /></label>
        </div>
        {alertFilter && <button type="button" className="filterChip" onClick={() => setAlertFilter(null)}>{alertFilter.value} <X size={13} /></button>}
        <div className="metricResultList">
          {visibleRows.map((item, index) => {
            if (mode === "countries" || mode === "scenarios") {
              return <button type="button" className="metricResultRow groupResult" key={item.label} onClick={() => openGroup(mode === "countries" ? "country" : "scenario", item.label)}><strong>{item.label || "unknown"}</strong><span>{item.count} log events</span></button>;
            }
            const ip = item.ip || item.value || "";
            return <button type="button" className="metricResultRow" key={`${item.id || ip}-${index}`} onClick={() => ip && onSelectIp(ip)} disabled={!ip}><time>{formatRelativeTime(item.createdAt)}</time><strong>{ip || "No IP"}</strong><span>{item.country || "??"}</span><span title={item.scenario}>{item.scenario || "unknown"}</span>{mode === "bans" ? <em>{item.duration || "active"}</em> : <em>{item.count || 1} events</em>}</button>;
          })}
          {visibleRows.length === 0 && <p className="metricEmpty">No matching entries.</p>}
        </div>
        <footer className="metricPager"><button type="button" disabled={page === 0} onClick={() => setPage((value) => value - 1)}>Previous</button><span>Page {page + 1} / {pageCount}</span><button type="button" disabled={page + 1 >= pageCount} onClick={() => setPage((value) => value + 1)}>Next</button></footer>
      </section>
    </div>
  );
}

function Panel({ rankings, initialMode, storageKey, wide = false }) {
  const [mode, setMode] = useState(() => readStoredRankMode(storageKey, initialMode));
  const [visibleCount, setVisibleCount] = useState(Number.POSITIVE_INFINITY);
  const panelRef = useRef(null);
  const headerRef = useRef(null);
  const measureRef = useRef(null);
  const items = rankings[mode] || EMPTY_RANK_ITEMS;
  const isBanMode = mode === "bans";
  const max = Math.max(...items.map((item) => item.count), 1);
  const hasMeasuredLimit = Number.isFinite(visibleCount);
  const collapsedLimit = hasMeasuredLimit ? Math.max(1, visibleCount) : items.length;
  const visibleItems = items;
  const hasMore = items.length > collapsedLimit;

  useEffect(() => {
    window.localStorage.setItem(`${RANK_MODE_STORAGE_PREFIX}:${storageKey}`, mode);
  }, [mode, storageKey]);

  useLayoutEffect(() => {
    const panel = panelRef.current;
    const header = headerRef.current;
    const measure = measureRef.current;
    if (!panel || !header || !measure) {
      return undefined;
    }

    const updateVisibleCount = () => {
      const rows = [...measure.querySelectorAll(".rankRow")];
      if (rows.length === 0) {
        setVisibleCount(Number.POSITIVE_INFINITY);
        return;
      }

      const panelStyles = window.getComputedStyle(panel);
      const listStyles = window.getComputedStyle(measure);
      const panelPadding = parseFloat(panelStyles.paddingTop) + parseFloat(panelStyles.paddingBottom);
      const listGap = parseFloat(listStyles.rowGap || listStyles.gap || 0);
      const headerBottom = header.offsetHeight + parseFloat(window.getComputedStyle(header).marginBottom || 0);
      const rowHeight = Math.max(...rows.map((row) => row.offsetHeight));
      const available = panel.clientHeight - panelPadding - headerBottom - 30;
      const possible = Math.floor((available + listGap) / (rowHeight + listGap));

      if (rows.length * rowHeight + Math.max(0, rows.length - 1) * listGap <= available) {
        setVisibleCount(Number.POSITIVE_INFINITY);
        return;
      }

      setVisibleCount(Math.max(1, possible));
    };

    updateVisibleCount();
    const observer = new ResizeObserver(updateVisibleCount);
    observer.observe(panel);
    observer.observe(measure);
    return () => observer.disconnect();
  }, [items]);

  return (
    <section className={wide ? "panel panelWide" : "panel"} ref={panelRef}>
      <div className="panelHeader" ref={headerRef}>
        <div className="rankSwitch" role="group" aria-label="Ranking mode">
          {RANK_MODES.map(([value, label]) => (
            <button
              type="button"
              className={mode === value ? "active" : ""}
              key={value}
              onClick={() => setMode(value)}
            >
              {label}
            </button>
          ))}
        </div>
      </div>
      <div className="rankList">
        {items.length === 0 && <p className="empty">No data yet</p>}
        {visibleItems.map((item) => (
          <div className={isBanMode ? "rankRow banRow" : "rankRow"} key={item.label}>
            <span title={item.label}>{item.label}</span>
            {isBanMode ? (
              <em title={item.detail || item.meta || ""}>{item.meta || item.detail || "active"}</em>
            ) : (
              <>
                <div className="bar"><i style={{ width: `${Math.max(8, (item.count / max) * 100)}%` }} /></div>
                <strong>{item.count}</strong>
              </>
            )}
          </div>
        ))}
      </div>
      {hasMore && <div className="rankOverflowHint" aria-hidden="true" />}
      <div className="rankList rankMeasure" ref={measureRef} aria-hidden="true">
        {items.map((item) => (
          <div className={isBanMode ? "rankRow banRow" : "rankRow"} key={`${item.label}-measure`}>
            <span>{item.label}</span>
            {isBanMode ? (
              <em>{item.meta || item.detail || "active"}</em>
            ) : (
              <>
                <div className="bar"><i style={{ width: `${Math.max(8, (item.count / max) * 100)}%` }} /></div>
                <strong>{item.count}</strong>
              </>
            )}
          </div>
        ))}
      </div>
    </section>
  );
}

function Toolbar({ view, setView, theme, setTheme, source, setSource, refreshSeconds, setRefreshSeconds, data, loading, onRefresh, onOpenHiddenMenu }) {
  const [sourceOpen, setSourceOpen] = useState(false);
  const [intervalOpen, setIntervalOpen] = useState(false);
  const hiddenMenuPressTimer = useRef(null);
  const displayedSource = data?.source || source || "...";
  const openHiddenMenu = (event) => {
    if (!event.shiftKey || !event.ctrlKey) {
      return;
    }
    event.preventDefault();
    event.stopPropagation();
    onOpenHiddenMenu();
  };
  const startHiddenMenuLongPress = (event) => {
    if (event.pointerType !== "touch") {
      return;
    }
    event.preventDefault();
    window.clearTimeout(hiddenMenuPressTimer.current);
    hiddenMenuPressTimer.current = window.setTimeout(() => {
      onOpenHiddenMenu();
    }, 3000);
  };
  const cancelHiddenMenuLongPress = () => {
    window.clearTimeout(hiddenMenuPressTimer.current);
    hiddenMenuPressTimer.current = null;
  };

  useEffect(() => cancelHiddenMenuLongPress, []);

  const title = view === "live" ? (data?.demoMode ? "Demo snapshot" : "Live attacks") : view === "history" ? "History" : view === "protection" ? "Protection" : "Block decisions";
  const subtitle = view === "live" ? `${data?.demoMode ? "Sanitized snapshot updated" : "Last update"} ${formatTime(data?.generatedAt)}` : view === "history" ? `Repeated sources ${formatTime(data?.generatedAt)}` : view === "protection" ? "Proxy access logs · no Grafana or Prometheus required" : "Enforcement data · not detected attacks";
  return (
    <header className={`toolbar ${view === "live" ? "toolbarLive" : "toolbarHistory"}`}>
      <div>
        <div className="titleLine">
          <h2>{title}</h2>
          {data?.publicTargetIp && <span title={`Public target IP: ${data.publicTargetIpSource || "unknown"}`}>{data.publicTargetIp}</span>}
        </div>
        <p>{subtitle}</p>
      </div>
      <div className="toolbarControls">
        <div className="viewSwitch" role="group" aria-label="Dashboard view">
          <button
            type="button"
            className={view === "live" ? "active" : ""}
            onClick={() => setView("live")}
            title="Live map"
          >
            <MapIcon size={15} /> Live
          </button>
          <button
            type="button"
            className={view === "history" ? "active" : ""}
            onClick={() => setView("history")}
            title="History analysis"
          >
            <BarChart3 size={15} /> History
          </button>
          <button
            type="button"
            className={view === "protection" ? "active" : ""}
            onClick={() => setView("protection")}
            title="Protection statistics from access logs"
          >
            <ShieldCheck size={15} /> Protection
          </button>
          <button
            type="button"
            className={view === "decisions" ? "active" : ""}
            onClick={() => setView("decisions")}
            title="Block decisions"
          >
            <ShieldAlert size={15} /> Decisions
          </button>
        </div>
        {view !== "decisions" && view !== "protection" && <div className="toolbarStatus">
          {!data?.demoMode && <>
            <div className="toolbarMenuWrap">
              <span>Source</span>
              <button
                type="button"
                className="toolbarMenuTrigger sourceTrigger"
                onClick={() => {
                  setSourceOpen((value) => !value);
                  setIntervalOpen(false);
                }}
                aria-expanded={sourceOpen}
                aria-haspopup="menu"
                title="Data source"
              >
                <strong>{displayedSource}</strong>
              </button>
              {sourceOpen && (
                <div className="toolbarMenu sourceMenu" role="menu">
                  {SOURCE_OPTIONS.map(([value, label]) => (
                    <button
                      type="button"
                      className={source === value ? "active" : ""}
                      key={value}
                      onClick={() => {
                        setSource(value);
                        setSourceOpen(false);
                      }}
                      role="menuitem"
                    >
                      {label}
                    </button>
                  ))}
                </div>
              )}
            </div>
          </>}
          <div className="toolbarMenuWrap">
            <span>Intervall</span>
            <button
              type="button"
              className="toolbarMenuTrigger intervalTrigger"
              onClick={() => {
                setIntervalOpen((value) => !value);
                setSourceOpen(false);
              }}
              aria-expanded={intervalOpen}
              aria-haspopup="menu"
              title="Refresh interval"
            >
              <Timer size={13} /> <strong>{formatRefreshInterval(refreshSeconds)}</strong>
            </button>
            {intervalOpen && (
              <div className="toolbarMenu intervalMenu" role="menu">
                {REFRESH_OPTIONS.map(([value, label]) => (
                  <button
                    type="button"
                    className={refreshSeconds === value ? "active" : ""}
                    key={value}
                    onClick={() => {
                      setRefreshSeconds(value);
                      setIntervalOpen(false);
                    }}
                    role="menuitem"
                  >
                    {label}
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>}
        <button type="button" onClick={onRefresh} disabled={loading && view !== "decisions" && view !== "protection"} title="Refresh" aria-label="Refresh">
          <RefreshCcw size={17} className={loading ? "spin" : ""} />
        </button>
        <button
          type="button"
          className="themeToggle"
          onClick={() => setTheme((value) => value === "dark" ? "light" : "dark")}
          title={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
          aria-label={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
        >
          {theme === "dark" ? <Sun size={17} /> : <Moon size={17} />}
        </button>
      </div>
      {view === "history" && (
        <button
          type="button"
          className="hiddenMenuTrigger"
          onMouseDown={openHiddenMenu}
          onPointerDown={startHiddenMenuLongPress}
          onPointerUp={cancelHiddenMenuLongPress}
          onPointerCancel={cancelHiddenMenuLongPress}
          onPointerLeave={cancelHiddenMenuLongPress}
          onContextMenu={openHiddenMenu}
          title="π - Ctrl+Shift click or touch and hold for 3 seconds"
          aria-label="Hidden menu"
        >
          π
        </button>
      )}
    </header>
  );
}

function HiddenMenuModal({ onClose }) {
  const [summary, setSummary] = useState(null);
  const [lapiStatus, setLapiStatus] = useState(null);
  const [investigationSources, setInvestigationSources] = useState(null);
  const [updateStatus, setUpdateStatus] = useState(null);
  const [pathCopied, setPathCopied] = useState(false);
  const [error, setError] = useState("");

  const loadSummary = useCallback(async () => {
    setError("");
    try {
      const [summaryResponse, lapiResponse, investigationResponse, updateResponse] = await Promise.all([
        fetch("/api/access-log/summary?days=7"),
        fetch("/api/lapi/credentials/status"),
        fetch("/api/investigation/sources"),
        fetch("/api/system/update-status")
      ]);
      if (!summaryResponse.ok || !lapiResponse.ok || !investigationResponse.ok || !updateResponse.ok) {
        throw new Error(`HTTP ${!summaryResponse.ok ? summaryResponse.status : !lapiResponse.ok ? lapiResponse.status : !investigationResponse.ok ? investigationResponse.status : updateResponse.status}`);
      }
      const [summaryPayload, lapiPayload, investigationPayload, updatePayload] = await Promise.all([summaryResponse.json(), lapiResponse.json(), investigationResponse.json(), updateResponse.json()]);
      setSummary(summaryPayload);
      setLapiStatus(lapiPayload);
      setInvestigationSources(investigationPayload);
      setUpdateStatus(updatePayload);
    } catch (loadError) {
      setError(loadError.message);
    }
  }, []);

  useEffect(() => {
    loadSummary();
  }, [loadSummary]);

  useEffect(() => {
    const onKeyDown = (event) => {
      if (event.key === "Escape") {
        onClose();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [onClose]);

  const copyCredentialsPath = async () => {
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
      <section className="hiddenMenuModal" role="dialog" aria-modal="true" aria-labelledby="hidden-menu-title" onClick={(event) => event.stopPropagation()}>
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
              <Metric icon={<Activity />} label="24h visits" value={summary.visits24h || 0} />
              <Metric icon={<Crosshair />} label="Unique IPs" value={summary.uniqueIps || 0} />
              <Metric icon={<Timer />} label="Retention" value={`${summary.retentionDays}d`} />
            </div>
            {!summary.enabled && <div className="warning">Access log is disabled.</div>}
            <HiddenMenuList title="Top IPs" items={summary.topIps || []} />
            <HiddenMenuList title="Top countries" items={summary.topCountries || []} />
            <div className="hiddenRecent">
              <h4>Recent visits</h4>
              {(summary.recent || []).slice(0, 12).map((visit) => (
                <div className="hiddenRecentRow" key={`${visit.ts}-${visit.ip}-${visit.path}`}>
                  <time>{formatRelativeTime(visit.ts)}</time>
                  <strong title={visit.ip}>{visit.ip}</strong>
                  <span>{visit.country || "??"}</span>
                  <em title={visit.userAgent}>{visit.path}</em>
                </div>
              ))}
              {(summary.recent || []).length === 0 && <p>No visits logged yet.</p>}
            </div>
            {lapiStatus && <div className="hiddenRecent lapiCredentials">
              <h4>LAPI credentials</h4>
              <p>{lapiStatus.watcherConfigured ? "Watcher credentials configured" : "Watcher credentials not configured"} · {lapiStatus.decisionsConfigured ? "Decisions key configured" : "No Decisions key"}</p>
              <div className="lapiCredentialsPath">
                <code title={lapiStatus.file}>{lapiStatus.file}</code>
                <button type="button" onClick={copyCredentialsPath} title="Copy container path"><Copy size={14} /> {pathCopied ? "Copied" : "Copy path"}</button>
              </div>
              {lapiStatus.autoSetupEnabled && <p>Automatic setup runs on container start.</p>}
            </div>}
            {investigationSources && <div className="hiddenRecent investigationSources">
              <h4>Investigation log paths</h4>
              <p>{investigationSources.sources.length} readable source{investigationSources.sources.length === 1 ? "" : "s"} · Auto detect {investigationSources.autoDetectEnabled ? "enabled" : "disabled"}</p>
              {investigationSources.sources.map((source) => (
                <div className="investigationSourcePath" key={`${source.location}-${source.path}`}>
                  <span>{source.location}</span>
                  <code title={source.path}>{source.path}</code>
                </div>
              ))}
              {investigationSources.sources.length === 0 && <p>No readable log sources. Configured: {investigationSources.configuredPaths.join(", ") || "none"}</p>}
            </div>}
            {updateStatus && <div className="hiddenRecent updateStatus">
              <h4>Container image · GitHub dev</h4>
              <p className={`updateState ${updateStatus.state}`}>{updateStatus.state === "current" ? "Current" : updateStatus.state === "update_available" ? "Update available" : "Check unavailable"}</p>
              <p>{updateStatus.message}</p>
              {updateStatus.image && <code title={updateStatus.image}>{updateStatus.image}</code>}
              {updateStatus.runningRevision && <p>Running: <code>{updateStatus.runningRevision.slice(0, 12)}</code> · Dev: {updateStatus.devUrl ? <a href={updateStatus.devUrl} target="_blank" rel="noreferrer"><code>{updateStatus.devRevision.slice(0, 12)}</code></a> : <code>{updateStatus.devRevision.slice(0, 12)}</code>}</p>}
            </div>}
          </div>
        )}
      </section>
    </div>
  );
}

function ProtectionView({ refreshSignal }) {
  const [days, setDays] = useState(1);
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const loadProtection = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const response = await fetch(`/api/protection?days=${days}`);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      setSummary(await response.json());
    } catch (loadError) {
      setError(loadError.message);
    } finally {
      setLoading(false);
    }
  }, [days]);

  useEffect(() => { loadProtection(); }, [loadProtection]);

  useEffect(() => {
    if (refreshSignal > 0) loadProtection();
  }, [loadProtection, refreshSignal]);

  const maxRequests = Math.max(1, ...(summary?.timeline || []).map((item) => item.processedRequests));
  return (
    <section className="protectionView">
      <div className="protectionControls">
        <div className="segmented" role="group" aria-label="Protection time range">
          {[1, 3, 7].map((value) => <button type="button" className={days === value ? "active" : ""} key={value} onClick={() => setDays(value)}>{value === 1 ? "24h" : `${value}d`}</button>)}
        </div>
      </div>

      <div className="protectionSummary">
        <Metric icon={<Activity />} label="Processed Requests" value={summary?.totals?.processedRequests || 0} />
        <Metric icon={<ShieldAlert />} label="HTTP Blocked" value={summary?.totals?.httpBlockedRequests || 0} />
        <Metric icon={<ShieldCheck />} label="Block Rate" value={`${summary?.totals?.blockRate || 0}%`} />
        <Metric icon={<Globe2 />} label="Active Hostnames" value={summary?.totals?.activeHostnames || 0} />
      </div>

      {error && <div className="warning">protection: {error}</div>}
      {!error && loading && !summary && <div className="modalLoading">Reading proxy access logs...</div>}
      {summary?.warning && <div className="warning">{summary.warning}</div>}
      {summary?.timedOut && <div className="warning">Log scan stopped at the configured investigation timeout; increase INVESTIGATION_TIMEOUT_MS for a complete result.</div>}

      <div className="protectionGrid">
        <section className="protectionTrend">
          <header><div><h3>Request activity</h3><p>{summary?.parsedRequests || 0} parsed access-log entries · {summary?.availableFiles || 0} readable source{summary?.availableFiles === 1 ? "" : "s"}</p></div><span>403 / 429 / 444 are counted as HTTP-blocked</span></header>
          <div className="protectionBars" aria-label="Processed request volume by hour">
            {(summary?.timeline || []).map((item) => <div className="protectionBucket" key={item.timestamp} title={`${formatTime(item.timestamp)} · ${item.processedRequests} requests · ${item.httpBlockedRequests} blocked`}><i style={{ height: `${Math.max(4, (item.processedRequests / maxRequests) * 100)}%` }} />{item.httpBlockedRequests > 0 && <b style={{ height: `${Math.max(4, (item.httpBlockedRequests / maxRequests) * 100)}%` }} />}</div>)}
            {!summary?.timeline?.length && <p className="protectionEmpty">No timestamped access-log entries in this period.</p>}
          </div>
          <footer><span>Teal: processed requests</span><span>Amber: HTTP 403 / 429 / 444</span></footer>
        </section>

        <section className="protectionHosts">
          <header><div><h3>Top protected hostnames</h3><p>Sorted by HTTP-blocked requests</p></div></header>
          <div className="protectionTableWrap"><table><thead><tr><th>Hostname</th><th>Requests</th><th>Blocked</th><th>Rate</th></tr></thead><tbody>
            {(summary?.hosts || []).map((item) => <tr key={item.hostname}><td><strong>{item.hostname}</strong></td><td>{item.processedRequests}</td><td>{item.httpBlockedRequests}</td><td><span className={item.httpBlockedRequests ? "blockRate hot" : "blockRate"}>{item.blockRate}%</span></td></tr>)}
            {summary && !summary.hosts?.length && <tr><td colSpan="4" className="protectionEmpty">No supported access-log entries found.</td></tr>}
          </tbody></table></div>
        </section>
      </div>
    </section>
  );
}

function DecisionsView({ onSelectIp, refreshSeconds, refreshSignal }) {
  const [decisions, setDecisions] = useState(null);
  const [query, setQuery] = useState("");
  const [appliedQuery, setAppliedQuery] = useState("");
  const [offset, setOffset] = useState(0);
  const [sort, setSort] = useState("");
  const [direction, setDirection] = useState("asc");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const loadDecisions = useCallback(async (refresh = false) => {
    setLoading(true);
    setError("");
    try {
      const params = new URLSearchParams({ limit: "50", offset: String(offset) });
      if (appliedQuery) params.set("search", appliedQuery);
      if (sort) {
        params.set("sort", sort);
        params.set("direction", direction);
      }
      if (refresh) params.set("refresh", "1");
      const response = await fetch(`/api/decisions?${params}`);
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || `HTTP ${response.status}`);
      setDecisions(payload);
    } catch (loadError) {
      setError(loadError.message);
    } finally {
      setLoading(false);
    }
  }, [appliedQuery, direction, offset, sort]);

  useEffect(() => {
    loadDecisions();
  }, [loadDecisions]);

  useEffect(() => {
    const interval = window.setInterval(() => loadDecisions(), refreshSeconds * 1000);
    return () => window.clearInterval(interval);
  }, [loadDecisions, refreshSeconds]);

  useEffect(() => {
    if (refreshSignal > 0) loadDecisions(true);
  }, [loadDecisions, refreshSignal]);

  const applySearch = (event) => {
    event.preventDefault();
    setOffset(0);
    setAppliedQuery(query.trim());
  };

  const changeSort = (field) => {
    setOffset(0);
    if (sort === field) {
      setDirection((value) => value === "asc" ? "desc" : "asc");
    } else {
      setSort(field);
      setDirection("asc");
    }
  };

  const sortHeader = (field, label) => (
    <button type="button" className={sort === field ? "active" : ""} onClick={() => changeSort(field)} aria-label={`Sort by ${label}`}>
      <span>{label}</span>
      {sort === field && (direction === "asc" ? <ChevronUp size={14} /> : <ChevronDown size={14} />)}
    </button>
  );

  return (
    <section className="decisionsView">
      <div className="decisionsControls">
        <form onSubmit={applySearch}>
          <Search size={16} />
          <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search, e.g. origin=capi or scenario=/http-.*/i" title="Field filters: value, scope, country, scenario, origin, duration, until. Regex: /pattern/i" />
          <button type="submit">Search</button>
        </form>
      </div>

      <div className="decisionsSummary">
        <Metric icon={<ShieldAlert />} label="All Decisions" value={decisions?.total || 0} />
        <Metric icon={<Search />} label="Matching" value={decisions?.matched || 0} />
        <Metric icon={<Globe2 />} label="Countries" value={decisions?.countries || 0} />
        <Metric icon={<Crosshair />} label="Scenarios" value={decisions?.scenarios || 0} />
      </div>

      <DecisionBlockedIpSummary total={decisions?.uniqueBlockedIps || 0} origins={decisions?.blockedIpsByOrigin || []} />

      <div className="decisionRankingStrip">
        <DecisionRanks title="Top scenarios" items={decisions?.topScenarios || []} />
        <DecisionRanks title="Top countries" items={decisions?.topCountries || []} />
        <DecisionRanks title="Top origins" items={decisions?.topOrigins || []} />
      </div>

      <div className="decisionsTableWrap">
        {error && <div className="warning">decisions: {error}</div>}
        {!error && loading && !decisions && <div className="modalLoading">Loading CrowdSec enforcement decisions...</div>}
        {!error && decisions && (
          <table className="decisionsTable">
            <thead><tr><th>{sortHeader("value", "Value")}</th><th>{sortHeader("scope", "Scope")}</th><th>{sortHeader("country", "Country")}</th><th>{sortHeader("scenario", "Scenario / blocklist")}</th><th>{sortHeader("origin", "Origin")}</th><th>{sortHeader("duration", "Duration / until")}</th></tr></thead>
            <tbody>
              {decisions.items.map((item) => (
                <tr className={isIpv4(item.ip) ? "clickableRow" : ""} key={item.id} onClick={() => isIpv4(item.ip) && onSelectIp(item.ip)}>
                  <td><strong>{item.ip || item.value || "unknown"}</strong></td>
                  <td>{item.scope || "Ip"}</td>
                  <td>{item.country || "??"}</td>
                  <td title={item.scenario}>{item.scenario || "unknown"}</td>
                  <td>{item.origin || "unknown"}</td>
                  <td title={item.until}>{item.duration || item.until || "active"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <footer className="decisionsPager">
        <span>Cached {formatRelativeTime(decisions?.cachedAt)} · 50 per page</span>
        <div>
          <button type="button" disabled={offset === 0 || loading} onClick={() => setOffset((value) => Math.max(0, value - 50))}>Previous</button>
          <strong>{offset + 1}–{Math.min(offset + 50, decisions?.matched || 0)} of {decisions?.matched || 0}</strong>
          <button type="button" disabled={decisions?.nextOffset == null || loading} onClick={() => setOffset(decisions.nextOffset)}>Next</button>
        </div>
      </footer>
    </section>
  );
}

function HistoryView() {
  const [days, setDays] = useState(90);
  const [groupBy, setGroupBy] = useState("cidr24");
  const [history, setHistory] = useState(null);
  const [offset, setOffset] = useState(0);
  const [selectedIp, setSelectedIp] = useState("");
  const [selectedGroup, setSelectedGroup] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const loadHistory = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const params = new URLSearchParams({ days: String(days), groupBy, offset: String(offset), limit: "50" });
      const response = await fetch(`/api/history?${params}`);
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      setHistory(await response.json());
    } catch (loadError) {
      setError(loadError.message);
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
              onClick={() => { setOffset(0); setDays(value); }}
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
              onClick={() => { setOffset(0); setGroupBy(value); }}
            >
              {label}
            </button>
          ))}
        </div>
        <button type="button" className="historyRefresh" onClick={loadHistory} disabled={loading} title="Refresh history">
          <RefreshCcw size={16} className={loading ? "spin" : ""} />
        </button>
      </div>

      <div className="historySummary">
        <Metric icon={<BarChart3 />} label="Groups" value={history?.total || 0} />
        <Metric icon={<Activity />} label="Recorded Alerts" value={history?.matchedEvents || 0} />
        <Metric icon={<Timer />} label="Window" value={`${history?.days || days}d`} />
      </div>

      <p className="historySourceNote">Recorded locally by CrowdSec Map. This archive can include alerts that CrowdSec no longer retains.</p>

      <div className="historyTableWrap">
        {error && <div className="warning">{error}</div>}
        {!error && history?.items?.length === 0 && (
          <div className="historyEmpty">
            <strong>No history yet</strong>
            <span>History starts filling when live data is refreshed.</span>
          </div>
        )}
        {history?.items?.length > 0 && (
          <table className="historyTable">
            <thead>
              <tr>
                <th>{getHistoryGroupLabel(groupBy)}</th>
                <th>Days</th>
                <th>Log events</th>
                <th>IPs</th>
                <th>Last seen</th>
                <th>Top scenario</th>
                <th>Country</th>
              </tr>
            </thead>
            <tbody>
              {history.items.map((item) => {
                const isIpRow = groupBy === "ip" && isIpv4(item.label);
                const isGroupRow = !isIpRow;
                return (
                  <tr
                    className={isIpRow || isGroupRow ? "clickableRow" : ""}
                    key={item.label}
                    onClick={() => {
                      if (isIpRow) {
                        setSelectedIp(item.label);
                        return;
                      }
                      setSelectedGroup({ groupBy, label: item.label });
                    }}
                  >
                    <td>
                      <strong title={item.label}>{item.label}</strong>
                      <div className="historyBar"><i style={{ width: `${Math.max(4, (item.alerts / maxAlerts) * 100)}%` }} /></div>
                    </td>
                    <td>{item.daysSeen}/{history.days}</td>
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
          <button type="button" disabled={offset === 0 || loading} onClick={() => setOffset((value) => Math.max(0, value - 50))}>Previous</button>
          <strong>{history?.total ? `${offset + 1}–${Math.min(offset + (history.limit || 50), history.total)} of ${history.total}` : "0 groups"}</strong>
          <button type="button" disabled={history?.nextOffset == null || loading} onClick={() => setOffset(history.nextOffset)}>Next</button>
        </div>
      </footer>
      {selectedIp && (
        <IpDetailModal
          days={days}
          ip={selectedIp}
          onClose={() => setSelectedIp("")}
        />
      )}
      {selectedGroup && (
        <GroupDetailModal
          days={days}
          group={selectedGroup}
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

function GroupDetailModal({ group, days, onClose, onSelectIp }) {
  const [detail, setDetail] = useState(null);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const loadDetail = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const params = new URLSearchParams({
        days: String(days),
        groupBy: group.groupBy,
        label: group.label,
        offset: String(offset),
        limit: "50"
      });
      const response = await fetch(`/api/history/group?${params}`);
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      setDetail(await response.json());
    } catch (loadError) {
      setError(loadError.message);
    } finally {
      setLoading(false);
    }
  }, [days, group.groupBy, group.label, offset]);

  useEffect(() => {
    loadDetail();
  }, [loadDetail]);

  useEffect(() => {
    const onKeyDown = (event) => {
      if (event.key === "Escape") {
        onClose();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [onClose]);

  const maxAlerts = Math.max(...(detail?.items || []).map((item) => item.alerts), 1);

  return (
    <div className="modalBackdrop" role="presentation" onClick={onClose}>
      <section className="ipModal groupModal" role="dialog" aria-modal="true" aria-labelledby="group-detail-title" onClick={(event) => event.stopPropagation()}>
        <header className="modalHeader">
          <div>
            <h3 id="group-detail-title">{group.label}</h3>
            <p>{getHistoryGroupLabel(group.groupBy)} · {days}d window · select an IP for cscli details</p>
          </div>
          <button type="button" onClick={onClose} title="Close" aria-label="Close">
            <X size={18} />
          </button>
        </header>

        {error && <div className="warning">{error}</div>}
        {loading && <div className="modalLoading">Loading group IPs...</div>}
        {!loading && detail && (
          <>
            <div className="ipSummaryGrid">
              <Metric icon={<BarChart3 />} label="IPs" value={detail.items.length || 0} />
              <Metric icon={<Activity />} label="Recorded Alerts" value={detail.matchedEvents || 0} />
              <Metric icon={<Timer />} label="Window" value={`${detail.days}d`} />
            </div>

            <div className="groupIpList">
              {detail.items.length === 0 ? (
                <p>No IPs found in the selected window.</p>
              ) : (
                detail.items.map((item) => (
                  <button type="button" className="groupIpRow" key={item.ip} onClick={() => onSelectIp(item.ip)}>
                    <span>
                      <strong>{item.ip}</strong>
                      <i style={{ width: `${Math.max(4, (item.alerts / maxAlerts) * 100)}%` }} />
                    </span>
                    <em>{item.alerts} log events</em>
                    <small>{item.daysSeen}/{detail.days} days</small>
                    <small title={item.topScenario}>{item.topScenario}</small>
                    <small>{item.topCountry}</small>
                  </button>
                ))
              )}
            </div>
            <footer className="decisionsPager">
              <span>{detail.total || 0} IPs · 50 per page</span>
              <div>
                <button type="button" disabled={offset === 0 || loading} onClick={() => setOffset((value) => Math.max(0, value - 50))}>Previous</button>
                <strong>{detail.total ? `${offset + 1}–${Math.min(offset + (detail.limit || 50), detail.total)} of ${detail.total}` : "0 IPs"}</strong>
                <button type="button" disabled={detail.nextOffset == null || loading} onClick={() => setOffset(detail.nextOffset)}>Next</button>
              </div>
            </footer>
          </>
        )}
      </section>
    </div>
  );
}

function IpDetailModal({ ip, days, onClose }) {
  const [detail, setDetail] = useState(null);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);
  const [commandCopied, setCommandCopied] = useState(false);

  const loadDetail = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const params = new URLSearchParams({ days: String(days), offset: String(offset), limit: "20" });
      const response = await fetch(`/api/history/ip/${encodeURIComponent(ip)}?${params}`);
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      setDetail(await response.json());
    } catch (loadError) {
      setError(loadError.message);
    } finally {
      setLoading(false);
    }
  }, [days, ip, offset]);

  useEffect(() => {
    loadDetail();
  }, [loadDetail]);

  useEffect(() => {
    const onKeyDown = (event) => {
      if (event.key === "Escape") {
        onClose();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [onClose]);

  const copyRaw = async () => {
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
      <section className="ipModal" role="dialog" aria-modal="true" aria-labelledby="ip-detail-title" onClick={(event) => event.stopPropagation()}>
        <header className="modalHeader">
          <div>
            <h3 id="ip-detail-title">{ip}</h3>
            <p>{days}d history window · CrowdSec raw details</p>
          </div>
          <button type="button" onClick={onClose} title="Close" aria-label="Close">
            <X size={18} />
          </button>
        </header>

        {error && <div className="warning">{error}</div>}
        {loading && <div className="modalLoading">Loading IP details...</div>}
        {!loading && detail && (
          <>
            <div className="ipSummaryGrid">
              <Metric icon={<Activity />} label="Log Events" value={detail.alerts || 0} />
              <Metric icon={<BarChart3 />} label="Recorded Alerts" value={detail.events || 0} />
              <Metric icon={<Timer />} label="Days seen" value={`${detail.daysSeen || 0}/${detail.days}`} />
            </div>

            <div className="ipMetaGrid">
              <div>
                <span>ASN</span>
                <strong title={detail.topAsName}>{detail.topAsName}</strong>
              </div>
              <div>
                <span>Top scenario</span>
                <strong title={detail.topScenario}>{detail.topScenario}</strong>
              </div>
              <div>
                <span>Country</span>
                <strong>{detail.topCountry}</strong>
              </div>
              <div>
                <span>Last seen</span>
                <strong title={detail.lastSeen}>{formatRelativeTime(detail.lastSeen)}</strong>
              </div>
            </div>

            <IpLookupBlock ip={ip} />

            <InvestigationBlock ip={ip} days={days} />

            <div className="recentEvents">
              <h4>Recent alerts</h4>
              {detail.recentEvents.length === 0 ? (
                <p>No alerts in the selected history window.</p>
              ) : (
                <div className="eventList">
                  {detail.recentEvents.map((event) => (
                    <div className="eventRow" key={`${event.seenAt}-${event.scenario}-${event.count}`}>
                      <time>{formatRelativeTime(event.seenAt)}</time>
                      <strong>{event.count}</strong>
                      <span title={event.scenario}>{event.scenario}</span>
                      <em>{event.country}</em>
                    </div>
                  ))}
                </div>
              )}
              <footer className="decisionsPager">
                <span>{detail.events || 0} events · 20 per page</span>
                <div>
                  <button type="button" disabled={offset === 0 || loading} onClick={() => setOffset((value) => Math.max(0, value - 20))}>Previous</button>
                  <strong>{detail.events ? `${offset + 1}–${Math.min(offset + (detail.limit || 20), detail.events)} of ${detail.events}` : "0 events"}</strong>
                  <button type="button" disabled={detail.nextOffset == null || loading} onClick={() => setOffset(detail.nextOffset)}>Next</button>
                </div>
              </footer>
            </div>

            <div className="rawBlock">
              <div className="rawHeader">
                <div>
                  <h4>cscli raw details</h4>
                  <p>{detail.note}</p>
                </div>
                <div className="rawActions">
                  <button type="button" onClick={loadDetail} disabled={loading} title="Refresh IP details">
                    <RefreshCcw size={15} className={loading ? "spin" : ""} />
                  </button>
                  <button type="button" onClick={copyRaw} disabled={!detail.cscli} title="Copy raw output">
                    <Copy size={15} /> {copied ? "Copied" : "Copy"}
                  </button>
                </div>
              </div>
              {detail.cscliWarning && <div className="warning">cscli: {detail.cscliWarning}</div>}
              <div className="rawCommand">
                <code>{detail.cscliCommand || "cscli command unavailable"}</code>
                <button type="button" onClick={copyCommand} disabled={!detail.cscliCommand} title="Copy cscli command">
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

function InvestigationBlock({ ip, days }) {
  const [investigation, setInvestigation] = useState(null);
  const [selectedSource, setSelectedSource] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [lineLimit, setLineLimit] = useState(50);

  const loadInvestigation = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const params = new URLSearchParams({
        days: String(days),
        maxLines: String(clampLineLimit(lineLimit))
      });
      const response = await fetch(`/api/investigation/ip/${encodeURIComponent(ip)}?${params}`);
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload.error || `HTTP ${response.status}`);
      }
      setInvestigation(payload);
    } catch (loadError) {
      setError(loadError.message);
    } finally {
      setLoading(false);
    }
  }, [days, ip, lineLimit]);

  useEffect(() => {
    setInvestigation(null);
    setError("");
  }, [days, ip]);

  return (
    <div className="investigationBlock">
      <div className="investigationHeader">
        <div>
          <h4><Search size={15} /> Investigation</h4>
          <p>Checks configured host logs for this IP in the selected {days}d window.</p>
        </div>
        <div className="investigationRunControls">
          <label>
            <span>Lines</span>
            <input
              type="number"
              min="1"
              max="200"
              step="1"
              value={lineLimit}
              onChange={(event) => setLineLimit(event.target.value)}
              onBlur={() => setLineLimit(clampLineLimit(lineLimit))}
              aria-label="Investigation sample lines"
            />
          </label>
          <button type="button" onClick={loadInvestigation} disabled={loading}>
            <RefreshCcw size={14} className={loading ? "spin" : ""} /> Run
          </button>
        </div>
      </div>

      {error && <div className="warning">investigation: {error}</div>}
      {!investigation && !error && (
        <p className="investigationHint">Inspired by csfind: compare CrowdSec context with Zoraxy, Authelia, Proxmox, or other mounted logs.</p>
      )}
      {investigation && (
        <>
          {investigation.warning && <div className="warning">investigation: {investigation.warning}</div>}
          <div className="investigationGrid">
            <div>
              <span>Hits</span>
              <strong>{investigation.totalHits}</strong>
            </div>
            <div>
              <span>'403 (Forbidden)'</span>
              <strong>{investigation.totalForbidden}</strong>
            </div>
            <div title={buildActiveBanTitle(investigation.activeBans)}>
              <span>Active Bans</span>
              <strong>{investigation.activeBans?.count || 0}</strong>
            </div>
            <div title={buildActiveBanTitle(investigation.activeBans)}>
              <span>Ban since</span>
              <strong>{formatBanSince(investigation.activeBans?.since)}</strong>
            </div>
            <div title={buildActiveBanTitle(investigation.activeBans)}>
              <span>Remaining</span>
              <strong>{formatBanRemaining(investigation.activeBans?.remaining)}</strong>
            </div>
            <div>
              <span>Files</span>
              <strong>{investigation.scannedFiles}/{investigation.availableFiles}</strong>
            </div>
          </div>

          {investigation.sources.length > 0 && (
            <div className="investigationSources">
              {investigation.sources.map((source) => (
                <details key={source.path} open={source.hits > 0}>
                  <summary>
                    <strong title={source.path}>{source.name}</strong>
                    <span>
                      {source.hits > 0 && (
                        <button type="button" onClick={(event) => {
                          event.preventDefault();
                          event.stopPropagation();
                          setSelectedSource(source);
                        }}>
                          <Search size={14} /> Deep investigation
                        </button>
                      )}
                      {source.hits} hits · {source.forbidden} '403 (Forbidden)'
                    </span>
                  </summary>
                  {source.error && <div className="warning">{source.error}</div>}
                  {source.sampledLines.length > 0 ? (
                    <pre>{source.sampledLines.join("\n")}</pre>
                  ) : (
                    <p>No matching sample lines in this window.</p>
                  )}
                </details>
              ))}
            </div>
          )}
        </>
      )}
      {selectedSource && (
        <InvestigationLogModal
          activeBans={investigation?.activeBans}
          days={days}
          ip={ip}
          sources={investigation?.sources || []}
          source={selectedSource}
          onSelectSource={setSelectedSource}
          onClose={() => setSelectedSource(null)}
        />
      )}
    </div>
  );
}

function InvestigationLogModal({ ip, days, source, sources, activeBans, onSelectSource, onClose }) {
  const [lines, setLines] = useState([]);
  const [summary, setSummary] = useState(null);
  const [filter, setFilter] = useState("all");
  const [sort, setSort] = useState("newest");
  const [search, setSearch] = useState("");
  const [appliedSearch, setAppliedSearch] = useState("");
  const [timestampWarning, setTimestampWarning] = useState(null);
  const [nextOffset, setNextOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const loadLines = useCallback(async ({ offset = 0, reset = false } = {}) => {
    setLoading(true);
    setError("");
    try {
      const params = new URLSearchParams({
        days: String(days),
        path: source.path,
        offset: String(offset),
        limit: "200",
        filter,
        sort,
        search: appliedSearch
      });
      const response = await fetch(`/api/investigation/ip/${encodeURIComponent(ip)}/log-lines?${params}`);
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload.error || `HTTP ${response.status}`);
      }
      setSummary(payload);
      setNextOffset(payload.nextOffset);
      setLines((current) => reset ? payload.lines : [...current, ...payload.lines]);
    } catch (loadError) {
      setError(loadError.message);
    } finally {
      setLoading(false);
    }
  }, [appliedSearch, days, filter, ip, sort, source.path]);

  useEffect(() => {
    setLines([]);
    setNextOffset(0);
    setTimestampWarning(null);
    loadLines({ offset: 0, reset: true });
  }, [appliedSearch, filter, loadLines, sort, source.path]);

  useEffect(() => {
    const onKeyDown = (event) => {
      if (event.key === "Escape") {
        onClose();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [onClose]);

  const applySearch = (event) => {
    event.preventDefault();
    setAppliedSearch(search.trim());
  };
  const banSinceSearch = activeBans?.since ? formatBanSinceExact(activeBans.since) : "";

  const applyBanSinceSearch = ({ force = false } = {}) => {
    const warning = buildZoraxyTimestampWarning(source, sources, banSinceSearch);
    if (warning && !force) {
      setTimestampWarning(warning);
      return;
    }
    setTimestampWarning(null);
    setSearch(banSinceSearch);
    setAppliedSearch(banSinceSearch);
  };

  const openMatchingZoraxyLog = () => {
    if (!timestampWarning?.matchingSource) {
      return;
    }
    setTimestampWarning(null);
    setSearch(banSinceSearch);
    setAppliedSearch(banSinceSearch);
    onSelectSource(timestampWarning.matchingSource);
  };

  const clearTimestampSearch = () => {
    setTimestampWarning(null);
    setSearch("");
    setAppliedSearch("");
  };

  return (
    <div className="modalBackdrop" role="presentation" onClick={onClose}>
      <section className="ipModal investigationLogModal" role="dialog" aria-modal="true" aria-labelledby="investigation-log-title" onClick={(event) => event.stopPropagation()}>
        <header className="modalHeader">
          <div>
            <h3 id="investigation-log-title">{source.name}</h3>
            <div className="logModalMeta">
              <span>{ip} · {days}d window · {summary?.filteredHits ?? source.hits} matching lines</span>
              {banSinceSearch && (
                <>
                  <span>· ban since: {banSinceSearch}</span>
                  <button type="button" onClick={() => applyBanSinceSearch()}>
                    Use timestamp
                  </button>
                </>
              )}
            </div>
          </div>
          <button type="button" onClick={onClose} title="Close" aria-label="Close">
            <X size={18} />
          </button>
        </header>

        {timestampWarning && (
          <div className="logTimestampWarning" role="alert">
            <div>
              <strong>Timestamp does not match this Zoraxy log.</strong>
              <span>{timestampWarning.message}</span>
            </div>
            <div>
              {timestampWarning.matchingSource && (
                <button type="button" onClick={openMatchingZoraxyLog}>
                  Open {timestampWarning.matchingSource.name}
                </button>
              )}
              <button type="button" onClick={() => applyBanSinceSearch({ force: true })}>
                Filter anyway
              </button>
              <button type="button" onClick={clearTimestampSearch}>
                Clear timestamp
              </button>
            </div>
          </div>
        )}

        <form className="logLineControls" onSubmit={applySearch}>
          <label>
            <span>Search</span>
            <input type="search" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="path, router, origin..." />
          </label>
          <label>
            <span>Filter</span>
            <select value={filter} onChange={(event) => setFilter(event.target.value)}>
              <option value="all">All</option>
              <option value="forbidden">403 only</option>
              <option value="non-forbidden">Non-403</option>
            </select>
          </label>
          <label>
            <span>Sort</span>
            <select value={sort} onChange={(event) => setSort(event.target.value)}>
              <option value="newest">Newest first</option>
              <option value="oldest">Oldest first</option>
            </select>
          </label>
          <button type="submit">Apply</button>
        </form>

        {error && <div className="warning">log-lines: {error}</div>}
        {summary && (
          <div className="logLineMeta">
            <span>{summary.totalHits} hits</span>
            <span>{summary.totalForbidden} '403 (Forbidden)'</span>
            <span>{summary.filteredHits} after filter</span>
            <span>showing {lines.length}</span>
          </div>
        )}

        <div className="logLineList">
          {lines.length === 0 && !loading && <p>No log lines match the current filters.</p>}
          {lines.map((item, index) => (
            <div className={item.forbidden ? "logLineRow forbidden" : "logLineRow"} key={`${item.timestamp}-${index}-${item.line}`}>
              <span>{item.forbidden ? "403" : "OK"}</span>
              <code>{item.line}</code>
            </div>
          ))}
        </div>

        <div className="logLineFooter">
          <button type="button" onClick={() => loadLines({ offset: nextOffset || 0 })} disabled={loading || nextOffset === null}>
            <RefreshCcw size={14} className={loading ? "spin" : ""} /> {nextOffset === null ? "All loaded" : "Load more"}
          </button>
        </div>
      </section>
    </div>
  );
}

function IpLookupBlock({ ip }) {
  const [reputation, setReputation] = useState(null);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const abuseIpDbUrl = `https://www.abuseipdb.com/check/${encodeURIComponent(ip)}`;
  const shodanUrl = `https://www.shodan.io/host/${encodeURIComponent(ip)}`;

  const loadStats = useCallback(async () => {
    try {
      const response = await fetch("/api/reputation/stats");
      if (response.ok) {
        setStats(await response.json());
      }
    } catch {
      setStats(null);
    }
  }, []);

  const loadReputation = useCallback(async (options = {}) => {
    setLoading(true);
    setError("");
    try {
      const params = new URLSearchParams();
      if (options.refresh) {
        params.set("refresh", "1");
      }
      const suffix = params.toString() ? `?${params}` : "";
      const response = await fetch(`/api/reputation/ip/${encodeURIComponent(ip)}${suffix}`);
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload.error || `HTTP ${response.status}`);
      }
      setReputation(payload);
      setStats(payload.stats || null);
    } catch (loadError) {
      setError(loadError.message);
    } finally {
      setLoading(false);
    }
  }, [ip]);

  useEffect(() => {
    setReputation(null);
    setError("");
    loadStats();
  }, [ip, loadStats]);

  return (
    <div className="lookupBlock">
      <div className="lookupHeader">
        <div>
          <h4><ShieldAlert size={15} /> IP lookup</h4>
          <p>External reputation checks only run when selected.</p>
        </div>
        {stats && <span>{stats.networkRequests} CTI request{stats.networkRequests === 1 ? "" : "s"} this month</span>}
      </div>
      <div className="lookupActions">
        <button type="button" onClick={() => loadReputation()} disabled={loading}>
          <ShieldAlert size={14} className={loading ? "spin" : ""} /> CrowdSec CTI
        </button>
        <a href={abuseIpDbUrl} target="_blank" rel="noreferrer">
          <ShieldAlert size={14} /> AbuseIPDB
        </a>
        <a href={shodanUrl} target="_blank" rel="noreferrer">
          <Crosshair size={14} /> Shodan.io
        </a>
      </div>
      {stats && (
        <p className="lookupStats">
          Cache hits {stats.cacheHits} · cached IPs {stats.cachedIps} · cache {stats.cacheHours}h
        </p>
      )}
      {(reputation || error) && (
        <CtiReputationBlock
          reputation={reputation}
          warning={error}
          onRefresh={() => loadReputation({ refresh: true })}
          loading={loading}
        />
      )}
    </div>
  );
}

function CtiReputationBlock({ reputation, warning, onRefresh, loading }) {
  if (!reputation && !warning) {
    return null;
  }

  const status = reputation?.status || "error";
  const statusLabel = {
    false_positive: "false positive",
    malicious: "malicious",
    suspicious: "suspicious",
    unknown: "unknown",
    not_configured: "not configured",
    error: "error"
  }[status] || status;

  return (
    <div className={`ctiBlock cti-${status}`}>
      <div className="ctiHeader">
        <div>
          <h4><ShieldAlert size={15} /> CrowdSec CTI reputation</h4>
          <p>{warning || reputation?.summary || "No CrowdSec CTI data available."}</p>
        </div>
        <span>{statusLabel}</span>
      </div>

      {warning ? (
        <div className="warning">cti: {warning}</div>
      ) : (
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
              <strong title={reputation.cachedAt}>
                {reputation.cached ? `cached ${formatRelativeTime(reputation.cachedAt)}` : "fresh"}
              </strong>
            </div>
          </div>

          {reputation.behaviors?.length > 0 && (
            <div className="ctiTags" aria-label="CrowdSec CTI behaviors">
              {reputation.behaviors.map((behavior) => <span key={behavior}>{behavior}</span>)}
            </div>
          )}

          {reputation.configured ? (
            <div className="ctiActions">
              <a href={reputation.webUrl} target="_blank" rel="noreferrer">Open CrowdSec CTI</a>
              <button type="button" onClick={onRefresh} disabled={loading} title={`Refresh CTI, cache is ${reputation.cacheHours}h`}>
                <RefreshCcw size={14} className={loading ? "spin" : ""} /> Refresh CTI
              </button>
            </div>
          ) : (
            <p className="ctiHint">Set CTI_API_KEY to enable on-demand reputation checks. Results are cached for {reputation.cacheHours}h.</p>
          )}
        </>
      )}
    </div>
  );
}

function WorldMap({ attacks, showPaths = true, initialLoading = false, expanded = false, onExpand, onSelectPoint }) {
  const projection = useMemo(() => geoEqualEarth().fitSize([1120, 590], { type: "Sphere" }), []);
  const path = useMemo(() => geoPath(projection), [projection]);
  const homePoint = projection([HOME.longitude, HOME.latitude]);
  const mapAttacks = useMemo(() => compactMapAttacks(attacks), [attacks]);
  const plotted = mapAttacks.slice(0, MAX_MAP_POINTS)
    .map((attack) => {
      const point = projection([attack.longitude, attack.latitude]);
      return point && homePoint ? { ...attack, x: point[0], y: point[1], hx: homePoint[0], hy: homePoint[1] } : null;
    })
    .filter(Boolean);
  const activePaths = (showPaths ? plotted.slice(0, MAX_SIGNAL_PATHS) : []).map((attack) => ({
    ...attack,
    arcPath: createArcPath(attack)
  }));

  return (
    <div className={`mapWrap ${expanded ? "mapWrapExpanded" : ""}`} onClick={!expanded ? onExpand : undefined} role={!expanded ? "button" : undefined} tabIndex={!expanded ? 0 : undefined} onKeyDown={(event) => !expanded && (event.key === "Enter" || event.key === " ") && onExpand?.()}>
      {!expanded && <button type="button" className="mapExpandButton" title="Expand live map" aria-label="Expand live map" onClick={(event) => { event.stopPropagation(); onExpand?.(); }}><Maximize2 size={16} /></button>}
      {initialLoading && (
        <div className="mapLoadingStatus" role="status" aria-live="polite">
          <span className="mapLoadingSpinner" aria-hidden="true">
            {Array.from({ length: 8 }, (_, index) => <i key={index} style={{ "--dot": index }} />)}
          </span>
          <span>Loading live data…</span>
        </div>
      )}
      <svg viewBox="0 0 1120 590" role="img" aria-label="World map of CrowdSec alerts">
        <defs>
          <radialGradient id="pulse" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#ffcf6e" stopOpacity="0.95" />
            <stop offset="100%" stopColor="#ff4d6d" stopOpacity="0.05" />
          </radialGradient>
        </defs>
        <path className="sphere" d={path({ type: "Sphere" })} />
        {countries.map((country, index) => (
          <path key={`${country.id || "country"}-${index}`} className="country" d={path(country)} />
        ))}
        {activePaths.map((attack) => (
          <path
            className={`arc ${getAgeClass(attack.createdAt)}`}
            key={`${attack.id}-arc`}
            d={attack.arcPath}
          />
        ))}
        {activePaths.map((attack, index) => (
          <circle className={`signalRunner ${getAgeClass(attack.createdAt)}`} r={Math.min(4.5, 2.4 + attack.count / 7)} key={`${attack.id}-runner`}>
            <animateMotion
              dur={`${getSignalDuration(attack.count, index)}s`}
              begin={`${(index % 7) * -0.55}s`}
              repeatCount="indefinite"
              path={attack.arcPath}
            />
          </circle>
        ))}
        <circle className="homeRing" cx={homePoint[0]} cy={homePoint[1]} r="11" />
        <circle className="homeDot" cx={homePoint[0]} cy={homePoint[1]} r="4" />
        {plotted.map((attack) => {
          const radii = getAttackMarkerRadii(attack.count);
          return (
            <g className={`attackPoint ${getAgeClass(attack.createdAt)} ${expanded ? "interactive" : ""}`} key={attack.id} role={expanded ? "button" : undefined} tabIndex={expanded ? 0 : undefined} onClick={expanded ? (event) => { event.stopPropagation(); onSelectPoint?.(attack); } : undefined} onKeyDown={expanded ? (event) => (event.key === "Enter" || event.key === " ") && onSelectPoint?.(attack) : undefined}>
              <circle cx={attack.x} cy={attack.y} r={radii.glow} fill="url(#pulse)" />
              <circle cx={attack.x} cy={attack.y} r={radii.core} />
              <title>{`${attack.country} ${attack.sourceCount} source${attack.sourceCount === 1 ? "" : "s"} ${attack.scenario}`}</title>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

function ExpandedMapModal({ attacks, error, selectedGroup, onSelectGroup, onClose, onInspect, onInvestigate }) {
  useEffect(() => {
    const closeOnEscape = (event) => event.key === "Escape" && onClose();
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [onClose]);
  const sources = selectedGroup ? groupEventSources(selectedGroup.attacks || []) : [];
  return (
    <div className="expandedMapBackdrop" role="presentation">
      <section className="expandedMapModal" role="dialog" aria-modal="true" aria-label="Expanded live attack map">
        <header><div><span>Live map investigation</span><h2>Attack sources</h2><p>Click a source point to inspect its IPs, ASNs and scenarios.</p></div><button type="button" onClick={onClose} aria-label="Close expanded map"><X size={20} /></button></header>
        <div className="expandedMapBody">
          <div className="expandedMapCanvas"><WorldMap attacks={attacks} expanded showPaths onSelectPoint={onSelectGroup} /></div>
          <div className="expandedMapInsights">
            <ActivityTrend attacks={attacks} onSelectBucket={(bucket) => onInspect({ title: `Attack activity · ${bucket.label}`, subtitle: `${bucket.count} attempts in this time segment`, attacks: bucket.attacks })} />
            <Timeline attacks={attacks} error={error} onSelectGroup={(group) => onInspect({ title: `Timeline · ${group.ip}`, subtitle: `${group.totalCount} attempts around ${formatTime(group.createdAt)}`, attacks: group.attacks })} />
          </div>
          {selectedGroup && <aside className="mapSourcePanel"><header><div><span>{selectedGroup.country || "Unknown"}</span><h3>{selectedGroup.sourceCount} source{selectedGroup.sourceCount === 1 ? "" : "s"}</h3><p>{selectedGroup.count} attempts · {readableScenario(selectedGroup.scenario)}</p></div><button type="button" onClick={() => onSelectGroup(null)} aria-label="Close source details"><X size={16} /></button></header><div className="mapSourceList">{sources.map((source) => <article key={source.ip}><div><strong>{source.ip}</strong><span>{source.asn || "ASN / provider unavailable"}</span><small>{source.scenarios.join(" · ")}</small></div><button type="button" onClick={() => onInvestigate(source.ip)}>Investigate IP <ArrowUpRight size={14} /></button></article>)}</div></aside>}
        </div>
      </section>
    </div>
  );
}

function Timeline({ attacks, error, onSelectGroup }) {
  const recent = useMemo(() => compactTimelineAttacks(attacks), [attacks]);
  const [visibleRows, setVisibleRows] = useState(readStoredTimelineRows);
  const [visibleColumns, setVisibleColumns] = useState(MAX_TIMELINE_COLUMNS);
  const timelineRef = useRef(null);
  const availableRows = recent.length > 0
    ? Math.max(1, Math.min(MAX_TIMELINE_ROWS, Math.ceil(recent.length / visibleColumns)))
    : visibleRows;
  const safeVisibleRows = Math.min(visibleRows, availableRows);
  const visibleLimit = visibleColumns * safeVisibleRows;
  const visibleItems = recent.slice(0, visibleLimit);
  const canExpand = recent.length > visibleLimit && safeVisibleRows < MAX_TIMELINE_ROWS;
  const canCollapse = safeVisibleRows > 1;

  useLayoutEffect(() => {
    const timeline = timelineRef.current;
    if (!timeline) {
      return undefined;
    }

    const updateVisibleColumns = () => {
      const rect = timeline.getBoundingClientRect();
      const availableWidth = Math.max(0, Math.min(timeline.clientWidth, window.innerWidth - rect.left));
      const columns = Math.floor((availableWidth + TIMELINE_GAP) / (TIMELINE_MIN_CARD_WIDTH + TIMELINE_GAP));
      setVisibleColumns(Math.max(1, Math.min(MAX_TIMELINE_COLUMNS, columns)));
    };

    updateVisibleColumns();
    const observer = new ResizeObserver(updateVisibleColumns);
    observer.observe(timeline);
    window.addEventListener("resize", updateVisibleColumns);
    return () => {
      observer.disconnect();
      window.removeEventListener("resize", updateVisibleColumns);
    };
  }, []);

  useEffect(() => {
    if (visibleRows !== safeVisibleRows) {
      setVisibleRows(safeVisibleRows);
    }
  }, [safeVisibleRows, visibleRows]);

  useEffect(() => {
    window.localStorage.setItem(TIMELINE_ROWS_STORAGE_KEY, String(safeVisibleRows));
  }, [safeVisibleRows]);

  return (
    <div className={`timelineDock ${(canExpand || canCollapse) ? "hasTimelineControls" : ""}`}>
      <footer
        className={`timeline timelineRows${safeVisibleRows}`}
        ref={timelineRef}
        style={{ "--timeline-columns": visibleColumns }}
      >
        {error && <div className="warning">{error}</div>}
        {visibleItems.map((attack) => (
          <article className={`${getAgeClass(attack.createdAt)} clickable`} key={`${attack.id}-timeline`} role="button" tabIndex={0} onClick={() => onSelectGroup(attack)} onKeyDown={(event) => (event.key === "Enter" || event.key === " ") && onSelectGroup(attack)}>
            <span>{formatTime(attack.createdAt)}</span>
            <strong title={attack.ip}>{attack.ip || "unknown"}</strong>
            <p title={attack.scenario}>
              {attack.country} · {attack.totalCount} alert{attack.totalCount === 1 ? "" : "s"} · {attack.scenario}
            </p>
          </article>
        ))}
      </footer>
      {(canExpand || canCollapse) && (
        <div className="timelineControls" aria-label="Timeline rows">
          <button
            type="button"
            onClick={() => setVisibleRows((rows) => Math.min(MAX_TIMELINE_ROWS, rows + 1))}
            disabled={!canExpand}
            title="Show more timeline rows"
            aria-label="Show more timeline rows"
          >
            <ChevronUp size={16} />
          </button>
          <button
            type="button"
            onClick={() => setVisibleRows((rows) => Math.max(1, rows - 1))}
            disabled={!canCollapse}
            title="Show fewer timeline rows"
            aria-label="Show fewer timeline rows"
          >
            <ChevronDown size={16} />
          </button>
        </div>
      )}
    </div>
  );
}

export default App;
