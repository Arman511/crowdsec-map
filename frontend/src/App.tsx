import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import packageInfo from "../package.json";
import { AgeLegend } from "./components/AgeLegend";
import { HiddenMenuModal } from "./components/HiddenMenuModal";
import { IpDetailModal } from "./components/IpDetailModal";
import {
  ActivityTrend,
  EventCollectionDrawer,
  EventDetailDrawer,
  EventTable,
  LiveFilterBar,
} from "./components/LiveEvents";
import { ExpandedMapModal, Timeline, WorldMap } from "./components/LiveMap";
import { MetricDrilldownModal } from "./components/MetricDrilldownModal";
import { Panel } from "./components/Panel";
import { Sidebar } from "./components/Sidebar";
import { Toolbar } from "./components/Toolbar";
import { EMPTY_RANK_ITEMS, REFRESH_STORAGE_KEY, THEME_STORAGE_KEY } from "./constants";
import { DecisionsPage } from "./pages/DecisionsPage";
import { HistoryPage } from "./pages/HistoryPage";
import { HistoryView } from "./pages/HistoryView";
import { LivePage } from "./pages/LivePage";
import { ProtectionPage } from "./pages/ProtectionPage";
import "./styles.css";
import type { Alert, AttacksResponse } from "./types";
import {
  buildFilterOptions,
  filterAttacks,
  readStoredRefreshSeconds,
  readStoredTheme,
} from "./utils";

const APP_VERSION = `v${packageInfo.version}`;

function App() {
  const [source, setSource] = useState("auto");
  const [refreshSeconds, setRefreshSeconds] = useState<number>(readStoredRefreshSeconds);
  const [theme, setTheme] = useState<"light" | "dark">(readStoredTheme);
  const [view, setView] = useState("history");
  const [hiddenMenuOpen, setHiddenMenuOpen] = useState(false);
  const [data, setData] = useState<AttacksResponse | undefined>(undefined);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [metricMode, setMetricMode] = useState("");
  const [selectedIp, setSelectedIp] = useState("");
  const [selectedEvent, setSelectedEvent] = useState<Alert | undefined>(undefined);
  const [eventDrilldown, setEventDrilldown] = useState<any>(null);
  const [mapExpanded, setMapExpanded] = useState(false);
  const [viewRefreshSignals, setViewRefreshSignals] = useState({
    protection: 0,
    decisions: 0,
  });
  const [selectedMapGroup, setSelectedMapGroup] = useState<any>(null);
  const [filters, setFilters] = useState({
    query: "",
    country: "all",
    scenario: "all",
    age: "all",
  });
  const requestControllerRef = useRef<AbortController | null>(null);

  const loadData = useCallback(async () => {
    requestControllerRef.current?.abort();
    const controller = new AbortController();
    requestControllerRef.current = controller;
    setLoading(true);
    setError("");
    try {
      const response = await fetch(`/api/attacks?source=${encodeURIComponent(source)}`, {
        signal: controller.signal,
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      setData(await response.json());
    } catch (loadError) {
      if (loadError instanceof Error && loadError.name === "AbortError") return;
      if (loadError instanceof Error) {
        setError(loadError.message);
      } else {
        setError(String(loadError));
      }
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

  const attacks = data?.alerts || [];
  const totals = data?.totals || { alerts: 0, countries: 0, scenarios: 0, bans: 0, activeBans: 0 };
  const filterOptions = useMemo(() => buildFilterOptions(attacks), [attacks]);
  const filteredAttacks = useMemo(() => filterAttacks(attacks, filters), [attacks, filters]);

  useEffect(() => {
    if (selectedEvent && !filteredAttacks.includes(selectedEvent)) setSelectedEvent(undefined);
  }, [filteredAttacks, selectedEvent]);

  const refreshCurrentView = useCallback(() => {
    if (view === "protection" || view === "decisions") {
      setViewRefreshSignals((current) => ({
        ...current,
        [view]: current[view] + 1,
      }));
      return;
    }
    loadData();
  }, [loadData, view]);

  return (
    <main className={`appShell theme${theme === "light" ? "Light" : "Dark"}`}>
      <Sidebar
        data={data}
        totals={totals}
        attacks={filteredAttacks}
        onOpenMetric={setMetricMode}
        Panel={Panel}
        appVersion={APP_VERSION}
      />
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
          <LivePage
            attacks={filteredAttacks}
            activeBans={data?.activeBans || []}
            data={data}
            error={error}
            filterOptions={filterOptions}
            filters={filters}
            loading={loading}
            mapExpanded={mapExpanded}
            onCloseEvent={() => {
              setSelectedEvent(undefined);
              setEventDrilldown(null);
            }}
            onCloseMap={() => {
              setMapExpanded(false);
              setSelectedMapGroup(null);
            }}
            onEventDrilldown={(bucket) =>
              setEventDrilldown({
                title: `Attack activity · ${bucket.label}`,
                subtitle: `${bucket.count} attempts in this time segment`,
                attacks: bucket.attacks,
              })
            }
            onExpandMap={() => {
              setSelectedMapGroup(null);
              setMapExpanded(true);
            }}
            onInvestigate={(ip) => {
              setSelectedEvent(undefined);
              setEventDrilldown(null);
              setMapExpanded(false);
              setSelectedMapGroup(null);
              setSelectedIp(ip);
            }}
            onSelectEvent={setSelectedEvent}
            onSelectMapGroup={setSelectedMapGroup}
            onSetFilters={(f) => setFilters(f as typeof filters)}
            onInspectMap={(detail: any) => {
              setMapExpanded(false);
              setSelectedMapGroup(null);
              setEventDrilldown(detail);
            }}
            selectedEvent={selectedEvent}
            selectedMapGroup={selectedMapGroup}
            eventDrilldown={eventDrilldown}
            EventCollectionDrawer={EventCollectionDrawer}
            EventDetailDrawer={EventDetailDrawer}
            EventTable={EventTable}
            ExpandedMapModal={ExpandedMapModal}
            LiveFilterBar={LiveFilterBar}
            ActivityTrend={ActivityTrend}
            AgeLegend={AgeLegend}
            WorldMap={WorldMap}
            Timeline={Timeline}
          />
        ) : view === "history" ? (
          <HistoryPage HistoryView={HistoryView} />
        ) : view === "protection" ? (
          <ProtectionPage refreshSignal={viewRefreshSignals.protection} />
        ) : (
          <DecisionsPage
            onSelectIp={setSelectedIp}
            refreshSeconds={refreshSeconds}
            refreshSignal={viewRefreshSignals.decisions}
          />
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

export default App;
