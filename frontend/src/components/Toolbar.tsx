import { useEffect, useRef, useState } from "react";

import {
  BarChart3,
  Map as MapIcon,
  Moon,
  RefreshCcw,
  ShieldAlert,
  ShieldCheck,
  Sun,
  Timer,
} from "lucide-react";

import { REFRESH_OPTIONS, SOURCE_OPTIONS } from "../constants";
import type { AttacksResponse } from "../types";
import { formatRefreshInterval, formatTime } from "../utils";

export function Toolbar({
  view,
  setView,
  theme,
  setTheme,
  source,
  setSource,
  refreshSeconds,
  setRefreshSeconds,
  data,
  loading,
  onRefresh,
  onOpenHiddenMenu,
}: {
  view: string;
  setView: (v: string) => void;
  theme: string;
  setTheme: (t: "dark" | "light") => void;
  source: string;
  setSource: (s: string) => void;
  refreshSeconds: number;
  setRefreshSeconds: (r: number) => void;
  data?: AttacksResponse;
  loading: boolean;
  onRefresh: () => void;
  onOpenHiddenMenu: () => void;
}) {
  const [sourceOpen, setSourceOpen] = useState(false);
  const [intervalOpen, setIntervalOpen] = useState(false);
  const hiddenMenuPressTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const displayedSource = data?.source || source || "...";
  const openHiddenMenu = (event: React.MouseEvent) => {
    if (!event.shiftKey || !event.ctrlKey) return;
    event.preventDefault();
    event.stopPropagation();
    onOpenHiddenMenu();
  };
  const startHiddenMenuLongPress = (event: React.PointerEvent) => {
    if (event.pointerType !== "touch") return;
    event.preventDefault();
    window.clearTimeout(hiddenMenuPressTimer.current ?? undefined);
    hiddenMenuPressTimer.current = window.setTimeout(onOpenHiddenMenu, 3000);
  };
  const cancelHiddenMenuLongPress = () => {
    window.clearTimeout(hiddenMenuPressTimer.current ?? undefined);
    hiddenMenuPressTimer.current = null;
  };
  useEffect(() => cancelHiddenMenuLongPress, []);

  const title =
    view === "live"
      ? data?.demoMode
        ? "Demo snapshot"
        : "Live attacks"
      : view === "history"
        ? "History"
        : view === "protection"
          ? "Protection"
          : "Block decisions";
  const subtitle =
    view === "live"
      ? `${data?.demoMode ? "Sanitized snapshot updated" : "Last update"} ${formatTime(data?.generatedAt || "")}`
      : view === "history"
        ? `Repeated sources ${formatTime(data?.generatedAt || "")}`
        : view === "protection"
          ? "Proxy access logs · no Grafana or Prometheus required"
          : "Enforcement data · not detected attacks";
  return (
    <header className={`toolbar ${view === "live" ? "toolbarLive" : "toolbarHistory"}`}>
      <div>
        <div className="titleLine">
          <h2>{title}</h2>
          {data?.publicTargetIp && (
            <span title={`Public target IP: ${data.publicTargetIpSource || "unknown"}`}>
              {data.publicTargetIp}
            </span>
          )}
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
        {view !== "decisions" && view !== "protection" && (
          <div className="toolbarStatus">
            {!data?.demoMode && (
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
            )}
            <div className="toolbarMenuWrap">
              <span>Interval</span>
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
                  {(REFRESH_OPTIONS as [number, string][]).map(([value, label]) => (
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
          </div>
        )}
        <button
          type="button"
          onClick={onRefresh}
          disabled={loading && view !== "decisions" && view !== "protection"}
          title="Refresh"
          aria-label="Refresh"
        >
          <RefreshCcw size={17} className={loading ? "spin" : ""} />
        </button>
        <button
          type="button"
          className="themeToggle"
          onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
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
