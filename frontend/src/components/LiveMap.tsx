
import { geoEqualEarth, geoPath } from "d3-geo";
import type { Feature } from "geojson";
import { ArrowUpRight, ChevronDown, ChevronUp, Maximize2, X } from "lucide-react";
import { CSSProperties, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import type * as React from "react";
import { feature } from "topojson-client";
import world from "world-atlas/countries-110m.json";

import {
  HOME,
  MAX_MAP_POINTS,
  MAX_SIGNAL_PATHS,
  MAX_TIMELINE_COLUMNS,
  MAX_TIMELINE_ROWS,
  TIMELINE_GAP,
  TIMELINE_MIN_CARD_WIDTH,
  TIMELINE_ROWS_STORAGE_KEY,
} from "../constants";
import type { Alert, EventDrilldown, MapGroup, TimelineAttackGroup } from "../types";
import {
  compactMapAttacks,
  compactTimelineAttacks,
  createArcPath,
  formatTime,
  getAgeClass,
  getAttackMarkerRadii,
  getSignalDuration,
  groupEventSources,
  readStoredTimelineRows,
  readableScenario,
} from "../utils";

const countries =
  (
    feature(
      world as any,
      ((world as Record<string, unknown>).objects as unknown as { countries: unknown })
        .countries as any,
    ) as unknown as { features?: Feature[] }
  ).features || [];

export function WorldMap({
  attacks,
  showPaths = true,
  initialLoading = false,
  expanded = false,
  onExpand,
  onSelectPoint,
}: {
  attacks: Alert[];
  showPaths?: boolean;
  initialLoading?: boolean;
  expanded?: boolean;
  onExpand: () => void;
  onSelectPoint?: (g: MapGroup | null) => void;
}) {
  const projection = useMemo(() => geoEqualEarth().fitSize([1120, 590], { type: "Sphere" }), []);

  const path = useMemo(() => geoPath(projection), [projection]);

  const homePoint = projection([HOME.longitude, HOME.latitude]);

  const plotted = useMemo(
    () =>
      compactMapAttacks(attacks)
        .slice(0, MAX_MAP_POINTS)
        .map((attack) => {
          const point = projection([attack.longitude, attack.latitude]);

          return point ? { ...attack, x: point[0], y: point[1] } : null;
        })
        .filter(Boolean),
    [attacks, projection],
  );

  const activePaths = (showPaths ? plotted.slice(0, MAX_SIGNAL_PATHS) : []).map((attack) => {
    const hp = homePoint as [number, number];

    return {
      ...attack,
      arcPath: createArcPath({ ...attack, hx: hp[0], hy: hp[1] }),
    };
  });

  return (
    <div
      className={`mapWrap ${expanded ? "mapWrapExpanded" : ""}`}
      onClick={!expanded ? onExpand : undefined}
      role={!expanded ? "button" : undefined}
      tabIndex={!expanded ? 0 : undefined}
    >
      <button
        type="button"
        className="mapExpandButton"
        title="Expand live map"
        aria-label="Expand live map"
        onClick={(event) => {
          event.stopPropagation();
          onExpand?.();
        }}
        hidden={expanded}
      >
        <Maximize2 size={16} />
      </button>
      {initialLoading && (
        <div className="mapLoadingStatus" role="status">
          Loading live data...
        </div>
      )}
      <svg viewBox="0 0 1120 590" role="img" aria-label="World map of CrowdSec alerts">
        <defs>
          <radialGradient id="pulse" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#ffcf6e" stopOpacity="0.95" />
            <stop offset="100%" stopColor="#ff4d6d" stopOpacity="0.05" />
          </radialGradient>
        </defs>
        <path className="sphere" d={path({ type: "Sphere" }) ?? ""} />
        {countries.map((country, index: number) => (
          <path
            className="country"
            d={path(country) ?? ""}
            key={`${(country.id as string) || "country"}-${index}`}
          />
        ))}
        {activePaths.map((attack) => (
          <path
            className={`arc ${getAgeClass(attack.createdAt)}`}
            d={attack.arcPath}
            key={`${attack.id}-arc`}
          />
        ))}
        {activePaths.map((attack, index) => (
          <circle
            className={`signalRunner ${getAgeClass(attack.createdAt)}`}
            r={Math.min(4.5, 2.4 + attack.count / 7)}
            key={`${attack.id}-runner`}
          >
            <animateMotion
              dur={`${getSignalDuration(attack.count, index)}s`}
              begin={`${(index % 7) * -0.55}s`}
              repeatCount="indefinite"
              path={attack.arcPath}
            />
          </circle>
        ))}
        <circle
          className="homeRing"
          cx={(homePoint as [number, number])[0]}
          cy={(homePoint as [number, number])[1]}
          r="11"
        />
        <circle
          className="homeDot"
          cx={(homePoint as [number, number])[0]}
          cy={(homePoint as [number, number])[1]}
          r="4"
        />
        {plotted.map((attack) => {
          const radii = getAttackMarkerRadii(attack.count);

          return (
            <g
              className={`attackPoint ${getAgeClass(attack.createdAt)} ${expanded ? "interactive" : ""}`}
              key={attack.id}
              onClick={
                expanded
                  ? (event) => {
                      event.stopPropagation();
                      onSelectPoint?.(attack);
                    }
                  : undefined
              }
            >
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

export function ExpandedMapModal({
  attacks,
  error,
  selectedGroup,
  onSelectGroup,
  onClose,
  onInspect,
  onInvestigate,
  ActivityTrend: Trend,
  Timeline: TimelineComponent,
}: {
  attacks: Alert[];
  error?: string;
  selectedGroup?: MapGroup;
  onSelectGroup: (g: MapGroup | null) => void;
  onClose: () => void;
  onInspect?: (detail: EventDrilldown) => void;
  onInvestigate?: (ip: string) => void;
  ActivityTrend: React.ComponentType<Record<string, unknown>>;
  Timeline: React.ComponentType<Record<string, unknown>>;
}) {
  useEffect(() => {
    const close = (event: KeyboardEvent) => event.key === "Escape" && onClose();
    window.addEventListener("keydown", close);

    return () => window.removeEventListener("keydown", close);
  }, [onClose]);
  const sources = selectedGroup ? groupEventSources(selectedGroup.attacks || []) : [];

  return (
    <div className="expandedMapBackdrop" role="presentation">
      <section
        className="expandedMapModal"
        role="dialog"
        aria-modal="true"
        aria-label="Expanded live attack map"
      >
        <header>
          <div>
            <span>Live map investigation</span>
            <h2>Attack sources</h2>
            <p>Click a source point to inspect its IPs, ASNs and scenarios.</p>
          </div>
          <button type="button" onClick={onClose} aria-label="Close expanded map">
            <X size={20} />
          </button>
        </header>
        <div className="expandedMapBody">
          <div className="expandedMapCanvas">
            <WorldMap
              attacks={attacks}
              expanded
              onExpand={() => {}}
              onSelectPoint={onSelectGroup}
            />
          </div>
          <div className="expandedMapInsights">
            <Trend
              attacks={attacks}
              onSelectBucket={(bucket: Record<string, unknown>): void =>
                onInspect?.({
                  title: `Attack activity · ${bucket.label || ""}`,
                  subtitle: `${bucket.count || 0} attempts in this time segment`,
                  attacks: (bucket.attacks as Alert[]) || [],
                })
              }
            />
            <TimelineComponent
              attacks={attacks}
              error={error}
              onSelectGroup={(group: Record<string, unknown>): void =>
                onInspect?.({
                  title: `Timeline · ${group.ip || ""}`,
                  subtitle: `${group.totalCount || 0} attempts around ${formatTime(String(group.createdAt || ""))}`,
                  attacks: (group.attacks as Alert[]) || [],
                })
              }
            />
          </div>
          {selectedGroup && (
            <aside className="mapSourcePanel">
              <header>
                <div>
                  <span>{selectedGroup.country || "Unknown"}</span>
                  <h3>{selectedGroup.sourceCount} sources</h3>
                  <p>
                    {selectedGroup.count} attempts · {readableScenario(selectedGroup.scenario)}
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => onSelectGroup(null)}
                  aria-label="Close source details"
                >
                  <X size={16} />
                </button>
              </header>
              <div className="mapSourceList">
                {sources.map((source) => (
                  <article key={source.ip}>
                    <div>
                      <strong>{source.ip}</strong>
                      <span>{source.asn || "ASN unavailable"}</span>
                      <small>{source.scenarios.join(" · ")}</small>
                    </div>
                    <button type="button" onClick={() => onInvestigate?.(source.ip)}>
                      Investigate IP <ArrowUpRight size={14} />
                    </button>
                  </article>
                ))}
              </div>
            </aside>
          )}
        </div>
      </section>
    </div>
  );
}

export function Timeline({
  attacks,
  error,
  onSelectGroup,
}: {
  attacks: Alert[];
  error?: string;
  onSelectGroup: (g: TimelineAttackGroup) => void;
}) {
  const recent = useMemo(() => compactTimelineAttacks(attacks), [attacks]);

  const [visibleRows, setVisibleRows] = useState(readStoredTimelineRows);

  const [visibleColumns, setVisibleColumns] = useState(MAX_TIMELINE_COLUMNS);

  const timelineRef = useRef(null);

  const availableRows = recent.length
    ? Math.max(1, Math.min(MAX_TIMELINE_ROWS, Math.ceil(recent.length / visibleColumns)))
    : visibleRows;

  const safeRows = Math.min(visibleRows, availableRows);

  const visibleItems = recent.slice(0, visibleColumns * safeRows);

  const canExpand = recent.length > visibleItems.length && safeRows < MAX_TIMELINE_ROWS;
  useLayoutEffect(() => {
    const timeline = timelineRef.current as HTMLElement | null;
    if (!timeline) return undefined;
    const update = () =>
      setVisibleColumns(
        Math.max(
          1,
          Math.min(
            MAX_TIMELINE_COLUMNS,
            Math.floor(
              (timeline.clientWidth + TIMELINE_GAP) / (TIMELINE_MIN_CARD_WIDTH + TIMELINE_GAP),
            ),
          ),
        ),
      );
    update();
    const observer = new ResizeObserver(update);
    observer.observe(timeline);

    return () => observer.disconnect();
  }, []);
  useEffect(() => {
    window.localStorage.setItem(TIMELINE_ROWS_STORAGE_KEY, String(safeRows));
  }, [safeRows]);

  return (
    <div className={`timelineDock ${canExpand || safeRows > 1 ? "hasTimelineControls" : ""}`}>
      <footer
        className={`timeline timelineRows${safeRows}`}
        ref={timelineRef}
        style={{ "--timeline-columns": visibleColumns } as CSSProperties}
      >
        {error && <div className="warning">{error}</div>}
        {visibleItems.map((attack: TimelineAttackGroup) => (
          <article
            className={`${getAgeClass(attack.createdAt)} clickable`}
            key={`${attack.id}-timeline`}
            onClick={() => onSelectGroup(attack)}
          >
            <span>{formatTime(attack.createdAt)}</span>
            <strong>{attack.ip || "unknown"}</strong>
            <p>
              {attack.country} · {attack.totalCount} alerts · {attack.scenario}
            </p>
          </article>
        ))}
      </footer>
      {(canExpand || safeRows > 1) && (
        <div className="timelineControls">
          <button
            type="button"
            onClick={() => setVisibleRows((rows) => Math.min(MAX_TIMELINE_ROWS, rows + 1))}
            disabled={!canExpand}
          >
            <ChevronUp size={16} />
          </button>
          <button
            type="button"
            onClick={() => setVisibleRows((rows) => Math.max(1, rows - 1))}
            disabled={safeRows <= 1}
          >
            <ChevronDown size={16} />
          </button>
        </div>
      )}
    </div>
  );
}
