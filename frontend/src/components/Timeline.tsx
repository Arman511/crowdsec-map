import { ChevronUp, ChevronDown } from "lucide-react";
import { useMemo, useState, useRef, useLayoutEffect, useEffect, type CSSProperties } from "react";

import {
  MAX_TIMELINE_COLUMNS,
  MAX_TIMELINE_ROWS,
  TIMELINE_GAP,
  TIMELINE_MIN_CARD_WIDTH,
  TIMELINE_ROWS_STORAGE_KEY,
} from "../constants";
import { compactTimelineAttacks, readStoredTimelineRows, getAgeClass, formatTime } from "../utils";

import type { Alert, TimelineAttackGroup } from "../types";
import "../styles/components/Timeline.scss";
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

  const timelineRef = useRef<HTMLElement | null>(null);

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
    try {
      window.localStorage.setItem(TIMELINE_ROWS_STORAGE_KEY, String(safeRows));
    } catch {
      // Ignore localStorage errors
    }
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
            role="button"
            tabIndex={0}
            onClick={() => onSelectGroup(attack)}
            onKeyDown={(event) => {
              if (event.key === "Enter" || event.key === " ") {
                event.preventDefault();
                onSelectGroup(attack);
              }
            }}
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
