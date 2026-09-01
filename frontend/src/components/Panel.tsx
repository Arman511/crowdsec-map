import { JSX, useEffect, useLayoutEffect, useRef, useState } from "react";

import { EMPTY_RANK_ITEMS, RANK_MODES, RANK_MODE_STORAGE_PREFIX } from "../constants";
import type { ActiveBan, RankItem } from "../types";
import { readStoredRankMode } from "../utils";

export function Panel({
  rankings,
  initialMode,
  storageKey,
  wide = false,
}: {
  rankings: Record<string, RankItem[] | ActiveBan[]>;
  initialMode: string;
  storageKey: string;
  wide?: boolean;
}) {
  const [mode, setMode] = useState(() => readStoredRankMode(storageKey, initialMode));

  const [visibleCount, setVisibleCount] = useState(Number.POSITIVE_INFINITY);

  const panelRef = useRef<HTMLElement | null>(null);

  const headerRef = useRef<HTMLDivElement | null>(null);

  const measureRef = useRef<HTMLDivElement | null>(null);

  const items = rankings[mode as string] || EMPTY_RANK_ITEMS;

  const isBanMode = mode === "bans";

  const max = Math.max(
    ...items.map((item: RankItem | ActiveBan) => ("count" in item ? (item.count ?? 0) : 1)),
    1,
  );

  const collapsedLimit = Number.isFinite(visibleCount) ? Math.max(1, visibleCount) : items.length;

  const visibleItems = items.slice(0, collapsedLimit);

  const hasMore = items.length > collapsedLimit;

  useEffect(() => {
    window.localStorage.setItem(`${RANK_MODE_STORAGE_PREFIX}:${storageKey}`, mode as string);
  }, [mode, storageKey]);

  useLayoutEffect(() => {
    const panel = panelRef.current;

    const header = headerRef.current;

    const measure = measureRef.current;
    if (!panel || !header || !measure) return undefined;
    const updateVisibleCount = () => {
      const rows = [...measure.querySelectorAll(".rankRow")];
      if (!rows.length) {
        setVisibleCount(Number.POSITIVE_INFINITY);

        return;
      }
      const panelStyles = window.getComputedStyle(panel);

      const listStyles = window.getComputedStyle(measure);

      const panelPadding =
        parseFloat(panelStyles.paddingTop) + parseFloat(panelStyles.paddingBottom);

      const listGap = parseFloat((listStyles.rowGap || listStyles.gap || "0") as string);

      const headerBottom =
        ((header as HTMLElement).offsetHeight as number) +
        parseFloat((window.getComputedStyle(header).marginBottom as string) || "0");

      const rowHeight = Math.max(...rows.map((row: Element) => (row as HTMLElement).offsetHeight));

      const available = panel.clientHeight - panelPadding - headerBottom - 30;

      const possible = Math.floor((available + listGap) / (rowHeight + listGap));
      if (rows.length * rowHeight + Math.max(0, rows.length - 1) * listGap <= available)
        setVisibleCount(Number.POSITIVE_INFINITY);
      else setVisibleCount(Math.max(1, possible));
    };
    updateVisibleCount();
    const observer = new ResizeObserver(updateVisibleCount);
    observer.observe(panel);
    observer.observe(measure);

    return () => observer.disconnect();
  }, [items]);

  const row = (item: RankItem | ActiveBan, key: string): JSX.Element => {
    return (
      <div className={isBanMode ? "rankRow banRow" : "rankRow"} key={key}>
        <span title={item.label}>{item.label}</span>
        {isBanMode ? (
          <em title={item.detail || item.meta || ""}>{item.meta || item.detail || "active"}</em>
        ) : (
          <>
            <div className="bar">
              <i style={{ width: `${Math.max(8, ((item as RankItem).count / max) * 100)}%` }} />
            </div>
            <strong>{(item as RankItem).count}</strong>
          </>
        )}
      </div>
    );
  };

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
        {visibleItems.map((item) =>
          row(item, String((item as unknown as Record<string, unknown>).label)),
        )}
      </div>
      {hasMore && <div className="rankOverflowHint" aria-hidden="true" />}
      <div className="rankList rankMeasure" ref={measureRef} aria-hidden="true">
        {items.map((item) =>
          row(item, `${String((item as unknown as Record<string, unknown>).label)}-measure`),
        )}
      </div>
    </section>
  );
}
