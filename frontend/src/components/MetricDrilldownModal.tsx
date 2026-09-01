import { Search, X } from "lucide-react";
import React, { useEffect, useMemo, useState } from "react";

import { EMPTY_RANK_ITEMS, METRIC_PAGE_SIZE } from "../constants";
import { formatRelativeTime, groupCounts } from "../utils";

import type { ActiveBan, Alert, AttacksResponse } from "../types";


export function MetricDrilldownModal({
  data,
  initialMode,
  onClose,
  onSelectIp,
}: {
  data: AttacksResponse;
  initialMode: string;
  onClose: () => void;
  onSelectIp: (ip: string) => void;
}) {
  const [mode, setMode] = useState(initialMode);

  const [query, setQuery] = useState("");

  const [page, setPage] = useState(0);

  const [alertFilter, setAlertFilter] = useState<{ field: string; value: string } | null>(null);

  const alerts = (data?.alerts as Alert[]) || EMPTY_RANK_ITEMS;

  const bans = (data?.activeBans as ActiveBan[]) || EMPTY_RANK_ITEMS;

  const grouped = useMemo(
    () => ({
      countries: groupCounts(alerts, "country"),
      scenarios: groupCounts(alerts, "scenario"),
    }),
    [alerts],
  );

  const rows: Array<Record<string, unknown>> = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (mode === "bans") {
      return (bans as unknown[]).filter((item: unknown) => {
        const ban = item as ActiveBan;

        return [ban.ip, ban.country, ban.scenario, ban.duration].some((value: unknown) =>
          String(value || "")
            .toLowerCase()
            .includes(needle),
        );
      }) as unknown as Array<Record<string, unknown>>;
    }
    if (mode === "countries" || mode === "scenarios") {
      return (
        grouped[mode as keyof typeof grouped] as unknown as Array<Record<string, unknown>>
      ).filter((item: Record<string, unknown>) =>
        String(item.label).toLowerCase().includes(needle),
      );
    }

    return (alerts as unknown[]).filter((item: unknown) => {
      const alert = item as Alert;

      return (
        (!alertFilter ||
          String(alert[alertFilter.field as keyof Alert] || "unknown") === alertFilter.value) &&
        [alert.ip, alert.country, alert.scenario, alert.createdAt].some((value: unknown) =>
          String(value || "")
            .toLowerCase()
            .includes(needle),
        )
      );
    }) as unknown as Array<Record<string, unknown>>;
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
              {rows.length} matching entries · {(data?.source as string) || "unknown"}
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
          {visibleRows.map((item: Record<string, unknown>, index: number) =>
            mode === "countries" || mode === "scenarios" ? (
              <button
                type="button"
                className="metricResultRow groupResult"
                key={item.label as string}
                onClick={() =>
                  openGroup(mode === "countries" ? "country" : "scenario", item.label as string)
                }
              >
                <strong>{(item.label as string) || "unknown"}</strong>
                <span>{item.count as number} log events</span>
              </button>
            ) : (
              <button
                type="button"
                className="metricResultRow"
                key={`${(item.id || item.ip || item.value) as string}-${index}`}
                onClick={() => item.ip && onSelectIp(item.ip as string)}
                disabled={!item.ip}
              >
                <time>
                  {formatRelativeTime(item.createdAt as string | number | Date | undefined)}
                </time>
                <strong>{(item.ip as string) || "No IP"}</strong>
                <span>{(item.country as string) || "??"}</span>
                <span title={item.scenario as string}>
                  {(item.scenario as string) || "unknown"}
                </span>
                <em>
                  {mode === "bans"
                    ? (item.duration as string) || "active"
                    : `${(item.count as number) || 1} events`}
                </em>
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
