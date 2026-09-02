import { ArrowUpRight, X } from "lucide-react";
import { useEffect } from "react";
import type * as React from "react";

import { formatTime, groupEventSources, readableScenario } from "../utils";

import type { Alert, EventDrilldown, MapGroup } from "../types";
import "../styles/components/ExpandedMapModal.scss";

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
  WorldMap,
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
  WorldMap: React.ComponentType<Record<string, unknown>>;
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
            <WorldMap attacks={attacks} expanded onExpand={onClose} onSelectPoint={onSelectGroup} />
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
