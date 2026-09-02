import { Activity, AlertTriangle, Globe2, ShieldAlert, UserRoundSearch } from "lucide-react";
import { useMemo } from "react";

import { buildAnomaly, buildRankings } from "../utils";

import { Metric } from "./Metric";

import type { ActiveBan, Alert, AttacksResponse, RankItem, Totals } from "../types";
import type * as React from "react";
import "../styles/components/Sidebar.scss";

export function Sidebar({
  data,
  totals,
  attacks,
  onOpenMetric,
  Panel,
  appVersion,
}: {
  data?: AttacksResponse;
  totals: Totals;
  attacks: Alert[];
  onOpenMetric: (mode: string) => void;
  Panel: React.ComponentType<{
    rankings: Record<string, RankItem[] | ActiveBan[]>;
    initialMode: string;
    storageKey: string;
    wide?: boolean;
  }>;
  appVersion: string;
}) {
  const rankings = useMemo(
    () => buildRankings(data?.alerts || [], data?.activeBans || []),
    [data?.alerts, data?.activeBans],
  );

  const uniqueAttackers = useMemo(
    () => new Set((data?.alerts || []).map((item: Alert) => item.ip).filter(Boolean)).size,
    [data?.alerts],
  );

  const anomaly = useMemo(() => buildAnomaly(attacks), [attacks]);

  return (
    <aside className="sidebar">
      <div className="brand">
        <span className="brandMark">
          <ShieldAlert size={22} />
        </span>
        <div>
          <h1>CrowdSec Map</h1>
          <p>
            Live attacks <small>{appVersion}</small>
          </p>
        </div>
      </div>
      <div className="metricGrid">
        <Metric
          icon={<Activity />}
          label="Current Alerts"
          value={totals.alerts || 0}
          onClick={() => onOpenMetric("alerts")}
        />
        <Metric
          icon={<UserRoundSearch />}
          label="Unique Attackers"
          value={uniqueAttackers}
          onClick={() => onOpenMetric("alerts")}
        />
        <Metric
          icon={<Globe2 />}
          label="Countries"
          value={totals.countries || 0}
          onClick={() => onOpenMetric("countries")}
        />
        <Metric
          icon={<ShieldAlert />}
          label="Active Bans"
          value={totals.activeBans || 0}
          onClick={() => onOpenMetric("bans")}
        />
      </div>
      <Panel rankings={rankings} initialMode="countries" storageKey="top" />
      <Panel rankings={rankings} initialMode="ips" storageKey="bottom" wide />
      <div className="anomalyCard">
        <AlertTriangle size={17} />
        <div>
          <strong>{anomaly ? "Activity concentration" : "No anomaly detected"}</strong>
          <p>{anomaly || "Attack distribution is currently stable."}</p>
        </div>
      </div>
    </aside>
  );
}
