import { ChevronDown, ChevronUp, Crosshair, Globe2, Search, ShieldAlert } from "lucide-react";
import { useCallback, useEffect, useState } from "react";

import { DecisionBlockedIpSummary } from "../components/DecisionBlockedIpSummary";
import { DecisionRanks } from "../components/DecisionRanks";
import { Metric } from "../components/Metric";
import { formatRelativeTime, isIpv4 } from "../utils";

import type { DecisionsResponse } from "../types";


export function DecisionsPage({
  onSelectIp,
  refreshSeconds,
  refreshSignal,
}: {
  onSelectIp: (ip: string) => void;
  refreshSeconds: number;
  refreshSignal: number;
}) {
  const [decisions, setDecisions] = useState<DecisionsResponse | null>(null);

  const [query, setQuery] = useState("");

  const [appliedQuery, setAppliedQuery] = useState("");

  const [offset, setOffset] = useState(0);

  const [sort, setSort] = useState("");

  const [direction, setDirection] = useState("asc");

  const [loading, setLoading] = useState(true);

  const [error, setError] = useState("");

  const loadDecisions = useCallback(
    async (refresh = false) => {
      setLoading(true);
      setError("");
      try {
        const params = new URLSearchParams({
          limit: "50",
          offset: String(offset),
        });
        if (appliedQuery) params.set("search", appliedQuery);
        if (sort) {
          params.set("sort", sort);
          params.set("direction", direction);
        }
        if (refresh) params.set("refresh", "1");
        const response = await fetch(`/api/decisions?${params}`);

        const payload = (await response.json()) as DecisionsResponse;
        if (!response.ok) throw new Error(payload.error || `HTTP ${response.status}`);
        setDecisions(payload);
      } catch (loadError) {
        setError(loadError instanceof Error ? loadError.message : String(loadError));
      } finally {
        setLoading(false);
      }
    },
    [appliedQuery, direction, offset, sort],
  );

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

  const applySearch = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setOffset(0);
    setAppliedQuery(query.trim());
  };

  const changeSort = (field: string) => {
    setOffset(0);
    if (sort === field) setDirection((value) => (value === "asc" ? "desc" : "asc"));
    else {
      setSort(field);
      setDirection("asc");
    }
  };

  const sortHeader = (field: string, label: string) => (
    <button
      type="button"
      className={sort === field ? "active" : ""}
      onClick={() => changeSort(field)}
      aria-label={`Sort by ${label}`}
    >
      <span>{label}</span>
      {sort === field &&
        (direction === "asc" ? <ChevronUp size={14} /> : <ChevronDown size={14} />)}
    </button>
  );

  return (
    <section className="decisionsView">
      <div className="decisionsControls">
        <form onSubmit={applySearch}>
          <Search size={16} />
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search, e.g. origin=capi or scenario=/http-.*/i"
            title="Field filters: value, scope, country, scenario, origin, duration, until. Regex: /pattern/i"
          />
          <button type="submit">Search</button>
        </form>
      </div>
      <div className="decisionsSummary">
        <Metric icon={<ShieldAlert />} label="All Decisions" value={decisions?.total || 0} />
        <Metric icon={<Search />} label="Matching" value={decisions?.matched || 0} />
        <Metric icon={<Globe2 />} label="Countries" value={decisions?.countries || 0} />
        <Metric icon={<Crosshair />} label="Scenarios" value={decisions?.scenarios || 0} />
      </div>
      <DecisionBlockedIpSummary
        total={decisions?.uniqueBlockedIps || 0}
        origins={decisions?.blockedIpsByOrigin || []}
      />
      <div className="decisionRankingStrip">
        <DecisionRanks title="Top scenarios" items={decisions?.topScenarios || []} />
        <DecisionRanks title="Top countries" items={decisions?.topCountries || []} />
        <DecisionRanks title="Top origins" items={decisions?.topOrigins || []} />
      </div>
      <div className="decisionsTableWrap">
        {error && <div className="warning">decisions: {error}</div>}
        {!error && loading && !decisions && (
          <div className="modalLoading">Loading CrowdSec enforcement decisions...</div>
        )}
        {!error && decisions && (
          <table className="decisionsTable">
            <thead>
              <tr>
                <th>{sortHeader("value", "Value")}</th>
                <th>{sortHeader("scope", "Scope")}</th>
                <th>{sortHeader("country", "Country")}</th>
                <th>{sortHeader("scenario", "Scenario / blocklist")}</th>
                <th>{sortHeader("origin", "Origin")}</th>
                <th>{sortHeader("duration", "Duration / until")}</th>
              </tr>
            </thead>
            <tbody>
              {decisions.items.map((item) => (
                <tr
                  className={isIpv4(item.ip) ? "clickableRow" : ""}
                  key={item.id}
                  onClick={() => isIpv4(item.ip) && onSelectIp(item.ip)}
                >
                  <td>
                    <strong>{item.ip || item.value || "unknown"}</strong>
                  </td>
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
          <button
            type="button"
            disabled={offset === 0 || loading}
            onClick={() => setOffset((value) => Math.max(0, value - 50))}
          >
            Previous
          </button>
          <strong>
            {offset + 1}–{Math.min(offset + 50, decisions?.matched || 0)} of{" "}
            {decisions?.matched || 0}
          </strong>
          <button
            type="button"
            disabled={decisions?.nextOffset == null || loading}
            onClick={() => decisions?.nextOffset != null && setOffset(decisions.nextOffset)}
          >
            Next
          </button>
        </div>
      </footer>
    </section>
  );
}
