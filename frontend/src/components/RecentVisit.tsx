import { formatRelativeTime } from "../utils";

import type { RecentVisitItem } from "../types";
import "../styles/components/RecentVisit.scss";

export function RecentVisit({ visit }: { visit: RecentVisitItem }) {
  return (
    <div className="hiddenRecentRow" key={`${visit.ts}-${visit.ip}-${visit.path}`}>
      <time>{formatRelativeTime(visit.ts)}</time>
      <strong title={visit.ip}>{visit.ip}</strong>
      <span>{visit.country || "??"}</span>
      <em title={visit.userAgent}>{visit.path}</em>
    </div>
  );
}
