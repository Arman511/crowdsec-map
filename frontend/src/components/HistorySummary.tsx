import { Activity, BarChart3, Timer } from "lucide-react";
import { Metric } from "./Metric";

export function HistorySummary({ history, days }: { history: any; days: number }) {
  return (
    <>
      <Metric icon={<BarChart3 />} label="Groups" value={history?.items?.length || 0} />
      <Metric icon={<Activity />} label="Recorded Alerts" value={history?.matchedEvents || 0} />
      <Metric icon={<Timer />} label="Window" value={`${history?.days || days}d`} />
    </>
  );
}
