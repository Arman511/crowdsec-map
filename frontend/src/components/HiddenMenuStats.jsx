import { Activity, Crosshair, Timer } from "lucide-react";
import { Metric } from "./Metric";

export function HiddenMenuStats() {
    return <>
        <Metric icon={<Activity />} label="24h visits" value={0} />
        <Metric icon={<Crosshair />} label="Unique IPs" value={0} />
        <Metric icon={<Timer />} label="Retention" value="0d" />
    </>;
}
