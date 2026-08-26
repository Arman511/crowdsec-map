import { ShieldAlert } from "lucide-react";
import { Metric } from "./Metric";

export function DecisionBlockedIpSummary({ total, origins }) {
    return (
        <section className="decisionBlockedIpSummary" aria-label="Blocked IP address summary">
            <Metric icon={<ShieldAlert />} label="Blocked IP addresses" value={total} />
            <div className="decisionBlockedIpOrigins" aria-label="Blocked IP addresses by decision origin">
                {origins.map((origin) => <div className={`decisionOrigin decisionOrigin--${origin.key}`} key={origin.key}><span>{origin.label}</span><strong>{origin.count}</strong></div>)}
                {!origins.length && <span className="decisionOriginEmpty">No IP decisions</span>}
            </div>
        </section>
    );
}
