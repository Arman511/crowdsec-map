import { geoEqualEarth, geoPath } from "d3-geo";
import { Maximize2 } from "lucide-react";
import { useMemo } from "react";
import { feature } from "topojson-client";
import world from "world-atlas/countries-110m.json";

import { HOME, MAX_MAP_POINTS, MAX_SIGNAL_PATHS } from "../constants";
import {
  compactMapAttacks,
  createArcPath,
  getAgeClass,
  getAttackMarkerRadii,
  getSignalDuration,
} from "../utils";

import type { Alert, MapGroup } from "../types";
import type { Feature } from "geojson";
import "../styles/components/LiveMap.scss";

const countries =
  (
    feature(
      world as any,
      ((world as Record<string, unknown>).objects as unknown as { countries: unknown })
        .countries as any,
    ) as unknown as { features?: Feature[] }
  ).features || [];

export function WorldMap({
  attacks,
  showPaths = true,
  initialLoading = false,
  expanded = false,
  onExpand,
  onSelectPoint,
}: {
  attacks: Alert[];
  showPaths?: boolean;
  initialLoading?: boolean;
  expanded?: boolean;
  onExpand: () => void;
  onSelectPoint?: (g: MapGroup | null) => void;
}) {
  const projection = useMemo(() => geoEqualEarth().fitSize([1120, 590], { type: "Sphere" }), []);

  const path = useMemo(() => geoPath(projection), [projection]);

  const homePoint = projection([HOME.longitude, HOME.latitude]);

  const plotted = useMemo(
    () =>
      compactMapAttacks(attacks)
        .slice(0, MAX_MAP_POINTS)
        .map((attack) => {
          const point = projection([attack.longitude, attack.latitude]);

          return point ? { ...attack, x: point[0], y: point[1] } : null;
        })
        .filter(Boolean),
    [attacks, projection],
  );

  const activePaths = (showPaths ? plotted.slice(0, MAX_SIGNAL_PATHS) : []).map((attack) => {
    const hp = homePoint as [number, number];

    return {
      ...attack,
      arcPath: createArcPath({ ...attack, hx: hp[0], hy: hp[1] }),
    };
  });

  return (
    <div
      className={`mapWrap ${expanded ? "mapWrapExpanded" : ""}`}
      onClick={!expanded ? onExpand : undefined}
      role={!expanded ? "button" : undefined}
      tabIndex={!expanded ? 0 : undefined}
    >
      {!expanded && (
        <button
          type="button"
          className="mapExpandButton"
          title="Expand live map"
          aria-label="Expand live map"
          aria-expanded={expanded}
          onClick={(event) => {
            event.stopPropagation();
            onExpand?.();
          }}
        >
          <Maximize2 size={16} />
        </button>
      )}
      {initialLoading && (
        <div className="mapLoadingStatus" role="status">
          Loading live data...
        </div>
      )}
      <svg viewBox="0 0 1120 590" role="img" aria-label="World map of CrowdSec alerts">
        <defs>
          <radialGradient id="pulse" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#ffcf6e" stopOpacity="0.95" />
            <stop offset="100%" stopColor="#ff4d6d" stopOpacity="0.05" />
          </radialGradient>
        </defs>
        <path className="sphere" d={path({ type: "Sphere" }) ?? ""} />
        {countries.map((country, index: number) => (
          <path
            className="country"
            d={path(country) ?? ""}
            key={`${(country.id as string) || "country"}-${index}`}
          />
        ))}
        {activePaths.map((attack) => (
          <path
            className={`arc ${getAgeClass(attack.createdAt)}`}
            d={attack.arcPath}
            key={`${attack.id}-arc`}
          />
        ))}
        {activePaths.map((attack, index) => (
          <circle
            className={`signalRunner ${getAgeClass(attack.createdAt)}`}
            r={Math.min(4.5, 2.4 + attack.count / 7)}
            key={`${attack.id}-runner`}
          >
            <animateMotion
              dur={`${getSignalDuration(attack.count, index)}s`}
              begin={`${(index % 7) * -0.55}s`}
              repeatCount="indefinite"
              path={attack.arcPath}
            />
          </circle>
        ))}
        <circle
          className="homeRing"
          cx={(homePoint as [number, number])[0]}
          cy={(homePoint as [number, number])[1]}
          r="11"
        />
        <circle
          className="homeDot"
          cx={(homePoint as [number, number])[0]}
          cy={(homePoint as [number, number])[1]}
          r="4"
        />
        {plotted.map((attack) => {
          const radii = getAttackMarkerRadii(attack.count);

          return (
            <g
              className={`attackPoint ${getAgeClass(attack.createdAt)} ${expanded ? "interactive" : ""}`}
              key={attack.id}
              onClick={
                expanded
                  ? (event) => {
                      event.stopPropagation();
                      onSelectPoint?.(attack);
                    }
                  : undefined
              }
            >
              <circle cx={attack.x} cy={attack.y} r={radii.glow} fill="url(#pulse)" />
              <circle cx={attack.x} cy={attack.y} r={radii.core} />
              <title>{`${attack.country} ${attack.sourceCount} source${attack.sourceCount === 1 ? "" : "s"} ${attack.scenario}`}</title>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
