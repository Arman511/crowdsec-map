import {
  HISTORY_GROUP_OPTIONS,
  MAX_TIMELINE_COLUMNS,
  MAX_TIMELINE_ROWS,
  RANK_MODES,
  RANK_MODE_STORAGE_PREFIX,
  REFRESH_OPTIONS,
  REFRESH_STORAGE_KEY,
  THEME_STORAGE_KEY,
  TIMELINE_ROWS_STORAGE_KEY,
} from "./constants";

export function groupEventSources(attacks) {
  const sources = new Map();
  for (const attack of attacks) {
    const ip = attack.ip || "unknown";
    const current = sources.get(ip) || {
      ip,
      country: attack.country,
      asn: attack.asn || attack.asName,
      attempts: 0,
      scenarios: new Set(),
    };
    current.attempts += Number(attack.count) || 1;
    if (attack.scenario)
      current.scenarios.add(readableScenario(attack.scenario));
    sources.set(ip, current);
  }
  return [...sources.values()]
    .map((source) => ({
      ...source,
      scenarios: [...source.scenarios].slice(0, 3),
    }))
    .sort((a, b) => b.attempts - a.attempts);
}

export function buildTrendBuckets(attacks, bucketCount) {
  if (!attacks.length)
    return Array.from({ length: bucketCount }, (_, index) => ({
      key: index,
      label: "-",
      count: 0,
      attacks: [],
    }));
  let newest = 0;
  let oldest = Number.POSITIVE_INFINITY;
  for (const item of attacks) {
    const timestamp = new Date(item.createdAt).getTime();
    if (!Number.isFinite(timestamp)) continue;
    newest = Math.max(newest, timestamp);
    oldest = Math.min(oldest, timestamp);
  }
  if (!Number.isFinite(oldest) || newest <= oldest) oldest = newest - 3600000;
  const rawStep = Math.max(60000, (newest - oldest) / bucketCount);
  const steps = [
    60000, 300000, 900000, 1800000, 3600000, 7200000, 10800000, 21600000,
    43200000, 86400000,
  ];
  const step =
    steps.find((value) => value >= rawStep) ||
    Math.ceil(rawStep / 86400000) * 86400000;
  const rangeEnd = Math.ceil(newest / step) * step;
  const rangeStart = rangeEnd - bucketCount * step;
  const spansMultipleDays =
    new Date(rangeStart).toDateString() !==
    new Date(rangeEnd - 1).toDateString();
  const buckets = Array.from({ length: bucketCount }, (_, index) => {
    const timestamp = rangeStart + index * step;
    const date = new Date(timestamp);
    return {
      key: timestamp,
      label: date.toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
      }),
      dateLabel: spansMultipleDays
        ? date.toLocaleDateString("de-CH", { day: "2-digit", month: "2-digit" })
        : "",
      count: 0,
      attacks: [],
    };
  });
  for (const item of attacks) {
    const timestamp = new Date(item.createdAt).getTime();
    if (!Number.isFinite(timestamp)) continue;
    const index = Math.min(
      bucketCount - 1,
      Math.max(0, Math.floor((timestamp - rangeStart) / step)),
    );
    buckets[index].count += Number(item.count) || 1;
    buckets[index].attacks.push(item);
  }
  return buckets.reverse();
}

export function buildFilterOptions(attacks) {
  const countriesSet = new Set();
  const scenariosSet = new Set();
  for (const item of attacks) {
    if (item.country) countriesSet.add(item.country);
    if (item.scenario) scenariosSet.add(item.scenario);
  }
  return {
    countries: [...countriesSet].sort(),
    scenarios: [...scenariosSet].sort(),
  };
}

export function filterAttacks(attacks, filters) {
  const needle = filters.query.trim().toLowerCase();
  const ageMs =
    filters.age === "15m"
      ? 900000
      : filters.age === "1h"
        ? 3600000
        : filters.age === "24h"
          ? 86400000
          : 0;
  const now = Date.now();
  return attacks.filter((item) => {
    if (filters.country !== "all" && item.country !== filters.country)
      return false;
    if (filters.scenario !== "all" && item.scenario !== filters.scenario)
      return false;
    if (ageMs && now - new Date(item.createdAt).getTime() > ageMs) return false;
    if (!needle) return true;
    return [item.ip, item.country, item.scenario, item.asn, item.asName].some(
      (value) =>
        String(value || "")
          .toLowerCase()
          .includes(needle),
    );
  });
}

export function buildAnomaly(attacks) {
  if (attacks.length < 8) return "";
  const scenarios = groupCounts(attacks, "scenario");
  const top = scenarios[0];
  const totalAttempts = attacks.reduce(
    (total, item) => total + Number(item.count || 1),
    0,
  );
  if (!top || !totalAttempts || top.count / totalAttempts < 0.45) return "";
  return `${readableScenario(top.label)} accounts for ${Math.round((top.count / totalAttempts) * 100)}% of the filtered attempts.`;
}

export function readableScenario(value) {
  return String(value || "Unknown")
    .replace(/^crowdsecurity\//, "")
    .replace(/[-_]/g, " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

export function clampLineLimit(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) {
    return 50;
  }
  return Math.max(1, Math.min(200, Math.round(number)));
}

export function buildZoraxyTimestampWarning(source, sources, timestamp) {
  const sourceMonth = parseZoraxyLogMonth(source?.name);
  const timestampMonth = parseTimestampMonth(timestamp);
  if (
    !sourceMonth ||
    !timestampMonth ||
    sourceMonth.key === timestampMonth.key
  ) {
    return null;
  }

  const matchingSource = sources.find(
    (candidate) =>
      parseZoraxyLogMonth(candidate.name)?.key === timestampMonth.key,
  );
  const message = matchingSource
    ? `The timestamp is from ${formatYearMonth(timestampMonth)}, but ${source.name} is ${formatYearMonth(sourceMonth)}.`
    : `The timestamp is from ${formatYearMonth(timestampMonth)}, but ${source.name} is ${formatYearMonth(sourceMonth)}. No matching Zoraxy log was found.`;

  return {
    message,
    matchingSource,
  };
}

export function parseZoraxyLogMonth(name) {
  const match = String(name || "").match(/^zr_(\d{4})-(\d{1,2})\.log$/i);
  if (!match) {
    return null;
  }
  const year = Number(match[1]);
  const month = Number(match[2]);
  if (
    !Number.isInteger(year) ||
    !Number.isInteger(month) ||
    month < 1 ||
    month > 12
  ) {
    return null;
  }
  return {
    year,
    month,
    key: year * 100 + month,
  };
}

export function parseTimestampMonth(value) {
  const match = String(value || "").match(/^(\d{4})-(\d{2})-\d{2}/);
  if (!match) {
    return null;
  }
  const year = Number(match[1]);
  const month = Number(match[2]);
  if (
    !Number.isInteger(year) ||
    !Number.isInteger(month) ||
    month < 1 ||
    month > 12
  ) {
    return null;
  }
  return {
    year,
    month,
    key: year * 100 + month,
  };
}

export function formatYearMonth(value) {
  return `${value.year}-${String(value.month).padStart(2, "0")}`;
}

export function formatBanSince(value) {
  return formatBanSinceCompact(value);
}

export function formatBanSinceCompact(value) {
  if (!value) {
    return "none";
  }

  const timestamp = new Date(value).getTime();
  if (!Number.isFinite(timestamp)) {
    return value;
  }

  const totalMinutes = Math.max(
    0,
    Math.round((Date.now() - timestamp) / 60000),
  );
  const hours = Math.floor(totalMinutes / 60);
  const minutes = totalMinutes % 60;
  if (hours > 0) {
    return `${hours}h ${pad2(minutes)}m ago`;
  }
  return `${minutes}m ago`;
}

export function formatBanSinceExact(value) {
  if (!value) {
    return "none";
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return (
    [date.getFullYear(), pad2(date.getMonth() + 1), pad2(date.getDate())].join(
      "-",
    ) + ` ${pad2(date.getHours())}:${pad2(date.getMinutes())}`
  );
}

export function formatBanRemaining(value) {
  const seconds = parseDurationSeconds(value);
  if (!Number.isFinite(seconds)) {
    return value ? `${value} left` : "none";
  }

  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  return `${hours}h ${pad2(minutes)}m left`;
}

export function buildActiveBanTitle(activeBans) {
  if (activeBans?.warning) {
    return `Active ban lookup failed: ${activeBans.warning}`;
  }
  if (!activeBans?.items?.length) {
    return "No active ban for this IP.";
  }
  return activeBans.items
    .map((ban) =>
      [
        `ID ${ban.id}`,
        ban.scenario,
        ban.origin && `origin ${ban.origin}`,
        ban.createdAt &&
          `since ${formatBanSinceExact(ban.createdAt)} (${ban.createdAt})`,
        ban.duration &&
          `remaining ${formatBanRemaining(ban.duration)} (${ban.duration})`,
        ban.until && `until ${ban.until}`,
      ]
        .filter(Boolean)
        .join(" · "),
    )
    .join("\n");
}

export function parseDurationSeconds(value) {
  const text = String(value || "");
  if (!text) {
    return NaN;
  }

  let seconds = 0;
  const regex = /(\d+)\s*(d|h|m|s)/g;
  let match;
  while ((match = regex.exec(text)) !== null) {
    const amount = Number(match[1]);
    if (match[2] === "d") {
      seconds += amount * 86400;
    } else if (match[2] === "h") {
      seconds += amount * 3600;
    } else if (match[2] === "m") {
      seconds += amount * 60;
    } else {
      seconds += amount;
    }
  }
  return seconds || NaN;
}

export function pad2(value) {
  return String(value).padStart(2, "0");
}

export function getAgeClass(createdAt) {
  const ageMinutes = (Date.now() - new Date(createdAt).getTime()) / 60000;

  if (!Number.isFinite(ageMinutes)) {
    return "ageOld";
  }
  if (ageMinutes <= 15) {
    return "ageHot";
  }
  if (ageMinutes <= 60) {
    return "ageWarm";
  }
  return "ageOld";
}

export function getSignalDuration(count, index) {
  const weightedCount = Math.max(1, Number(count || 1));
  const baseDuration = 8.2 - Math.min(4.2, Math.log2(weightedCount + 1) * 0.9);
  return Math.max(3.2, baseDuration + (index % 4) * 0.25).toFixed(2);
}

export function getAttackMarkerRadii(count) {
  const frequency = Math.log2(Math.max(1, Number(count || 1)) + 1);
  return {
    glow: Math.min(15, 4.5 + frequency * 1.4),
    core: Math.min(6, 2 + frequency * 0.55),
  };
}

export function compactMapAttacks(attacks) {
  const groups = new Map();

  for (const attack of attacks) {
    if (
      attack.latitude === null ||
      attack.latitude === undefined ||
      attack.longitude === null ||
      attack.longitude === undefined
    ) {
      continue;
    }
    const latitude = Number(attack.latitude);
    const longitude = Number(attack.longitude);
    if (!Number.isFinite(latitude) || !Number.isFinite(longitude)) {
      continue;
    }

    const key = [
      attack.country || "??",
      latitude.toFixed(1),
      longitude.toFixed(1),
      attack.scenario || "unknown",
    ].join("|");
    const existing = groups.get(key);

    if (existing) {
      existing.count += Number(attack.count || 1);
      existing.attacks.push(attack);
      if (attack.ip) existing.sourceIps.add(attack.ip);
      existing.sourceCount = existing.sourceIps.size;
      if (new Date(attack.createdAt) > new Date(existing.createdAt)) {
        existing.createdAt = attack.createdAt;
      }
      continue;
    }

    groups.set(key, {
      ...attack,
      id: `map-${key}`,
      latitude,
      longitude,
      count: Number(attack.count || 1),
      sourceCount: attack.ip ? 1 : 0,
      sourceIps: new Set(attack.ip ? [attack.ip] : []),
      attacks: [attack],
    });
  }

  return [...groups.values()]
    .map((group) => {
      const result = { ...group };
      delete result.sourceIps;
      return result;
    })
    .sort((a, b) => {
      if (b.count !== a.count) {
        return b.count - a.count;
      }
      return new Date(b.createdAt) - new Date(a.createdAt);
    });
}

export function createArcPath(attack) {
  const lift = Math.max(
    48,
    Math.min(128, Math.abs(attack.x - attack.hx) * 0.12),
  );
  return `M${attack.x},${attack.y} Q${(attack.x + attack.hx) / 2},${Math.min(attack.y, attack.hy) - lift} ${attack.hx},${attack.hy}`;
}

export function buildRankings(attacks, activeBans) {
  return {
    countries: groupCounts(attacks, "country"),
    ips: groupCounts(attacks, "ip"),
    scenarios: groupCounts(attacks, "scenario"),
    bans: activeBans.map((ban) => ({
      label: ban.ip,
      count: 1,
      meta: ban.duration || "active",
      detail: [ban.country, ban.scenario].filter(Boolean).join(" · "),
    })),
  };
}

export function groupCounts(items, field) {
  const counts = new Map();
  for (const item of items) {
    const key = item[field] || "unknown";
    counts.set(key, (counts.get(key) || 0) + Number(item.count || 1));
  }
  return [...counts.entries()]
    .map(([label, count]) => ({ label, count }))
    .sort((a, b) => {
      if (b.count !== a.count) {
        return b.count - a.count;
      }
      return a.label.localeCompare(b.label);
    });
}

export function compactTimelineAttacks(attacks) {
  const groups = new Map();

  for (const attack of attacks) {
    const minute = getMinuteKey(attack.createdAt);
    const ip = attack.ip || "unknown";
    const key = `${ip}|${minute}`;
    const count = Number(attack.count || 1);
    const existing = groups.get(key);

    if (existing) {
      existing.totalCount += count;
      existing.attacks.push(attack);
      existing.scenarioCounts.set(
        attack.scenario,
        (existing.scenarioCounts.get(attack.scenario) || 0) + count,
      );
      if (new Date(attack.createdAt) > new Date(existing.createdAt)) {
        existing.createdAt = attack.createdAt;
        existing.country = attack.country || existing.country;
      }
      existing.scenario = getTopScenario(existing.scenarioCounts);
      continue;
    }

    groups.set(key, {
      ...attack,
      id: `timeline-${key}`,
      ip,
      totalCount: count,
      attacks: [attack],
      scenarioCounts: new Map([[attack.scenario, count]]),
    });
  }

  return [...groups.values()]
    .map(({ scenarioCounts, ...attack }) => ({
      ...attack,
      scenario: getTopScenario(scenarioCounts),
    }))
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
    .slice(0, MAX_TIMELINE_COLUMNS * MAX_TIMELINE_ROWS);
}

export function getMinuteKey(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "unknown";
  }
  date.setSeconds(0, 0);
  return date.toISOString();
}

export function getTopScenario(counts) {
  return (
    [...counts.entries()].sort(
      (a, b) => b[1] - a[1] || a[0].localeCompare(b[0]),
    )[0]?.[0] || "unknown"
  );
}

export function readStoredRankMode(storageKey, fallback) {
  try {
    const stored = window.localStorage.getItem(
      `${RANK_MODE_STORAGE_PREFIX}:${storageKey}`,
    );
    return RANK_MODES.some(([value]) => value === stored) ? stored : fallback;
  } catch {
    return fallback;
  }
}

export function readStoredTimelineRows() {
  try {
    const stored = Number(
      window.localStorage.getItem(TIMELINE_ROWS_STORAGE_KEY),
    );
    return Number.isInteger(stored)
      ? Math.max(1, Math.min(MAX_TIMELINE_ROWS, stored))
      : 1;
  } catch {
    return 1;
  }
}

export function readStoredRefreshSeconds() {
  try {
    const stored = Number(window.localStorage.getItem(REFRESH_STORAGE_KEY));
    return REFRESH_OPTIONS.some(([value]) => value === stored) ? stored : 30;
  } catch {
    return 30;
  }
}

export function readStoredTheme() {
  try {
    return window.localStorage.getItem(THEME_STORAGE_KEY) === "light"
      ? "light"
      : "dark";
  } catch {
    return "dark";
  }
}

export function formatTime(value) {
  if (!value) {
    return "...";
  }
  return new Intl.DateTimeFormat("de-CH", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(new Date(value));
}

export function formatRefreshInterval(seconds) {
  if (seconds < 60) {
    return `${seconds}s`;
  }
  return `${seconds / 60}min`;
}

export function getHistoryGroupLabel(groupBy) {
  return (
    HISTORY_GROUP_OPTIONS.find(([value]) => value === groupBy)?.[1] || "Group"
  );
}

export function formatRelativeTime(value) {
  const timestamp = new Date(value).getTime();
  if (!Number.isFinite(timestamp)) {
    return "...";
  }

  const diffMinutes = Math.max(0, Math.round((Date.now() - timestamp) / 60000));
  if (diffMinutes < 60) {
    return `${diffMinutes}m ago`;
  }
  const diffHours = Math.round(diffMinutes / 60);
  if (diffHours < 48) {
    return `${diffHours}h ago`;
  }
  return `${Math.round(diffHours / 24)}d ago`;
}

export function formatCtiScore(value, scale) {
  if (value === null || value === undefined || value === "") {
    return "n/a";
  }
  const number = Number(value);
  if (!Number.isFinite(number)) {
    return "n/a";
  }
  if (scale === "percent") {
    return `${Math.round(number * 100)}%`;
  }
  return `${number}/10`;
}

export function isIpv4(value) {
  const parts = String(value || "").split(".");
  return (
    parts.length === 4 &&
    parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255)
  );
}
