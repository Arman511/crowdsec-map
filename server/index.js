import path from "node:path";
import { fileURLToPath } from "node:url";
import express from "express";
import { readAccessSummary, recordAccessVisit } from "./accessLog.js";
import { config } from "./config.js";
import { readIpReputation, readReputationStats } from "./cti.js";
import { isIpAddress, readGroupIps, readHistorySummary, readIpHistory, recordHistory } from "./history.js";
import { readInvestigationLogLines, readInvestigationLogSources, readIpInvestigation, readProtectionSummary } from "./investigation.js";
import { autoConfigureLapiCredentials, getLapiCredentialsStatus } from "./lapiCredentials.js";
import { groupCounts } from "./normalize.js";
import { readPublicTargetIp } from "./publicIp.js";
import { readActiveBans, readCrowdSecData, readCscliIpDetails, readDemoDecisionOverview, readLapiDecisionOverview } from "./sources.js";
import { readImageUpdateStatus } from "./updateStatus.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
app.set("trust proxy", config.trustProxy);

// The dashboard often asks for the same data more than once while it starts
// (or when several browser tabs are open). Cache the assembled response, not
// just individual source calls, so Docker/LAPI and IP lookups are coalesced.
const attacksCache = new Map();

app.get("/api/health", async (_request, response) => {
  const publicTargetIp = await readPublicTargetIp();
  response.json({
    ok: true,
    source: config.dataSource,
    refreshSeconds: config.refreshSeconds,
    publicTargetIp: publicTargetIp.ip,
    publicTargetIpSource: publicTargetIp.source,
    publicTargetIpWarning: publicTargetIp.warning
  });
});

app.get("/api/attacks", async (request, response) => {
  response.json(await readAttacksResponse(request.query.source || "auto"));
});

async function readAttacksResponse(source) {
  const cacheKey = String(source || "auto");
  const now = Date.now();
  const cached = attacksCache.get(cacheKey);

  if (cached?.expiresAt > now) {
    return cached.value;
  }
  if (cached?.pending) {
    return cached.pending;
  }

  const pending = buildAttacksResponse(cacheKey)
    .then((value) => {
      attacksCache.set(cacheKey, {
        value,
        expiresAt: Date.now() + Math.max(0, config.attacksCacheSeconds) * 1000
      });
      return value;
    })
    .catch((error) => {
      attacksCache.delete(cacheKey);
      throw error;
    });

  attacksCache.set(cacheKey, { pending });
  return pending;
}

async function buildAttacksResponse(source) {
  const activeBansRequest = config.demoMode
    ? Promise.resolve({ activeBans: [], warning: "" })
    : readActiveBans()
      .then((activeBans) => ({ activeBans, warning: "" }))
      .catch((error) => ({ activeBans: [], warning: `active-bans: ${error.message}` }));

  // These calls are independent. Running them together makes the response
  // take roughly as long as the slowest source instead of their combined time.
  const [data, publicTargetIp, bans] = await Promise.all([
    readCrowdSecData(source),
    readPublicTargetIp(),
    activeBansRequest
  ]);

  // History persistence must not hold up the live map. It is idempotent and
  // errors are logged for diagnostics instead of failing the dashboard load.
  if (data.source !== "lapi-decisions") {
    recordHistory(data.alerts).catch((error) => console.error(`Could not record alert history: ${error.message}`));
  }

  return {
    ...data,
    activeBans: bans.activeBans,
    refreshSeconds: config.refreshSeconds,
    publicTargetIp: publicTargetIp.ip,
    publicTargetIpSource: publicTargetIp.source,
    demoMode: config.demoMode,
    warning: [data.warning, bans.warning, publicTargetIp.warning && `public-ip: ${publicTargetIp.warning}`].filter(Boolean).join(" | "),
    totals: {
      ...data.totals,
      activeBans: bans.activeBans.length
    },
    topCountries: groupCounts(data.alerts, "country"),
    topScenarios: groupCounts(data.alerts, "scenario")
  };
}

app.get("/api/history", async (request, response) => {
  response.json(await readHistorySummary({
    days: request.query.days,
    groupBy: request.query.groupBy
  }));
});

app.get("/api/decisions", async (request, response) => {
  if (config.demoMode) {
    response.json(await readDemoDecisionOverview({
      search: request.query.search,
      sort: request.query.sort,
      direction: request.query.direction,
      offset: request.query.offset,
      limit: request.query.limit
    }));
    return;
  }
  try {
    response.json(await readLapiDecisionOverview({
      search: request.query.search,
      sort: request.query.sort,
      direction: request.query.direction,
      offset: request.query.offset,
      limit: request.query.limit,
      refresh: request.query.refresh === "1"
    }));
  } catch (error) {
    response.status(error.name === "DecisionQueryError" ? 400 : 500).json({ error: error.message });
  }
});

app.get("/api/history/group", async (request, response) => {
  try {
    response.json(await readGroupIps({
      days: request.query.days,
      groupBy: request.query.groupBy,
      label: request.query.label
    }));
  } catch (error) {
    response.status(400).json({ error: error.message });
  }
});

app.get("/api/history/ip/:ip", async (request, response) => {
  if (!isIpAddress(request.params.ip)) {
    response.status(400).json({ error: "Invalid IP address" });
    return;
  }

  const history = await readIpHistory(request.params.ip, { days: request.query.days });
  let cscli = "";
  let cscliCommand = "";
  let cscliWarning = "";

  try {
    const cscliDetails = await readCscliIpDetails(request.params.ip);
    cscli = cscliDetails.output;
    cscliCommand = cscliDetails.command;
  } catch (error) {
    cscliWarning = error.message;
  }

  response.json({
    ...history,
    cscli,
    cscliCommand,
    cscliWarning,
    note: "CrowdSec alert records, not active bans. History is filtered by the selected window; raw details depend on CrowdSec alert retention."
  });
});

app.get("/api/reputation/stats", async (_request, response) => {
  try {
    response.json(await readReputationStats());
  } catch (error) {
    response.status(500).json({ error: error.message });
  }
});

app.get("/api/lapi/credentials/status", async (_request, response) => {
  try {
    response.json(await getLapiCredentialsStatus());
  } catch (error) {
    response.status(500).json({ error: error.message });
  }
});

app.get("/api/reputation/ip/:ip", async (request, response) => {
  if (!isIpAddress(request.params.ip)) {
    response.status(400).json({ error: "Invalid IP address" });
    return;
  }

  try {
    response.json(await readIpReputation(request.params.ip, { force: request.query.refresh === "1" }));
  } catch (error) {
    response.status(502).json({ error: error.message });
  }
});

app.get("/api/investigation/ip/:ip", async (request, response) => {
  if (!isIpAddress(request.params.ip)) {
    response.status(400).json({ error: "Invalid IP address" });
    return;
  }

  try {
    response.json(await readIpInvestigation(request.params.ip, {
      days: request.query.days,
      maxLines: request.query.maxLines
    }));
  } catch (error) {
    response.status(500).json({ error: error.message });
  }
});

app.get("/api/investigation/ip/:ip/log-lines", async (request, response) => {
  if (!isIpAddress(request.params.ip)) {
    response.status(400).json({ error: "Invalid IP address" });
    return;
  }

  try {
    response.json(await readInvestigationLogLines(request.params.ip, {
      days: request.query.days,
      path: request.query.path,
      offset: request.query.offset,
      limit: request.query.limit,
      filter: request.query.filter,
      sort: request.query.sort,
      search: request.query.search
    }));
  } catch (error) {
    response.status(400).json({ error: error.message });
  }
});

app.get("/api/investigation/sources", async (_request, response) => {
  try {
    response.json(await readInvestigationLogSources());
  } catch (error) {
    response.status(500).json({ error: error.message });
  }
});

app.get("/api/protection", async (request, response) => {
  try {
    response.json(await readProtectionSummary({ days: request.query.days }));
  } catch (error) {
    response.status(500).json({ error: error.message });
  }
});

app.get("/api/system/update-status", async (_request, response) => {
  try {
    response.json(await readImageUpdateStatus());
  } catch (error) {
    response.status(500).json({ error: error.message });
  }
});

const staticRoot = path.resolve(__dirname, "..", config.staticDir);
app.get("/api/access-log/summary", async (request, response) => {
  response.json(await readAccessSummary({ days: request.query.days }));
});

app.use(recordAccessVisit);
app.use(express.static(staticRoot));
app.get("*", (_request, response) => {
  response.sendFile(path.join(staticRoot, "index.html"));
});

app.listen(config.port, () => {
  console.log(`CrowdSec Map listening on ${config.port}`);
  autoConfigureLapiCredentials()
    .then((result) => result.configured && console.log(`LAPI automatic setup completed (alerts: ${result.alerts}, decisions: ${result.decisions})`))
    .catch((error) => console.error(`LAPI automatic setup failed: ${error.message}`));
});
