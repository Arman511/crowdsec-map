/** API Response Types */

export interface Alert {
  id: string;
  ip: string;
  country: string;
  city: string;
  latitude?: number;
  longitude?: number;
  scenario: string;
  decisionType: string;
  value: string;
  createdAt: string;
  count: number;
  asName: string;
  asn?: string;
  origin: string;
  scope: string;
  duration: string;
  until: string;
}

export interface ActiveBan {
  id: string;
  ip: string;
  value: string;
  country: string;
  scenario: string;
  origin: string;
  scope: string;
  duration: string;
  until: string;
  type: string;
  createdAt: string;
  count?: number;
  label?: string;
  meta?: string;
  detail?: string;
  since?: string;
  remaining?: string;
}

export interface LabelCount {
  label: string;
  count: number;
}

export interface Totals {
  alerts: number;
  countries: number;
  scenarios: number;
  bans: number;
  activeBans: number;
}

export interface AttacksResponse {
  source: string;
  generatedAt: string;
  alerts: Alert[];
  activeBans: ActiveBan[];
  activeBansTotal: number;
  refreshSeconds: number;
  publicTargetIp: string;
  publicTargetIpSource: string;
  demoMode: boolean;
  warning: string;
  totals: Totals;
  topCountries: LabelCount[];
  topScenarios: LabelCount[];
}

export interface BansResponse {
  generatedAt: string;
  total: number;
  offset: number;
  limit: number;
  nextOffset: number | null;
  items: ActiveBan[];
}

export interface HistoryItem {
  label: string;
  alerts: number;
  events: number;
  daysSeen: number;
  ipCount: number;
  lastSeen: string;
  topScenario: string;
  topCountry: string;
}

export interface HistoryResponse {
  generatedAt: string;
  days: number;
  groupBy: string;
  totalEvents: number;
  matchedEvents: number;
  total: number;
  offset: number;
  limit: number;
  nextOffset?: number;
  items: HistoryItem[];
}

export interface GroupDetailItem {
  ip: string;
  alerts: number;
  events: number;
  daysSeen: number;
  lastSeen: string;
  topScenario: string;
  topCountry: string;
  topAsName: string;
}

export interface GroupDetailResponse {
  generatedAt: string;
  days: number;
  groupBy: string;
  label: string;
  matchedEvents: number;
  total: number;
  offset: number;
  limit: number;
  nextOffset?: number;
  items: GroupDetailItem[];
}

export interface HistoryIpEvent {
  seenAt: string;
  scenario: string;
  country: string;
  asName: string;
  count: number;
}

export interface HistoryIpResponse {
  ip: string;
  days: number;
  generatedAt: string;
  alerts: number;
  events: number;
  daysSeen: number;
  firstSeen: string;
  lastSeen: string;
  topScenario: string;
  topCountry: string;
  topAsName: string;
  offset: number;
  limit: number;
  nextOffset?: number;
  recentEvents: HistoryIpEvent[];
  cscli: string;
  cscliCommand: string;
  cscliWarning: string;
  note: string;
}

export interface DecisionItem {
  id?: string;
  ip: string;
  value: string;
  country: string;
  scenario: string;
  origin: string;
  scope: string;
  duration: string;
  until: string;
}

export interface BlockedIpsByOrigin {
  key: string;
  label: string;
  count: number;
}

export interface DecisionsResponse {
  generatedAt: string;
  cachedAt: string;
  cacheSeconds: number;
  total: number;
  matched: number;
  countries: number;
  scenarios: number;
  topCountries: LabelCount[];
  topScenarios: LabelCount[];
  topOrigins: LabelCount[];
  uniqueBlockedIps: number;
  blockedIpsByOrigin: BlockedIpsByOrigin[];
  sort: string;
  direction: string;
  offset: number;
  limit: number;
  nextOffset?: number;
  error?: string;
  items: DecisionItem[];
}

export interface ReputationStats {
  configured: boolean;
  cacheHours: number;
  period: string;
  networkRequests: number;
  cacheHits: number;
  cachedIps: number;
}

export interface ReputationIp {
  configured: boolean;
  cached?: boolean;
  cachedAt?: string;
  cacheHours: number;
  stats: ReputationStats;
  status: string;
  summary: string;
  maliciousness?: string;
  backgroundNoise?: string;
  isFalsePositive?: string;
  behaviors?: string[];
  categories?: string[];
  asName?: string;
  country?: string;
  firstSeen?: string;
  lastSeen?: string;
  webUrl?: string;
  shodanUrl?: string;
}

export interface InvestigationLogSource {
  path: string;
  label: string;
  name?: string;
  mtime: string;
  isSuspicious: boolean;
  warning: string;
  hits?: number;
  forbidden?: number;
  sampledLines?: string[];
}

export interface InvestigationLogLine {
  line: string;
  lineNumber: number;
  forbidden: boolean;
  timestamp: string;
}

export interface ActiveBansData {
  count: number;
  since: string;
  remaining: string;
  items: ActiveBan[];
}

export interface InvestigationLogResponse {
  totalHits: number;
  totalForbidden: number;
  activeBans: ActiveBansData;
  scannedFiles: number;
  availableFiles: number;
  lines: InvestigationLogLine[];
  sources: InvestigationLogSource[];
}

export interface ProtectionTimeline {
  timestamp: string;
  processedRequests: number;
  httpBlockedRequests: number;
}

export interface ProtectionTotals {
  processedRequests: number;
  httpBlockedRequests: number;
  blockRate: number;
  activeHostnames: number;
}

export interface ProtectionResponse {
  generatedAt: string;
  days: number;
  availableFiles: number;
  parsedRequests: number;
  warning?: string;
  timedOut?: boolean;
  error?: string;
  demoMode?: boolean;
  totals: ProtectionTotals;
  hosts: Array<{
    hostname: string;
    processedRequests: number;
    httpBlockedRequests: number;
    blockRate: number;
  }>;
  timeline: ProtectionTimeline[];
}

export interface AccessLogSummary {
  "24hVisits": number;
  uniqueIps: number;
  retention: string;
  enabled?: boolean;
  topIps?: LabelCount[];
  topCountries?: LabelCount[];
  recent?: Array<{ ts: string; ip: string; country: string; path: string; userAgent: string }>;
}

export interface UpdateStatus {
  state: "current" | "update_available" | "unavailable";
  message: string;
  image: string;
  runningRevision: string;
  revision: string;
  url: string;
}

export interface LapiCredentialsStatus {
  file: string;
  configured: boolean;
  warning: string;
  watcherConfigured?: boolean;
  decisionsConfigured?: boolean;
}

export interface RankItem {
  label: string;
  count: number;
  meta?: string;
  detail?: string;
}

export interface RecentVisitItem {
  ts: string;
  ip: string;
  country: string;
  path: string;
  userAgent: string;
}

export interface Rankings {
  countries: RankItem[];
  ips: RankItem[];
  scenarios: RankItem[];
  bans: RankItem[];
}

export interface EventDrilldown {
  title: string;
  subtitle: string;
  attacks: Alert[];
}

export interface EventSource {
  ip: string;
  country?: string;
  asn?: string;
  attempts: number;
  scenarios: string[];
}

export interface MapGroup extends Alert {
  attacks: Alert[];
  sourceCount: number;
  x?: number;
  y?: number;
}

export interface TimelineAttackGroup extends Alert {
  id: string;
  ip: string;
  totalCount: number;
  attacks: Alert[];
}
