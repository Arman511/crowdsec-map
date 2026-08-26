export const HOME = { latitude: 47.4426, longitude: 9.5329 };

export const SOURCE_OPTIONS = [
    ["auto", "Auto"],
    ["lapi-alerts", "LAPI alerts · detections"],
    ["cscli", "cscli · fallback"],
    ["sample", "Sample"]
];

export const REFRESH_OPTIONS = [
    [30, "30s"],
    [60, "1min"],
    [300, "5min"],
    [1800, "30min"]
];

export const REFRESH_STORAGE_KEY = "crowdsec-map-refresh-seconds";
export const MAX_MAP_POINTS = 180;
export const MAX_SIGNAL_PATHS = 30;
export const MAX_TIMELINE_COLUMNS = 9;
export const MAX_TIMELINE_ROWS = 3;
export const METRIC_PAGE_SIZE = 50;
export const TIMELINE_MIN_CARD_WIDTH = 132;
export const TIMELINE_GAP = 10;

export const RANK_MODES = [
    ["countries", "Countries"],
    ["ips", "IPs"],
    ["scenarios", "Scenarios"],
    ["bans", "Bans"]
];

export const EMPTY_RANK_ITEMS = [];
export const RANK_MODE_STORAGE_PREFIX = "crowdsec-map-rank-mode";
export const TIMELINE_ROWS_STORAGE_KEY = "crowdsec-map-timeline-rows";
export const THEME_STORAGE_KEY = "crowdsec-map-theme";

export const HISTORY_DAYS_OPTIONS = [7, 30, 90];
export const HISTORY_GROUP_OPTIONS = [
    ["cidr24", "CIDR /24"],
    ["asn", "ASN"],
    ["ip", "IP"],
    ["scenario", "Scenario"],
    ["country", "Country"]
];
