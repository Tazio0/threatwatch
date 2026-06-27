import { feedItems, metrics, routes } from "./data.js";

export const apiContract = {
  liveThreats: "/api/threats/live",
  threatStats: "/api/threats/stats",
  heatmap: "/api/map/heatmap-data",
  southAfricaThreats: "/api/sa/threats",
  southAfricaStats: "/api/sa/stats",
  search: "/api/search?q=<indicator>"
};

export const demoCountries = [
  {
    code: "ZA",
    name: "South Africa",
    region: "Southern Africa",
    marker: { x: "56%", y: "58%" },
    severity: "critical",
    score: 94,
    signals: 253,
    critical: 37,
    lastSeen: "42s ago",
    posture: "Primary watch lane",
    summary: "Inbound credential abuse and SSH brute-force activity converging on Johannesburg, Cape Town, and Durban demo lanes.",
    sources: ["AbuseIPDB", "Blocklist.de", "URLhaus"],
    indicators: ["185.220.101.42", "malicious-login-check[.]xyz", "196.25.1.5"],
    tags: ["ZA focus", "review first", "export ready"]
  },
  {
    code: "NG",
    name: "Nigeria",
    region: "West Africa",
    marker: { x: "48%", y: "50%" },
    severity: "critical",
    score: 87,
    signals: 97,
    critical: 14,
    lastSeen: "2m ago",
    posture: "Credential spray origin",
    summary: "Repeated login attempts appear as clustered origin activity in the current demo window.",
    sources: ["AbuseIPDB", "AlienVault OTX"],
    indicators: ["185.220.101.42", "102.89.12.44"],
    tags: ["origin", "auth abuse", "clustered"]
  },
  {
    code: "SG",
    name: "Singapore",
    region: "Southeast Asia",
    marker: { x: "67%", y: "50%" },
    severity: "high",
    score: 79,
    signals: 44,
    critical: 6,
    lastSeen: "7m ago",
    posture: "Phishing relay",
    summary: "A smaller but high-confidence phishing lane currently targets South African review queues.",
    sources: ["URLhaus", "PhishTank"],
    indicators: ["malicious-login-check[.]xyz", "sg-auth-reset[.]site"],
    tags: ["phishing", "relay", "watch"]
  },
  {
    code: "US",
    name: "United States",
    region: "North America",
    marker: { x: "33%", y: "43%" },
    severity: "critical",
    score: 91,
    signals: 112,
    critical: 19,
    lastSeen: "1m ago",
    posture: "Cloud edge origin",
    summary: "Ashburn-origin traffic is modeled as infrastructure abuse rather than attribution.",
    sources: ["Blocklist.de", "AbuseIPDB"],
    indicators: ["203.0.113.88", "198.51.100.17"],
    tags: ["cloud", "ssh", "high volume"]
  },
  {
    code: "GB",
    name: "United Kingdom",
    region: "Western Europe",
    marker: { x: "49%", y: "38%" },
    severity: "medium",
    score: 66,
    signals: 31,
    critical: 2,
    lastSeen: "13m ago",
    posture: "Scanner context",
    summary: "Moderate-confidence scanner reports are retained for analyst context, not automatic blocking.",
    sources: ["AlienVault OTX"],
    indicators: ["91.240.118.172"],
    tags: ["scanner", "context", "medium"]
  },
  {
    code: "AU",
    name: "Australia",
    region: "Oceania",
    marker: { x: "73%", y: "65%" },
    severity: "low",
    score: 42,
    signals: 18,
    critical: 0,
    lastSeen: "28m ago",
    posture: "Low confidence probe",
    summary: "Low-severity honeypot probe retained to show noise filtering in the demo interface.",
    sources: ["Spiderweb"],
    indicators: ["honeypot-probe:tokyo-sydney"],
    tags: ["noise", "honeypot", "low"]
  }
];

export function getDashboardSnapshot() {
  return { metrics, routes, feedItems };
}

export function getCountryProfile(countryCode) {
  return demoCountries.find((country) => country.code === countryCode) || demoCountries[0];
}

export function getCountryRoutes(countryCode) {
  return routes.filter((route) => route.originCode === countryCode || route.targetCode === countryCode);
}

export function getBackendReadinessNotes() {
  return [
    "Replace this adapter with fetch calls when FastAPI routes are ready.",
    "Keep country codes, severity, indicators, and route ids stable between mock and API data.",
    "The globe drawer already consumes country profiles and route arrays as plain objects."
  ];
}
