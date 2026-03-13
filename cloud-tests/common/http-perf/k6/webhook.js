import http from "k6/http";
import { check } from "k6";

const targetUrls = (__ENV.TARGET_URLS || "")
  .split(",")
  .map((v) => v.trim())
  .filter((v) => v.length > 0);

const requestPath = __ENV.REQUEST_PATH || "/webhooks/allowed/default";
const requestMethod = (__ENV.REQUEST_METHOD || "POST").toUpperCase();
const payloadBytes = Number(__ENV.PAYLOAD_BYTES || "32768");
const rps = Number(__ENV.RPS || "500");
const rampSeconds = Number(__ENV.RAMP_SECONDS || "30");
const steadySeconds = Number(__ENV.STEADY_SECONDS || "45");
let preAllocatedVus = Number(__ENV.PRE_ALLOCATED_VUS || "0");
if (!Number.isFinite(preAllocatedVus) || preAllocatedVus <= 0) {
  preAllocatedVus = Math.max(100, Math.floor(rps / 2));
}
let maxVus = Number(__ENV.MAX_VUS || "0");
if (!Number.isFinite(maxVus) || maxVus <= 0) {
  maxVus = Math.max(400, rps * 2);
}
const tlsInsecure = (__ENV.TLS_INSECURE || "1") === "1";
const scenarioLabel = __ENV.SCENARIO_LABEL || "http-perf";
const enforceThresholds = (__ENV.ENFORCE_THRESHOLDS || "0") === "1";
const connectionMode = (__ENV.CONNECTION_MODE || "keep_alive").trim();

if (targetUrls.length === 0) {
  throw new Error("TARGET_URLS must contain at least one target URL");
}

if (!["keep_alive", "new_connection_heavy"].includes(connectionMode)) {
  throw new Error(`unsupported CONNECTION_MODE: ${connectionMode}`);
}

const padBytes = Math.max(0, payloadBytes - 512);
const payload = JSON.stringify({
  webhook_id: `${scenarioLabel}-event`,
  tenant_id: "tenant-001",
  event_type: "customer.subscription.updated",
  ts_unix_ms: Date.now(),
  payload: "x".repeat(padBytes),
});

export const options = {
  discardResponseBodies: true,
  insecureSkipTLSVerify: tlsInsecure,
  noConnectionReuse: connectionMode === "new_connection_heavy",
  noVUConnectionReuse: connectionMode === "new_connection_heavy",
  scenarios: {
    webhooks: {
      executor: "ramping-arrival-rate",
      startRate: Math.max(1, Math.floor(rps / 10)),
      timeUnit: "1s",
      preAllocatedVUs: preAllocatedVus,
      maxVUs: maxVus,
      stages: [
        { target: rps, duration: `${rampSeconds}s` },
        { target: rps, duration: `${steadySeconds}s` },
      ],
    },
  },
};

if (enforceThresholds) {
  options.thresholds = {
    checks: ["rate>0.95"],
    http_req_failed: ["rate<0.05"],
  };
}

function pickTargetUrl() {
  const idx = Math.floor(Math.random() * targetUrls.length);
  return targetUrls[idx];
}

export default function () {
  const base = pickTargetUrl();
  const url = `${base}${requestPath}`;
  const headers = {
    "Content-Type": "application/json",
    "X-Webhook-Id": `${scenarioLabel}-${__VU}-${__ITER}`,
    "X-Tenant-Id": "tenant-001",
    "X-Event-Type": "customer.subscription.updated",
    "X-Signature": "sha256=dummy-signature",
    "X-Connection-Mode": connectionMode,
  };

  const res = http.request(requestMethod, url, payload, { headers });
  check(res, {
    "status is 2xx": (r) => r.status >= 200 && r.status < 300,
  });
}
