import "dotenv/config";
import express from "express";
import crypto from "crypto";
import { createClient } from "@supabase/supabase-js";
import { google } from "googleapis";
import { getAuthUrl, getOAuthClient } from "./ga4_oauth.js";

const app = express();
app.set("trust proxy", true);
app.use(express.json());

// Avoid browser caching during testing
app.use((req, res, next) => {
  res.setHeader("Cache-Control", "no-store");
  next();
});

/**
 * Never log secret values. Only log whether they exist.
 */
function envExists(name) {
  return Boolean(process.env[name] && String(process.env[name]).trim());
}

function requireEnv(names) {
  return names.filter((n) => !envExists(n));
}

/**
 * UUID sanity check (because your Supabase oauth_tokens.client_id is uuid)
 */
function isUuid(v) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
    String(v || "")
  );
}

/**
 * Lazy-init Supabase so the process can still boot and expose /health
 * even if env is misconfigured (prevents Cloud Run "didn't listen" confusion).
 */
let _supabase = null;
function getSupabase() {
  if (_supabase) return _supabase;

  const missing = requireEnv(["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"]);
  if (missing.length) {
    throw new Error(`Missing env vars: ${missing.join(", ")}`);
  }

  _supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY
  );
  return _supabase;
}

async function logAudit({
  workspace_id,
  action,
  external_id = null,
  request_json = null,
  row_count = null,
  status = "success",
  error_message = null,
}) {
  try {
    if (!workspace_id) return;
    const supabase = getSupabase();
    const { error } = await supabase.from("connector_audit_logs").insert({
      workspace_id,
      connector_type: "ga4",
      action,
      external_id,
      request_json,
      row_count,
      status,
      error_message,
    });
    if (error) console.error("Audit log insert failed:", error);
  } catch (auditErr) {
    console.error("Audit log error:", auditErr);
  }
}

/**
 * Signed state to prevent tampering
 * state = "<payloadBase64url>.<hmacSigBase64url>"
 */
function signState(obj) {
  const missing = requireEnv(["STATE_SIGNING_SECRET"]);
  if (missing.length) throw new Error(`Missing env vars: ${missing.join(", ")}`);

  const payload = Buffer.from(JSON.stringify(obj)).toString("base64url");
  const sig = crypto
    .createHmac("sha256", process.env.STATE_SIGNING_SECRET)
    .update(payload)
    .digest("base64url");

  return `${payload}.${sig}`;
}

function verifyState(state) {
  const parts = String(state).split(".");
  if (parts.length !== 2) throw new Error("Invalid state format");

  const [payload, sig] = parts;
  const expected = crypto
    .createHmac("sha256", process.env.STATE_SIGNING_SECRET)
    .update(payload)
    .digest("base64url");

  // timing-safe compare
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    throw new Error("State signature mismatch");
  }

  const json = Buffer.from(payload, "base64url").toString("utf8");
  return JSON.parse(json);
}

/**
 * Dedupe helpers (Step 8)
 */
function makeDedupeKey(parts) {
  return parts.map((p) => String(p ?? "").trim()).join("|");
}

function stableJoin(arr) {
  return (Array.isArray(arr) ? [...arr] : []).map(String).sort().join(",");
}

/**
 * GA4 auth helper: loads refresh_token, refreshes access token if needed,
 * and persists latest access token back to Supabase.
 */
async function getGa4AuthForWorkspace(workspace_id) {
  const supabase = getSupabase();

  const { data, error } = await supabase
    .from("oauth_tokens")
    .select("*")
    .eq("client_id", workspace_id)
    .eq("connector_type", "ga4")
    .single();

  if (error) throw error;
  if (!data?.refresh_token) throw new Error("No GA4 refresh_token stored for this workspace");

  const oauth2Client = getOAuthClient();
  oauth2Client.setCredentials({
    refresh_token: data.refresh_token,
    access_token: data.access_token || undefined,
    expiry_date: data.expiry_date || undefined,
  });

  // Force refresh if needed
  await oauth2Client.getAccessToken();

  // Persist refreshed access token
  const c = oauth2Client.credentials;
  if (c.access_token && c.expiry_date) {
    await supabase
      .from("oauth_tokens")
      .update({ access_token: c.access_token, expiry_date: c.expiry_date })
      .eq("client_id", workspace_id)
      .eq("connector_type", "ga4");
  }

  return oauth2Client;
}

async function getBoundGa4Property(workspace_id) {
  const supabase = getSupabase();

  const { data, error } = await supabase
    .from("workspace_connectors")
    .select("*")
    .eq("workspace_id", workspace_id)
    .eq("connector_type", "ga4")
    .maybeSingle();

  if (error) throw error;
  if (!data?.external_id) throw new Error("GA4 not bound. Call POST /ga4/bind first.");

  return data; // includes external_id = "properties/..."
}

/**
 * Normalize GA4 report output
 */
function normalizeReport(report) {
  const dimNames = (report.dimensionHeaders || []).map((d) => d.name);
  const metNames = (report.metricHeaders || []).map((m) => m.name);

  const totals =
    report.totals?.[0]?.metricValues?.reduce((acc, mv, i) => {
      acc[metNames[i]] = Number(mv.value);
      return acc;
    }, {}) || {};

  const rows = (report.rows || []).map((r) => {
    const obj = {};
    (r.dimensionValues || []).forEach((dv, i) => (obj[dimNames[i]] = dv.value));
    (r.metricValues || []).forEach((mv, i) => (obj[metNames[i]] = Number(mv.value)));
    return obj;
  });

  return { totals, rows };
}

/**
 * Preset builder (Step 6 presets included)
 */
function buildGa4Request(preset, date_from, date_to, limit = 50, offset = 0) {
  const base = {
    dateRanges: [{ startDate: date_from, endDate: date_to }],
    limit,
    offset,
  };

  switch (preset) {
    case "overview":
      return {
        ...base,
        metrics: [
          { name: "activeUsers" },
          { name: "newUsers" },
          { name: "sessions" },
          { name: "screenPageViews" },
          { name: "engagedSessions" },
          { name: "engagementRate" },
        ],
      };

    case "top_pages":
      return {
        ...base,
        dimensions: [{ name: "pagePathPlusQueryString" }],
        metrics: [{ name: "screenPageViews" }, { name: "activeUsers" }, { name: "sessions" }],
        orderBys: [{ metric: { metricName: "screenPageViews" }, desc: true }],
      };

    case "acquisition":
      return {
        ...base,
        dimensions: [{ name: "sessionSource" }, { name: "sessionMedium" }],
        metrics: [{ name: "sessions" }, { name: "activeUsers" }],
        orderBys: [{ metric: { metricName: "sessions" }, desc: true }],
      };

    case "geo":
      return {
        ...base,
        dimensions: [{ name: "country" }],
        metrics: [{ name: "activeUsers" }, { name: "sessions" }],
        orderBys: [{ metric: { metricName: "activeUsers" }, desc: true }],
      };

    case "devices":
      return {
        ...base,
        dimensions: [{ name: "deviceCategory" }],
        metrics: [{ name: "activeUsers" }, { name: "sessions" }],
        orderBys: [{ metric: { metricName: "activeUsers" }, desc: true }],
      };

    // Step 6 additions
    case "events":
      return {
        ...base,
        dimensions: [{ name: "eventName" }],
        metrics: [{ name: "eventCount" }, { name: "activeUsers" }],
        orderBys: [{ metric: { metricName: "eventCount" }, desc: true }],
      };

    case "landing_pages":
      return {
        ...base,
        dimensions: [{ name: "landingPagePlusQueryString" }],
        metrics: [{ name: "sessions" }, { name: "activeUsers" }, { name: "screenPageViews" }],
        orderBys: [{ metric: { metricName: "sessions" }, desc: true }],
      };

    // If this fails for some properties, swap metric to whatever metadata shows.
    case "conversions":
      return {
        ...base,
        dimensions: [{ name: "eventName" }],
        metrics: [{ name: "keyEvents" }, { name: "eventCount" }],
        orderBys: [{ metric: { metricName: "keyEvents" }, desc: true }],
      };

    default:
      throw new Error(`Unknown preset: ${preset}`);
  }
}

/**
 * HEALTH
 */
app.get("/health", (req, res) => {
  res.json({
    ok: true,
    env: {
      PORT: process.env.PORT || "not-set",
      SUPABASE_URL: envExists("SUPABASE_URL"),
      SUPABASE_SERVICE_ROLE_KEY: envExists("SUPABASE_SERVICE_ROLE_KEY"),
      GA4_OAUTH_CLIENT_ID: envExists("GA4_OAUTH_CLIENT_ID"),
      GA4_OAUTH_CLIENT_SECRET: envExists("GA4_OAUTH_CLIENT_SECRET"),
      GA4_OAUTH_REDIRECT_URI: envExists("GA4_OAUTH_REDIRECT_URI"),
      STATE_SIGNING_SECRET: envExists("STATE_SIGNING_SECRET"),
      POST_OAUTH_REDIRECT_URL: envExists("POST_OAUTH_REDIRECT_URL"),
    },
  });
});

/**
 * OAuth Start
 * /auth/ga4/start?workspace_id=<UUID>
 */
app.get("/auth/ga4/start", async (req, res) => {
  try {
    const workspace_id =
      (Array.isArray(req.query.workspace_id) ? req.query.workspace_id[0] : req.query.workspace_id) ||
      (Array.isArray(req.query.client_id) ? req.query.client_id[0] : req.query.client_id);

    if (!workspace_id) {
      return res.status(400).json({
        error: "workspace_id required",
        example: "/auth/ga4/start?workspace_id=7a6e6ce9-f949-4824-9583-264593e98127",
      });
    }

    if (!isUuid(workspace_id)) {
      return res.status(400).json({
        error: "workspace_id must be a UUID (matches workspaces.id in Supabase)",
        got: String(workspace_id),
      });
    }

    const missing = requireEnv([
      "GA4_OAUTH_CLIENT_ID",
      "GA4_OAUTH_CLIENT_SECRET",
      "GA4_OAUTH_REDIRECT_URI",
      "STATE_SIGNING_SECRET",
    ]);
    if (missing.length) {
      return res.status(500).json({
        error: "Server misconfigured (missing env vars)",
        missing,
      });
    }

    const nonce = crypto.randomUUID();
    const state = signState({ workspace_id, nonce });

    const url = getAuthUrl(state);
    return res.redirect(url);
  } catch (e) {
    console.error("❌ /auth/ga4/start error:", e);
    return res.status(500).json({ error: "Failed to start OAuth" });
  }
});

/**
 * OAuth Callback
 * ✅ refresh_token overwrite protection
 */
app.get("/auth/ga4/callback", async (req, res) => {
  let workspace_id = null;
  try {
    const code = Array.isArray(req.query.code) ? req.query.code[0] : req.query.code;
    const state = Array.isArray(req.query.state) ? req.query.state[0] : req.query.state;

    if (!code || !state) return res.status(400).send("Missing code/state");

    const decoded = verifyState(state);
    workspace_id = decoded.workspace_id;

    if (!isUuid(workspace_id)) return res.status(400).send("Invalid workspace_id in state");

    const oauth2Client = getOAuthClient();
    const { tokens } = await oauth2Client.getToken(code);

    const supabase = getSupabase();

    const payload = {
      client_id: workspace_id,
      connector_type: "ga4",
      access_token: tokens.access_token || null,
      expiry_date: tokens.expiry_date || null,
      token_type: tokens.token_type || null,
      scope: tokens.scope || null,
      updated_at: new Date().toISOString(),
    };

    // ✅ only set refresh_token if Google sends it
    if (tokens.refresh_token) payload.refresh_token = tokens.refresh_token;

    const { error } = await supabase
      .from("oauth_tokens")
      .upsert(payload, { onConflict: "client_id,connector_type" });

    if (error) throw error;

    await logAudit({
      workspace_id,
      action: "oauth_connected",
      external_id: null,
      request_json: req.query,
      status: "success",
    });

    const redirectTo = process.env.POST_OAUTH_REDIRECT_URL || "https://brifly.ai?ga4=connected";
    return res.redirect(redirectTo);
  } catch (e) {
    await logAudit({
      workspace_id,
      action: "oauth_connected",
      external_id: null,
      request_json: req.query,
      status: "failed",
      error_message: String(e?.message || e),
    });
    console.error("❌ /auth/ga4/callback error:", e);
    return res.status(500).send("OAuth failed");
  }
});

/**
 * Debug: raw accounts response
 */
app.get("/ga4/accounts", async (req, res) => {
  try {
    const workspace_id = Array.isArray(req.query.workspace_id)
      ? req.query.workspace_id[0]
      : req.query.workspace_id;

    if (!workspace_id) return res.status(400).json({ error: "workspace_id required" });

    const auth = await getGa4AuthForWorkspace(workspace_id);
    const admin = google.analyticsadmin({ version: "v1beta", auth });

    const resp = await admin.accountSummaries.list();
    return res.json(resp.data);
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Failed to list accounts", details: String(e?.message || e) });
  }
});
/**
 * 9) GET LATEST SNAPSHOT (NO GOOGLE CALL)
 *
 * Example:
 * /ga4/latest?workspace_id=UUID&preset=overview&date_from=30daysAgo&date_to=today
 *
 * OR for custom:
 * /ga4/latest?workspace_id=UUID&date_from=30daysAgo&date_to=today&dimensions=country&metrics=activeUsers,sessions&limit=50
 */
app.get("/ga4/latest", async (req, res) => {
  try {
    const {
      workspace_id,
      preset,
      date_from,
      date_to,
      dimensions,
      metrics,
      limit,
      offset
    } = req.query;

    if (!workspace_id) {
      return res.status(400).json({ error: "workspace_id required" });
    }

    const supabase = getSupabase();

    let dedupe_key;

    if (preset) {
      const binding = await getBoundGa4Property(workspace_id);
      dedupe_key = makeDedupeKey([
        "ga4",
        workspace_id,
        binding.external_id,
        String(preset),
        String(date_from || "30daysAgo"),
        String(date_to || "today"),
        Number(limit || 50),
        Number(offset || 0),
      ]);
    } else {
      const binding = await getBoundGa4Property(workspace_id);
      const dims = dimensions
        ? Array.isArray(dimensions)
          ? dimensions
          : String(dimensions).split(",").filter(Boolean)
        : [];
      const mets = metrics
        ? Array.isArray(metrics)
          ? metrics
          : String(metrics).split(",").filter(Boolean)
        : [];

      dedupe_key = makeDedupeKey([
        "ga4",
        workspace_id,
        binding.external_id,
        "custom",
        String(date_from || "30daysAgo"),
        String(date_to || "today"),
        stableJoin(dims),
        stableJoin(mets),
        Number(limit || 50),
        Number(offset || 0),
      ]);
    }

    const { data, error } = await supabase
      .from("connector_snapshots")
      .select("*")
      .eq("dedupe_key", dedupe_key)
      .order("updated_at", { ascending: false })
      .limit(1)
      .single();

    if (error || !data) {
      return res.status(404).json({
        error: "No snapshot found",
        dedupe_key
      });
    }

    return res.json({
      ok: true,
      dedupe_key,
      pulled_at: data.data_json?.pulled_at || null,
      updated_at: data.updated_at,
      row_count: data.data_json?.quality?.row_count || 0,
      payload: data.data_json
    });

  } catch (e) {
    console.error(e);
    return res.status(500).json({
      error: "Failed to fetch latest snapshot",
      details: String(e?.message || e)
    });
  }
});
/**
 * UI-friendly flattened properties list
 */
app.get("/ga4/properties", async (req, res) => {
  try {
    const workspace_id = Array.isArray(req.query.workspace_id)
      ? req.query.workspace_id[0]
      : req.query.workspace_id;

    if (!workspace_id) return res.status(400).json({ error: "workspace_id required" });

    const auth = await getGa4AuthForWorkspace(workspace_id);
    const admin = google.analyticsadmin({ version: "v1beta", auth });

    const resp = await admin.accountSummaries.list();
    const summaries = resp.data.accountSummaries || [];

    const properties = summaries.flatMap((acc) =>
      (acc.propertySummaries || []).map((p) => ({
        account_id: acc.account,
        account_name: acc.displayName,
        property_id: p.property,
        property_name: p.displayName,
        property_type: p.propertyType,
      }))
    );

    return res.json({ properties });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Failed to list properties", details: String(e?.message || e) });
  }
});

/**
 * Bind a property to workspace (one active property per workspace)
 * POST /ga4/bind
 * body: { workspace_id, property_id }
 */
app.post("/ga4/bind", async (req, res) => {
  let workspace_id = null;
  let external_id = null;
  try {
    const { workspace_id: ws, property_id } = req.body || {};
    workspace_id = ws;

    if (!workspace_id) return res.status(400).json({ error: "workspace_id required" });
    if (!isUuid(workspace_id)) return res.status(400).json({ error: "workspace_id must be a UUID" });

    if (!property_id)
      return res.status(400).json({ error: "property_id required (example: properties/523107704)" });

    // Validate property is accessible under this OAuth connection
    const auth = await getGa4AuthForWorkspace(workspace_id);
    const admin = google.analyticsadmin({ version: "v1beta", auth });
    const resp = await admin.accountSummaries.list();

    const summaries = resp.data.accountSummaries || [];
    let found = null;

    for (const acc of summaries) {
      for (const p of acc.propertySummaries || []) {
        if (p.property === property_id) {
          found = {
            account_id: acc.account,
            account_name: acc.displayName,
            property_id: p.property,
            property_name: p.displayName,
          };
          break;
        }
      }
      if (found) break;
    }

    if (!found) {
      return res.status(400).json({
        error: "property_id not accessible for this OAuth connection",
        hint: "Call GET /ga4/properties and choose a property_id from that list",
      });
    }

    const supabase = getSupabase();
    external_id = found.property_id;

    const row = {
      workspace_id,
      connector_type: "ga4",
      external_id: found.property_id,
      account_id: found.account_id,
      display_name: found.property_name,
      account_name: found.account_name,
      status: "connected",
      updated_at: new Date().toISOString(),
    };

    const { error } = await supabase
      .from("workspace_connectors")
      .upsert(row, { onConflict: "workspace_id,connector_type" });

    if (error) throw error;

    await logAudit({
      workspace_id,
      action: "bind_property",
      external_id,
      request_json: req.body,
      status: "success",
    });

    return res.json({ ok: true, bound: row });
  } catch (e) {
    await logAudit({
      workspace_id,
      action: "bind_property",
      external_id,
      request_json: req.body,
      status: "failed",
      error_message: String(e?.message || e),
    });
    console.error(e);
    return res.status(500).json({ error: "Failed to bind property", details: String(e?.message || e) });
  }
});

/**
 * Status endpoint (for UI)
 */
app.get("/ga4/status", async (req, res) => {
  try {
    const workspace_id = Array.isArray(req.query.workspace_id)
      ? req.query.workspace_id[0]
      : req.query.workspace_id;

    if (!workspace_id) return res.status(400).json({ error: "workspace_id required" });

    const supabase = getSupabase();

    const [{ data: binding, error: bindErr }, { data: tokenRow, error: tokErr }] = await Promise.all([
      supabase
        .from("workspace_connectors")
        .select("*")
        .eq("workspace_id", workspace_id)
        .eq("connector_type", "ga4")
        .maybeSingle(),
      supabase
        .from("oauth_tokens")
        .select("client_id, connector_type, refresh_token, scope, expiry_date, updated_at")
        .eq("client_id", workspace_id)
        .eq("connector_type", "ga4")
        .maybeSingle(),
    ]);

    if (bindErr) throw bindErr;
    if (tokErr) throw tokErr;

    const hasToken = !!tokenRow?.refresh_token;

    return res.json({
      connected: !!binding && hasToken,
      has_token: hasToken,
      binding: binding || null,
      token_meta: tokenRow
        ? {
            scope: tokenRow.scope || null,
            expiry_date: tokenRow.expiry_date || null,
            updated_at: tokenRow.updated_at || null,
          }
        : null,
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Failed to fetch status", details: String(e?.message || e) });
  }
});

/**
 * Metadata (optional)
 */
app.get("/ga4/metadata", async (req, res) => {
  try {
    const workspace_id = Array.isArray(req.query.workspace_id)
      ? req.query.workspace_id[0]
      : req.query.workspace_id;

    if (!workspace_id) return res.status(400).json({ error: "workspace_id required" });

    const binding = await getBoundGa4Property(workspace_id);
    const auth = await getGa4AuthForWorkspace(workspace_id);

    const dataApi = google.analyticsdata({ version: "v1beta", auth });

    const metaResp = await dataApi.properties.getMetadata({
      name: `${binding.external_id}/metadata`,
    });

    return res.json(metaResp.data);
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Failed to fetch metadata", details: String(e?.message || e) });
  }
});

/**
 * Report (read-only)
 * GET /ga4/report?workspace_id=...&preset=overview&date_from=30daysAgo&date_to=today
 */
app.get("/ga4/report", async (req, res) => {
  try {
    const workspace_id = Array.isArray(req.query.workspace_id)
      ? req.query.workspace_id[0]
      : req.query.workspace_id;

    const preset = (Array.isArray(req.query.preset) ? req.query.preset[0] : req.query.preset) || "overview";
    const date_from = (Array.isArray(req.query.date_from) ? req.query.date_from[0] : req.query.date_from) || "30daysAgo";
    const date_to = (Array.isArray(req.query.date_to) ? req.query.date_to[0] : req.query.date_to) || "today";

    const limitRaw = (Array.isArray(req.query.limit) ? req.query.limit[0] : req.query.limit) || "50";
    const offsetRaw = (Array.isArray(req.query.offset) ? req.query.offset[0] : req.query.offset) || "0";
    const limit = Math.max(1, Math.min(500, Number(limitRaw)));
    const offset = Math.max(0, Number(offsetRaw));

    if (!workspace_id) return res.status(400).json({ error: "workspace_id required" });

    const binding = await getBoundGa4Property(workspace_id);
    const auth = await getGa4AuthForWorkspace(workspace_id);

    const dataApi = google.analyticsdata({ version: "v1beta", auth });
    const requestBody = buildGa4Request(preset, date_from, date_to, limit, offset);

    const resp = await dataApi.properties.runReport({
      property: binding.external_id,
      requestBody,
    });

    const normalized = normalizeReport(resp.data);

    const envelope = {
      schema_version: "1.0",
      connector_type: "ga4",
      workspace_id,
      pulled_at: new Date().toISOString(),
      request: {
        preset,
        date_from,
        date_to,
        property_id: binding.external_id,
        limit,
        offset,
      },
      data: normalized,
      quality: {
        row_count: normalized.rows.length,
        warnings: [],
      },
      raw: resp.data,
    };

    return res.json(envelope);
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Failed to run GA4 report", details: String(e?.message || e) });
  }
});

/**
 * Store single preset (deduped)
 * POST /ga4/store
 */
app.post("/ga4/store", async (req, res) => {
  let workspace_id = null;
  let external_id = null;
  try {
    const {
      workspace_id: ws,
      preset = "overview",
      date_from = "30daysAgo",
      date_to = "today",
      limit = 50,
      offset = 0,
    } = req.body || {};
    workspace_id = ws;

    if (!workspace_id) return res.status(400).json({ error: "workspace_id required" });

    const binding = await getBoundGa4Property(workspace_id);
    external_id = binding.external_id;
    const auth = await getGa4AuthForWorkspace(workspace_id);
    const dataApi = google.analyticsdata({ version: "v1beta", auth });

    const requestBody = buildGa4Request(preset, date_from, date_to, limit, offset);

    const resp = await dataApi.properties.runReport({
      property: binding.external_id,
      requestBody,
    });

    const normalized = normalizeReport(resp.data);

    const envelope = {
      schema_version: "1.0",
      connector_type: "ga4",
      workspace_id,
      pulled_at: new Date().toISOString(),
      request: {
        preset,
        date_from,
        date_to,
        property_id: binding.external_id,
        limit,
        offset,
      },
      data: normalized,
      quality: { row_count: normalized.rows.length, warnings: [] },
      raw: resp.data,
    };

    const dedupe_key = makeDedupeKey([
      "ga4",
      workspace_id,
      envelope.request.property_id,
      preset,
      date_from,
      date_to,
      limit,
      offset,
    ]);

    const supabase = getSupabase();
    const { data, error } = await supabase
      .from("connector_snapshots")
      .upsert(
        {
          workspace_id: workspace_id || req.body?.workspace_id,
          connector_type: "ga4",
          external_id: binding.external_id,
          report_type: "preset",
          preset_name: preset,
          date_from,
          date_to,
          dimensions: [],
          metrics: [],
          limit_value: Number(limit),
          offset_value: Number(offset),
          dedupe_key,
          payload_json: envelope,
          data_json: envelope,
          status: "success",
          updated_at: new Date().toISOString(),
        },
        { onConflict: "dedupe_key" }
      )
      .select()
      .single();

    if (error) throw error;

    await logAudit({
      workspace_id,
      action: "preset_store",
      external_id,
      request_json: req.body,
      row_count: envelope.quality.row_count,
      status: "success",
    });

    return res.json({ ok: true, stored: data });
  } catch (e) {
    await logAudit({
      workspace_id,
      action: "preset_store",
      external_id,
      request_json: req.body,
      status: "failed",
      error_message: String(e?.message || e),
    });
    console.error(e);
    return res.status(500).json({ error: "Failed to store GA4 data", details: String(e?.message || e) });
  }
});

/**
 * Store multiple presets (deduped)
 * POST /ga4/store-presets
 */
app.post("/ga4/store-presets", async (req, res) => {
  let workspace_id = null;
  let external_id = null;
  try {
    const {
      workspace_id: ws,
      date_from = "30daysAgo",
      date_to = "today",
      presets = ["overview", "top_pages", "acquisition", "geo", "devices", "events", "landing_pages", "conversions"],
      limit = 50,
      offset = 0,
    } = req.body || {};
    workspace_id = ws;

    if (!workspace_id) return res.status(400).json({ error: "workspace_id required" });

    const binding = await getBoundGa4Property(workspace_id);
    external_id = binding.external_id;
    const auth = await getGa4AuthForWorkspace(workspace_id);
    const dataApi = google.analyticsdata({ version: "v1beta", auth });
    const supabase = getSupabase();

    const results = [];

    for (const preset of presets) {
      try {
        const requestBody = buildGa4Request(preset, date_from, date_to, limit, offset);

        const resp = await dataApi.properties.runReport({
          property: binding.external_id,
          requestBody,
        });

        const normalized = normalizeReport(resp.data);

        const envelope = {
          schema_version: "1.0",
          connector_type: "ga4",
          workspace_id,
          pulled_at: new Date().toISOString(),
          request: {
            preset,
            date_from,
            date_to,
            property_id: binding.external_id,
            limit,
            offset,
          },
          data: normalized,
          quality: { row_count: normalized.rows.length, warnings: [] },
          raw: resp.data,
        };

        const dedupe_key = makeDedupeKey([
          "ga4",
          workspace_id,
          envelope.request.property_id,
          preset,
          date_from,
          date_to,
          limit,
          offset,
        ]);

        const { data, error } = await supabase
          .from("connector_snapshots")
          .upsert(
            {
              workspace_id: workspace_id || req.body?.workspace_id,
              connector_type: "ga4",
              external_id: binding.external_id,
              report_type: "preset",
              preset_name: preset,
              date_from,
              date_to,
              dimensions: [],
              metrics: [],
              limit_value: Number(limit),
              offset_value: Number(offset),
              dedupe_key,
              payload_json: envelope,
              data_json: envelope,
              status: "success",
              updated_at: new Date().toISOString(),
            },
            { onConflict: "dedupe_key" }
          )
          .select()
          .single();

        if (error) throw error;

        results.push({
          preset,
          ok: true,
          row_count: envelope.quality.row_count,
          stored_id: data.id,
          created_at: data.created_at,
        });
      } catch (innerErr) {
        results.push({
          preset,
          ok: false,
          error: String(innerErr?.message || innerErr),
        });
      }
    }

    const okCount = results.filter((r) => r.ok).length;
    const failCount = results.length - okCount;
    const totalRowCount = results.filter((r) => r.ok).reduce((sum, r) => sum + Number(r.row_count || 0), 0);

    await logAudit({
      workspace_id,
      action: "preset_store_bulk",
      external_id,
      request_json: req.body,
      row_count: totalRowCount,
      status: failCount === 0 ? "success" : "failed",
      error_message: failCount > 0 ? `${failCount} preset(s) failed` : null,
    });

    return res.json({
      ok: failCount === 0,
      workspace_id,
      property_id: binding.external_id,
      date_from,
      date_to,
      stored: okCount,
      failed: failCount,
      results,
    });
  } catch (e) {
    await logAudit({
      workspace_id,
      action: "preset_store_bulk",
      external_id,
      request_json: req.body,
      status: "failed",
      error_message: String(e?.message || e),
    });
    console.error(e);
    return res.status(500).json({ error: "Failed to store presets", details: String(e?.message || e) });
  }
});

// ----------------------
// Step 7: Safe custom report
// ----------------------

const _ga4MetaCache = new Map(); // key: property_id
const META_TTL_MS = 6 * 60 * 60 * 1000; // 6 hours

async function getGa4FieldsForWorkspace(workspace_id) {
  const binding = await getBoundGa4Property(workspace_id);
  const propertyId = binding.external_id;

  const cached = _ga4MetaCache.get(propertyId);
  if (cached && Date.now() - cached.ts < META_TTL_MS) return cached;

  const auth = await getGa4AuthForWorkspace(workspace_id);
  const dataApi = google.analyticsdata({ version: "v1beta", auth });

  const metaResp = await dataApi.properties.getMetadata({
    name: `${propertyId}/metadata`,
  });

  const dims = (metaResp.data.dimensions || []).map((d) => d.apiName).filter(Boolean);
  const mets = (metaResp.data.metrics || []).map((m) => m.apiName).filter(Boolean);

  const obj = {
    ts: Date.now(),
    dimsSet: new Set(dims),
    metsSet: new Set(mets),
    dimensions: dims,
    metrics: mets,
    propertyId,
  };

  _ga4MetaCache.set(propertyId, obj);
  return obj;
}

function validateCustomFields({ dimensions = [], metrics = [] }, meta) {
  const errors = [];

  if (dimensions.length > 9) errors.push("Too many dimensions (max 9)");
  if (metrics.length > 10) errors.push("Too many metrics (max 10)");
  if (dimensions.length === 0 && metrics.length === 0) errors.push("At least one dimension or metric is required");

  for (const d of dimensions) if (!meta.dimsSet.has(d)) errors.push(`Invalid dimension: ${d}`);
  for (const m of metrics) if (!meta.metsSet.has(m)) errors.push(`Invalid metric: ${m}`);

  return errors;
}

/**
 * Fields list for UI
 * GET /ga4/fields?workspace_id=...
 */
app.get("/ga4/fields", async (req, res) => {
  try {
    const workspace_id = Array.isArray(req.query.workspace_id)
      ? req.query.workspace_id[0]
      : req.query.workspace_id;

    if (!workspace_id) return res.status(400).json({ error: "workspace_id required" });

    const meta = await getGa4FieldsForWorkspace(workspace_id);

    return res.json({
      property_id: meta.propertyId,
      dimensions: meta.dimensions,
      metrics: meta.metrics,
      cache_ttl_hours: 6,
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Failed to fetch GA4 fields", details: String(e?.message || e) });
  }
});

/**
 * Custom report (no store)
 * POST /ga4/custom-report
 */
app.post("/ga4/custom-report", async (req, res) => {
  try {
    const {
      workspace_id,
      date_from = "30daysAgo",
      date_to = "today",
      dimensions = [],
      metrics = [],
      limit = 50,
      offset = 0,
    } = req.body || {};

    if (!workspace_id) return res.status(400).json({ error: "workspace_id required" });

    const binding = await getBoundGa4Property(workspace_id);
    const meta = await getGa4FieldsForWorkspace(workspace_id);

    const errors = validateCustomFields({ dimensions, metrics }, meta);
    if (errors.length) {
      return res.status(400).json({
        error: "Invalid fields",
        errors,
        hint: "Use GET /ga4/fields to pick valid dimensions/metrics",
      });
    }

    const auth = await getGa4AuthForWorkspace(workspace_id);
    const dataApi = google.analyticsdata({ version: "v1beta", auth });

    const safeLimit = Math.max(1, Math.min(500, Number(limit)));
    const safeOffset = Math.max(0, Number(offset));

    const requestBody = {
      dateRanges: [{ startDate: date_from, endDate: date_to }],
      dimensions: dimensions.map((d) => ({ name: d })),
      metrics: metrics.map((m) => ({ name: m })),
      limit: safeLimit,
      offset: safeOffset,
    };

    const resp = await dataApi.properties.runReport({
      property: binding.external_id,
      requestBody,
    });

    const normalized = normalizeReport(resp.data);

    const envelope = {
      schema_version: "1.0",
      connector_type: "ga4",
      workspace_id,
      pulled_at: new Date().toISOString(),
      request: {
        preset: "custom",
        date_from,
        date_to,
        property_id: binding.external_id,
        dimensions,
        metrics,
        limit: safeLimit,
        offset: safeOffset,
      },
      data: normalized,
      quality: { row_count: normalized.rows.length, warnings: [] },
      raw: resp.data,
    };

    return res.json(envelope);
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Failed to run custom GA4 report", details: String(e?.message || e) });
  }
});

/**
 * Custom report + store (deduped)
 * POST /ga4/custom-store
 */
app.post("/ga4/custom-store", async (req, res) => {
  let workspace_id = null;
  let external_id = null;
  try {
    const {
      workspace_id: ws,
      date_from = "30daysAgo",
      date_to = "today",
      dimensions = [],
      metrics = [],
      limit = 50,
      offset = 0,
    } = req.body || {};
    workspace_id = ws;

    if (!workspace_id) return res.status(400).json({ error: "workspace_id required" });

    const binding = await getBoundGa4Property(workspace_id);
    external_id = binding.external_id;
    const meta = await getGa4FieldsForWorkspace(workspace_id);

    const errors = validateCustomFields({ dimensions, metrics }, meta);
    if (errors.length) {
      return res.status(400).json({
        error: "Invalid fields",
        errors,
        hint: "Use GET /ga4/fields to pick valid dimensions/metrics",
      });
    }

    const auth = await getGa4AuthForWorkspace(workspace_id);
    const dataApi = google.analyticsdata({ version: "v1beta", auth });

    const safeLimit = Math.max(1, Math.min(500, Number(limit)));
    const safeOffset = Math.max(0, Number(offset));

    const requestBody = {
      dateRanges: [{ startDate: date_from, endDate: date_to }],
      dimensions: dimensions.map((d) => ({ name: d })),
      metrics: metrics.map((m) => ({ name: m })),
      limit: safeLimit,
      offset: safeOffset,
    };

    const resp = await dataApi.properties.runReport({
      property: binding.external_id,
      requestBody,
    });

    const normalized = normalizeReport(resp.data);

    const envelope = {
      schema_version: "1.0",
      connector_type: "ga4",
      workspace_id,
      pulled_at: new Date().toISOString(),
      request: {
        preset: "custom",
        date_from,
        date_to,
        property_id: binding.external_id,
        dimensions,
        metrics,
        limit: safeLimit,
        offset: safeOffset,
      },
      data: normalized,
      quality: { row_count: normalized.rows.length, warnings: [] },
      raw: resp.data,
    };

    const dedupe_key = makeDedupeKey([
      "ga4",
      workspace_id,
      envelope.request.property_id,
      "custom",
      date_from,
      date_to,
      stableJoin(dimensions),
      stableJoin(metrics),
      safeLimit,
      safeOffset,
    ]);

    const supabase = getSupabase();
    const { data, error } = await supabase
      .from("connector_snapshots")
      .upsert(
        {
          workspace_id: workspace_id || req.body?.workspace_id,
          connector_type: "ga4",
          external_id: binding.external_id,
          report_type: "custom",
          preset_name: null,
          date_from,
          date_to,
          dimensions,
          metrics,
          limit_value: safeLimit,
          offset_value: safeOffset,
          dedupe_key,
          payload_json: envelope,
          data_json: envelope,
          status: "success",
          updated_at: new Date().toISOString(),
        },
        { onConflict: "dedupe_key" }
      )
      .select()
      .single();

    if (error) throw error;

    await logAudit({
      workspace_id,
      action: "custom_store",
      external_id,
      request_json: req.body,
      row_count: envelope.quality.row_count,
      status: "success",
    });

    return res.json({
      ok: true,
      stored_id: data.id,
      created_at: data.created_at,
      row_count: envelope.quality.row_count,
      dedupe_key,
    });
  } catch (e) {
    await logAudit({
      workspace_id,
      action: "custom_store",
      external_id,
      request_json: req.body,
      status: "failed",
      error_message: String(e?.message || e),
    });
    console.error(e);
    return res.status(500).json({ error: "Failed to store custom GA4 report", details: String(e?.message || e) });
  }
});

/**
 * Make Cloud Run happy:
 * - MUST listen on process.env.PORT
 * - Bind to 0.0.0.0
 */
const PORT = Number(process.env.PORT) || 8080;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`✅ brifly-api listening on ${PORT}`);
});

// Helps catch “silent crashes”
process.on("unhandledRejection", (err) => console.error("unhandledRejection:", err));
process.on("uncaughtException", (err) => console.error("uncaughtException:", err));
