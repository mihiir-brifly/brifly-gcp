import "dotenv/config";
import express from "express";
import crypto from "crypto";
import { createClient } from "@supabase/supabase-js";
import { google } from "googleapis";
import { getAuthUrl, getOAuthClient } from "./ga4_oauth.js";

const app = express();
app.use(express.json());
app.set("trust proxy", true);

// ----------------------
// Helpers
// ----------------------

function isUuid(v) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
    String(v || "")
  );
}

let _supabase = null;
function getSupabase() {
  if (_supabase) return _supabase;

  _supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY
  );

  return _supabase;
}

function makeDedupeKey(parts) {
  return parts.map((p) => String(p ?? "").trim()).join("|");
}

function stableJoin(arr) {
  return (Array.isArray(arr) ? [...arr] : []).map(String).sort().join(",");
}

// ----------------------
// OAuth State Signing
// ----------------------

function signState(obj) {
  const payload = Buffer.from(JSON.stringify(obj)).toString("base64url");
  const sig = crypto
    .createHmac("sha256", process.env.STATE_SIGNING_SECRET)
    .update(payload)
    .digest("base64url");

  return `${payload}.${sig}`;
}

function verifyState(state) {
  const [payload, sig] = String(state).split(".");
  const expected = crypto
    .createHmac("sha256", process.env.STATE_SIGNING_SECRET)
    .update(payload)
    .digest("base64url");

  if (sig !== expected) throw new Error("Invalid state signature");

  return JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
}

// ----------------------
// GA4 Auth Helpers
// ----------------------

async function getGa4AuthForWorkspace(workspace_id) {
  const supabase = getSupabase();

  const { data, error } = await supabase
    .from("oauth_tokens")
    .select("*")
    .eq("client_id", workspace_id)
    .eq("connector_type", "ga4")
    .single();

  if (error) throw error;
  if (!data?.refresh_token) throw new Error("No GA4 refresh token");

  const oauth2Client = getOAuthClient();
  oauth2Client.setCredentials({
    refresh_token: data.refresh_token,
    access_token: data.access_token || undefined,
    expiry_date: data.expiry_date || undefined,
  });

  await oauth2Client.getAccessToken();

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
  if (!data?.external_id) throw new Error("GA4 property not bound");

  return data;
}

// ----------------------
// Normalize GA4
// ----------------------

function normalizeReport(report) {
  const dimNames = (report.dimensionHeaders || []).map((d) => d.name);
  const metNames = (report.metricHeaders || []).map((m) => m.name);

  const rows = (report.rows || []).map((r) => {
    const obj = {};
    r.dimensionValues?.forEach((v, i) => (obj[dimNames[i]] = v.value));
    r.metricValues?.forEach((v, i) => (obj[metNames[i]] = Number(v.value)));
    return obj;
  });

  return { rows };
}

// ----------------------
// OAuth Start
// ----------------------

app.get("/auth/ga4/start", (req, res) => {
  const workspace_id = req.query.workspace_id;
  if (!workspace_id || !isUuid(workspace_id)) {
    return res.status(400).json({ error: "Valid workspace_id required" });
  }

  const state = signState({ workspace_id });
  const url = getAuthUrl(state);

  res.redirect(url);
});

// ----------------------
// OAuth Callback
// ----------------------

app.get("/auth/ga4/callback", async (req, res) => {
  try {
    const { code, state } = req.query;
    const decoded = verifyState(state);
    const workspace_id = decoded.workspace_id;

    const oauth2Client = getOAuthClient();
    const { tokens } = await oauth2Client.getToken(code);

    const supabase = getSupabase();

    const payload = {
      client_id: workspace_id,
      connector_type: "ga4",
      access_token: tokens.access_token || null,
      expiry_date: tokens.expiry_date || null,
      scope: tokens.scope || null,
      updated_at: new Date().toISOString(),
    };

    if (tokens.refresh_token) {
      payload.refresh_token = tokens.refresh_token;
    }

    const { error } = await supabase
      .from("oauth_tokens")
      .upsert(payload, { onConflict: "client_id,connector_type" });

    if (error) throw error;

    res.redirect(process.env.POST_OAUTH_REDIRECT_URL || "http://localhost:3000");
  } catch (e) {
    console.error(e);
    res.status(500).send("OAuth failed");
  }
});

// ----------------------
// Bind Property
// ----------------------

app.post("/ga4/bind", async (req, res) => {
  try {
    const { workspace_id, property_id } = req.body;

    const supabase = getSupabase();

    const row = {
      workspace_id,
      connector_type: "ga4",
      external_id: property_id,
      updated_at: new Date().toISOString(),
    };

    const { error } = await supabase
      .from("workspace_connectors")
      .upsert(row, { onConflict: "workspace_id,connector_type" });

    if (error) throw error;

    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Bind failed" });
  }
});

// ----------------------
// Store Preset Snapshot
// ----------------------

app.post("/ga4/store", async (req, res) => {
  try {
    const {
      workspace_id,
      preset = "overview",
      date_from = "30daysAgo",
      date_to = "today",
    } = req.body;

    const binding = await getBoundGa4Property(workspace_id);
    const auth = await getGa4AuthForWorkspace(workspace_id);

    const dataApi = google.analyticsdata({ version: "v1beta", auth });

    const resp = await dataApi.properties.runReport({
      property: binding.external_id,
      requestBody: {
        dateRanges: [{ startDate: date_from, endDate: date_to }],
        metrics: [{ name: "activeUsers" }, { name: "sessions" }],
      },
    });

    const normalized = normalizeReport(resp.data);

    const dedupe_key = makeDedupeKey([
      "ga4",
      workspace_id,
      binding.external_id,
      preset,
      date_from,
      date_to,
    ]);

    const supabase = getSupabase();

    const { data, error } = await supabase
      .from("connector_snapshots")
      .upsert(
        {
          workspace_id,
          connector_type: "ga4",
          dedupe_key,
          payload_json: normalized,
          updated_at: new Date().toISOString(),
        },
        { onConflict: "dedupe_key" }
      )
      .select()
      .single();

    if (error) throw error;

    res.json({ ok: true, stored_id: data.id });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Store failed", details: String(e.message) });
  }
});

// ----------------------
// Custom Store
// ----------------------

app.post("/ga4/custom-store", async (req, res) => {
  try {
    const {
      workspace_id,
      date_from,
      date_to,
      dimensions = [],
      metrics = [],
    } = req.body;

    const binding = await getBoundGa4Property(workspace_id);
    const auth = await getGa4AuthForWorkspace(workspace_id);

    const dataApi = google.analyticsdata({ version: "v1beta", auth });

    const resp = await dataApi.properties.runReport({
      property: binding.external_id,
      requestBody: {
        dateRanges: [{ startDate: date_from, endDate: date_to }],
        dimensions: dimensions.map((d) => ({ name: d })),
        metrics: metrics.map((m) => ({ name: m })),
      },
    });

    const normalized = normalizeReport(resp.data);

    const dedupe_key = makeDedupeKey([
      "ga4",
      workspace_id,
      binding.external_id,
      "custom",
      date_from,
      date_to,
      stableJoin(dimensions),
      stableJoin(metrics),
    ]);

    const supabase = getSupabase();

    const { data, error } = await supabase
      .from("connector_snapshots")
      .upsert(
        {
          workspace_id,
          connector_type: "ga4",
          dedupe_key,
          payload_json: normalized,
          updated_at: new Date().toISOString(),
        },
        { onConflict: "dedupe_key" }
      )
      .select()
      .single();

    if (error) throw error;

    res.json({ ok: true, stored_id: data.id });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Custom store failed", details: String(e.message) });
  }
});

// ----------------------

const PORT = process.env.PORT || 8080;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`✅ GA4 API running on ${PORT}`);
});
