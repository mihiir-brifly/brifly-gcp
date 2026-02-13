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
 * GA4 auth helper: loads refresh_token, refreshes access token if needed,
 * and optionally persists latest access token back to Supabase.
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

  // Persist refreshed access token (optional but good)
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

/**
 * HEALTH (must always work)
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
 * 1) START OAUTH
 * Call:
 *   /auth/ga4/start?workspace_id=<UUID>
 * Backwards compatible: accepts client_id too.
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
 * 2) OAUTH CALLBACK
 * Google redirects here with ?code=...&state=...
 *
 * ✅ IMPORTANT FIX:
 * Google often returns refresh_token ONLY the first time.
 * So we only write refresh_token if Google actually sends one.
 */
app.get("/auth/ga4/callback", async (req, res) => {
  try {
    const code = Array.isArray(req.query.code) ? req.query.code[0] : req.query.code;
    const state = Array.isArray(req.query.state) ? req.query.state[0] : req.query.state;

    if (!code || !state) return res.status(400).send("Missing code/state");

    const decoded = verifyState(state);
    const { workspace_id } = decoded;

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

    if (tokens.refresh_token) {
      payload.refresh_token = tokens.refresh_token;
    }

    const { error } = await supabase
      .from("oauth_tokens")
      .upsert(payload, { onConflict: "client_id,connector_type" });

    if (error) throw error;

    const redirectTo = process.env.POST_OAUTH_REDIRECT_URL || "https://brifly.ai?ga4=connected";
    return res.redirect(redirectTo);
  } catch (e) {
    console.error("❌ /auth/ga4/callback error:", e);
    return res.status(500).send("OAuth failed");
  }
});

/**
 * GA4: Raw admin response (debug / internal)
 * GET /ga4/accounts?workspace_id=<uuid>
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
 * Step 2: UI-friendly properties list (flattened)
 * GET /ga4/properties?workspace_id=<uuid>
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
 * Step 3: Bind a selected GA4 property to this workspace
 * POST /ga4/bind
 * body: { workspace_id: "<uuid>", property_id: "properties/523107704" }
 */
app.post("/ga4/bind", async (req, res) => {
  try {
    const { workspace_id, property_id } = req.body || {};

    if (!workspace_id) return res.status(400).json({ error: "workspace_id required" });
    if (!isUuid(workspace_id)) return res.status(400).json({ error: "workspace_id must be a UUID" });

    if (!property_id)
      return res.status(400).json({ error: "property_id required (example: properties/523107704)" });

    // Validate: property must be accessible using this workspace OAuth connection
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

    const row = {
      workspace_id,
      connector_type: "ga4",
      external_id: found.property_id, // GA4 property
      account_id: found.account_id,   // GA4 account
      display_name: found.property_name,
      account_name: found.account_name,
      status: "connected",
      updated_at: new Date().toISOString(),
    };

    const { error } = await supabase
      .from("workspace_connectors")
      .upsert(row, { onConflict: "workspace_id,connector_type" });

    if (error) throw error;

    return res.json({ ok: true, bound: row });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Failed to bind property", details: String(e?.message || e) });
  }
});

/**
 * Step 4: Status endpoint (for UI)
 * GET /ga4/status?workspace_id=<uuid>
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
