import "dotenv/config";
import express from "express";
import crypto from "crypto";
import { createClient } from "@supabase/supabase-js";
import { getAuthUrl, getOAuthClient } from "./ga4_oauth.js";

const app = express();
app.set("trust proxy", true);
app.use(express.json());

/**
 * Never log secret values. Only log whether they exist.
 */
function envExists(name) {
  return Boolean(process.env[name] && String(process.env[name]).trim());
}

function requireEnv(names) {
  const missing = names.filter((n) => !envExists(n));
  return missing;
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
  if (missing.length) {
    throw new Error(`Missing env vars: ${missing.join(", ")}`);
  }

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
 * HEALTH (must always work, even if other env vars are missing)
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
    },
  });
});

/**
 * 1) START OAUTH
 * Use workspace_id as your internal tenant/client identifier
 *
 * Call:
 *   /auth/ga4/start?workspace_id=abc123
 *
 * (Backwards compatible: accepts client_id too)
 */
app.get("/auth/ga4/start", async (req, res) => {
  try {
    const workspace_id =
      (Array.isArray(req.query.workspace_id)
        ? req.query.workspace_id[0]
        : req.query.workspace_id) ||
      (Array.isArray(req.query.client_id)
        ? req.query.client_id[0]
        : req.query.client_id);

    if (!workspace_id) {
      return res.status(400).json({
        error: "workspace_id required",
        example: "/auth/ga4/start?workspace_id=test_workspace",
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
 */
app.get("/auth/ga4/callback", async (req, res) => {
  try {
    const code = Array.isArray(req.query.code) ? req.query.code[0] : req.query.code;
    const state = Array.isArray(req.query.state) ? req.query.state[0] : req.query.state;

    if (!code || !state) return res.status(400).send("Missing code/state");

    const decoded = verifyState(state);
    const { workspace_id } = decoded;

    const oauth2Client = getOAuthClient();
    const { tokens } = await oauth2Client.getToken(code);

    const payload = {
      client_id: workspace_id, // keep column name if your DB uses client_id
      connector_type: "ga4",
      access_token: tokens.access_token || null,
      refresh_token: tokens.refresh_token || null,
      expiry_date: tokens.expiry_date || null,
      token_type: tokens.token_type || null,
      scope: tokens.scope || null,
      updated_at: new Date().toISOString(),
    };

    const supabase = getSupabase();

    const { error } = await supabase
      .from("oauth_tokens")
      .upsert(payload, { onConflict: "client_id,connector_type" });

    if (error) throw error;

    // For now just redirect to homepage
    return res.redirect(`https://brifly.ai?ga4=connected`);
  } catch (e) {
    console.error("❌ /auth/ga4/callback error:", e);
    return res.status(500).send("OAuth failed");
  }
});

/**
 * Make Cloud Run happy:
 * - MUST listen on process.env.PORT
 * - Bind to 0.0.0.0
 */
const PORT = Number(process.env.PORT) || 8080;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`✅ Server listening on ${PORT}`);
});

// Helps catch “silent crashes”
process.on("unhandledRejection", (err) => console.error("unhandledRejection:", err));
process.on("uncaughtException", (err) => console.error("uncaughtException:", err));
