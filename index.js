import express from "express";
import crypto from "crypto";
import { google } from "googleapis";
import { createClient } from "@supabase/supabase-js";
import { getAuthUrl, getOAuthClient } from "./ga4_oauth.js";

const app = express();
app.use(express.json());

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// 1) Start OAuth: user hits this, gets redirected to Google
app.get("/auth/ga4/start", async (req, res) => {
  // IMPORTANT: you should pass your client_id / tenant_id here
  // Example call: /auth/ga4/start?client_id=43a7...
  const client_id = req.query.client_id;

  if (!client_id) return res.status(400).json({ error: "client_id required" });

  // state = signed value so nobody tampers
  const nonce = crypto.randomUUID();
  const state = Buffer.from(JSON.stringify({ client_id, nonce })).toString("base64url");

  const url = getAuthUrl(state);
  return res.redirect(url);
});

// 2) OAuth callback: Google redirects here with ?code=...
app.get("/auth/ga4/callback", async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code || !state) return res.status(400).send("Missing code/state");

    const decoded = JSON.parse(Buffer.from(state, "base64url").toString("utf8"));
    const { client_id } = decoded;

    const oauth2Client = getOAuthClient();
    const { tokens } = await oauth2Client.getToken(code);

    // Save tokens in Supabase (recommended: encrypt later)
    const payload = {
      client_id,
      connector_type: "ga4",
      access_token: tokens.access_token || null,
      refresh_token: tokens.refresh_token || null,
      expiry_date: tokens.expiry_date || null,
      token_type: tokens.token_type || null,
      scope: tokens.scope || null,
    };

    // upsert into a table you create: public.oauth_tokens
    const { error } = await supabase
      .from("oauth_tokens")
      .upsert(payload, { onConflict: "client_id,connector_type" });

    if (error) throw error;

    // Redirect back to your frontend (change this)
    return res.redirect(`https://brifly.ai?ga4=connected`);
  } catch (e) {
    console.error(e);
    return res.status(500).send("OAuth failed");
  }
});

app.get("/health", (req, res) => res.json({ ok: true }));

const port = process.env.PORT || 8080;
app.listen(port, () => console.log("Server running on", port));
