// ga4_oauth.js
import { google } from "googleapis";

export function getOAuthClient() {
  const clientId = process.env.GA4_OAUTH_CLIENT_ID;
  const clientSecret = process.env.GA4_OAUTH_CLIENT_SECRET;
  const redirectUri = process.env.GA4_OAUTH_REDIRECT_URL;

  if (!clientId || !clientSecret || !redirectUri) {
    throw new Error("Missing GA4 OAuth env vars (client id/secret/redirect url)");
  }

  return new google.auth.OAuth2(clientId, clientSecret, redirectUri);
}

export function getAuthUrl(state) {
  const oauth2Client = getOAuthClient();

  // Minimal scopes for GA4 reporting + listing properties
  const scopes = [
    "openid",
    "email",
    "profile",
    "https://www.googleapis.com/auth/analytics.readonly",
  ];

  return oauth2Client.generateAuthUrl({
    access_type: "offline",         // gives refresh_token (important)
    prompt: "consent",              // forces refresh_token on first connect
    scope: scopes,
    state,                          // we’ll pass client_id / tenant_id safely here
    include_granted_scopes: true,
  });
}
