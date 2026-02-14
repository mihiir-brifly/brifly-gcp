import { google } from "googleapis";

export function getOAuthClient() {
  const clientId =
    process.env.GA4_OAUTH_CLIENT_ID || process.env.GA4_OAUTH_CLIENTID;
  const clientSecret =
    process.env.GA4_OAUTH_CLIENT_SECRET || process.env.GA4_OAUTH_CLIENTSECRET;
  const redirectUri =
    process.env.GA4_OAUTH_REDIRECT_URI || process.env.GA4_OAUTH_REDIRECT_URL;

  if (!clientId || !clientSecret || !redirectUri) {
    throw new Error(
      "Missing GA4 OAuth env vars (client id/secret/redirect url)"
    );
  }

  return new google.auth.OAuth2(clientId, clientSecret, redirectUri);
}

export function getAuthUrl(state) {
  const oauth2Client = getOAuthClient();
  return oauth2Client.generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    scope: [
      "https://www.googleapis.com/auth/analytics.readonly",
      "https://www.googleapis.com/auth/analytics.edit",
    ],
    state,
  });
}
