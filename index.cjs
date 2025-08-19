const express = require('express');
const admin = require('firebase-admin');

/*
 * KC Events – Discord OAuth Bridge
 *
 * This Express server handles the Discord OAuth2 flow and ties a Discord user
 * to an existing KC Events profile stored in Firestore. The flow works as
 * follows:
 *
 * 1) A user action (e.g., in a web UI) generates a URL pointing at
 * `/oauth/discord/start?state=<discord_id>`. When the user clicks the link,
 * it redirects them to Discord’s OAuth2 authorize endpoint. The only scope
 * requested is `identify` – this is enough to retrieve the user’s ID and
 * username. The user's Discord ID is passed through the `state` parameter.
 *
 * 2) After the user authorizes, Discord calls back to
 * `/oauth/discord/callback?code=...&state=<discord_id>`. The bridge
 * exchanges the code for an access token, fetches the user profile from
 * Discord, finds (or creates) a Firestore `users/{uid}` document, updates
 * it with the Discord profile info, writes a mapping to the Realtime
 * Database (`discordLinks/{discordId}` -> `{uid}`), issues a Firebase
 * custom token for the KC user, and finally redirects the user to
 * `PUBLIC_WEB_SUCCESS_URL?customToken=<token>`.
 */

// Load service account credentials for Firebase Admin SDK. Two methods
// are supported:
//
// 1. Set `FB_SERVICE_ACCOUNT_JSON` in the environment containing the
//    JSON string of the service account (useful in serverless
//    deployments).
// 2. Set `FB_SERVICE_ACCOUNT_PATH` to the path of a JSON file on disk
//    (e.g. ./serviceAccountKey.json). When both are absent, the
//    application will throw an error on startup.
let credential;
if (process.env.FB_SERVICE_ACCOUNT_JSON) {
  const json = JSON.parse(process.env.FB_SERVICE_ACCOUNT_JSON);
  credential = admin.credential.cert(json);
} else if (process.env.FB_SERVICE_ACCOUNT_PATH) {
  // Dynamically require the JSON file from the provided path
  const json = require(process.env.FB_SERVICE_ACCOUNT_PATH);
  credential = admin.credential.cert(json);
} else {
  throw new Error('Missing FB_SERVICE_ACCOUNT_JSON or FB_SERVICE_ACCOUNT_PATH environment variable');
}

// Initialize Firebase Admin SDK. Include databaseURL so Realtime Database
// operations (e.g. writing discordLinks) work correctly. When databaseURL
// is undefined, admin.database() will attempt to infer the URL from the
// service account project ID.
admin.initializeApp({
  credential,
  databaseURL: process.env.FB_DATABASE_URL,
});

const db = admin.firestore();

const app = express();

// Serve static files from the 'public' directory
app.use(express.static('public'));

// -----------------------------------------------------------------------------
// Custom success and error pages for Discord account linking
//
// These endpoints serve simple HTML pages after the OAuth flow completes. They
// extract the custom Firebase token (if present) and provide a link to the
// KC Events login page with the token appended as a query parameter. If no
// token is provided, the link points directly to the login page. Hosting these
// pages on the auth bridge removes the need to create static pages on
// Squarespace.

// Route: /discord-login-success
// Responds with an HTML page indicating success and linking to the KC Events
// login page. Accepts an optional `customToken` query parameter.
app.get('/discord-login-success', (req, res) => {
  // Prefer the `customToken` query param but fall back to `token` for
  // backwards compatibility. Older versions of the auth bridge used
  // `token` instead of `customToken` when redirecting to the success page.
  const token = req.query.customToken || req.query.token;
  // Base login URL for KC Events. If you change your KC Events domain or
  // path, update this constant accordingly.
  const baseLoginUrl =
    'https://kcevents.uk/#loginpage';
  // Append the custom token as a query parameter if present. Many Firebase
  // client apps expect a token parameter named `token`, but adjust as needed.
  const loginUrl = token
    ? `${baseLoginUrl}?token=${encodeURIComponent(token)}`
    : baseLoginUrl;
  const html = `<!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <title>KC Events – Account Linked</title>
    </head>
    <body style="font-family: sans-serif; background: #f4f4f8; color: #333; padding: 2rem;">
      <h1>Account linked successfully</h1>
      <p>Your Discord account has been linked to your KC Events profile.</p>
      <p>
        Click the button below to continue to KC Events.  If you aren’t logged in
        automatically, simply sign in with your existing KC Events email and password.
      </p>
      <p>
        <a href="${loginUrl}" style="
          display: inline-block;
          padding: 0.75rem 1.5rem;
          background: #4f46e5;
          color: white;
          border-radius: 4px;
          text-decoration: none;
          font-weight: 600;
        ">Continue to KC Events</a>
      </p>
    </body>
    </html>`;
  res.set('Content-Type', 'text/html').send(html);
});

// Route: /discord-login-error
// Responds with an HTML page indicating an error during the linking process.
app.get('/discord-login-error', (req, res) => {
  const html = `<!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <title>KC Events – Linking Error</title>
    </head>
    <body style="font-family: sans-serif; background: #f4f4f8; color: #333; padding: 2rem;">
      <h1>Linking error</h1>
      <p>We were unable to link your Discord account. This may happen if you
      denied the Discord authorization or if the link expired. Please return to
      Discord and try again, or contact support if the issue persists.</p>
    </body>
    </html>`;
  res.set('Content-Type', 'text/html').send(html);
});

// This handler now accepts a Discord ID directly as the state parameter.
app.get('/oauth/discord/start', async (req, res) => {
  const state = String(req.query.state || '').trim();
  if (!/^\d{17,20}$/.test(state)) return res.status(400).send('Bad state');

  const params = new URLSearchParams({
    client_id: process.env.DISCORD_CLIENT_ID,
    redirect_uri: process.env.DISCORD_REDIRECT_URI,
    response_type: 'code',
    scope: 'identify',
    state,
    prompt: 'consent'
  });

  res.redirect(`https://discord.com/api/oauth2/authorize?${params}`);
});

// NEW: /oauth/discord/callback handler
// This version just exchanges the code and redirects to the link page.
app.get('/oauth/discord/callback', async (req, res) => {
  try {
    const code  = String(req.query.code || '');
    const state = String(req.query.state || ''); // original discordId passed through

    if (!code || !state) return res.status(400).send('Missing code or state');

    // 1) Exchange code -> token (to validate the flow)
    const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: process.env.DISCORD_CLIENT_ID,
        client_secret: process.env.DISCORD_CLIENT_SECRET,
        grant_type: 'authorization_code',
        code,
        redirect_uri: process.env.DISCORD_REDIRECT_URI
      })
    });
    if (!tokenRes.ok) {
      console.error('Token exchange failed', await tokenRes.text());
      return res.redirect(process.env.PUBLIC_WEB_ERROR_URL || '/discord-login-error');
    }

    // 2) (Optional) you can fetch /users/@me here if you want to log it:
    // const { access_token, token_type } = await tokenRes.json();
    // const me = await fetch('https://discord.com/api/users/@me', {
    //   headers: { Authorization: `${token_type} ${access_token}` }
    // }).then(r => r.json());
    // console.log('Discord user:', me);

    // 3) Redirect user to the KC login/confirm page to finish linking
    const target = `https://auth.kcevents.uk/link.html?state=${encodeURIComponent(state)}&ok=1`;
    return res.redirect(target);
  } catch (err) {
    console.error('callback error:', err);
    return res.redirect(process.env.PUBLIC_WEB_ERROR_URL || '/discord-login-error');
  }
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Auth bridge listening on port ${PORT}`);
});
