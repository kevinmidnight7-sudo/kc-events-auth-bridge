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

// =============================================================================
// CHANGE 1: /oauth/discord/start handler updated
// This handler now accepts a Discord ID directly as the state parameter.
// =============================================================================
app.get('/oauth/discord/start', async (req, res) => {
  try {
    const state = String(req.query.state || '').trim();

    // Basic sanity check: Discord snowflakes are 17–20 digits
    if (!/^\d{17,20}$/.test(state)) {
      return res.status(400).send('Bad state');
    }

    const params = new URLSearchParams({
      client_id: process.env.DISCORD_CLIENT_ID,
      redirect_uri: process.env.DISCORD_REDIRECT_URI, // e.g. https://auth.kcevents.uk/oauth/discord/callback
      response_type: 'code',
      scope: 'identify',
      state,                 // pass the discordId through unchanged
      prompt: 'consent'
    });

    const authorizeUrl = `https://discord.com/api/oauth2/authorize?${params.toString()}`;
    return res.redirect(authorizeUrl);
  } catch (err) {
    console.error('start error:', err);
    return res.status(500).send('Start error');
  }
});

// Helper function to perform POST requests with form data
async function postForm(url, params) {
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams(params),
  });
  return response;
}

// GET /oauth/discord/callback
// Handle the OAuth2 callback. Exchange the code for tokens, fetch the
// Discord user, update Firestore and issue a custom token.
app.get('/oauth/discord/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code || !state) {
      return res.status(400).send('Missing code or state');
    }

    // The old state validation logic has been removed as we now pass the
    // Discord ID directly.

    // Exchange the authorization code for an access token
    const tokenRes = await postForm('https://discord.com/api/oauth2/token', {
      client_id: process.env.DISCORD_CLIENT_ID,
      client_secret: process.env.DISCORD_CLIENT_SECRET,
      grant_type: 'authorization_code',
      code: code,
      redirect_uri: process.env.DISCORD_REDIRECT_URI,
    });
    if (!tokenRes.ok) {
      console.error('Token exchange failed', await tokenRes.text());
      return res.redirect(process.env.PUBLIC_WEB_ERROR_URL || '/');
    }
    const tokenData = await tokenRes.json();
    const accessToken = tokenData.access_token;

    // Fetch the user’s Discord profile
    const userRes = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (!userRes.ok) {
      console.error('Failed to fetch Discord user', await userRes.text());
      return res.redirect(process.env.PUBLIC_WEB_ERROR_URL || '/');
    }
    const discordUser = await userRes.json(); // Renamed to discordUser for clarity
    const discordIdFromApi = String(discordUser.id);
    const discordUsername = discordUser.username;
    const avatarHash = discordUser.avatar;
    const avatarUrl = avatarHash
      ? `https://cdn.discordapp.com/avatars/${discordIdFromApi}/${avatarHash}.png`
      : null;

    // Look up existing KC user by discordId
    let userDoc = null;
    const snap = await db
      .collection('users')
      .where('discordId', '==', discordIdFromApi)
      .limit(1)
      .get();
    if (!snap.empty) {
      userDoc = snap.docs[0];
    }

    // If no existing user, create a new one.
    if (!userDoc) {
      const newRef = db.collection('users').doc();
      await newRef.set({
        displayName: discordUsername,
        username: discordUsername,
        joined: Date.now(),
        discordId: discordIdFromApi,
        discordUsername: discordUsername,
        discordAvatarURL: avatarUrl,
      });
      userDoc = await newRef.get();
    } else {
      // Update the existing document with current Discord info
      await userDoc.ref.update({
        discordId: discordIdFromApi,
        discordUsername: discordUsername,
        discordAvatarURL: avatarUrl,
      });
    }

    const uid = userDoc.id;

    // =============================================================================
    // CHANGE 2: Read state as Discord ID and save the mapping
    // This block reads the state from the callback, validates it as a Discord ID,
    // and writes the mapping to the Realtime Database.
    // =============================================================================
    const discordIdFromState = String(req.query.state || '').trim();
    const discordId = /^\d{17,20}$/.test(discordIdFromState)
      ? discordIdFromState
      : (discordUser?.id || '');

    // If we still don't have a valid discordId, bail
    if (!/^\d{17,20}$/.test(discordId)) {
      return res.status(400).send('Missing discord id');
    }

    // Write mapping into RTDB so bot can resolve quickly
    await admin.database().ref(`discordLinks/${discordId}`).set({
      uid,
      linkedAt: Date.now(),
    });

    // Optional mirror on the user
    await admin.database().ref(`users/${uid}/linkedDiscordId`).set(discordId);
    // =============================================================================
    // End of Change 2
    // =============================================================================

    // Issue a Firebase custom token for this user.
    const customToken = await admin
      .auth()
      .createCustomToken(uid, { discordId });

    // Redirect to success URL with the custom token appended
    const successUrl = new URL(process.env.PUBLIC_WEB_SUCCESS_URL);
    successUrl.searchParams.set('customToken', customToken);
    return res.redirect(successUrl.toString());
  } catch (err) {
    console.error(err);
    return res.redirect(process.env.PUBLIC_WEB_ERROR_URL || '/');
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Auth bridge listening on port ${PORT}`);
});
