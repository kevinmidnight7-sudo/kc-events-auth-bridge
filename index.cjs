/**
 * KC Events — Discord OAuth Auth Bridge
 *
 * Supports two linking flows:
 *
 *   A) Legacy bot flow:  state = Discord user ID (17-20 digits)
 *      The Discord bot initiates the OAuth flow and passes the user's Discord ID as state.
 *      /start    → validates state matches /^\d{17,20}$/, redirects to Discord OAuth
 *      /callback → redirects to link.html?state=<discordId>&ok=1
 *                  (link.html / the bot handles the actual Firebase writes for this flow)
 *
 *   B) Web UI flow (kcnow.html):  state = Firestore linkStates document ID (random alphanumeric)
 *      kcnow.html creates a linkStates/{state} doc with the user's KC uid, then sends state.
 *      /start    → validates linkStates/{state} doc exists, not used, not expired
 *      /callback → reads linkStates/{state}.uid (kcUid), marks doc used,
 *                  writes Firestore users/{uid}.discordId + RTDB users/{uid}/discordId +
 *                  RTDB discordLinks/{discordId}, issues custom Firebase Auth token,
 *                  redirects to PUBLIC_WEB_SUCCESS_URL?customToken=<token>
 */

'use strict';
const express      = require('express');
const fetch        = require('node-fetch');
const admin        = require('firebase-admin');
const path         = require('path');

const app = express();

// Serve static files (link.html, discord-login-success.html, etc.)
app.use(express.static(path.join(__dirname, 'public')));

// ── Firebase Admin ────────────────────────────────────────────────────────────
// FB_SERVICE_ACCOUNT_JSON: the full service account JSON as a string (Render env var)
// FB_DATABASE_URL: the Realtime Database URL (Render env var)
if (!admin.apps.length) {
    const serviceAccount = JSON.parse(process.env.FB_SERVICE_ACCOUNT_JSON);
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
        databaseURL: process.env.FB_DATABASE_URL,
    });
}
const fsdb = admin.firestore();
const rtdb = admin.database();

// ── Config (from env) ─────────────────────────────────────────────────────────
const CLIENT_ID          = process.env.DISCORD_CLIENT_ID;
const CLIENT_SECRET      = process.env.DISCORD_CLIENT_SECRET;
const REDIRECT_URI       = process.env.DISCORD_REDIRECT_URI;
const PUBLIC_WEB_SUCCESS = process.env.PUBLIC_WEB_SUCCESS_URL || 'https://kevinmidnight7-sudo.github.io/messageboardkc/kcnow.html';
const PORT               = process.env.PORT || 3000;

const LINK_STATE_TTL_MS  = 15 * 60 * 1000; // 15 minutes

// ── CORS headers ──────────────────────────────────────────────────────────────
app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    next();
});

// ── /oauth/discord/start ──────────────────────────────────────────────────────
app.get('/oauth/discord/start', async (req, res) => {
    const state = String(req.query.state || '').trim();
    if (!state) return res.status(400).send('Missing state');

    const isDiscordId = /^\d{17,20}$/.test(state);

    if (!isDiscordId) {
        // Web UI flow — validate Firestore linkStates document
        try {
            const doc = await fsdb.collection('linkStates').doc(state).get();
            if (!doc.exists) return res.status(400).send('Unknown state');
            const data = doc.data();
            const createdMs = data.createdAt?.toMillis?.() || (data.createdAt?._seconds * 1000) || 0;
            if (data.used) return res.status(400).send('State already used');
            if (Date.now() - createdMs > LINK_STATE_TTL_MS) return res.status(400).send('State expired');
        } catch (err) {
            console.error('[start] Firestore error:', err);
            return res.status(500).send('Internal error');
        }
    }

    const params = new URLSearchParams({
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        response_type: 'code',
        scope: 'identify',
        state,
        prompt: 'none',
    });
    res.redirect(`https://discord.com/oauth2/authorize?${params}`);
});

// ── /oauth/discord/callback ───────────────────────────────────────────────────
app.get('/oauth/discord/callback', async (req, res) => {
    const { code, state, error } = req.query;

    if (error) return res.status(400).send(`Discord error: ${error}`);
    if (!code || !state) return res.status(400).send('Missing code or state');

    const isDiscordIdState = /^\d{17,20}$/.test(String(state).trim());

    if (isDiscordIdState) {
        // ── Legacy bot flow ───────────────────────────────────────────────────
        // state = Discord user ID. No API calls needed — redirect straight to
        // link.html which handles everything for this flow.
        const target = `https://auth.kcevents.uk/link.html?state=${encodeURIComponent(state)}&ok=1`;
        return res.redirect(target);
    }

    // ── Web UI flow only: exchange code + fetch Discord identity ─────────────
    let accessToken;
    try {
        const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                client_id: CLIENT_ID,
                client_secret: CLIENT_SECRET,
                grant_type: 'authorization_code',
                code,
                redirect_uri: REDIRECT_URI,
            }).toString(),
        });
        const tokenData = await tokenRes.json();
        if (!tokenData.access_token) {
            console.error('[callback] Token exchange failed:', tokenData);
            return res.status(500).send('Token exchange failed');
        }
        accessToken = tokenData.access_token;
    } catch (err) {
        console.error('[callback] Token exchange error:', err);
        return res.status(500).send('Internal error');
    }

    let discordUser;
    try {
        const userRes = await fetch('https://discord.com/api/users/@me', {
            headers: { Authorization: `Bearer ${accessToken}` },
        });
        discordUser = await userRes.json();
        if (!discordUser.id) {
            console.error('[callback] Discord user fetch failed:', discordUser);
            return res.status(500).send('Failed to get Discord identity');
        }
    } catch (err) {
        console.error('[callback] Discord user fetch error:', err);
        return res.status(500).send('Internal error');
    }

    const discordId = discordUser.id;

    // ── Firestore linkStates lookup ───────────────────────────────────────────
    const stateKey = String(state).trim();
    let kcUid;
    try {
        const docRef = fsdb.collection('linkStates').doc(stateKey);
        const doc = await docRef.get();
        if (!doc.exists) return res.status(400).send('Unknown state');
        const data = doc.data();
        const createdMs = data.createdAt?.toMillis?.() || (data.createdAt?._seconds * 1000) || 0;
        if (data.used) return res.status(400).send('State already used');
        if (Date.now() - createdMs > LINK_STATE_TTL_MS) return res.status(400).send('State expired');
        kcUid = data.uid;
        await docRef.update({ used: true });
    } catch (err) {
        console.error('[callback] Firestore linkStates error:', err);
        return res.status(500).send('Internal error');
    }

    // Write Discord ID to Firestore + RTDB
    try {
        await Promise.all([
            fsdb.collection('users').doc(kcUid).set({ discordId }, { merge: true }),
            rtdb.ref(`users/${kcUid}/discordId`).set(discordId),
            rtdb.ref(`discordLinks/${discordId}`).set({
                kcUid,
                linkedAt: admin.database.ServerValue.TIMESTAMP,
            }),
        ]);
    } catch (err) {
        console.error('[callback] Firebase write error:', err);
        return res.status(500).send('Failed to save link');
    }

    // Issue custom Firebase Auth token and redirect back to KC NOW
    let customToken;
    try {
        customToken = await admin.auth().createCustomToken(kcUid, { discordId });
    } catch (err) {
        console.error('[callback] Custom token error:', err);
        return res.status(500).send('Failed to issue token');
    }

    return res.redirect(`${PUBLIC_WEB_SUCCESS}?customToken=${encodeURIComponent(customToken)}`);
});

// ── Health check ──────────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.send('OK'));

app.listen(PORT, () => console.log(`Auth bridge listening on port ${PORT}`));
