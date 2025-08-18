import express from 'express';
import fetch from 'node-fetch';
import admin from 'firebase-admin';
import fs from 'fs';

const app = express();
const port = process.env.PORT || 3000;

const {
  DISCORD_CLIENT_ID,
  DISCORD_CLIENT_SECRET,
  DISCORD_REDIRECT_URI,
  PUBLIC_WEB_SUCCESS_URL,
  PUBLIC_WEB_ERROR_URL,
  FB_SERVICE_ACCOUNT_JSON,
  FB_SERVICE_ACCOUNT_PATH,
} = process.env;

let serviceAccount;
if (FB_SERVICE_ACCOUNT_JSON) {
  serviceAccount = JSON.parse(FB_SERVICE_ACCOUNT_JSON);
} else if (FB_SERVICE_ACCOUNT_PATH) {
  const jsonStr = fs.readFileSync(FB_SERVICE_ACCOUNT_PATH, 'utf8');
  serviceAccount = JSON.parse(jsonStr);
} else {
  throw new Error('Service account credentials not provided');
}

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});
const firestore = admin.firestore();

app.get('/oauth/discord/start', async (req, res) => {
  const state = req.query.state;
  if (!state) {
    return res.status(400).send('Missing state');
  }
  const stateRef = firestore.collection('discordLinkStates').doc(state);
  const stateDoc = await stateRef.get();
  if (!stateDoc.exists || stateDoc.data().used) {
    return res.redirect(PUBLIC_WEB_ERROR_URL);
  }
  const oauthUrl = `https://discord.com/oauth2/authorize?client_id=${DISCORD_CLIENT_ID}&response_type=code&scope=identify&state=${state}&redirect_uri=${encodeURIComponent(DISCORD_REDIRECT_URI)}`;
  res.redirect(oauthUrl);
});

app.get('/oauth/discord/callback', async (req, res) => {
  const { code, state } = req.query;
  if (!code || !state) {
    return res.redirect(PUBLIC_WEB_ERROR_URL);
  }
  const stateRef = firestore.collection('discordLinkStates').doc(state);
  const stateDoc = await stateRef.get();
  if (!stateDoc.exists || stateDoc.data().used) {
    return res.redirect(PUBLIC_WEB_ERROR_URL);
  }
  try {
    // Exchange code for access token
    const tokenResponse = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        client_secret: DISCORD_CLIENT_SECRET,
        code,
        grant_type: 'authorization_code',
        redirect_uri: DISCORD_REDIRECT_URI,
        scope: 'identify',
      }),
    });
    const tokenData = await tokenResponse.json();
    const access_token = tokenData.access_token;

    // Fetch Discord user
    const userResponse = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${access_token}` },
    });
    const userData = await userResponse.json();

    // Find existing user by discordId or create new
    let userRef;
    const existingSnap = await firestore.collection('users').where('discordId', '==', userData.id).limit(1).get();
    if (!existingSnap.empty) {
      userRef = existingSnap.docs[0].ref;
    } else {
      userRef = firestore.collection('users').doc();
    }

    await userRef.set(
      {
        discordId: userData.id,
        discordUsername: `${userData.username}#${userData.discriminator}`,
        discordAvatarURL: userData.avatar
          ? `https://cdn.discordapp.com/avatars/${userData.id}/${userData.avatar}.png`
          : null,
      },
      { merge: true }
    );

    // Mark state as used
    await stateRef.update({ used: true });

    // Create Firebase custom token
    const customToken = await admin.auth().createCustomToken(userRef.id);
    const successUrl = `${PUBLIC_WEB_SUCCESS_URL}?token=${customToken}`;
    res.redirect(successUrl);
  } catch (err) {
    console.error(err);
    res.redirect(PUBLIC_WEB_ERROR_URL);
  }
});

app.listen(port, () => {
  console.log(`Auth bridge listening on port ${port}`);
});
