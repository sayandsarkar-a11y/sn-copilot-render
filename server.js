import express from "express";
import cookieParser from "cookie-parser";
import crypto from "crypto";

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(express.static("public"));

const APP_BASE_URL = process.env.APP_BASE_URL;
const SN_CLIENT_ID = process.env.SN_CLIENT_ID;
const SN_CLIENT_SECRET = process.env.SN_CLIENT_SECRET;
const SN_REDIRECT_URI = `${APP_BASE_URL}/auth/callback`;

const sessions = new Map();

function getOrCreateSid(req, res) {
  let sid = req.cookies.sid;
  if (!sid || !sessions.has(sid)) {
    sid = crypto.randomBytes(16).toString("hex");
    sessions.set(sid, {});
    res.cookie("sid", sid, { httpOnly: true, sameSite: "lax", secure: true });
  }
  return sid;
}

function getSession(req) {
  const sid = req.cookies.sid;
  if (!sid) return null;
  return sessions.get(sid) || null;
}

function base64url(buf) {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function randomVerifier() {
  return base64url(crypto.randomBytes(32));
}
function pkceChallenge(verifier) {
  const hash = crypto.createHash("sha256").update(verifier).digest();
  return base64url(hash);
}

app.get("/auth/start", (req, res) => {
  const instanceUrl = (req.query.instance || "").toString().replace(/\/+$/, "");
  if (!instanceUrl.startsWith("https://")) return res.status(400).send("Invalid instance URL");

  const sid = getOrCreateSid(req, res);
  const verifier = randomVerifier();
  const challenge = pkceChallenge(verifier);
  const state = crypto.randomBytes(16).toString("hex");

  const s = sessions.get(sid);
  s.instanceUrl = instanceUrl;
  s.pkceVerifier = verifier;
  s.oauthState = state;

  const authUrl =
    `${instanceUrl}/oauth_auth.do?` +
    new URLSearchParams({
      response_type: "code",
      client_id: SN_CLIENT_ID,
      redirect_uri: SN_REDIRECT_URI,
      code_challenge: challenge,
      code_challenge_method: "S256",
      state
    }).toString();

  res.redirect(authUrl);
});

app.get("/auth/callback", async (req, res) => {
  const code = req.query.code?.toString();
  const state = req.query.state?.toString();

  const s = getSession(req);
  if (!s || !code || !state) return res.status(400).send("Missing session/code/state");
  if (state !== s.oauthState) return res.status(400).send("State mismatch");

  const tokenUrl = `${s.instanceUrl}/oauth_token.do`;
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: SN_REDIRECT_URI,
    client_id: SN_CLIENT_ID,
    client_secret: SN_CLIENT_SECRET,
    code_verifier: s.pkceVerifier
  });

  const r = await fetch(tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body
  });

  const text = await r.text();
  if (!r.ok) return res.status(500).send(`Token exchange failed: ${text}`);

  const json = JSON.parse(text);
  s.accessToken = json.access_token;

  delete s.pkceVerifier;
  delete s.oauthState;

  res.redirect("/");
});

app.get("/api/status", async (req, res) => {
  const s = getSession(req);
  if (!s?.instanceUrl || !s?.accessToken) return res.json({ connected: false });

  const r = await fetch(`${s.instanceUrl}/api/now/ui/meta`, {
    headers: { Authorization: `Bearer ${s.accessToken}` }
  });

  if (!r.ok) return res.json({ connected: false });

  res.json({ connected: true, instanceUrl: s.instanceUrl });
});

app.post("/api/chat", (req, res) => {
  const s = getSession(req);
  if (!s?.accessToken) return res.status(401).json({ error: "Not connected" });

  res.json({
    plan: {
      intent: "FIELD_CHANGE",
      table: "incident",
      operations: [
        {
          action: "CREATE_FIELD",
          name: "u_example_field",
          internal_type: "string",
          label: "Example field",
          mandatory: false
        }
      ],
      requires_approval: true
    }
  });
});

app.listen(process.env.PORT || 10000);
