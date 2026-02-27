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
const SESSION_SECRET = process.env.SESSION_SECRET || "change_this_secret";

const SN_REDIRECT_URI = `${APP_BASE_URL}/auth/callback`;

// =======================
// Helper: sign + verify cookies
// =======================

function sign(data) {
  const payload = Buffer.from(JSON.stringify(data)).toString("base64url");
  const sig = crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(payload)
    .digest("base64url");
  return `${payload}.${sig}`;
}

function verify(token) {
  if (!token) return null;
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const [payload, sig] = parts;

  const expected = crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(payload)
    .digest("base64url");

  if (sig !== expected) return null;

  return JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
}

// =======================
// PKCE Helpers
// =======================

function base64url(buf) {
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function randomVerifier() {
  return base64url(crypto.randomBytes(32));
}

function pkceChallenge(verifier) {
  const hash = crypto.createHash("sha256").update(verifier).digest();
  return base64url(hash);
}

// =======================
// AUTH START
// =======================

app.get("/auth/start", (req, res) => {
  const instanceUrl = (req.query.instance || "")
    .toString()
    .replace(/\/+$/, "");

  if (!instanceUrl.startsWith("https://")) {
    return res.status(400).send("Invalid instance URL");
  }

  const verifier = randomVerifier();
  const challenge = pkceChallenge(verifier);
  const state = crypto.randomBytes(16).toString("hex");

  // Store transient OAuth state in signed cookie
  res.cookie(
    "sn_auth",
    sign({ instanceUrl, verifier, state }),
    {
      httpOnly: true,
      sameSite: "lax",
      secure: true,
      path: "/",
      maxAge: 10 * 60 * 1000
    }
  );

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

app.get("/api/test-call", async (req, res) => {
  const conn = verify(req.cookies.sn_conn);
  if (!conn?.accessToken) return res.status(401).json({ error: "Not connected" });

  const r = await fetch(`${conn.instanceUrl}/api/now/table/sys_user?sysparm_limit=1`, {
    headers: { Authorization: `Bearer ${conn.accessToken}`, Accept: "application/json" }
  });

  const text = await r.text();
  res.status(r.status).send(text);
});

// =======================
// AUTH CALLBACK
// =======================

app.get("/auth/callback", async (req, res) => {
  const code = req.query.code?.toString();
  const state = req.query.state?.toString();

  const auth = verify(req.cookies.sn_auth);

  if (!auth || !code || !state) {
    return res.status(400).send("Missing auth/code/state");
  }

  if (state !== auth.state) {
    return res.status(400).send("State mismatch");
  }

  const tokenUrl = `${auth.instanceUrl}/oauth_token.do`;

  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: SN_REDIRECT_URI,
    client_id: SN_CLIENT_ID,
    client_secret: SN_CLIENT_SECRET,
    code_verifier: auth.verifier
  });

  const r = await fetch(tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body
  });

  const text = await r.text();

  if (!r.ok) {
    console.error("Token exchange failed:", text);
    return res.status(500).send("Token exchange failed");
  }

  const json = JSON.parse(text);

  if (!json.access_token) {
    return res.status(500).send("No access_token returned");
  }

  // Store persistent connection in signed cookie
  res.cookie(
    "sn_conn",
    sign({
      instanceUrl: auth.instanceUrl,
      accessToken: json.access_token
    }),
    {
      httpOnly: true,
      sameSite: "lax",
      secure: true,
      path: "/",
      maxAge: 60 * 60 * 1000
    }
  );

  // Clear temp cookie
  res.cookie("sn_auth", "", { path: "/", maxAge: 0 });

  res.redirect("/");
});

// =======================
// STATUS CHECK
// =======================

app.get("/api/status", (req, res) => {
  const conn = verify(req.cookies.sn_conn);

  if (!conn?.instanceUrl || !conn?.accessToken) {
    return res.json({ connected: false });
  }

  return res.json({
    connected: true,
    instanceUrl: conn.instanceUrl
  });
});

// =======================
// CHAT (stub)
// =======================

app.post("/api/chat", (req, res) => {
  const conn = verify(req.cookies.sn_conn);
  if (!conn?.accessToken) {
    return res.status(401).json({ error: "Not connected" });
  }

  const msg = (req.body?.message || "").toString();

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
      original_user_text: msg,
      requires_approval: true
    }
  });
});

// =======================
// EXECUTE (dry run for now)
// =======================

app.post("/api/execute", (req, res) => {
  const conn = verify(req.cookies.sn_conn);
  if (!conn?.accessToken) {
    return res.status(401).json({ error: "Not connected" });
  }

  res.json({
    status: "DRY_RUN_ONLY",
    received_plan: req.body?.plan || null
  });
});

// =======================

const port = process.env.PORT || 10000;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
