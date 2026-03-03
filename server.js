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

async function deepseekGeneratePlan({ userText }) {
  const apiKey = process.env.DEEPSEEK_API_KEY;
  if (!apiKey) throw new Error("Missing DEEPSEEK_API_KEY env var");

  const systemPrompt = `
You convert natural-language ServiceNow change requests into strict JSON.

Return ONLY JSON. No markdown. No commentary.

Required format:
{
  "intent": "FIELD_CHANGE",
  "operations": [
    {
      "action": "CREATE_FIELD",
      "table": "incident",
      "name": "u_field_name",
      "internal_type": "string|integer|boolean|date|choice",
      "label": "Field Label",
      "mandatory": true|false,
      "choices": ["A","B"]   // REQUIRED if internal_type is "choice"
    }
  ],
  "notes": "optional notes"
}

Rules:
- Field name MUST start with u_
- If user requests choice field, internal_type MUST be "choice"
- If internal_type is choice, choices array MUST be included
- Always include table inside each operation
- Mandatory true only if user explicitly says mandatory/required
`;

  const response = await fetch("https://api.deepseek.com/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${apiKey}`
    },
    body: JSON.stringify({
      model: "deepseek-chat",
      temperature: 0,
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: userText }
      ]
    })
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error(`DeepSeek error: ${JSON.stringify(data)}`);
  }

  const text = data?.choices?.[0]?.message?.content?.trim();
  if (!text) throw new Error("DeepSeek returned empty response");

  let plan;
  try {
    plan = JSON.parse(text);
  } catch (err) {
    throw new Error("DeepSeek did not return valid JSON:\n" + text);
  }

  // ---- HARD VALIDATION ----
  if (plan.intent !== "FIELD_CHANGE") plan.intent = "FIELD_CHANGE";
  if (!Array.isArray(plan.operations) || plan.operations.length === 0) {
    throw new Error("No operations returned from DeepSeek");
  }

  const op = plan.operations[0];
  op.action = "CREATE_FIELD";

  if (!op.table) throw new Error("Missing table");
  if (!op.name?.startsWith("u_")) throw new Error("Field name must start with u_");

  const allowedTypes = ["string", "integer", "boolean", "date", "choice"];
  if (!allowedTypes.includes(op.internal_type)) {
    throw new Error("Invalid internal_type: " + op.internal_type);
  }

  if (op.internal_type === "choice") {
    if (!Array.isArray(op.choices) || op.choices.length === 0) {
      throw new Error("Choice field requires non-empty choices array");
    }

    // sanitize choices
    const seen = new Set();
    op.choices = op.choices
      .map(c => String(c).trim())
      .filter(c => c && !seen.has(c) && (seen.add(c), true));
  } else {
    delete op.choices;
  }

  plan.operations = [op];
  return plan;
}

// async function geminiGeneratePlan({ userText }) {
//   const apiKey = process.env.GEMINI_API_KEY;
//   if (!apiKey) throw new Error("Missing GEMINI_API_KEY env var");

//   const model = "gemini-3-pro-preview";
//   const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`;

//   const systemInstruction = `
// Return ONLY valid JSON (no markdown).
// Convert the user request into a ServiceNow field-change plan.

// Required output shape:
// {
//   "intent": "FIELD_CHANGE",
//   "operations": [
//     {
//       "action": "CREATE_FIELD",
//       "table": "<table>",
//       "name": "u_<field_name>",
//       "internal_type": "string|integer|boolean|date|choice",
//       "label": "<label>",
//       "mandatory": true|false,
//       "choices": ["A","B"] // REQUIRED if internal_type is "choice"
//     }
//   ],
//   "notes": "..."
// }

// Rules:
// - Field name must start with u_
// - If user asks for a choice field, internal_type MUST be "choice" and choices MUST be present and non-empty.
// - Put the table inside the operation as "table".
// `.trim();

//   const response_schema = {
//     type: "OBJECT",
//     properties: {
//       intent: { type: "STRING" },
//       operations: {
//         type: "ARRAY",
//         items: {
//           type: "OBJECT",
//           properties: {
//             action: { type: "STRING" },
//             table: { type: "STRING" },
//             name: { type: "STRING" },
//             internal_type: { type: "STRING" },
//             label: { type: "STRING" },
//             mandatory: { type: "BOOLEAN" },
//             choices: { type: "ARRAY", items: { type: "STRING" } }
//           },
//           required: ["action", "table", "name", "internal_type", "label", "mandatory"]
//         }
//       },
//       notes: { type: "STRING" }
//     },
//     required: ["intent", "operations"]
//   };

//   const body = {
//     system_instruction: { parts: [{ text: systemInstruction }] },
//     contents: [{ role: "user", parts: [{ text: userText }] }],
//     generationConfig: {
//       response_mime_type: "application/json",
//       response_schema
//     }
//   };

//   const r = await fetch(url, {
//     method: "POST",
//     headers: { "Content-Type": "application/json", "x-goog-api-key": apiKey },
//     body: JSON.stringify(body)
//   });

//   const j = await r.json();
//   if (!r.ok) throw new Error(`Gemini error: ${JSON.stringify(j)}`);

//   const text = j?.candidates?.[0]?.content?.parts?.map(p => p.text || "").join("")?.trim() || "";
//   if (!text) throw new Error("Gemini returned empty response");

//   const plan = JSON.parse(text);

//   // hard guards
//   if (plan.intent !== "FIELD_CHANGE") plan.intent = "FIELD_CHANGE";
//   if (!Array.isArray(plan.operations) || plan.operations.length === 0) throw new Error("No operations returned");

//   const op = plan.operations[0];
//   op.action = "CREATE_FIELD";

//   if (!op.table) throw new Error("Missing table in operation");
//   if (typeof op.name !== "string" || !op.name.startsWith("u_")) throw new Error("Field name must start with u_");

//   if (op.internal_type === "choice") {
//     if (!Array.isArray(op.choices) || op.choices.length === 0) {
//       throw new Error("Choice field requires choices[]");
//     }
//     // cleanup
//     const seen = new Set();
//     op.choices = op.choices.map(c => String(c).trim()).filter(c => c && !seen.has(c) && (seen.add(c), true));
//     if (op.choices.length === 0) throw new Error("choices[] empty after cleanup");
//   } else {
//     delete op.choices;
//   }

//   plan.operations = [op];
//   return plan;
// }

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

// app.post("/api/chat", (req, res) => {
//   const conn = verify(req.cookies.sn_conn);
//   if (!conn?.accessToken) {
//     return res.status(401).json({ error: "Not connected" });
//   }

//   const msg = (req.body?.message || "").toString();

//   res.json({
//     plan: {
//       intent: "FIELD_CHANGE",
//       table: "incident",
//       operations: [
//         {
//           action: "CREATE_FIELD",
//           name: "u_example_field",
//           internal_type: "string",
//           label: "Example field",
//           mandatory: false
//         }
//       ],
//       original_user_text: msg,
//       requires_approval: true
//     }
//   });
// });

// app.post("/api/chat", async (req, res) => {
//   const conn = verify(req.cookies.sn_conn);
//   if (!conn?.accessToken) return res.status(401).json({ error: "Not connected" });

//   const msg = (req.body?.message || "").toString().trim();
//   if (!msg) return res.status(400).json({ error: "Missing message" });

//   try {
//     const plan = await geminiGeneratePlan({ userText: msg });

//     // Optional: include original text & approval flag for UI
//     plan.original_user_text = msg;
//     plan.requires_approval = true;

//     return res.json({ plan });
//   } catch (e) {
//     return res.status(500).json({ error: String(e.message || e) });
//   }
// });

app.post("/api/chat", async (req, res) => {
  const conn = verify(req.cookies.sn_conn);
  if (!conn?.accessToken) {
    return res.status(401).json({ error: "Not connected" });
  }

  const msg = (req.body?.message || "").trim();
  if (!msg) {
    return res.status(400).json({ error: "Missing message" });
  }

  try {
    const plan = await deepseekGeneratePlan({ userText: msg });

    plan.original_user_text = msg;
    plan.requires_approval = true;

    return res.json({ plan });
  } catch (err) {
    return res.status(500).json({ error: String(err.message || err) });
  }
});

// =======================
// EXECUTE (dry run for now)
// =======================

app.post("/api/execute", async (req, res) => {
  const conn = verify(req.cookies.sn_conn);
  if (!conn?.accessToken) return res.status(401).json({ error: "Not connected" });

  const plan = req.body?.plan;
  if (!plan?.operations?.length) return res.status(400).json({ error: "Invalid plan" });

  const op = plan.operations[0]; // MVP: single operation

  // ---- Safety checks ----
  const table = (op.table || plan.table || "").toString();
  const name = (op.name || "").toString();
  const type = (op.internal_type || "").toString();
  const label = (op.label || "").toString();
  const mandatory = !!op.mandatory;
  const choices = Array.isArray(op.choices) ? op.choices : [];

  const allowedTypes = new Set(["string", "integer", "boolean", "date", "choice"]);
  if (!table) return res.status(400).json({ error: "Missing table" });
  if (!/^u_[a-zA-Z0-9_]+$/.test(name)) return res.status(400).json({ error: "Field name must start with u_" });
  if (!allowedTypes.has(type)) return res.status(400).json({ error: `Unsupported type: ${type}` });
  if (type === "choice" && choices.length === 0) return res.status(400).json({ error: "Choice field requires choices[]" });

  try {
    // 1) Check if field exists
    const existsUrl =
      `${conn.instanceUrl}/api/now/table/sys_dictionary?` +
      new URLSearchParams({
        sysparm_query: `name=${table}^element=${name}`,
        sysparm_fields: "sys_id",
        sysparm_limit: "1"
      }).toString();

    const existsRes = await fetch(existsUrl, {
      headers: { Authorization: `Bearer ${conn.accessToken}`, Accept: "application/json" }
    });

    const existsJson = await existsRes.json();
    if (existsJson?.result?.length) {
      return res.json({ status: "SKIPPED", message: "Field already exists", sys_id: existsJson.result[0].sys_id });
    }

    // 2) Create sys_dictionary record
    const dictBody = {
      name: table,
      element: name,
      internal_type: type,
      column_label: label || name,
      mandatory: mandatory ? "true" : "false"
    };

    const dictRes = await fetch(`${conn.instanceUrl}/api/now/table/sys_dictionary`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${conn.accessToken}`,
        Accept: "application/json",
        "Content-Type": "application/json"
      },
      body: JSON.stringify(dictBody)
    });

    const dictText = await dictRes.text();
    if (!dictRes.ok) {
      return res.status(500).json({ error: "sys_dictionary create failed", details: dictText });
    }

    const dictJson = JSON.parse(dictText);
    const dictSysId = dictJson?.result?.sys_id;

    // 3) Create sys_choice records (if choice)
    const createdChoices = [];
    if (type === "choice") {
      for (let i = 0; i < choices.length; i++) {
        const choice = String(choices[i]).trim();
        if (!choice) continue;

        const choiceBody = {
          name: table,
          element: name,
          label: choice,
          value: choice,
          sequence: String(100 + i * 10)
        };

        const chRes = await fetch(`${conn.instanceUrl}/api/now/table/sys_choice`, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${conn.accessToken}`,
            Accept: "application/json",
            "Content-Type": "application/json"
          },
          body: JSON.stringify(choiceBody)
        });

        const chText = await chRes.text();
        if (!chRes.ok) {
          return res.status(500).json({
            error: "sys_choice create failed",
            details: chText,
            partial: { dictSysId, createdChoices }
          });
        }

        const chJson = JSON.parse(chText);
        createdChoices.push(chJson?.result?.sys_id);
      }
    }

    return res.json({
      status: "CREATED",
      dict_sys_id: dictSysId,
      choices_sys_ids: createdChoices
    });
  } catch (e) {
    return res.status(500).json({ error: "Execution error", details: String(e) });
  }
});

// =======================

const port = process.env.PORT || 10000;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
