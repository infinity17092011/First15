/**
 * Today's 15 backend
 *  - PayPal subscription verification ($4.99/month) + webhook sync
 *  - Photo -> 15-minute workout via Groq (OpenAI-compatible vision API)
 *  - Postgres (Render) for subscriptions and free-tier usage
 *
 * Required env vars (set in Render):
 *   DATABASE_URL           Postgres connection string
 *   GROQ_API_KEY           Groq API key
 *   JWT_SECRET             Long random string used to sign Pro tokens
 *   PAYPAL_CLIENT_ID       PayPal app client id
 *   PAYPAL_CLIENT_SECRET   PayPal app secret
 *   PAYPAL_PLAN_ID         The $4.99/month plan id (starts with P-)
 *   PAYPAL_WEBHOOK_ID      Webhook id from the PayPal developer dashboard
 * Optional:
 *   PAYPAL_ENV             "sandbox" (default) or "live"
 *   GROQ_MODEL             Defaults to a Llama 4 vision model; check Groq's docs for current names
 *   ALLOWED_ORIGIN         Comma-separated list of allowed site origins (recommended)
 *   FREE_DAILY_LIMIT       Free workouts per day (default 1)
 *   PRO_DAILY_LIMIT        Pro workouts per day (default 20)
 *   PGSSL                  "false" to disable SSL for the database (default: on)
 */
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const { Pool } = require("pg");

const {
  DATABASE_URL, GROQ_API_KEY, JWT_SECRET,
  PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET, PAYPAL_PLAN_ID, PAYPAL_WEBHOOK_ID,
} = process.env;
const PAYPAL_BASE = process.env.PAYPAL_ENV === "live"
  ? "https://api-m.paypal.com"
  : "https://api-m.sandbox.paypal.com";
const GROQ_MODEL = process.env.GROQ_MODEL || "meta-llama/llama-4-scout-17b-16e-instruct";
const FREE_LIMIT = parseInt(process.env.FREE_DAILY_LIMIT || "1", 10);
const PRO_LIMIT = parseInt(process.env.PRO_DAILY_LIMIT || "20", 10);
const MAX_DEVICES_PER_SUB = 5;

for (const [k, v] of Object.entries({ DATABASE_URL, GROQ_API_KEY, JWT_SECRET, PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET, PAYPAL_PLAN_ID, PAYPAL_WEBHOOK_ID })) {
  if (!v) console.warn(`[config] Missing env var: ${k}`);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.PGSSL === "false" ? false : { rejectUnauthorized: false },
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS subscriptions (
      subscription_id TEXT PRIMARY KEY,
      plan_id TEXT NOT NULL,
      status TEXT NOT NULL,
      payer_email TEXT,
      next_billing_time TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS sub_devices (
      subscription_id TEXT NOT NULL REFERENCES subscriptions(subscription_id) ON DELETE CASCADE,
      device_id TEXT NOT NULL,
      PRIMARY KEY (subscription_id, device_id)
    );
    CREATE TABLE IF NOT EXISTS usage (
      key TEXT NOT NULL,
      day DATE NOT NULL,
      count INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (key, day)
    );
  `);
}

/* ---------- PayPal helpers ---------- */
let ppToken = { value: null, exp: 0 };
async function paypalToken() {
  if (ppToken.value && Date.now() < ppToken.exp) return ppToken.value;
  const auth = Buffer.from(`${PAYPAL_CLIENT_ID}:${PAYPAL_CLIENT_SECRET}`).toString("base64");
  const r = await fetch(`${PAYPAL_BASE}/v1/oauth2/token`, {
    method: "POST",
    headers: { Authorization: `Basic ${auth}`, "Content-Type": "application/x-www-form-urlencoded" },
    body: "grant_type=client_credentials",
  });
  if (!r.ok) throw new Error(`PayPal auth failed (${r.status})`);
  const d = await r.json();
  ppToken = { value: d.access_token, exp: Date.now() + (d.expires_in - 60) * 1000 };
  return ppToken.value;
}
async function paypalFetch(path, opts = {}) {
  const token = await paypalToken();
  return fetch(`${PAYPAL_BASE}${path}`, {
    ...opts,
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json", ...(opts.headers || {}) },
  });
}

/* ---------- App ---------- */
const app = express();
app.set("trust proxy", 1); // Render sits behind a proxy
app.use(express.json({ limit: "6mb" }));
const origins = (process.env.ALLOWED_ORIGIN || "").split(",").map((s) => s.trim()).filter(Boolean);
app.use(cors({
  origin: origins.length ? origins : true,
  allowedHeaders: ["Content-Type", "Authorization", "x-device-id"],
}));
app.use(rateLimit({ windowMs: 60 * 1000, limit: 60, standardHeaders: true, legacyHeaders: false }));

const wrap = (fn) => (req, res) => fn(req, res).catch((e) => {
  console.error(e);
  res.status(500).json({ error: "Server error. Please try again." });
});

app.get("/health", (_req, res) => res.json({ ok: true }));

/* ---------- Auth helpers ---------- */
function deviceIdOf(req) {
  const d = String(req.get("x-device-id") || "").trim();
  return /^[A-Za-z0-9_-]{8,64}$/.test(d) ? d : null;
}
async function getPro(req) {
  const h = req.get("authorization") || "";
  if (!h.startsWith("Bearer ")) return null;
  try {
    const { sub } = jwt.verify(h.slice(7), JWT_SECRET);
    const { rows } = await pool.query("SELECT * FROM subscriptions WHERE subscription_id=$1", [sub]);
    const row = rows[0];
    return row && row.status === "ACTIVE" ? row : null;
  } catch { return null; }
}

/* ---------- PayPal: verify a subscription after checkout ---------- */
app.post("/api/paypal/verify", wrap(async (req, res) => {
  const subscriptionId = String(req.body.subscriptionId || "");
  const deviceId = deviceIdOf(req);
  if (!/^I-[A-Z0-9]{6,40}$/.test(subscriptionId)) return res.status(400).json({ error: "Invalid subscription id." });
  if (!deviceId) return res.status(400).json({ error: "Missing device id." });

  const r = await paypalFetch(`/v1/billing/subscriptions/${subscriptionId}`);
  if (!r.ok) return res.status(402).json({ error: "Could not verify this subscription with PayPal." });
  const s = await r.json();

  if (s.plan_id !== PAYPAL_PLAN_ID) return res.status(402).json({ error: "Subscription is for a different plan." });
  if (s.status !== "ACTIVE") return res.status(402).json({ error: `Subscription is ${s.status}. If you just paid, try again in a moment.` });

  const email = s.subscriber && s.subscriber.email_address || null;
  const next = s.billing_info && s.billing_info.next_billing_time || null;
  await pool.query(
    `INSERT INTO subscriptions (subscription_id, plan_id, status, payer_email, next_billing_time)
     VALUES ($1,$2,'ACTIVE',$3,$4)
     ON CONFLICT (subscription_id) DO UPDATE SET status='ACTIVE', payer_email=EXCLUDED.payer_email,
       next_billing_time=EXCLUDED.next_billing_time, updated_at=now()`,
    [subscriptionId, s.plan_id, email, next]
  );

  // Limit how many devices can share one subscription
  const { rows } = await pool.query("SELECT device_id FROM sub_devices WHERE subscription_id=$1", [subscriptionId]);
  const known = rows.some((x) => x.device_id === deviceId);
  if (!known) {
    if (rows.length >= MAX_DEVICES_PER_SUB) return res.status(403).json({ error: "This subscription is used on too many devices." });
    await pool.query("INSERT INTO sub_devices (subscription_id, device_id) VALUES ($1,$2)", [subscriptionId, deviceId]);
  }

  const token = jwt.sign({ sub: subscriptionId }, JWT_SECRET, { expiresIn: "90d" });
  res.json({ pro: true, token, nextBillingTime: next });
}));

/* ---------- PayPal: webhook keeps status in sync (cancel, fail, renew) ---------- */
const EVENT_STATUS = {
  "BILLING.SUBSCRIPTION.ACTIVATED": "ACTIVE",
  "BILLING.SUBSCRIPTION.RE-ACTIVATED": "ACTIVE",
  "BILLING.SUBSCRIPTION.CANCELLED": "CANCELLED",
  "BILLING.SUBSCRIPTION.SUSPENDED": "SUSPENDED",
  "BILLING.SUBSCRIPTION.EXPIRED": "EXPIRED",
  "BILLING.SUBSCRIPTION.PAYMENT.FAILED": "PAYMENT_FAILED",
};
app.post("/api/paypal/webhook", wrap(async (req, res) => {
  const h = (n) => req.get(n);
  const v = await paypalFetch("/v1/notifications/verify-webhook-signature", {
    method: "POST",
    body: JSON.stringify({
      auth_algo: h("paypal-auth-algo"),
      cert_url: h("paypal-cert-url"),
      transmission_id: h("paypal-transmission-id"),
      transmission_sig: h("paypal-transmission-sig"),
      transmission_time: h("paypal-transmission-time"),
      webhook_id: PAYPAL_WEBHOOK_ID,
      webhook_event: req.body,
    }),
  });
  const vd = v.ok ? await v.json() : null;
  if (!vd || vd.verification_status !== "SUCCESS") return res.status(400).json({ error: "Invalid signature." });

  const type = req.body.event_type;
  const id = req.body.resource && (req.body.resource.id || req.body.resource.billing_agreement_id);
  const status = EVENT_STATUS[type];
  if (status && id) {
    await pool.query("UPDATE subscriptions SET status=$1, updated_at=now() WHERE subscription_id=$2", [status, id]);
  } else if (type === "PAYMENT.SALE.COMPLETED" && req.body.resource.billing_agreement_id) {
    await pool.query("UPDATE subscriptions SET status='ACTIVE', updated_at=now() WHERE subscription_id=$1 AND status='PAYMENT_FAILED'",
      [req.body.resource.billing_agreement_id]);
  }
  res.json({ ok: true });
}));

/* ---------- Check Pro status ---------- */
app.get("/api/status", wrap(async (req, res) => {
  const pro = await getPro(req);
  res.json({ pro: !!pro, freeDailyLimit: FREE_LIMIT });
}));

/* ---------- Photo -> workout ---------- */
const FALLBACK = [
  ["Marching in place", "Lift knees to hip height, swing your arms."],
  ["Standing hip circles", "Big slow circles, then switch direction."],
  ["Bodyweight squats", "Sit back, chest tall, knees over toes."],
  ["Incline push-ups", "Hands on a wall or desk, body in one line."],
  ["Reverse lunges", "Step back, drop the knee, switch sides."],
  ["Glute bridges", "Squeeze at the top, ribs down."],
  ["Plank", "Forearms down, belly braced, breathe."],
  ["Chair dips", "Hands on a sturdy chair, elbows back."],
  ["Side-step squats", "Stay low, step wide, keep tension."],
  ["Dead bugs", "Lower back pressed down, move slowly."],
  ["Superman holds", "Lift chest and legs, long neck."],
  ["Mountain climbers", "Hips low, drive knees in steadily."],
  ["Cat-cow stretch", "Round, then arch, move with your breath."],
  ["Standing quad stretch", "Hold a wall, knee under hip."],
  ["Deep breathing", "In through the nose, long slow exhale."],
].map(([n, c]) => ({ n, c }));

function parsePlan(text) {
  const a = text.indexOf("{"), b = text.lastIndexOf("}");
  if (a < 0 || b < a) throw new Error("No JSON in model output");
  const j = JSON.parse(text.slice(a, b + 1));
  const moves = (Array.isArray(j.moves) ? j.moves : [])
    .filter((m) => m && m.n)
    .map((m) => ({ n: String(m.n).slice(0, 60), c: String(m.c || "").slice(0, 120) }));
  while (moves.length < 15) moves.push(FALLBACK[moves.length]);
  return { note: String(j.note || "Here is a balanced 15 for today.").slice(0, 200), moves: moves.slice(0, 15) };
}

async function bump(key) {
  await pool.query(
    `INSERT INTO usage (key, day, count) VALUES ($1, CURRENT_DATE, 1)
     ON CONFLICT (key, day) DO UPDATE SET count = usage.count + 1`, [key]);
}
async function usedToday(keys) {
  const { rows } = await pool.query("SELECT COALESCE(MAX(count),0) AS c FROM usage WHERE key = ANY($1) AND day = CURRENT_DATE", [keys]);
  return rows[0].c;
}

app.post("/api/workout", wrap(async (req, res) => {
  const deviceId = deviceIdOf(req);
  if (!deviceId) return res.status(400).json({ error: "Missing device id." });
  const level = ["Beginner", "Intermediate", "Advanced"].includes(req.body.level) ? req.body.level : "Beginner";
  const image = String(req.body.image || "");
  if (!/^data:image\/(jpeg|png|webp);base64,/.test(image)) return res.status(400).json({ error: "Send the photo as a JPEG, PNG or WebP data URL." });
  if (image.length > 4_000_000) return res.status(413).json({ error: "Photo is too large. Try a smaller one." });

  const pro = await getPro(req);
  const keys = [`d:${deviceId}`, `i:${req.ip}`];
  const limit = pro ? PRO_LIMIT : FREE_LIMIT;
  if ((await usedToday(keys)) >= limit) {
    return res.status(429).json({
      error: pro ? "Daily limit reached. Come back tomorrow." : "You have used today’s free workout. Upgrade to Pro for more.",
      upgrade: !pro,
    });
  }

  const prompt =
    `You are a friendly personal trainer. The attached photo shows a person who wants a 15-minute, no-equipment workout today. Level: ${level}.\n` +
    `Use only what is visible for practical cues: posture, stance, and the space around them. Never comment on weight, body fat, shape or attractiveness, and do not guess at health conditions. If no person is visible, give a balanced full-body plan.\n` +
    `Return ONLY JSON with no backticks: {"note":"one warm, encouraging sentence on today's focus, no body judgments","moves":[{"n":"move name","c":"one short form cue"}]}\n` +
    `Exactly 15 moves: 2 warm-up, 11 main work, 2 cool-down stretches. Matched to the level. Safe, floor or standing, no equipment.`;

  let plan = null, aiFailed = false;
  try {
    const r = await fetch("https://api.groq.com/openai/v1/chat/completions", {
      method: "POST",
      headers: { Authorization: `Bearer ${GROQ_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        model: GROQ_MODEL,
        temperature: 0.7,
        max_tokens: 1200,
        messages: [{ role: "user", content: [
          { type: "text", text: prompt },
          { type: "image_url", image_url: { url: image } },
        ] }],
      }),
    });
    if (!r.ok) throw new Error(`Groq ${r.status}: ${(await r.text()).slice(0, 300)}`);
    const d = await r.json();
    plan = parsePlan(d.choices[0].message.content);
  } catch (e) {
    console.error("[workout] AI failed:", e.message);
    aiFailed = true;
    plan = { note: "Could not read the photo, so here is a balanced 15 for today.", moves: FALLBACK };
  }

  if (!aiFailed) await Promise.all(keys.map(bump)); // only count successful scans
  res.json({ ...plan, pro: !!pro, fallback: aiFailed });
}));

/* ---------- Start ---------- */
const port = process.env.PORT || 3000;
initDb()
  .then(() => app.listen(port, () => console.log(`Listening on ${port}`)))
  .catch((e) => { console.error("DB init failed:", e); process.exit(1); });
