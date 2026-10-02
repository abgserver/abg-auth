// language: Node.js, runtime: Vercel Serverless
// env vars: UPSTASH_REDIS_REST_URL, UPSTASH_REDIS_REST_TOKEN, ADMIN_TOKEN
// storage: Upstash Redis (REST API, no npm needed)

const REDIS_URL = process.env.UPSTASH_REDIS_REST_URL;
const REDIS_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

function nowSec() {
  return Math.floor(Date.now() / 1000);
}

function isoFromEpoch(epoch) {
  const d = new Date(epoch * 1000);
  const p = (n) => String(n).padStart(2, "0");
  return (
    d.getUTCFullYear() + "-" +
    p(d.getUTCMonth() + 1) + "-" +
    p(d.getUTCDate()) + "T" +
    p(d.getUTCHours()) + ":" +
    p(d.getUTCMinutes()) + ":" +
    p(d.getUTCSeconds()) + ".000Z"
  );
}

async function redis(command, ...args) {
  if (!REDIS_URL || !REDIS_TOKEN) {
    throw new Error("redis not configured");
  }
  const path = [command, ...args.map((a) => encodeURIComponent(String(a)))].join("/");
  const res = await fetch(`${REDIS_URL}/${path}`, {
    headers: { Authorization: `Bearer ${REDIS_TOKEN}` },
  });
  if (!res.ok) {
    throw new Error("redis http " + res.status);
  }
  const data = await res.json();
  return data.result;
}

function authAdmin(req) {
  if (!ADMIN_TOKEN) return false;
  const got = req.headers["authorization"] || "";
  return got === `Bearer ${ADMIN_TOKEN}`;
}

async function getKey(key) {
  const raw = await redis("GET", "key:" + key);
  if (!raw) return null;
  try { return JSON.parse(raw); } catch { return null; }
}

async function setKey(key, data) {
  await redis("SET", "key:" + key, JSON.stringify(data));
}

export default async function handler(req, res) {
  Object.entries(CORS).forEach(([k, v]) => res.setHeader(k, v));
  if (req.method === "OPTIONS") return res.status(200).end();

  const rawPath = req.query.path;
  const path = Array.isArray(rawPath) ? rawPath.join("/") : (rawPath || "");
  const route = "/api/" + path;

  try {
    // ---- health ----
    if (route === "/api/" || route === "/api" || route === "/api/health") {
      return res.status(200).json({ ok: true, ts: nowSec(), service: "abg-auth" });
    }

    // ---- login ----
    if (route === "/api/v1/sync" && req.method === "POST") {
      const { key, hwid } = req.body || {};
      const k = String(key || "").trim();
      const h = String(hwid || "").trim();
      if (k.length < 6) return res.status(200).json({ status: false, msg: "key tidak valid" });
      if (h.length < 4) return res.status(200).json({ status: false, msg: "hwid tidak valid" });

      const rec = await getKey(k);
      if (!rec) return res.status(200).json({ status: false, msg: "key tidak ditemukan" });
      if (rec.banned === true) return res.status(200).json({ status: false, msg: "key banned" });

      const exp = Number(rec.expiry || 0);
      if (exp > 0 && exp < nowSec()) {
        return res.status(200).json({ status: false, msg: "key expired" });
      }
      if (rec.hwid && rec.hwid !== "" && rec.hwid !== h) {
        return res.status(200).json({ status: false, msg: "key sudah terikat hwid lain" });
      }
      if (!rec.hwid || rec.hwid === "") {
        rec.hwid = h;
        rec.boundAt = nowSec();
        await setKey(k, rec);
        await redis("SET", "hwid:" + h, k);
      }
      const token = Buffer.from(`${k}|${h}|${nowSec()}`).toString("base64").replace(/=/g, "");
      return res.status(200).json({
        status: true,
        token,
        expiry: exp > 0 ? isoFromEpoch(exp) : "",
        tier: rec.tier || "standard",
      });
    }

    // ---- register ----
    if (route === "/api/v1/reg" && req.method === "POST") {
      if (!authAdmin(req)) return res.status(401).json({ status: false, msg: "unauthorized" });
      const { key, days, tier } = req.body || {};
      const k = String(key || "").trim();
      if (k.length < 6) return res.status(200).json({ status: false, msg: "key terlalu pendek" });
      const d = Number(days || 30);
      const expiry = nowSec() + d * 86400;
      const rec = { hwid: "", expiry, tier: String(tier || "standard"), banned: false, createdAt: nowSec() };
      await setKey(k, rec);
      return res.status(200).json({ status: true, key: k, expiry: isoFromEpoch(expiry), tier: rec.tier });
    }

    // ---- reset hwid ----
    if (route === "/api/v1/rel" && req.method === "POST") {
      if (!authAdmin(req)) return res.status(401).json({ status: false, msg: "unauthorized" });
      const { key } = req.body || {};
      const k = String(key || "").trim();
      const rec = await getKey(k);
      if (!rec) return res.status(200).json({ status: false, msg: "key tidak ditemukan" });
      if (rec.hwid) await redis("DEL", "hwid:" + rec.hwid);
      rec.hwid = "";
      rec.boundAt = 0;
      await setKey(k, rec);
      return res.status(200).json({ status: true, msg: "hwid reset" });
    }

    // ---- state ----
    if (route === "/api/v1/state" && req.method === "GET") {
      const k = String(req.query.key || "").trim();
      if (!k) return res.status(200).json({ status: false, msg: "no key" });
      const rec = await getKey(k);
      if (!rec) return res.status(200).json({ status: false, msg: "not found" });
      if (rec.banned) return res.status(200).json({ status: false, msg: "banned" });
      const exp = Number(rec.expiry || 0);
      if (exp > 0 && exp < nowSec()) return res.status(200).json({ status: false, msg: "expired" });
      return res.status(200).json({ status: true, expiry: exp > 0 ? isoFromEpoch(exp) : "", tier: rec.tier || "standard" });
    }

    // ---- ban ----
    if (route === "/api/v1/ban" && req.method === "POST") {
      if (!authAdmin(req)) return res.status(401).json({ status: false, msg: "unauthorized" });
      const { key, banned } = req.body || {};
      const k = String(key || "").trim();
      const rec = await getKey(k);
      if (!rec) return res.status(200).json({ status: false, msg: "key tidak ditemukan" });
      rec.banned = banned === true;
      await setKey(k, rec);
      return res.status(200).json({ status: true, key: k, banned: rec.banned });
    }

    return res.status(404).json({ status: false, msg: "endpoint not found", route });
  } catch (err) {
    return res.status(500).json({ status: false, msg: "server error: " + String(err) });
  }
}
