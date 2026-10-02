// language: TypeScript, runtime: Deno Deploy
// deps: Deno KV (built-in, gratis)
// env var: ADMIN_TOKEN (set di Deno Deploy nanti)

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

const kv = await Deno.openKv();

function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}

function isoFromEpoch(epoch: number): string {
  const d = new Date(epoch * 1000);
  const p = (n: number) => String(n).padStart(2, "0");
  return (
    d.getUTCFullYear() + "-" +
    p(d.getUTCMonth() + 1) + "-" +
    p(d.getUTCDate()) + "T" +
    p(d.getUTCHours()) + ":" +
    p(d.getUTCMinutes()) + ":" +
    p(d.getUTCSeconds()) + ".000Z"
  );
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...CORS, "Content-Type": "application/json" },
  });
}

function authAdmin(req: Request): boolean {
  const expected = Deno.env.get("ADMIN_TOKEN") || "";
  if (!expected) return false;
  const got = req.headers.get("Authorization") || "";
  return got === `Bearer ${expected}`;
}

async function handleSync(req: Request): Promise<Response> {
  let body: any;
  try {
    body = await req.json();
  } catch {
    return json({ status: false, msg: "invalid json" });
  }

  const key = String(body.key || "").trim();
  const hwid = String(body.hwid || "").trim();

  if (key.length < 6) return json({ status: false, msg: "key tidak valid" });
  if (hwid.length < 4) return json({ status: false, msg: "hwid tidak valid" });

  const entry = await kv.get(["keys", key]);
  if (!entry.value) return json({ status: false, msg: "key tidak ditemukan" });

  const data = entry.value as any;
  if (data.banned === true) return json({ status: false, msg: "key banned" });

  const exp = Number(data.expiry || 0);
  if (exp > 0 && exp < nowSec()) {
    return json({ status: false, msg: "key expired" });
  }

  if (data.hwid && data.hwid !== "" && data.hwid !== hwid) {
    return json({ status: false, msg: "key sudah terikat hwid lain" });
  }

  if (!data.hwid || data.hwid === "") {
    data.hwid = hwid;
    data.boundAt = nowSec();
    await kv.set(["keys", key], data);
    await kv.set(["hwids", hwid], key);
  }

  const tokenRaw = `${key}|${hwid}|${nowSec()}`;
  const token = btoa(tokenRaw).replace(/=/g, "");

  return json({
    status: true,
    token,
    expiry: exp > 0 ? isoFromEpoch(exp) : "",
    tier: data.tier || "standard",
  });
}

async function handleReg(req: Request): Promise<Response> {
  if (!authAdmin(req)) return json({ status: false, msg: "unauthorized" }, 401);

  let body: any;
  try {
    body = await req.json();
  } catch {
    return json({ status: false, msg: "invalid json" });
  }

  const key = String(body.key || "").trim();
  const days = Number(body.days || 30);
  const tier = String(body.tier || "standard");

  if (key.length < 6) return json({ status: false, msg: "key terlalu pendek" });

  const expiry = nowSec() + days * 86400;
  const rec = {
    hwid: "",
    expiry,
    tier,
    banned: false,
    createdAt: nowSec(),
  };
  await kv.set(["keys", key], rec);

  return json({
    status: true,
    key,
    expiry: isoFromEpoch(expiry),
    tier,
  });
}

async function handleRel(req: Request): Promise<Response> {
  if (!authAdmin(req)) return json({ status: false, msg: "unauthorized" }, 401);

  let body: any;
  try {
    body = await req.json();
  } catch {
    return json({ status: false, msg: "invalid json" });
  }

  const key = String(body.key || "").trim();
  const entry = await kv.get(["keys", key]);
  if (!entry.value) return json({ status: false, msg: "key tidak ditemukan" });

  const data = entry.value as any;
  if (data.hwid) await kv.delete(["hwids", data.hwid]);
  data.hwid = "";
  data.boundAt = 0;
  await kv.set(["keys", key], data);

  return json({ status: true, msg: "hwid reset" });
}

async function handleState(url: URL): Promise<Response> {
  const key = url.searchParams.get("key") || "";
  if (!key) return json({ status: false, msg: "no key" });

  const entry = await kv.get(["keys", key]);
  if (!entry.value) return json({ status: false, msg: "not found" });

  const data = entry.value as any;
  if (data.banned) return json({ status: false, msg: "banned" });

  const exp = Number(data.expiry || 0);
  if (exp > 0 && exp < nowSec()) return json({ status: false, msg: "expired" });

  return json({
    status: true,
    expiry: exp > 0 ? isoFromEpoch(exp) : "",
    tier: data.tier || "standard",
  });
}

async function handleBan(req: Request): Promise<Response> {
  if (!authAdmin(req)) return json({ status: false, msg: "unauthorized" }, 401);

  let body: any;
  try {
    body = await req.json();
  } catch {
    return json({ status: false, msg: "invalid json" });
  }

  const key = String(body.key || "").trim();
  const banned = body.banned === true;

  const entry = await kv.get(["keys", key]);
  if (!entry.value) return json({ status: false, msg: "key tidak ditemukan" });

  const data = entry.value as any;
  data.banned = banned;
  await kv.set(["keys", key], data);

  return json({ status: true, key, banned });
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: CORS });
  }

  const url = new URL(req.url);
  const path = url.pathname;

  try {
    if (path === "/api/v1/sync" && req.method === "POST") {
      return await handleSync(req);
    }
    if (path === "/api/v1/reg" && req.method === "POST") {
      return await handleReg(req);
    }
    if (path === "/api/v1/rel" && req.method === "POST") {
      return await handleRel(req);
    }
    if (path === "/api/v1/state" && req.method === "GET") {
      return await handleState(url);
    }
    if (path === "/api/v1/ban" && req.method === "POST") {
      return await handleBan(req);
    }

    return json({ ok: true, ts: nowSec(), service: "abg-auth" });
  } catch (err) {
    return json({ status: false, msg: "server error: " + String(err) }, 500);
  }
});
