// Pengecek key YanzXiter. Daftar key disimpan di Environment Variable "KEYS" (tidak publik).
// Format KEYS: pisahkan dengan koma atau baris baru.
//   KEYKU-123                -> berlaku selamanya
//   KEYKU-456|2026-12-31     -> berlaku sampai tanggal itu (zona WIB)
const crypto = require("crypto");

const fails = new Map(); // pembatas percobaan salah per IP (per instance server)
const MAX_FAILS = 8;
const WINDOW_MS = 60 * 1000;

function parseKeys() {
  const list = [];
  for (const raw of (process.env.KEYS || "").split(/[\n,]+/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const m = line.match(/^(.*?)\s*\|\s*(\d{4}-\d{2}-\d{2})$/);
    list.push(m ? { key: m[1], exp: m[2] } : { key: line, exp: null });
  }
  return list;
}

function same(a, b) {
  const ha = crypto.createHash("sha256").update(a).digest();
  const hb = crypto.createHash("sha256").update(b).digest();
  return crypto.timingSafeEqual(ha, hb);
}

module.exports = (req, res) => {
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");

  const ip = (req.headers["x-forwarded-for"] || "").split(",")[0].trim() || "x";
  const now = Date.now();
  const rec = fails.get(ip);
  if (rec && now - rec.t < WINDOW_MS && rec.n >= MAX_FAILS) {
    return res.status(200).send("limit");
  }

  const key = String((req.query && req.query.key) || "").trim();
  if (!key || key.length > 200) return res.status(200).send("invalid");

  let found = null;
  for (const k of parseKeys()) {
    if (same(key, k.key)) found = k;
  }

  if (!found) {
    const r = rec && now - rec.t < WINDOW_MS ? rec : { n: 0, t: now };
    r.n += 1;
    fails.set(ip, r);
    return res.status(200).send("invalid");
  }
  if (found.exp) {
    const end = new Date(found.exp + "T23:59:59+07:00").getTime();
    if (now > end) return res.status(200).send("expired");
  }
  return res.status(200).send("ok");
};
             
