// ═══════════════════════════════════════════════════════════════════════════
//  QuantHub Sales Scorecard — Cloudflare Worker
//  Auth-gated. Serves HTML + HubSpot/GitHub-backed API.
//
//  Secrets (set via: wrangler secret put <NAME>):
//    HUBSPOT_TOKEN     — HubSpot Private App token (pat-na1-...)
//    GITHUB_TOKEN      — GitHub classic token (data.json r/w)
//    ADMIN_PIN         — 4-digit PIN gating PUT + /refresh (defense in depth)
//    PORTAL_PASSWORD   — password used to log into the portal
//    SESSION_SECRET    — long random string for HMAC-signing session cookies
// ═══════════════════════════════════════════════════════════════════════════

// Gated entry page, bundled into the worker at build time (wrangler's default
// module rules import *.html as text). Served only after auth.
import INDEX_HTML from "./index.html";

const GITHUB_OWNER  = "krausshauss";
const GITHUB_REPO   = "quanthub-dashboard";
const GITHUB_BRANCH = "main";
const DATA_FILE     = "data.json";

const SESSION_COOKIE     = "qh_session";
const SESSION_DURATION_S = 30 * 24 * 60 * 60;
const MAX_FAILS          = 5;
const FAIL_WINDOW_MS     = 15 * 60 * 1000;

const failedAttempts = new Map();

// ── REP ROSTER ─────────────────────────────────────────────────────────────
const REPS = {
  "80811940": { name: "Nate Spargo",      role: "Director of CS",              initials: "NS" },
  "87448455": { name: "Michael Krause",   role: "Strategic Advisor",           initials: "MK" },
  "81657454": { name: "Joe DeRario",      role: "Sr. Sales Account Executive", initials: "JD" },
  "86826804": { name: "Jason Rupert",     role: "Sales Account Executive",     initials: "JR" },
  "84255670": { name: "Matthew Fickling", role: "Sales Account Executive",     initials: "MF" },
};
const SCORED_REPS = Object.keys(REPS);
const QUOTA       = 100000;
const TEAM_TARGET = 1000000;
const STALE_DAYS  = 7;

// ═══════════════════════════════════════════════════════════════════════════
//   MAIN HANDLER
// ═══════════════════════════════════════════════════════════════════════════

export default {
  async fetch(request, env) {
    const url      = new URL(request.url);
    const method   = request.method;
    const pathname = url.pathname;

    try {
      // ── Always-public auth routes ─────────────────────────────────
      if (pathname === "/login" && method === "GET")  return loginPage();
      if (pathname === "/auth"  && method === "POST") return handleAuth(request, env);
      if (pathname === "/logout")                     return logout();

      // ── Everything else requires a valid session ──────────────────
      if (!(await isAuthed(request, env))) {
        const wantsHtml = (request.headers.get("Accept") || "").includes("text/html");
        if (method === "GET" && wantsHtml) {
          return Response.redirect(new URL("/login", url), 302);
        }
        return jsonResp({ error: "Unauthorized" }, 401);
      }

      // ── Data API: GET / with a query string (must precede entry page) ──
      if (method === "GET" && (pathname === "/" || pathname === "") && url.searchParams.size > 0) {
        const forceRefresh = url.searchParams.get("refresh") === "1";

        if (!forceRefresh) {
          try {
            const { content } = await readDataJson(env);
            if (content && content.reps && content.reps.length) {
              const age = content.savedAt
                ? (Date.now() - new Date(content.savedAt).getTime()) / 3600000
                : 999;
              if (age < 4) {
                return jsonResp(content, 200, { "X-Source": "cache" });
              }
            }
          } catch (_) { /* cache miss — fall through */ }
        }

        const data = await buildScorecardData(env);
        try {
          const { sha } = await readDataJson(env);
          await writeDataJson(env, data, sha);
        } catch (e) { console.warn("Cache write failed:", e.message); }

        return jsonResp(data, 200, { "X-Source": "live" });
      }

      // ── Entry page: GET / with no query (bundled, gated) ──────────
      if (method === "GET" && (pathname === "/" || pathname === "")) {
        return new Response(INDEX_HTML, {
          headers: {
            "Content-Type":           "text/html; charset=utf-8",
            "Cache-Control":          "no-store",
            "X-Frame-Options":        "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy":        "no-referrer",
          },
        });
      }

      // ── PUT /  →  Save manual overrides (PIN-gated) ───────────────
      if (method === "PUT") {
        if (!checkPin(request, env)) return jsonResp({ error: "Unauthorized" }, 401);
        const body    = await request.json();
        const { sha } = await readDataJson(env);
        await writeDataJson(env, body, sha);
        return jsonResp({ ok: true });
      }

      // ── GET /refresh  →  Force live HubSpot pull (PIN-gated) ──────
      if (method === "GET" && pathname === "/refresh") {
        if (!checkPin(request, env, url)) return jsonResp({ error: "Unauthorized" }, 401);
        const data    = await buildScorecardData(env);
        const { sha } = await readDataJson(env);
        await writeDataJson(env, data, sha);
        return jsonResp({
          ok: true,
          deals: data.reps.reduce((s, r) => s + r.active_deals, 0),
          exportDate: data.exportDate,
        });
      }

      // ── POST /validate-pin ────────────────────────────────────────
      if (method === "POST" && pathname.includes("validate-pin")) {
        if (!checkPin(request, env)) return jsonResp({ error: "Invalid PIN" }, 401);
        return jsonResp({ ok: true });
      }

      return jsonResp({ error: "Not found" }, 404);

    } catch (e) {
      console.error("Worker error:", e.message);
      return jsonResp({ error: e.message }, 500);
    }
  },
};

function checkPin(request, env, url) {
  const pin = request.headers.get("X-Admin-Pin") || (url && url.searchParams.get("pin"));
  const correct = env.ADMIN_PIN || "";
  return pin && correct && timingSafeEqualStr(pin, correct);
}

// ═══════════════════════════════════════════════════════════════════════════
//   AUTH
// ═══════════════════════════════════════════════════════════════════════════

async function isAuthed(request, env) {
  const token = readCookie(request, SESSION_COOKIE);
  if (!token || !env.SESSION_SECRET) return false;
  return verifySession(token, env.SESSION_SECRET);
}

async function handleAuth(request, env) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  if (!checkRateLimit(ip)) {
    return loginPage("Too many failed attempts. Wait 15 minutes and try again.", 429);
  }
  if (!env.PORTAL_PASSWORD || !env.SESSION_SECRET) {
    return loginPage("Server misconfigured: missing secret(s).", 500);
  }

  const form     = await request.formData();
  const password = (form.get("password") || "").toString();
  if (!timingSafeEqualStr(password, env.PORTAL_PASSWORD)) {
    recordFailure(ip);
    return loginPage("Incorrect password.", 401);
  }
  clearFailures(ip);

  const token = await makeSession(env.SESSION_SECRET);
  return new Response(null, {
    status: 302,
    headers: { "Location": "/", "Set-Cookie": cookieHeader(token, SESSION_DURATION_S) },
  });
}

function logout() {
  return new Response(null, {
    status: 302,
    headers: { "Location": "/login", "Set-Cookie": cookieHeader("", 0) },
  });
}

function cookieHeader(value, maxAgeS) {
  return `${SESSION_COOKIE}=${encodeURIComponent(value)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAgeS}`;
}

function readCookie(request, name) {
  const raw = request.headers.get("Cookie") || "";
  const m   = raw.match(new RegExp("(?:^|; )" + name + "=([^;]*)"));
  return m ? decodeURIComponent(m[1]) : null;
}

const enc = new TextEncoder();
const dec = new TextDecoder();

function b64uEncode(buf) {
  const bytes = new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64uDecode(s) {
  const pad  = "=".repeat((4 - (s.length % 4)) % 4);
  const norm = s.replace(/-/g, "+").replace(/_/g, "/") + pad;
  const bin  = atob(norm);
  const out  = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function hmacSign(secret, data) {
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(data));
  return b64uEncode(sig);
}

async function makeSession(secret) {
  const now     = Math.floor(Date.now() / 1000);
  const payload = JSON.stringify({ iat: now, exp: now + SESSION_DURATION_S });
  const pb64    = b64uEncode(enc.encode(payload));
  const sig     = await hmacSign(secret, pb64);
  return `${pb64}.${sig}`;
}

async function verifySession(token, secret) {
  if (!token || !token.includes(".")) return false;
  const [pb64, sig] = token.split(".");
  if (!pb64 || !sig) return false;
  const expectedSig = await hmacSign(secret, pb64);
  if (!timingSafeEqualStr(sig, expectedSig)) return false;
  try {
    const payload = JSON.parse(dec.decode(b64uDecode(pb64)));
    return payload.exp > Math.floor(Date.now() / 1000);
  } catch { return false; }
}

function timingSafeEqualStr(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;
  let res = 0;
  for (let i = 0; i < a.length; i++) res |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return res === 0;
}

function checkRateLimit(ip) {
  const now   = Date.now();
  const entry = failedAttempts.get(ip);
  if (!entry) return true;
  if (now - entry.firstAt > FAIL_WINDOW_MS) { failedAttempts.delete(ip); return true; }
  return entry.count < MAX_FAILS;
}

function recordFailure(ip) {
  const now   = Date.now();
  const entry = failedAttempts.get(ip);
  if (!entry || now - entry.firstAt > FAIL_WINDOW_MS) {
    failedAttempts.set(ip, { count: 1, firstAt: now });
  } else {
    entry.count++;
  }
}

function clearFailures(ip) {
  failedAttempts.delete(ip);
}

function loginPage(errMsg = "", status = 200) {
  const safe = errMsg.replace(/[<>&"]/g, c => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", '"': "&quot;" }[c]));
  const body = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>QuantHub · Sign in</title>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link href="https://fonts.googleapis.com/css2?family=Manrope:wght@400;600;700&display=swap" rel="stylesheet" />
  <style>
    *,*::before,*::after { box-sizing: border-box; }
    html, body { height: 100%; margin: 0; }
    body { font-family: 'Manrope', -apple-system, sans-serif; background: #0a0e1a; color: #e6edf3; display: flex; align-items: center; justify-content: center; padding: 1rem; }
    .card { background: #161b22; padding: 2.5rem 2rem; border-radius: 14px; width: 100%; max-width: 360px; box-shadow: 0 12px 40px rgba(0,0,0,0.6); border: 1px solid #30363d; }
    .brand { color: #0077B5; font-weight: 800; letter-spacing: 0.05em; font-size: 0.85rem; text-transform: uppercase; }
    h1 { margin: 0.25rem 0 1.5rem; font-size: 1.4rem; font-weight: 700; }
    label { display: block; font-size: 0.8rem; color: #8b949e; margin-bottom: 0.4rem; }
    input { width: 100%; padding: 0.75rem 0.9rem; background: #0d1117; border: 1px solid #30363d; border-radius: 8px; color: #e6edf3; font-family: inherit; font-size: 0.95rem; }
    input:focus { outline: none; border-color: #0077B5; box-shadow: 0 0 0 3px rgba(0, 119, 181, 0.2); }
    button { width: 100%; margin-top: 1.1rem; padding: 0.8rem; background: #0077B5; color: white; border: none; border-radius: 8px; font-family: inherit; font-size: 0.95rem; font-weight: 700; cursor: pointer; transition: background 0.15s; }
    button:hover { background: #005c8a; }
    .err { color: #f85149; font-size: 0.85rem; margin-top: 0.9rem; min-height: 1.2em; text-align: center; }
  </style>
</head>
<body>
  <main class="card">
    <div class="brand">QuantHub</div>
    <h1>Sign in</h1>
    <form method="POST" action="/auth">
      <label for="pw">Password</label>
      <input id="pw" type="password" name="password" autocomplete="current-password" autofocus required />
      <button type="submit">Continue</button>
      <div class="err">${safe}</div>
    </form>
  </main>
</body>
</html>`;
  return new Response(body, {
    status,
    headers: {
      "Content-Type":           "text/html; charset=utf-8",
      "Cache-Control":          "no-store",
      "X-Frame-Options":        "DENY",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy":        "no-referrer",
    },
  });
}

function jsonResp(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...extra },
  });
}

// ═══════════════════════════════════════════════════════════════════════════
//   HUBSPOT  +  SCORECARD BUILD
// ═══════════════════════════════════════════════════════════════════════════

async function hs(env, path, opts = {}) {
  const res = await fetch(`https://api.hubapi.com${path}`, {
    ...opts,
    headers: {
      "Authorization": `Bearer ${env.HUBSPOT_TOKEN}`,
      "Content-Type":  "application/json",
      ...(opts.headers || {}),
    },
  });
  if (!res.ok) throw new Error(`HubSpot ${path} → ${res.status}`);
  return res.json();
}

async function hsAll(env, objectType, properties, filterGroups = []) {
  const results = [];
  let after = undefined;
  const limit = 100;
  while (true) {
    const body = { filterGroups, properties, limit, sorts: [], ...(after ? { after } : {}) };
    const data = await hs(env, `/crm/v3/objects/${objectType}/search`, {
      method: "POST",
      body:   JSON.stringify(body),
    });
    results.push(...(data.results || []));
    if (data.paging?.next?.after) { after = data.paging.next.after; } else { break; }
  }
  return results;
}

async function buildScorecardData(env) {
  const today   = new Date();
  const y2026   = new Date("2026-01-01T00:00:00Z");
  const weekAgo = new Date(today); weekAgo.setDate(weekAgo.getDate() - STALE_DAYS);

  const dealProps = [
    "dealname", "amount", "dealstage", "pipeline", "hubspot_owner_id",
    "closedate", "createdate", "hs_lastmodifieddate", "notes_last_updated",
    "hs_is_closed_won", "hs_is_closed", "hs_deal_stage_probability",
    "num_notes", "num_associated_contacts", "hs_next_step",
    "notes_last_contacted", "engagements_last_meeting_booked",
  ];

  const allDeals = await hsAll(env, "deals", dealProps, [
    { filters: [{ propertyName: "pipeline", operator: "EQ", value: "default" }] }
  ]);

  const activityMap = {};
  SCORED_REPS.forEach(id => { activityMap[id] = { calls: 0, meetings: 0, emails: 0 }; });

  try {
    const calls = await hsAll(env, "calls", ["hs_call_direction", "hubspot_owner_id", "hs_timestamp", "hs_call_status"], [{
      filters: [
        { propertyName: "hs_timestamp",   operator: "GTE", value: weekAgo.toISOString() },
        { propertyName: "hs_call_status", operator: "EQ",  value: "COMPLETED" },
      ]
    }]);
    calls.forEach(c => {
      const oid = c.properties?.hubspot_owner_id;
      if (oid && activityMap[oid]) activityMap[oid].calls++;
    });
  } catch (e) { console.warn("Calls fetch failed:", e.message); }

  try {
    const meetings = await hsAll(env, "meetings", ["hubspot_owner_id", "hs_timestamp", "hs_meeting_outcome"], [{
      filters: [{ propertyName: "hs_timestamp", operator: "GTE", value: weekAgo.toISOString() }]
    }]);
    meetings.forEach(m => {
      const oid = m.properties?.hubspot_owner_id;
      if (oid && activityMap[oid]) activityMap[oid].meetings++;
    });
  } catch (e) { console.warn("Meetings fetch failed:", e.message); }

  try {
    const emails = await hsAll(env, "emails", ["hubspot_owner_id", "hs_timestamp"], [{
      filters: [{ propertyName: "hs_timestamp", operator: "GTE", value: weekAgo.toISOString() }]
    }]);
    emails.forEach(e => {
      const oid = e.properties?.hubspot_owner_id;
      if (oid && activityMap[oid]) activityMap[oid].emails++;
    });
  } catch (e) { console.warn("Emails fetch failed:", e.message); }

  const grouped = {};
  SCORED_REPS.forEach(id => { grouped[id] = []; });
  allDeals.forEach(deal => {
    const oid = deal.properties?.hubspot_owner_id;
    if (oid && grouped[oid]) grouped[oid].push(deal.properties);
  });

  const reps = SCORED_REPS.map(ownerId => {
    const info  = REPS[ownerId];
    const deals = grouped[ownerId] || [];
    const act   = activityMap[ownerId] || { calls: 0, meetings: 0, emails: 0 };

    const active = deals.filter(d => {
      const stage = (d.dealstage || "").toLowerCase();
      return !d.hs_is_closed_won && d.hs_is_closed !== "true" &&
             !stage.includes("closed lost") && !stage.includes("closedlost");
    });

    const cwDeals2026 = deals.filter(d => {
      if (!d.hs_is_closed_won || d.hs_is_closed_won === "false") return false;
      const cd = d.closedate ? new Date(d.closedate) : null;
      return cd && cd >= y2026;
    });

    const cwAmount  = cwDeals2026.reduce((s, d) => s + (parseFloat(d.amount) || 0), 0);
    const pipeValue = active.reduce((s, d) => s + (parseFloat(d.amount) || 0), 0);

    const stale = active.filter(d => {
      const lastAct = d.notes_last_updated || d.hs_lastmodifieddate;
      if (!lastAct) return true;
      return new Date(lastAct) < weekAgo;
    }).length;

    const advancedWk = active.filter(d => {
      const lm = d.hs_lastmodifieddate;
      return lm && new Date(lm) >= weekAgo;
    }).length;

    const total  = active.length;
    const hasNS  = active.filter(d => d.hs_next_step && d.hs_next_step.trim()).length;
    const hasAmt = active.filter(d => parseFloat(d.amount) > 0).length;
    const hasCD  = active.filter(d => d.closedate).length;

    const VALID_STAGES = [
      "negotiation", "commit", "trial", "salesopportunity", "opportunity",
      "discovery", "demo", "sql", "closedwon", "closedlost"
    ];
    const stageFlow = active.filter(d => {
      const s = (d.dealstage || "").toLowerCase().replace(/[^a-z]/g, "");
      return VALID_STAGES.some(v => s.includes(v));
    }).length;

    const ages = active
      .filter(d => d.createdate)
      .map(d => (today - new Date(d.createdate)) / 86400000);
    const avgAge = ages.length
      ? Math.round(ages.reduce((a, b) => a + b, 0) / ages.length)
      : 45;

    const expansionDeals = cwDeals2026
      .filter(d => {
        const cd = d.closedate ? new Date(d.closedate) : null;
        return cd && (today - cd) / 86400000 < 90;
      })
      .map(d => ({
        name:   d.dealname || "",
        amount: parseFloat(d.amount) || 0,
        stage:  "Closed Won",
        cw:     true,
      }));

    const dealList = active.map(d => {
      let stage = d.dealstage || "Unknown";
      const sl = stage.toLowerCase();
      if (sl.includes("negotiat"))      stage = "Negotiation";
      else if (sl.includes("commit") || sl.includes("verbal")) stage = "Commit/Verbal";
      else if (sl.includes("trial"))    stage = "Trial (optional)";
      else if (sl.includes("opportun")) stage = "Sales Opportunity";
      else if (sl.includes("discov") || sl.includes("demo") || sl.includes("sql")) stage = "Discovery/Demo (SQL)";

      const lastAct = d.notes_last_updated || d.hs_lastmodifieddate;
      const staleDays = lastAct
        ? Math.round((today - new Date(lastAct)) / 86400000)
        : 999;

      return {
        name:   d.dealname || "",
        stage,
        amount: parseFloat(d.amount) || null,
        stale:  staleDays,
        next:   d.hs_next_step || "",
      };
    });

    const isMK = ownerId === "87448455";

    return {
      id:       info.initials.toLowerCase(),
      name:     info.name,
      initials: info.initials,
      role:     info.role,
      cw_amount:           cwAmount,
      cw_deals:            cwDeals2026.length,
      active_deals:        total,
      pipeline_value:      pipeValue,
      stale_7d:            stale,
      deals_advanced_week: advancedWk,
      avg_days_to_close:   avgAge,
      ip_meetings_week:    Math.round(act.meetings * 0.5),
      vr_calls_week:       act.meetings - Math.round(act.meetings * 0.5),
      phone_calls_week:    act.calls,
      text_touches_week:   0,
      raw_calls:           act.calls,
      raw_meetings:        act.meetings,
      raw_emails:          act.emails,
      meetings_target:     isMK ? 4  : 6,
      calls_target:        isMK ? 8  : 15,
      text_target:         isMK ? 3  : 5,
      next_step_pct:    total ? Math.round(hasNS    / total * 100) : 0,
      amount_populated: total ? Math.round(hasAmt   / total * 100) : 0,
      close_date_set:   total ? Math.round(hasCD    / total * 100) : 0,
      stage_flow_pct:   total ? Math.round(stageFlow / total * 100) : 0,
      bant_pct:         50,
      daily_verified:   80,
      expansion_deals: expansionDeals,
      deals:           dealList,
    };
  });

  return {
    reps,
    exportDate: today.toLocaleDateString("en-US", { month: "long", day: "numeric", year: "numeric" }),
    savedAt:    today.toISOString(),
    version:    10,
    source:     "hubspot-api",
  };
}

// ═══════════════════════════════════════════════════════════════════════════
//   GITHUB DATA STORE
// ═══════════════════════════════════════════════════════════════════════════

async function readDataJson(env) {
  const apiUrl  = `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${DATA_FILE}`;
  const headers = {
    "Authorization": `token ${env.GITHUB_TOKEN}`,
    "Accept":        "application/vnd.github.v3+json",
    "User-Agent":    "QuantHub-Worker/3.0",
  };
  const res = await fetch(`${apiUrl}?ref=${GITHUB_BRANCH}`, { headers });
  if (res.status === 404) return { content: null, sha: null };
  if (!res.ok) throw new Error(`GitHub read error: ${res.status}`);
  const file    = await res.json();
  const decoded = atob(file.content.replace(/\n/g, ""));
  return { content: JSON.parse(decoded), sha: file.sha };
}

async function writeDataJson(env, data, sha) {
  const apiUrl  = `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${DATA_FILE}`;
  const headers = {
    "Authorization": `token ${env.GITHUB_TOKEN}`,
    "Accept":        "application/vnd.github.v3+json",
    "User-Agent":    "QuantHub-Worker/3.0",
    "Content-Type":  "application/json",
  };
  const content = btoa(unescape(encodeURIComponent(JSON.stringify(data, null, 2))));
  const body    = {
    message: `Scorecard update: ${data.exportDate || new Date().toDateString()}`,
    content,
    branch: GITHUB_BRANCH,
    ...(sha ? { sha } : {}),
  };
  const res = await fetch(apiUrl, { method: "PUT", headers, body: JSON.stringify(body) });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.message || `GitHub write error: ${res.status}`);
  }
  return true;
}
