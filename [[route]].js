// ORBIT LOG comments API — Cloudflare Pages Function (catch-all under /api/*).
// D1 binding: env.DB (database "orbit-comments").
// Public: read comments without login. Login required: post / delete comments.
// Auth: username + password (PBKDF2-SHA256, 100k iterations), session token in
// an HttpOnly same-site cookie. The FIRST registered account becomes admin
// (can delete any comment); every user can delete their own comments.

const SESSION_DAYS = 30;
const COMMENT_MIN_INTERVAL_MS = 10 * 1000;
const USERNAME_RE = /^[\u4e00-\u9fa5A-Za-z0-9_-]{2,20}$/;

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

function bufToHex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function hexToBuf(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

export async function hashPassword(password, saltHex) {
  const salt = saltHex ? hexToBuf(saltHex) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    key,
    256
  );
  return { salt: bufToHex(salt), hash: bufToHex(bits) };
}

export async function verifyPassword(password, saltHex, hashHex) {
  const got = await hashPassword(password, saltHex);
  return got.hash === hashHex;
}

async function migrate(db) {
  await db.prepare(
    "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, salt TEXT NOT NULL, hash TEXT NOT NULL, is_admin INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, google_sub TEXT, email TEXT)"
  ).run();
  await db.prepare(
    "CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires_at INTEGER NOT NULL)"
  ).run();
  await db.prepare(
    "CREATE TABLE IF NOT EXISTS comments (id INTEGER PRIMARY KEY AUTOINCREMENT, post_id TEXT NOT NULL, user_id INTEGER NOT NULL, username TEXT NOT NULL, body TEXT NOT NULL, created_at INTEGER NOT NULL)"
  ).run();
  // Upgrade databases created before Google login existed.
  for (const sql of [
    "ALTER TABLE users ADD COLUMN google_sub TEXT",
    "ALTER TABLE users ADD COLUMN email TEXT",
  ]) {
    try {
      await db.prepare(sql).run();
    } catch {
      // Column already exists — nothing to do.
    }
  }
}

function parseSessionCookie(request) {
  const header = request.headers.get("Cookie") || "";
  const m = header.match(/(?:^|;\s*)session=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : null;
}

function sessionCookie(token, maxAge) {
  return `session=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=${maxAge}`;
}

async function currentUser(db, request) {
  const token = parseSessionCookie(request);
  if (!token) return null;
  const sess = await db.prepare("SELECT * FROM sessions WHERE token = ?").bind(token).first();
  if (!sess || sess.expires_at < Date.now()) return null;
  const user = await db.prepare("SELECT * FROM users WHERE id = ?").bind(sess.user_id).first();
  return user || null;
}

async function readJson(request) {
  try {
    return await request.json();
  } catch {
    return {};
  }
}

export async function onRequest(context) {
  const { request, env } = context;
  if (!env.DB) return json({ error: "comments database not bound" }, 500);
  const db = env.DB;
  await migrate(db);

  const url = new URL(request.url);
  const path = url.pathname.replace(/^\/api\//, "").replace(/\/$/, "");
  const method = request.method;

  // ---------- auth: register ----------
  if (path === "auth/register" && method === "POST") {
    const { username, password } = await readJson(request);
    if (typeof username !== "string" || !USERNAME_RE.test(username)) {
      return json({ error: "username must be 2-20 chars: Chinese, letters, digits, _ or -" }, 400);
    }
    if (typeof password !== "string" || password.length < 6 || password.length > 64) {
      return json({ error: "password must be 6-64 characters" }, 400);
    }
    const exists = await db.prepare("SELECT id FROM users WHERE username = ?").bind(username).first();
    if (exists) return json({ error: "username already taken" }, 409);
    const count = await db.prepare("SELECT COUNT(*) AS n FROM users").first();
    const isAdmin = count && count.n === 0 ? 1 : 0;
    const pw = await hashPassword(password);
    await db
      .prepare("INSERT INTO users (username, salt, hash, is_admin, created_at) VALUES (?, ?, ?, ?, ?)")
      .bind(username, pw.salt, pw.hash, isAdmin, Date.now())
      .run();
    return json({ ok: true, is_admin: isAdmin === 1 });
  }

  // ---------- auth: login ----------
  if (path === "auth/login" && method === "POST") {
    const { username, password } = await readJson(request);
    const user = await db.prepare("SELECT * FROM users WHERE username = ?").bind(username || "").first();
    if (!user || !(await verifyPassword(password || "", user.salt, user.hash))) {
      return json({ error: "wrong username or password" }, 401);
    }
    const token = crypto.randomUUID();
    const expiresAt = Date.now() + SESSION_DAYS * 24 * 3600 * 1000;
    await db.prepare("INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)").bind(token, user.id, expiresAt).run();
    return json(
      { ok: true, user: { username: user.username, is_admin: user.is_admin === 1 } },
      200,
      { "Set-Cookie": sessionCookie(token, SESSION_DAYS * 24 * 3600) }
    );
  }

  // ---------- auth: logout ----------
  if (path === "auth/logout" && method === "POST") {
    const token = parseSessionCookie(request);
    if (token) await db.prepare("DELETE FROM sessions WHERE token = ?").bind(token).run();
    return json({ ok: true }, 200, { "Set-Cookie": sessionCookie("", 0) });
  }

  // ---------- auth: me ----------
  if (path === "auth/me" && method === "GET") {
    const user = await currentUser(db, request);
    return json({ user: user ? { username: user.username, is_admin: user.is_admin === 1 } : null });
  }

  // ---------- auth: Google login ----------
  // Redirect URI registered in Google Cloud (must match exactly):
  const GOOGLE_REDIRECT = "https://myvpsroot.top/api/auth/google/callback";
  if (path === "auth/google/start" && method === "GET") {
    const clientId = env.GOOGLE_CLIENT_ID;
    if (!clientId) return json({ error: "Google login not configured" }, 500);
    const state = crypto.randomUUID();
    const params = new URLSearchParams({
      client_id: clientId,
      redirect_uri: GOOGLE_REDIRECT,
      response_type: "code",
      scope: "openid email profile",
      state,
      access_type: "online",
      prompt: "select_account",
    });
    return new Response(null, {
      status: 302,
      headers: {
        Location: "https://accounts.google.com/o/oauth2/v2/auth?" + params.toString(),
        "Set-Cookie": `oauth_state=${state}; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=600`,
      },
    });
  }
  if (path === "auth/google/callback" && method === "GET") {
    const clientId = env.GOOGLE_CLIENT_ID;
    const clientSecret = env.GOOGLE_CLIENT_SECRET;
    if (!clientId || !clientSecret) return new Response("Google login not configured", { status: 500 });
    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state");
    const cookieHeader = request.headers.get("Cookie") || "";
    const stateCookie = (cookieHeader.match(/(?:^|;\s*)oauth_state=([^;]+)/) || [])[1];
    if (!code || !state || state !== stateCookie) {
      return new Response("Google login failed: invalid state", { status: 400 });
    }
    const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        code,
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: GOOGLE_REDIRECT,
        grant_type: "authorization_code",
      }),
    });
    if (!tokenRes.ok) return new Response("Google login failed", { status: 400 });
    const tokens = await tokenRes.json();
    const infoRes = await fetch("https://openidconnect.googleapis.com/v1/userinfo", {
      headers: { Authorization: "Bearer " + tokens.access_token },
    });
    if (!infoRes.ok) return new Response("Google login failed", { status: 400 });
    const g = await infoRes.json();
    if (!g.sub) return new Response("Google login failed", { status: 400 });

    // If already logged in with a username account, link this Google account to it.
    const sessionUser = await currentUser(db, request);
    let user = null;
    if (sessionUser) {
      const taken = await db.prepare("SELECT id FROM users WHERE google_sub = ?").bind(g.sub).first();
      if (taken && taken.id !== sessionUser.id) {
        return new Response("This Google account is already linked to another user", { status: 409 });
      }
      await db
        .prepare("UPDATE users SET google_sub = ?, email = ? WHERE id = ?")
        .bind(g.sub, g.email || null, sessionUser.id)
        .run();
      user = sessionUser;
    } else {
      user = await db.prepare("SELECT * FROM users WHERE google_sub = ?").bind(g.sub).first();
      if (!user) {
        const raw = (g.name || (g.email || "user").split("@")[0] || "user").replace(/[^\u4e00-\u9fa5A-Za-z0-9_-]/g, "");
        const base = (raw || "user").slice(0, 17);
        let username = base;
        let n = 0;
        while (await db.prepare("SELECT id FROM users WHERE username = ?").bind(username).first()) {
          n++;
          username = base + "_" + n;
        }
        const count = await db.prepare("SELECT COUNT(*) AS n FROM users").first();
        const isAdmin = count && count.n === 0 ? 1 : 0;
        const pw = await hashPassword(crypto.randomUUID());
        await db
          .prepare("INSERT INTO users (username, salt, hash, is_admin, created_at, google_sub, email) VALUES (?, ?, ?, ?, ?, ?, ?)")
          .bind(username, pw.salt, pw.hash, isAdmin, Date.now(), g.sub, g.email || null)
          .run();
        user = await db.prepare("SELECT * FROM users WHERE google_sub = ?").bind(g.sub).first();
      }
    }
    const token = crypto.randomUUID();
    const expiresAt = Date.now() + SESSION_DAYS * 24 * 3600 * 1000;
    await db.prepare("INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)").bind(token, user.id, expiresAt).run();
    return new Response(null, {
      status: 302,
      headers: {
        Location: "/",
        "Set-Cookie": sessionCookie(token, SESSION_DAYS * 24 * 3600),
      },
    });
  }

  // ---------- comments: list (public) ----------
  if (path === "comments" && method === "GET") {
    const post = url.searchParams.get("post") || "";
    if (!post || post.length > 128) return json({ error: "missing post id" }, 400);
    const me = await currentUser(db, request);
    const rows = await db
      .prepare("SELECT * FROM comments WHERE post_id = ? ORDER BY id ASC LIMIT 200")
      .bind(post)
      .all();
    const list = (rows.results || []).map((c) => ({
      id: c.id,
      username: c.username,
      body: c.body,
      created_at: c.created_at,
      can_delete: !!me && (me.is_admin === 1 || me.id === c.user_id),
    }));
    return json({ comments: list, user: me ? { username: me.username, is_admin: me.is_admin === 1 } : null });
  }

  // ---------- comments: post (login required) ----------
  if (path === "comments" && method === "POST") {
    const me = await currentUser(db, request);
    if (!me) return json({ error: "login required" }, 401);
    const { post, body } = await readJson(request);
    if (typeof post !== "string" || !post || post.length > 128) return json({ error: "missing post id" }, 400);
    const text = typeof body === "string" ? body.trim() : "";
    if (!text || text.length > 500) return json({ error: "comment must be 1-500 characters" }, 400);
    const last = await db
      .prepare("SELECT created_at FROM comments WHERE user_id = ? ORDER BY id DESC LIMIT 1")
      .bind(me.id)
      .first();
    if (last && Date.now() - last.created_at < COMMENT_MIN_INTERVAL_MS) {
      return json({ error: "posting too fast, wait a few seconds" }, 429);
    }
    const res = await db
      .prepare("INSERT INTO comments (post_id, user_id, username, body, created_at) VALUES (?, ?, ?, ?, ?)")
      .bind(post, me.id, me.username, text, Date.now())
      .run();
    return json({ ok: true, id: res.meta.last_row_id });
  }

  // ---------- comments: delete (author or admin) ----------
  const delMatch = path.match(/^comments\/(\d+)$/);
  if (delMatch && method === "DELETE") {
    const me = await currentUser(db, request);
    if (!me) return json({ error: "login required" }, 401);
    const comment = await db.prepare("SELECT * FROM comments WHERE id = ?").bind(Number(delMatch[1])).first();
    if (!comment) return json({ error: "comment not found" }, 404);
    if (me.is_admin !== 1 && me.id !== comment.user_id) return json({ error: "not allowed" }, 403);
    await db.prepare("DELETE FROM comments WHERE id = ?").bind(comment.id).run();
    return json({ ok: true });
  }

  return json({ error: "not found" }, 404);
}
