const encoder = new TextEncoder();
const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Authorization, Content-Type',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS'
};

const json = (body, status = 200) => new Response(JSON.stringify(body), {
  status, headers: { ...cors, 'Content-Type': 'application/json; charset=utf-8' }
});
const b64 = (value) => {
  const bytes = typeof value === 'string' ? encoder.encode(value) : new Uint8Array(value);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
};
const unb64 = (value) => {
  const normalized = value.replaceAll('-', '+').replaceAll('_', '/');
  const binary = atob(normalized);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
};
const safeEqual = (left, right) => {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left[index] ^ right[index];
  return difference === 0;
};

export async function hashPassword(password, salt = crypto.getRandomValues(new Uint8Array(16))) {
  const material = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  // Cloudflare Workers currently caps PBKDF2 at 100,000 iterations.
  const hash = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 100_000 }, material, 256);
  return `${b64(salt)}:${b64(hash)}`;
}

export async function verifyPassword(password, stored) {
  const [salt, expected] = String(stored).split(':');
  if (!salt || !expected) return false;
  const actual = await hashPassword(password, unb64(salt));
  return safeEqual(encoder.encode(actual), encoder.encode(stored));
}

async function hmac(value, secret) {
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64(await crypto.subtle.sign('HMAC', key, encoder.encode(value)));
}

export async function signToken(payload, secret, ttl = 60 * 60 * 24 * 30) {
  const header = b64(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = b64(JSON.stringify({ ...payload, exp: Math.floor(Date.now() / 1000) + ttl }));
  return `${header}.${body}.${await hmac(`${header}.${body}`, secret)}`;
}

export async function verifyToken(token, secret) {
  const [header, body, signature] = String(token || '').split('.');
  if (!header || !body || !signature) return null;
  const expected = await hmac(`${header}.${body}`, secret);
  if (!safeEqual(encoder.encode(signature), encoder.encode(expected))) return null;
  try {
    const payload = JSON.parse(new TextDecoder().decode(unb64(body)));
    return payload.exp > Date.now() / 1000 ? payload : null;
  } catch { return null; }
}

const validEmail = (value) => typeof value === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) && value.length <= 254;
const cleanName = (value, fallback = 'Untitled') => (typeof value === 'string' ? value.trim().slice(0, 100) : '') || fallback;
function cleanWindows(windows) {
  if (!Array.isArray(windows) || windows.length > 20) throw new Error('windows must contain at most 20 entries');
  return windows.map((window, index) => {
    if (!Array.isArray(window.tabs) || window.tabs.length > 500) throw new Error('each window must contain at most 500 tabs');
    return {
      id: typeof window.id === 'string' && window.id.length <= 100 ? window.id : crypto.randomUUID(),
      name: cleanName(window.name, `Window ${index + 1}`),
      tabs: window.tabs.map((tab) => {
        if (typeof tab.url !== 'string' || tab.url.length > 8192 || !/^https?:\/\//i.test(tab.url)) throw new Error('only http(s) tab URLs are accepted');
        return { url: tab.url, title: typeof tab.title === 'string' ? tab.title.slice(0, 500) : tab.url, pinned: Boolean(tab.pinned) };
      })
    };
  });
}

async function ensureSchema(db) {
  await db.batch([
    db.prepare('CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, token_version INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL)'),
    db.prepare("CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL, revision INTEGER NOT NULL DEFAULT 1, windows TEXT NOT NULL DEFAULT '[]', updated_at TEXT NOT NULL, created_at TEXT NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)"),
    db.prepare('CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)'),
    db.prepare('CREATE INDEX IF NOT EXISTS sessions_user_updated ON sessions(user_id, updated_at DESC)')
  ]);
}

async function signingSecret(db) {
  let row = await db.prepare("SELECT value FROM settings WHERE key='signing_secret'").first();
  if (!row) {
    const value = b64(crypto.getRandomValues(new Uint8Array(32)));
    await db.prepare("INSERT OR IGNORE INTO settings (key,value) VALUES ('signing_secret',?)").bind(value).run();
    row = await db.prepare("SELECT value FROM settings WHERE key='signing_secret'").first();
  }
  return row.value;
}

const sessionFromRow = (row) => row && ({
  id: row.id, name: row.name, revision: row.revision, windows: JSON.parse(row.windows),
  updatedAt: row.updated_at, createdAt: row.created_at
});

async function bodyOf(request) {
  try { return await request.json(); } catch { throw new Error('Request body must be valid JSON.'); }
}

async function handle(request, env) {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/$/, '') || '/';
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
  if (path === '/health') return json({ ok: true, runtime: 'cloudflare' });
  await ensureSchema(env.DB);
  const secret = await signingSecret(env.DB);

  if (path === '/v1/auth/register' && request.method === 'POST') {
    const body = await bodyOf(request);
    const email = String(body.email || '').trim().toLowerCase();
    if (!validEmail(email) || typeof body.password !== 'string' || body.password.length < 10 || body.password.length > 200) {
      return json({ error: 'Use a valid email and a password of at least 10 characters.' }, 400);
    }
    const id = crypto.randomUUID();
    try {
      await env.DB.prepare('INSERT INTO users (id,email,password_hash,created_at) VALUES (?,?,?,?)')
        .bind(id, email, await hashPassword(body.password), new Date().toISOString()).run();
    } catch (error) {
      if (String(error).includes('UNIQUE')) return json({ error: 'An account with this email already exists.' }, 409);
      throw error;
    }
    return json({ token: await signToken({ sub: id, ver: 1 }, secret), user: { id, email } }, 201);
  }

  if (path === '/v1/auth/login' && request.method === 'POST') {
    const body = await bodyOf(request);
    const email = String(body.email || '').trim().toLowerCase();
    const user = await env.DB.prepare('SELECT * FROM users WHERE email=?').bind(email).first();
    if (!user || !await verifyPassword(body.password, user.password_hash)) return json({ error: 'Incorrect email or password.' }, 401);
    return json({ token: await signToken({ sub: user.id, ver: user.token_version }, secret), user: { id: user.id, email } });
  }

  if (!path.startsWith('/v1/')) return json({ error: 'Not found.' }, 404);
  const token = request.headers.get('Authorization')?.replace(/^Bearer\s+/i, '');
  const payload = await verifyToken(token, secret);
  if (!payload) return json({ error: 'Sign in again.' }, 401);
  const user = await env.DB.prepare('SELECT id FROM users WHERE id=? AND token_version=?').bind(payload.sub, payload.ver).first();
  if (!user) return json({ error: 'Sign in again.' }, 401);

  if (path === '/v1/sessions' && request.method === 'GET') {
    const result = await env.DB.prepare('SELECT * FROM sessions WHERE user_id=? ORDER BY updated_at DESC').bind(payload.sub).all();
    return json({ sessions: result.results.map(sessionFromRow) });
  }
  if (path === '/v1/sessions' && request.method === 'POST') {
    const body = await bodyOf(request);
    const windows = cleanWindows(body.windows || []);
    const id = crypto.randomUUID(); const now = new Date().toISOString();
    await env.DB.prepare('INSERT INTO sessions (id,user_id,name,windows,updated_at,created_at) VALUES (?,?,?,?,?,?)')
      .bind(id, payload.sub, cleanName(body.name, 'New session'), JSON.stringify(windows), now, now).run();
    return json({ session: { id, name: cleanName(body.name, 'New session'), revision: 1, windows, updatedAt: now, createdAt: now } }, 201);
  }

  const match = path.match(/^\/v1\/sessions\/([^/]+)$/);
  if (match && request.method === 'PUT') {
    const body = await bodyOf(request); const windows = cleanWindows(body.windows);
    if (!Number.isInteger(Number(body.revision))) return json({ error: 'revision is required' }, 400);
    const now = new Date().toISOString();
    const result = await env.DB.prepare('UPDATE sessions SET name=?,windows=?,revision=revision+1,updated_at=? WHERE id=? AND user_id=? AND revision=?')
      .bind(cleanName(body.name), JSON.stringify(windows), now, match[1], payload.sub, Number(body.revision)).run();
    if (!result.meta.changes) {
      const current = await env.DB.prepare('SELECT * FROM sessions WHERE id=? AND user_id=?').bind(match[1], payload.sub).first();
      return current ? json({ error: 'This session changed on another device.', session: sessionFromRow(current) }, 409) : json({ error: 'Session not found.' }, 404);
    }
    const updated = await env.DB.prepare('SELECT * FROM sessions WHERE id=?').bind(match[1]).first();
    return json({ session: sessionFromRow(updated) });
  }
  if (match && request.method === 'DELETE') {
    const result = await env.DB.prepare('DELETE FROM sessions WHERE id=? AND user_id=?').bind(match[1], payload.sub).run();
    return result.meta.changes ? new Response(null, { status: 204, headers: cors }) : json({ error: 'Session not found.' }, 404);
  }
  return json({ error: 'Not found.' }, 404);
}

export default {
  async fetch(request, env) {
    if (!env.DB) return json({ error: 'The DB binding is required.' }, 503);
    try { return await handle(request, env); }
    catch (error) { console.error(error); return json({ error: error.message || 'Unexpected server error.' }, 500); }
  }
};
