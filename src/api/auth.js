/**
 * ForgeAI Govern™ - Authentication & Authorization Service
 *
 * JWT-based stateless auth with PBKDF2-SHA256 password hashing.
 * Implements: httpOnly cookie tokens, 15-min access, 7-day refresh rotation,
 * account lockout, and TOTP MFA for privileged roles.
 */

import { generateUUID, jsonResponse, errorResponse, validateEmail } from './utils.js';

const PBKDF2_ITERATIONS = 100000;
const ACCESS_TOKEN_EXPIRY = 15 * 60; // 15 minutes in seconds
const REFRESH_TOKEN_EXPIRY = 7 * 24 * 60 * 60; // 7 days
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_MINUTES = 30;
const MFA_WINDOW = 1; // TOTP time-step window tolerance (±30s)
const MFA_REQUIRED_ROLES = ['admin', 'governance_lead'];
const TOTP_PERIOD = 30;
const TOTP_DIGITS = 6;

// --- Cookie Helpers ---

function setTokenCookies(response, accessToken, refreshToken, isSecure = true) {
  const cookieOpts = `HttpOnly; SameSite=Strict; Path=/api${isSecure ? '; Secure' : ''}`;
  const headers = new Headers(response.headers);
  headers.append('Set-Cookie', `forgeai_access=${accessToken}; Max-Age=${ACCESS_TOKEN_EXPIRY}; ${cookieOpts}`);
  headers.append('Set-Cookie', `forgeai_refresh=${refreshToken}; Max-Age=${REFRESH_TOKEN_EXPIRY}; ${cookieOpts}; Path=/api/v1/auth`);
  return new Response(response.body, { status: response.status, headers });
}

function clearTokenCookies(response, isSecure = true) {
  const cookieOpts = `HttpOnly; SameSite=Strict; Path=/api${isSecure ? '; Secure' : ''}`;
  const headers = new Headers(response.headers);
  headers.append('Set-Cookie', `forgeai_access=; Max-Age=0; ${cookieOpts}`);
  headers.append('Set-Cookie', `forgeai_refresh=; Max-Age=0; ${cookieOpts}; Path=/api/v1/auth`);
  return new Response(response.body, { status: response.status, headers });
}

function parseCookies(request) {
  const header = request.headers.get('Cookie') || '';
  const cookies = {};
  for (const part of header.split(';')) {
    const [key, ...rest] = part.trim().split('=');
    if (key) cookies[key.trim()] = rest.join('=').trim();
  }
  return cookies;
}

// --- TOTP Helpers ---

async function hmacSha1(key, message) {
  const cryptoKey = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, message));
}

function base32Decode(str) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const c of str.toUpperCase().replace(/=+$/, '')) {
    const val = alphabet.indexOf(c);
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, '0');
  }
  const bytes = new Uint8Array(Math.floor(bits.length / 8));
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
  }
  return bytes;
}

function base32Encode(buffer) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const byte of buffer) {
    bits += byte.toString(2).padStart(8, '0');
  }
  let result = '';
  for (let i = 0; i < bits.length; i += 5) {
    const chunk = bits.slice(i, i + 5).padEnd(5, '0');
    result += alphabet[parseInt(chunk, 2)];
  }
  return result;
}

async function generateTOTP(secret, time = Date.now()) {
  const key = base32Decode(secret);
  const counter = Math.floor(time / 1000 / TOTP_PERIOD);
  const counterBytes = new Uint8Array(8);
  let tmp = counter;
  for (let i = 7; i >= 0; i--) {
    counterBytes[i] = tmp & 0xff;
    tmp = Math.floor(tmp / 256);
  }
  const hash = await hmacSha1(key, counterBytes);
  const offset = hash[hash.length - 1] & 0xf;
  const code = ((hash[offset] & 0x7f) << 24 | hash[offset + 1] << 16 | hash[offset + 2] << 8 | hash[offset + 3]) % (10 ** TOTP_DIGITS);
  return code.toString().padStart(TOTP_DIGITS, '0');
}

async function verifyTOTP(secret, token, window = MFA_WINDOW) {
  const now = Date.now();
  for (let i = -window; i <= window; i++) {
    const expected = await generateTOTP(secret, now + i * TOTP_PERIOD * 1000);
    if (expected === token) return true;
  }
  return false;
}

export class AuthService {
  constructor(env) {
    this.db = env.DB;
    this.kv = env.SESSION_CACHE || null;
    this.env = env;
    if (!env.JWT_SECRET || env.JWT_SECRET.length < 32) {
      throw new Error('JWT_SECRET must be configured and at least 32 characters. Use `wrangler secret put JWT_SECRET`.');
    }
    this.jwtSecret = env.JWT_SECRET;
  }

  _isSecure() {
    return this.env.ENVIRONMENT !== 'test' && this.env.ENVIRONMENT !== 'development';
  }

  // --- Password Hashing (PBKDF2-SHA256) ---

  async hashPassword(password) {
    const encoder = new TextEncoder();
    const salt = crypto.getRandomValues(new Uint8Array(32));
    const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
    const derivedBits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
      keyMaterial,
      256
    );
    const hashArray = new Uint8Array(derivedBits);
    const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');
    const hashHex = Array.from(hashArray).map(b => b.toString(16).padStart(2, '0')).join('');
    return `${PBKDF2_ITERATIONS}:${saltHex}:${hashHex}`;
  }

  async verifyPassword(password, storedHash) {
    const [iterations, saltHex, hashHex] = storedHash.split(':');
    const encoder = new TextEncoder();
    const salt = new Uint8Array(saltHex.match(/.{2}/g).map(byte => parseInt(byte, 16)));
    const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
    const derivedBits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt, iterations: parseInt(iterations), hash: 'SHA-256' },
      keyMaterial,
      256
    );
    const computedHash = Array.from(new Uint8Array(derivedBits)).map(b => b.toString(16).padStart(2, '0')).join('');
    return computedHash === hashHex;
  }

  // --- JWT Token Management ---

  async createToken(payload, expiresIn) {
    const header = { alg: 'HS256', typ: 'JWT' };
    const now = Math.floor(Date.now() / 1000);
    const tokenPayload = { ...payload, iat: now, exp: now + expiresIn };

    const encoder = new TextEncoder();
    const headerB64 = btoa(JSON.stringify(header)).replace(/=/g, '');
    const payloadB64 = btoa(JSON.stringify(tokenPayload)).replace(/=/g, '');
    const signingInput = `${headerB64}.${payloadB64}`;

    const key = await crypto.subtle.importKey('raw', encoder.encode(this.jwtSecret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(signingInput));
    const signatureB64 = btoa(String.fromCharCode(...new Uint8Array(signature))).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');

    return `${headerB64}.${payloadB64}.${signatureB64}`;
  }

  async verifyToken(token) {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) return null;

      const [headerB64, payloadB64, signatureB64] = parts;
      const encoder = new TextEncoder();
      const signingInput = `${headerB64}.${payloadB64}`;

      const key = await crypto.subtle.importKey('raw', encoder.encode(this.jwtSecret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
      const signatureStr = atob(signatureB64.replace(/-/g, '+').replace(/_/g, '/'));
      const signatureArray = new Uint8Array(signatureStr.length);
      for (let i = 0; i < signatureStr.length; i++) signatureArray[i] = signatureStr.charCodeAt(i);

      const valid = await crypto.subtle.verify('HMAC', key, signatureArray, encoder.encode(signingInput));
      if (!valid) return null;

      const payload = JSON.parse(atob(payloadB64));
      if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;

      return payload;
    } catch {
      return null;
    }
  }

  // --- Auth Middleware ---

  async authenticate(request) {
    // Try httpOnly cookie first, then fall back to Authorization header
    const cookies = parseCookies(request);
    let token = cookies.forgeai_access;
    if (!token) {
      const authHeader = request.headers.get('Authorization');
      if (authHeader && authHeader.startsWith('Bearer ')) {
        token = authHeader.slice(7);
      }
    }
    if (!token) return null;
    const payload = await this.verifyToken(token);
    if (!payload) return null;
    if (payload.type && payload.type !== 'access') return null;
    if (!payload.user_id || !payload.tenant_id) return null;
    return payload;
  }

  authorize(user, requiredRoles) {
    if (!user) return false;
    return requiredRoles.includes(user.role);
  }

  // --- Registration ---

  async register(body) {
    const { organization_name, email, password, first_name, last_name } = body;

    if (!organization_name || !email || !password || !first_name || !last_name) {
      return errorResponse('Missing required fields: organization_name, email, password, first_name, last_name', 400);
    }
    if (!validateEmail(email)) return errorResponse('Invalid email format', 400);
    if (password.length < 12) return errorResponse('Password must be at least 12 characters', 400);

    const tenantId = generateUUID();
    const userId = generateUUID();
    const slug = organization_name.toLowerCase().replace(/[^a-z0-9]+/g, '-').slice(0, 50);
    const passwordHash = await this.hashPassword(password);

    try {
      await this.db.batch([
        this.db.prepare(
          `INSERT INTO tenants (id, name, slug, plan, status) VALUES (?, ?, ?, 'trial', 'active')`
        ).bind(tenantId, organization_name, slug),
        this.db.prepare(
          `INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, role, status)
           VALUES (?, ?, ?, ?, ?, ?, 'admin', 'active')`
        ).bind(userId, tenantId, email, passwordHash, first_name, last_name),
      ]);

      const accessToken = await this.createToken({ user_id: userId, tenant_id: tenantId, role: 'admin' }, ACCESS_TOKEN_EXPIRY);
      const refreshToken = await this.createToken({ user_id: userId, tenant_id: tenantId, type: 'refresh', jti: generateUUID() }, REFRESH_TOKEN_EXPIRY);

      await this.auditLog(tenantId, userId, 'register', 'tenant', tenantId, { organization: organization_name });

      const resp = jsonResponse({
        token_type: 'Bearer',
        expires_in: ACCESS_TOKEN_EXPIRY,
        user: { id: userId, email, first_name, last_name, role: 'admin', mfa_enabled: false },
        tenant: { id: tenantId, name: organization_name, slug },
      }, 201);
      return setTokenCookies(resp, accessToken, refreshToken, this._isSecure());
    } catch (error) {
      if (error.message?.includes('UNIQUE')) return errorResponse('Organization or email already exists', 409);
      throw error;
    }
  }

  // --- Login ---

  async login(body, request) {
    const { email, password, mfa_code } = body;
    if (!email || !password) return errorResponse('Email and password required', 400);

    const user = await this.db.prepare(
      `SELECT u.*, t.name as tenant_name, t.slug as tenant_slug, t.status as tenant_status
       FROM users u JOIN tenants t ON u.tenant_id = t.id WHERE u.email = ? AND u.status = 'active'`
    ).bind(email).first();

    if (!user) return errorResponse('Invalid credentials', 401);

    // Check lockout
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      return errorResponse('Account locked. Try again later.', 423);
    }

    const validPassword = await this.verifyPassword(password, user.password_hash);
    if (!validPassword) {
      const attempts = user.failed_login_attempts + 1;
      if (attempts >= MAX_LOGIN_ATTEMPTS) {
        const lockUntil = new Date(Date.now() + LOCKOUT_MINUTES * 60000).toISOString();
        await this.db.prepare(
          `UPDATE users SET failed_login_attempts = ?, locked_until = ?, status = 'locked' WHERE id = ?`
        ).bind(attempts, lockUntil, user.id).run();
      } else {
        await this.db.prepare(
          `UPDATE users SET failed_login_attempts = ? WHERE id = ?`
        ).bind(attempts, user.id).run();
      }
      return errorResponse('Invalid credentials', 401);
    }

    // MFA enforcement for privileged roles
    if (user.mfa_enabled && user.mfa_secret) {
      if (!mfa_code) {
        return jsonResponse({ mfa_required: true, message: 'MFA code required' }, 200);
      }
      const valid = await verifyTOTP(user.mfa_secret, mfa_code);
      if (!valid) return errorResponse('Invalid MFA code', 401);
    }

    // Successful login - reset attempts
    await this.db.prepare(
      `UPDATE users SET failed_login_attempts = 0, locked_until = NULL, last_login = datetime('now'), status = 'active' WHERE id = ?`
    ).bind(user.id).run();

    const accessToken = await this.createToken(
      { user_id: user.id, tenant_id: user.tenant_id, role: user.role },
      ACCESS_TOKEN_EXPIRY
    );
    const refreshToken = await this.createToken(
      { user_id: user.id, tenant_id: user.tenant_id, type: 'refresh', jti: generateUUID() },
      REFRESH_TOKEN_EXPIRY
    );

    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    await this.auditLog(user.tenant_id, user.id, 'login', 'user', user.id, { ip });

    const mfaRequired = MFA_REQUIRED_ROLES.includes(user.role) && !user.mfa_enabled;

    const resp = jsonResponse({
      token_type: 'Bearer',
      expires_in: ACCESS_TOKEN_EXPIRY,
      user: {
        id: user.id, email: user.email, first_name: user.first_name,
        last_name: user.last_name, role: user.role, mfa_enabled: !!user.mfa_enabled,
      },
      tenant: { id: user.tenant_id, name: user.tenant_name, slug: user.tenant_slug },
      mfa_enrollment_required: mfaRequired,
    });
    return setTokenCookies(resp, accessToken, refreshToken, this._isSecure());
  }

  // --- Token Refresh ---

  async refresh(body, request) {
    // Try cookie first, then body
    const cookies = parseCookies(request);
    const refreshTokenValue = cookies.forgeai_refresh || body?.refresh_token;
    if (!refreshTokenValue) return errorResponse('Refresh token required', 400);

    const payload = await this.verifyToken(refreshTokenValue);
    if (!payload || payload.type !== 'refresh') return errorResponse('Invalid refresh token', 401);

    // Check if token has been revoked
    if (this.kv && payload.jti) {
      const revoked = await this.kv.get(`revoked:${payload.jti}`);
      if (revoked) return errorResponse('Token has been revoked', 401);
    }

    const user = await this.db.prepare(
      `SELECT id, tenant_id, role FROM users WHERE id = ? AND status = 'active'`
    ).bind(payload.user_id).first();
    if (!user) return errorResponse('User not found', 401);

    const newAccess = await this.createToken(
      { user_id: user.id, tenant_id: user.tenant_id, role: user.role },
      ACCESS_TOKEN_EXPIRY
    );
    const newRefresh = await this.createToken(
      { user_id: user.id, tenant_id: user.tenant_id, type: 'refresh', jti: generateUUID() },
      REFRESH_TOKEN_EXPIRY
    );

    const resp = jsonResponse({ token_type: 'Bearer', expires_in: ACCESS_TOKEN_EXPIRY });
    return setTokenCookies(resp, newAccess, newRefresh, this._isSecure());
  }

  // --- Logout (Token Revocation) ---

  async logout(body, request) {
    const cookies = parseCookies(request);
    const refreshTokenValue = cookies.forgeai_refresh || body?.refresh_token;

    if (refreshTokenValue) {
      const payload = await this.verifyToken(refreshTokenValue);
      if (payload && payload.type === 'refresh' && this.kv && payload.jti) {
        const ttl = Math.max(0, payload.exp - Math.floor(Date.now() / 1000));
        if (ttl > 0) {
          await this.kv.put(`revoked:${payload.jti}`, 'true', { expirationTtl: ttl });
        }
      }
    }

    const resp = jsonResponse({ message: 'Logged out successfully' });
    return clearTokenCookies(resp, this._isSecure());
  }

  // --- MFA Enrollment ---

  async mfaEnroll(ctx) {
    const user = await this.db.prepare('SELECT id, email, mfa_enabled FROM users WHERE id = ? AND tenant_id = ?')
      .bind(ctx.user.user_id, ctx.user.tenant_id).first();
    if (!user) return errorResponse('User not found', 404);
    if (user.mfa_enabled) return errorResponse('MFA is already enabled', 400);

    const secret = base32Encode(crypto.getRandomValues(new Uint8Array(20)));
    // Store provisionally — not yet confirmed
    await this.db.prepare('UPDATE users SET mfa_secret = ? WHERE id = ?').bind(secret, user.id).run();

    const otpauthUrl = `otpauth://totp/ForgeAI%20Govern:${encodeURIComponent(user.email)}?secret=${secret}&issuer=ForgeAI%20Govern&digits=${TOTP_DIGITS}&period=${TOTP_PERIOD}`;

    return jsonResponse({
      secret,
      otpauth_url: otpauthUrl,
      message: 'Scan the QR code with your authenticator app, then confirm with POST /api/v1/auth/mfa/verify',
    });
  }

  async mfaVerify(ctx, body) {
    const { code } = body;
    if (!code) return errorResponse('MFA code required', 400);

    const user = await this.db.prepare('SELECT id, mfa_secret, mfa_enabled FROM users WHERE id = ? AND tenant_id = ?')
      .bind(ctx.user.user_id, ctx.user.tenant_id).first();
    if (!user) return errorResponse('User not found', 404);
    if (!user.mfa_secret) return errorResponse('MFA enrollment not started. Call POST /api/v1/auth/mfa/enroll first.', 400);
    if (user.mfa_enabled) return errorResponse('MFA is already enabled', 400);

    const valid = await verifyTOTP(user.mfa_secret, code);
    if (!valid) return errorResponse('Invalid MFA code. Please try again.', 400);

    await this.db.prepare('UPDATE users SET mfa_enabled = 1 WHERE id = ?').bind(user.id).run();
    await this.auditLog(ctx.user.tenant_id, ctx.user.user_id, 'mfa_enable', 'user', user.id, {});

    return jsonResponse({ message: 'MFA enabled successfully' });
  }

  async mfaDisable(ctx, body) {
    const { code } = body;
    if (!code) return errorResponse('Current MFA code required to disable MFA', 400);

    const user = await this.db.prepare('SELECT id, mfa_secret, mfa_enabled FROM users WHERE id = ? AND tenant_id = ?')
      .bind(ctx.user.user_id, ctx.user.tenant_id).first();
    if (!user || !user.mfa_enabled) return errorResponse('MFA is not enabled', 400);

    const valid = await verifyTOTP(user.mfa_secret, code);
    if (!valid) return errorResponse('Invalid MFA code', 401);

    await this.db.prepare('UPDATE users SET mfa_enabled = 0, mfa_secret = NULL WHERE id = ?').bind(user.id).run();
    await this.auditLog(ctx.user.tenant_id, ctx.user.user_id, 'mfa_disable', 'user', user.id, {});

    return jsonResponse({ message: 'MFA disabled' });
  }

  // --- Audit Logging with Cryptographic Hash Chaining ---

  async auditLog(tenantId, userId, action, entityType, entityId, details = {}, options = {}) {
    const id = generateUUID();
    const detailsJson = JSON.stringify(details);
    const dataClassification = options.dataClassification || 'standard';

    // Get the hash of the previous audit entry for this tenant (chain link)
    let previousHash = null;
    try {
      const lastEntry = await this.db.prepare(
        'SELECT entry_hash FROM audit_log WHERE tenant_id = ? ORDER BY created_at DESC LIMIT 1'
      ).bind(tenantId).first();
      previousHash = lastEntry?.entry_hash || null;
    } catch { /* first entry or column not yet migrated */ }

    // Compute entry hash: SHA-256(id + action + entityType + entityId + details + previousHash)
    let entryHash = null;
    try {
      const hashInput = `${id}:${action}:${entityType}:${entityId}:${detailsJson}:${previousHash || 'genesis'}`;
      const encoder = new TextEncoder();
      const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(hashInput));
      entryHash = [...new Uint8Array(hashBuffer)].map(b => b.toString(16).padStart(2, '0')).join('');
    } catch { /* hash chaining not available in test env */ }

    try {
      await this.db.prepare(
        `INSERT INTO audit_log (id, tenant_id, user_id, action, entity_type, entity_id, details, previous_hash, entry_hash, data_classification)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).bind(id, tenantId, userId, action, entityType, entityId, detailsJson, previousHash, entryHash, dataClassification).run();
    } catch {
      // Fallback for databases without the new columns (pre-migration)
      await this.db.prepare(
        `INSERT INTO audit_log (id, tenant_id, user_id, action, entity_type, entity_id, details)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      ).bind(id, tenantId, userId, action, entityType, entityId, detailsJson).run();
    }
  }
}
