/**
 * ForgeAI Govern™ - Authentication & Authorization Service
 *
 * JWT-based stateless auth with PBKDF2-SHA256 password hashing.
 * Implements: 15-min access tokens, 7-day refresh rotation, account lockout.
 */

import { generateUUID, jsonResponse, errorResponse, validateEmail } from './utils.js';

const PBKDF2_ITERATIONS = 100000;
const ACCESS_TOKEN_EXPIRY = 15 * 60; // 15 minutes in seconds
const REFRESH_TOKEN_EXPIRY = 7 * 24 * 60 * 60; // 7 days
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_MINUTES = 30;

export class AuthService {
  constructor(env) {
    this.db = env.DB;
    this.jwtSecret = env.JWT_SECRET || 'forgeai-dev-secret-replace-in-production';
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
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) return null;
    const token = authHeader.slice(7);
    return await this.verifyToken(token);
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
      const refreshToken = await this.createToken({ user_id: userId, tenant_id: tenantId, type: 'refresh' }, REFRESH_TOKEN_EXPIRY);

      await this.auditLog(tenantId, userId, 'register', 'tenant', tenantId, { organization: organization_name });

      return jsonResponse({
        access_token: accessToken,
        refresh_token: refreshToken,
        token_type: 'Bearer',
        expires_in: ACCESS_TOKEN_EXPIRY,
        user: { id: userId, email, first_name, last_name, role: 'admin' },
        tenant: { id: tenantId, name: organization_name, slug },
      }, 201);
    } catch (error) {
      if (error.message?.includes('UNIQUE')) return errorResponse('Organization or email already exists', 409);
      throw error;
    }
  }

  // --- Login ---

  async login(body, request) {
    const { email, password } = body;
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

    // Successful login - reset attempts
    await this.db.prepare(
      `UPDATE users SET failed_login_attempts = 0, locked_until = NULL, last_login = datetime('now'), status = 'active' WHERE id = ?`
    ).bind(user.id).run();

    const accessToken = await this.createToken(
      { user_id: user.id, tenant_id: user.tenant_id, role: user.role },
      ACCESS_TOKEN_EXPIRY
    );
    const refreshToken = await this.createToken(
      { user_id: user.id, tenant_id: user.tenant_id, type: 'refresh' },
      REFRESH_TOKEN_EXPIRY
    );

    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    await this.auditLog(user.tenant_id, user.id, 'login', 'user', user.id, { ip });

    return jsonResponse({
      access_token: accessToken,
      refresh_token: refreshToken,
      token_type: 'Bearer',
      expires_in: ACCESS_TOKEN_EXPIRY,
      user: {
        id: user.id, email: user.email, first_name: user.first_name,
        last_name: user.last_name, role: user.role, mfa_enabled: !!user.mfa_enabled,
      },
      tenant: { id: user.tenant_id, name: user.tenant_name, slug: user.tenant_slug },
    });
  }

  // --- Token Refresh ---

  async refresh(body) {
    const { refresh_token } = body;
    if (!refresh_token) return errorResponse('Refresh token required', 400);

    const payload = await this.verifyToken(refresh_token);
    if (!payload || payload.type !== 'refresh') return errorResponse('Invalid refresh token', 401);

    const user = await this.db.prepare(
      `SELECT id, tenant_id, role FROM users WHERE id = ? AND status = 'active'`
    ).bind(payload.user_id).first();
    if (!user) return errorResponse('User not found', 401);

    const newAccess = await this.createToken(
      { user_id: user.id, tenant_id: user.tenant_id, role: user.role },
      ACCESS_TOKEN_EXPIRY
    );
    const newRefresh = await this.createToken(
      { user_id: user.id, tenant_id: user.tenant_id, type: 'refresh' },
      REFRESH_TOKEN_EXPIRY
    );

    return jsonResponse({ access_token: newAccess, refresh_token: newRefresh, token_type: 'Bearer', expires_in: ACCESS_TOKEN_EXPIRY });
  }

  // --- Audit Logging ---

  async auditLog(tenantId, userId, action, entityType, entityId, details = {}) {
    await this.db.prepare(
      `INSERT INTO audit_log (id, tenant_id, user_id, action, entity_type, entity_id, details)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).bind(generateUUID(), tenantId, userId, action, entityType, entityId, JSON.stringify(details)).run();
  }
}
