/**
 * ForgeAI Govern™ - Per-Tenant Rate Limiting Middleware
 *
 * Uses KV-backed sliding window counters scoped to tenant_id.
 * Falls back to per-IP limiting when tenant is not yet identified.
 */

const DEFAULT_LIMIT = 200; // requests per window
const DEFAULT_WINDOW = 60; // seconds
const AUTH_LIMIT = 10;
const AUTH_WINDOW = 900; // 15 minutes

export function rateLimiter(options = {}) {
  const limit = options.limit || DEFAULT_LIMIT;
  const window = options.window || DEFAULT_WINDOW;

  return async (c, next) => {
    const kv = c.env?.SESSION_CACHE;
    if (!kv) {
      // No KV binding — skip rate limiting (local dev)
      await next();
      return;
    }

    // Determine rate limit key: prefer tenant_id, fall back to IP
    const user = c.get('user');
    const ip = c.req.header('CF-Connecting-IP') || c.req.header('X-Forwarded-For') || 'unknown';
    const tenantId = user?.tenant_id;
    const keyBase = tenantId ? `rl:tenant:${tenantId}` : `rl:ip:${ip}`;

    const now = Math.floor(Date.now() / 1000);
    const windowStart = now - (now % window);
    const key = `${keyBase}:${windowStart}`;

    try {
      const current = parseInt(await kv.get(key) || '0');

      if (current >= limit) {
        const retryAfter = windowStart + window - now;
        return new Response(JSON.stringify({ error: 'Rate limit exceeded', status: 429 }), {
          status: 429,
          headers: {
            'Content-Type': 'application/json',
            'Retry-After': String(retryAfter),
            'X-RateLimit-Limit': String(limit),
            'X-RateLimit-Remaining': '0',
            'X-RateLimit-Reset': String(windowStart + window),
          },
        });
      }

      // Increment counter
      await kv.put(key, String(current + 1), { expirationTtl: window * 2 });

      // Set rate limit headers
      c.header('X-RateLimit-Limit', String(limit));
      c.header('X-RateLimit-Remaining', String(Math.max(0, limit - current - 1)));
      c.header('X-RateLimit-Reset', String(windowStart + window));
    } catch {
      // Rate limiting failure should not block requests
    }

    await next();
  };
}

export function authRateLimiter() {
  return rateLimiter({ limit: AUTH_LIMIT, window: AUTH_WINDOW });
}
