/**
 * ForgeAI Govern™ - Structured Request Logging Middleware
 *
 * Produces JSON-formatted log entries with request ID, tenant context,
 * and latency metrics for every API call. Compatible with Cloudflare
 * Workers tail logging and third-party SIEM/APM integrations.
 */

/**
 * Generate a short unique request ID.
 */
function generateRequestId() {
  const bytes = crypto.getRandomValues(new Uint8Array(8));
  return [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Hono middleware that logs structured JSON for every request.
 * Attaches X-Request-ID header to response for correlation.
 */
export function requestLogger() {
  return async (c, next) => {
    const requestId = c.req.header('X-Request-ID') || generateRequestId();
    const startTime = Date.now();

    // Store request ID on context for downstream use
    c.set('requestId', requestId);

    try {
      await next();
    } finally {
      const duration = Date.now() - startTime;
      const user = c.get('user');
      const status = c.res?.status || 0;

      const logEntry = {
        timestamp: new Date().toISOString(),
        request_id: requestId,
        method: c.req.method,
        path: new URL(c.req.url).pathname,
        status,
        duration_ms: duration,
        tenant_id: user?.tenant_id || null,
        user_id: user?.user_id || null,
        user_agent: c.req.header('User-Agent') || null,
        ip: c.req.header('CF-Connecting-IP') || c.req.header('X-Forwarded-For') || null,
      };

      // Log at different levels based on status
      if (status >= 500) {
        console.error(JSON.stringify({ level: 'error', ...logEntry }));
      } else if (status >= 400) {
        console.warn(JSON.stringify({ level: 'warn', ...logEntry }));
      } else {
        console.log(JSON.stringify({ level: 'info', ...logEntry }));
      }

      // Add request ID to response headers for tracing
      if (c.res) {
        c.res.headers.set('X-Request-ID', requestId);
      }
    }
  };
}
