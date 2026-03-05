/**
 * ForgeAI Govern™ - Express ↔ Hono Router Adapter
 *
 * Bridges the Hono-based Workers Router (src/api/router.js) to Express,
 * eliminating the need to duplicate route handlers in server.js.
 *
 * Express requests are converted to Web API Request objects, passed through
 * the Router's handle() method, and the Web API Response is sent back through Express.
 */

/**
 * Convert an Express req into a Web API Request object compatible with
 * Hono's app.fetch() method.
 */
function expressToWorkerRequest(req) {
  const protocol = req.protocol || 'http';
  const host = req.get('host') || 'localhost:3000';
  const url = `${protocol}://${host}${req.originalUrl}`;

  // Build headers
  const headers = {};
  for (const [key, value] of Object.entries(req.headers)) {
    if (typeof value === 'string') {
      headers[key] = value;
    }
  }

  const method = req.method;
  const init = { method, headers };

  // Include body for methods that support it
  if (['POST', 'PUT', 'PATCH'].includes(method) && req.body !== undefined) {
    init.body = JSON.stringify(req.body);
    // Ensure content-type is set for JSON body
    if (!headers['content-type']) {
      headers['content-type'] = 'application/json';
    }
  }

  return new Request(url, init);
}

/**
 * Send a Web API Response back through Express res.
 */
async function sendWorkerResponse(workerResponse, res) {
  // Set status
  res.status(workerResponse.status);

  // Forward all response headers
  if (workerResponse.headers) {
    const entries = typeof workerResponse.headers.entries === 'function'
      ? workerResponse.headers.entries()
      : Object.entries(workerResponse.headers);
    for (const [key, value] of entries) {
      if (key.toLowerCase() !== 'transfer-encoding' && key.toLowerCase() !== 'content-length') {
        res.setHeader(key, value);
      }
    }
  }

  // Send body
  const text = await workerResponse.text();
  res.send(text);
}

/**
 * Create Express middleware that delegates all /api/ requests to the
 * Workers Router, falling through if the route is not found.
 *
 * @param {Function} createRouter - Async factory: (env) => Router instance
 * @param {Object} env - The D1-compatible environment object
 */
function createRouterMiddleware(createRouter, env) {
  let routerPromise = null;

  return async (req, res, next) => {
    try {
      // Lazy-initialize the router (ESM modules loaded via dynamic import)
      if (!routerPromise) {
        routerPromise = createRouter(env);
      }
      const router = await routerPromise;

      const workerRequest = expressToWorkerRequest(req);
      const workerResponse = await router.handle(workerRequest);

      await sendWorkerResponse(workerResponse, res);
    } catch (err) {
      console.error('Router adapter error:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  };
}

module.exports = { expressToWorkerRequest, sendWorkerResponse, createRouterMiddleware };
