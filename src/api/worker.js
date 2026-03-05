/**
 * ForgeAI Govern™ - Healthcare AI Governance Platform
 * Main Cloudflare Worker Entry Point
 *
 * Edge-deployed API with JWT authentication, RBAC, and multi-tenant isolation.
 * Aligned with NIST AI RMF, FDA SaMD, ONC HTI-1, HIPAA, and state AI laws.
 */

import { Router } from './router.js';
import { AuthService } from './auth.js';
import { corsHeaders, jsonResponse, errorResponse } from './utils.js';

export default {
  async fetch(request, env, ctx) {
    // Validate JWT_SECRET is configured (fail loudly)
    if (!env.JWT_SECRET || env.JWT_SECRET.length < 32) {
      console.error('FATAL: JWT_SECRET environment variable is not set or too short (minimum 32 characters). Use `wrangler secret put JWT_SECRET` to configure.');
      return errorResponse('Server configuration error: authentication not available', 500, request, env);
    }

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(request, env) });
    }

    const url = new URL(request.url);

    // Health check
    if (url.pathname === '/api/v1/health') {
      return jsonResponse({
        status: 'healthy',
        version: '1.0.0',
        timestamp: new Date().toISOString(),
        jwt_configured: !!(env.JWT_SECRET && env.JWT_SECRET.length >= 32),
      }, 200, request, env);
    }

    // API routes handled by the router
    if (url.pathname.startsWith('/api/')) {
      try {
        const router = new Router(env);
        return await router.handle(request);
      } catch (error) {
        console.error('Unhandled error:', error);
        return errorResponse('Internal server error', 500, request, env);
      }
    }

    // Non-API routes are served by Workers Static Assets (configured in wrangler.toml)
    // This fallback only triggers if assets middleware doesn't match
    return jsonResponse({ message: 'ForgeAI Govern™ API v1.0' }, 200, request, env);
  }
};
