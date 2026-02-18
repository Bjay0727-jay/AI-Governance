/**
 * ForgeAI Govern™ - Healthcare AI Governance Platform
 * Main Cloudflare Worker Entry Point
 *
 * Edge-deployed API with JWT authentication, RBAC, and multi-tenant isolation.
 * Aligned with NIST AI RMF, FDA SaMD, ONC HTI-1, HIPAA, and state AI laws.
 */

import { getAssetFromKV } from '@cloudflare/kv-asset-handler';
import manifestJSON from '__STATIC_CONTENT_MANIFEST';
import { Router } from './router.js';
import { AuthService } from './auth.js';
import { corsHeaders, jsonResponse, errorResponse } from './utils.js';

const assetManifest = JSON.parse(manifestJSON);

export default {
  async fetch(request, env, ctx) {
    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders() });
    }

    const url = new URL(request.url);

    // Health check
    if (url.pathname === '/api/v1/health') {
      return jsonResponse({ status: 'healthy', version: '1.0.0', timestamp: new Date().toISOString() });
    }

    // Serve frontend for non-API routes
    if (!url.pathname.startsWith('/api/')) {
      try {
        return await getAssetFromKV(
          { request, waitUntil: ctx.waitUntil.bind(ctx) },
          { ASSET_NAMESPACE: env.__STATIC_CONTENT, ASSET_MANIFEST: assetManifest }
        );
      } catch (e) {
        // If asset not found, serve index.html for SPA routing
        try {
          const indexRequest = new Request(new URL('/', request.url).toString(), request);
          return await getAssetFromKV(
            { request: indexRequest, waitUntil: ctx.waitUntil.bind(ctx) },
            { ASSET_NAMESPACE: env.__STATIC_CONTENT, ASSET_MANIFEST: assetManifest }
          );
        } catch (e2) {
          return jsonResponse({ message: 'ForgeAI Govern™ API v1.0' });
        }
      }
    }

    try {
      const router = new Router(env);
      return await router.handle(request);
    } catch (error) {
      console.error('Unhandled error:', error);
      return errorResponse('Internal server error', 500);
    }
  }
};
