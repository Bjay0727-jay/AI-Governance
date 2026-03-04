/**
 * ForgeAI Govern™ - Utility Functions
 */

// Default allowed origins - override via ALLOWED_ORIGINS env var (comma-separated)
const DEFAULT_ALLOWED_ORIGINS = ['https://app.forgeai.com'];

export function corsHeaders(request, env) {
  const allowedOrigins = env?.ALLOWED_ORIGINS
    ? env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
    : DEFAULT_ALLOWED_ORIGINS;

  const origin = request?.headers?.get?.('Origin');
  const headers = {
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-CSRF-Token',
    'Access-Control-Max-Age': '86400',
  };

  if (origin && allowedOrigins.includes(origin)) {
    headers['Access-Control-Allow-Origin'] = origin;
    headers['Access-Control-Allow-Credentials'] = 'true';
  }
  // No Access-Control-Allow-Origin header if origin doesn't match allowlist

  return headers;
}

export function jsonResponse(data, status = 200, request, env) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...corsHeaders(request, env),
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
    },
  });
}

export function errorResponse(message, status = 400, request, env) {
  return jsonResponse({ error: message, status }, status, request, env);
}

export function generateUUID() {
  return crypto.randomUUID();
}

export function sanitizeInput(str) {
  if (typeof str !== 'string') return str;
  return str.replace(/[<>"'&]/g, (char) => {
    const entities = { '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '&': '&amp;' };
    return entities[char];
  });
}

export function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

export function paginate(query, page = 1, limit = 25) {
  const offset = (Math.max(1, page) - 1) * Math.min(100, Math.max(1, limit));
  return { offset, limit: Math.min(100, Math.max(1, limit)) };
}

export function csvResponse(rows, columns, filename, request, env) {
  const header = columns.map(c => `"${c.label}"`).join(',');
  const lines = rows.map(r =>
    columns.map(c => `"${String(r[c.key] ?? '').replace(/"/g, '""')}"`).join(',')
  );
  return new Response([header, ...lines].join('\n'), {
    status: 200,
    headers: {
      'Content-Type': 'text/csv',
      'Content-Disposition': `attachment; filename="${filename}"`,
      ...corsHeaders(request, env),
    },
  });
}

export function htmlResponse(html, request, env) {
  return new Response(html, {
    status: 200,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; img-src data:",
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      ...corsHeaders(request, env),
    },
  });
}

// --- HTML Escaping for report generation ---

export function escapeHtml(str) {
  if (typeof str !== 'string') return str;
  return str.replace(/[<>"'&]/g, (char) => {
    const entities = { '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '&': '&amp;' };
    return entities[char];
  });
}

// Safe helper: escapes value or returns fallback (already safe string)
export function esc(val, fallback = '') {
  if (val === null || val === undefined || val === '') return fallback;
  return escapeHtml(String(val));
}

// --- CSRF Validation ---

export async function generateCsrfToken(secret) {
  const encoder = new TextEncoder();
  const nonce = [...crypto.getRandomValues(new Uint8Array(16))].map(b => b.toString(16).padStart(2, '0')).join('');
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(nonce));
  const sigHex = [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('');
  return `${nonce}.${sigHex}`;
}

export async function validateCsrfToken(token, secret) {
  if (!token || !secret) return false;
  const parts = token.split('.');
  if (parts.length !== 2) return false;
  const [nonce, sigHex] = parts;
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  const sigArray = new Uint8Array(sigHex.match(/.{2}/g).map(b => parseInt(b, 16)));
  return crypto.subtle.verify('HMAC', key, sigArray, encoder.encode(nonce));
}

// --- Input Validation ---

const SYSTEM_FIELDS = ['id', 'tenant_id', 'created_at', 'updated_at'];

export function validateRequestBody(body, allowedFields, maxSizeBytes = 10240) {
  const errors = [];
  const bodyStr = JSON.stringify(body);
  if (bodyStr.length > maxSizeBytes) {
    errors.push(`Request body exceeds maximum size of ${maxSizeBytes} bytes`);
  }
  // Reject system fields
  for (const field of SYSTEM_FIELDS) {
    if (body[field] !== undefined) {
      errors.push(`Cannot set system field: ${field}`);
    }
  }
  // Warn about unknown fields
  const unknownFields = Object.keys(body).filter(k => !allowedFields.includes(k) && !SYSTEM_FIELDS.includes(k));
  if (unknownFields.length > 0) {
    errors.push(`Unknown fields: ${unknownFields.join(', ')}`);
  }
  return errors.length > 0 ? errors : null;
}
