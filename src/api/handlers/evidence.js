/**
 * ForgeAI Govern™ - Evidence Management Handlers
 *
 * Compliance evidence artifacts linked to governance entities.
 * Supports both metadata-only links and R2-backed file uploads with SHA-256 integrity hashing.
 */

import { jsonResponse, errorResponse, generateUUID, sanitizeInput } from '../utils.js';

const ALLOWED_FILE_TYPES = {
  'application/pdf': '.pdf',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document': '.docx',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': '.xlsx',
  'image/png': '.png',
  'image/jpeg': '.jpg',
};
const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50 MB

export class EvidenceHandlers {
  constructor(env) {
    this.db = env.DB;
    this.r2 = env.EVIDENCE_STORE || null;
  }

  async list(ctx) {
    const entityType = ctx.url.searchParams.get('entity_type');
    const entityId = ctx.url.searchParams.get('entity_id');

    let where = 'WHERE e.tenant_id = ?';
    const params = [ctx.user.tenant_id];
    if (entityType) { where += ' AND e.entity_type = ?'; params.push(entityType); }
    if (entityId) { where += ' AND e.entity_id = ?'; params.push(entityId); }

    const results = await this.db.prepare(
      `SELECT e.*, u.first_name || ' ' || u.last_name as uploaded_by_name
       FROM evidence e LEFT JOIN users u ON e.uploaded_by = u.id
       ${where} ORDER BY e.created_at DESC`
    ).bind(...params).all();

    return jsonResponse({ data: results.results });
  }

  async create(ctx, body) {
    if (!ctx.auth.authorize(ctx.user, ['admin', 'governance_lead', 'reviewer'])) {
      return errorResponse('Insufficient permissions', 403);
    }

    const { entity_type, entity_id, title, description, evidence_type, url } = body;
    if (!entity_type || !entity_id || !title) {
      return errorResponse('entity_type, entity_id, and title are required', 400);
    }

    const validEntityTypes = ['ai_asset', 'risk_assessment', 'impact_assessment', 'vendor_assessment', 'control_implementation'];
    if (!validEntityTypes.includes(entity_type)) return errorResponse('Invalid entity_type', 400);

    const validEvidenceTypes = ['document', 'link', 'screenshot', 'test_result', 'policy', 'audit_report', 'certification', 'other'];
    const evType = validEvidenceTypes.includes(evidence_type) ? evidence_type : 'other';

    const id = generateUUID();
    await this.db.prepare(
      `INSERT INTO evidence (id, tenant_id, entity_type, entity_id, title, description, evidence_type, url, uploaded_by)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(id, ctx.user.tenant_id, entity_type, entity_id, sanitizeInput(title),
      description ? sanitizeInput(description) : null, evType, url || null, ctx.user.user_id).run();

    await ctx.auth.auditLog(ctx.user.tenant_id, ctx.user.user_id, 'create', 'evidence', id, { entity_type, entity_id, title });

    const evidence = await this.db.prepare('SELECT * FROM evidence WHERE id = ?').bind(id).first();
    return jsonResponse({ data: evidence }, 201);
  }

  /**
   * Upload a file to R2 and create an evidence record.
   * Accepts multipart/form-data with fields: file, entity_type, entity_id, title, description, evidence_type
   */
  async upload(ctx, request) {
    if (!ctx.auth.authorize(ctx.user, ['admin', 'governance_lead', 'reviewer'])) {
      return errorResponse('Insufficient permissions', 403);
    }

    if (!this.r2) {
      return errorResponse('File storage is not configured', 501);
    }

    let formData;
    try {
      formData = await request.formData();
    } catch {
      return errorResponse('Invalid multipart form data', 400);
    }

    const file = formData.get('file');
    if (!file || typeof file === 'string') {
      return errorResponse('File is required', 400);
    }

    const entityType = formData.get('entity_type');
    const entityId = formData.get('entity_id');
    const title = formData.get('title');
    if (!entityType || !entityId || !title) {
      return errorResponse('entity_type, entity_id, and title are required', 400);
    }

    const validEntityTypes = ['ai_asset', 'risk_assessment', 'impact_assessment', 'vendor_assessment', 'control_implementation'];
    if (!validEntityTypes.includes(entityType)) return errorResponse('Invalid entity_type', 400);

    // Validate file type
    const fileType = file.type;
    if (!ALLOWED_FILE_TYPES[fileType]) {
      return errorResponse(`File type not allowed. Accepted: PDF, DOCX, XLSX, PNG, JPEG`, 400);
    }

    // Validate file size
    const fileBuffer = await file.arrayBuffer();
    if (fileBuffer.byteLength > MAX_FILE_SIZE) {
      return errorResponse(`File exceeds maximum size of ${MAX_FILE_SIZE / 1024 / 1024}MB`, 400);
    }

    // Compute SHA-256 hash for integrity verification
    const hashBuffer = await crypto.subtle.digest('SHA-256', fileBuffer);
    const sha256Hash = [...new Uint8Array(hashBuffer)].map(b => b.toString(16).padStart(2, '0')).join('');

    // Build R2 key: tenant/entity_type/entity_id/uuid.ext
    const ext = ALLOWED_FILE_TYPES[fileType];
    const evidenceId = generateUUID();
    const fileKey = `${ctx.user.tenant_id}/${entityType}/${entityId}/${evidenceId}${ext}`;

    // Upload to R2
    await this.r2.put(fileKey, fileBuffer, {
      httpMetadata: { contentType: fileType },
      customMetadata: {
        tenant_id: ctx.user.tenant_id,
        evidence_id: evidenceId,
        sha256: sha256Hash,
        uploaded_by: ctx.user.user_id,
      },
    });

    // Determine evidence type and retention
    const evidenceType = formData.get('evidence_type') || 'document';
    const validEvidenceTypes = ['document', 'link', 'screenshot', 'test_result', 'policy', 'audit_report', 'certification', 'other'];
    const evType = validEvidenceTypes.includes(evidenceType) ? evidenceType : 'document';

    // Default retention: 6 years for HIPAA compliance
    const retentionYears = parseInt(formData.get('retention_years') || '6');
    const retentionDate = new Date();
    retentionDate.setFullYear(retentionDate.getFullYear() + retentionYears);

    await this.db.prepare(
      `INSERT INTO evidence (id, tenant_id, entity_type, entity_id, title, description, evidence_type, url, uploaded_by, file_key, file_name, file_size, file_type, sha256_hash, retention_expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      evidenceId, ctx.user.tenant_id, entityType, entityId,
      sanitizeInput(title),
      formData.get('description') ? sanitizeInput(formData.get('description')) : null,
      evType, null, ctx.user.user_id,
      fileKey, sanitizeInput(file.name), fileBuffer.byteLength, fileType,
      sha256Hash, retentionDate.toISOString()
    ).run();

    await ctx.auth.auditLog(ctx.user.tenant_id, ctx.user.user_id, 'create', 'evidence', evidenceId, {
      entity_type: entityType, entity_id: entityId, title, file_name: file.name, sha256: sha256Hash,
    });

    const evidence = await this.db.prepare('SELECT * FROM evidence WHERE id = ?').bind(evidenceId).first();
    return jsonResponse({ data: evidence }, 201);
  }

  /**
   * Generate a pre-signed download URL for R2-stored evidence.
   * Returns a time-limited redirect to the file.
   */
  async download(ctx, id) {
    const evidence = await this.db.prepare(
      'SELECT * FROM evidence WHERE id = ? AND tenant_id = ?'
    ).bind(id, ctx.user.tenant_id).first();

    if (!evidence) return errorResponse('Evidence not found', 404);
    if (!evidence.file_key) return errorResponse('No file attached to this evidence record', 400);

    if (!this.r2) return errorResponse('File storage is not configured', 501);

    const object = await this.r2.get(evidence.file_key);
    if (!object) return errorResponse('File not found in storage', 404);

    // Log read access for audit (PHI-containing evidence)
    await ctx.auth.auditLog(ctx.user.tenant_id, ctx.user.user_id, 'download', 'evidence', id, {
      file_name: evidence.file_name, sha256: evidence.sha256_hash,
    });

    return new Response(object.body, {
      headers: {
        'Content-Type': evidence.file_type || 'application/octet-stream',
        'Content-Disposition': `attachment; filename="${evidence.file_name}"`,
        'X-Content-Type-Options': 'nosniff',
        'X-Evidence-SHA256': evidence.sha256_hash,
      },
    });
  }

  /**
   * Verify the integrity of a stored evidence file by recomputing its SHA-256 hash.
   */
  async verify(ctx, id) {
    const evidence = await this.db.prepare(
      'SELECT * FROM evidence WHERE id = ? AND tenant_id = ?'
    ).bind(id, ctx.user.tenant_id).first();

    if (!evidence) return errorResponse('Evidence not found', 404);
    if (!evidence.file_key || !evidence.sha256_hash) {
      return errorResponse('No file or hash stored for this evidence record', 400);
    }

    if (!this.r2) return errorResponse('File storage is not configured', 501);

    const object = await this.r2.get(evidence.file_key);
    if (!object) return errorResponse('File not found in storage', 404);

    const fileBuffer = await object.arrayBuffer();
    const hashBuffer = await crypto.subtle.digest('SHA-256', fileBuffer);
    const computedHash = [...new Uint8Array(hashBuffer)].map(b => b.toString(16).padStart(2, '0')).join('');

    const intact = computedHash === evidence.sha256_hash;

    await ctx.auth.auditLog(ctx.user.tenant_id, ctx.user.user_id, 'verify', 'evidence', id, {
      expected_hash: evidence.sha256_hash, computed_hash: computedHash, intact,
    });

    return jsonResponse({
      data: {
        evidence_id: id,
        file_name: evidence.file_name,
        expected_hash: evidence.sha256_hash,
        computed_hash: computedHash,
        integrity_verified: intact,
        verified_at: new Date().toISOString(),
      },
    });
  }

  async delete(ctx, id) {
    if (!ctx.auth.authorize(ctx.user, ['admin', 'governance_lead'])) {
      return errorResponse('Insufficient permissions', 403);
    }

    const existing = await this.db.prepare('SELECT * FROM evidence WHERE id = ? AND tenant_id = ?')
      .bind(id, ctx.user.tenant_id).first();
    if (!existing) return errorResponse('Evidence not found', 404);

    // Delete from R2 if file exists
    if (existing.file_key && this.r2) {
      try { await this.r2.delete(existing.file_key); } catch { /* best effort */ }
    }

    await this.db.prepare('DELETE FROM evidence WHERE id = ?').bind(id).run();
    await ctx.auth.auditLog(ctx.user.tenant_id, ctx.user.user_id, 'delete', 'evidence', id, {
      title: existing.title, file_name: existing.file_name, sha256: existing.sha256_hash,
    });
    return jsonResponse({ message: 'Evidence deleted' });
  }
}
