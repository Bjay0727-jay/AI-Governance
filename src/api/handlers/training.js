/**
 * ForgeAI Govern™ - Training Module Handlers
 *
 * Governance training content, completion tracking, and progress reporting.
 */

import { jsonResponse, errorResponse, generateUUID } from '../utils.js';

export class TrainingHandlers {
  constructor(env) {
    this.db = env.DB;
  }

  async listModules(ctx) {
    const category = ctx.url.searchParams.get('category');
    let where = "WHERE status = 'active'";
    const params = [];
    if (category) { where += ' AND category = ?'; params.push(category); }

    const modules = await this.db.prepare(
      `SELECT * FROM training_modules ${where} ORDER BY sort_order ASC`
    ).bind(...params).all();

    const completions = await this.db.prepare(
      'SELECT module_id, score, completed_at FROM training_completions WHERE user_id = ?'
    ).bind(ctx.user.user_id).all();

    const completionMap = {};
    for (const c of completions.results) { completionMap[c.module_id] = c; }

    const data = modules.results.map(m => ({
      ...m,
      target_roles: JSON.parse(m.target_roles || '[]'),
      completed: !!completionMap[m.id],
      completion_data: completionMap[m.id] || null,
    }));

    return jsonResponse({ data });
  }

  async getModule(ctx, id) {
    const mod = await this.db.prepare("SELECT * FROM training_modules WHERE id = ? AND status = 'active'")
      .bind(id).first();
    if (!mod) return errorResponse('Training module not found', 404);

    const completion = await this.db.prepare(
      'SELECT * FROM training_completions WHERE module_id = ? AND user_id = ?'
    ).bind(id, ctx.user.user_id).first();

    mod.target_roles = JSON.parse(mod.target_roles || '[]');
    mod.completed = !!completion;
    mod.completion_data = completion || null;
    return jsonResponse({ data: mod });
  }

  async completeModule(ctx, id, body) {
    const mod = await this.db.prepare("SELECT * FROM training_modules WHERE id = ? AND status = 'active'")
      .bind(id).first();
    if (!mod) return errorResponse('Training module not found', 404);

    const existing = await this.db.prepare(
      'SELECT id FROM training_completions WHERE module_id = ? AND user_id = ?'
    ).bind(id, ctx.user.user_id).first();
    if (existing) return jsonResponse({ message: 'Already completed', data: existing });

    const score = body.score || 100;
    const completionId = generateUUID();
    await this.db.prepare(
      `INSERT INTO training_completions (id, module_id, user_id, tenant_id, score)
       VALUES (?, ?, ?, ?, ?)`
    ).bind(completionId, id, ctx.user.user_id, ctx.user.tenant_id, score).run();

    // Create notification
    try {
      await this.db.prepare(
        `INSERT INTO notifications (id, tenant_id, user_id, type, title, message, entity_type, entity_id)
         VALUES (?, ?, ?, 'success', ?, ?, 'training_module', ?)`
      ).bind(generateUUID(), ctx.user.tenant_id, ctx.user.user_id,
        'Training Completed', `You completed "${mod.title}"`, id).run();
    } catch (_) { /* ignore notification failures */ }

    const completion = await this.db.prepare('SELECT * FROM training_completions WHERE id = ?')
      .bind(completionId).first();
    return jsonResponse({ data: completion }, 201);
  }

  async getProgress(ctx) {
    const totalModules = await this.db.prepare("SELECT COUNT(*) as c FROM training_modules WHERE status = 'active'")
      .first();
    const completedModules = await this.db.prepare(
      'SELECT COUNT(*) as c FROM training_completions WHERE user_id = ?'
    ).bind(ctx.user.user_id).first();
    const completions = await this.db.prepare(
      `SELECT tc.*, tm.title, tm.category FROM training_completions tc
       JOIN training_modules tm ON tc.module_id = tm.id
       WHERE tc.user_id = ? ORDER BY tc.completed_at DESC`
    ).bind(ctx.user.user_id).all();
    const avgScore = await this.db.prepare(
      'SELECT AVG(score) as avg FROM training_completions WHERE user_id = ?'
    ).bind(ctx.user.user_id).first();

    const total = totalModules.c;
    const completed = completedModules.c;

    return jsonResponse({
      data: {
        total_modules: total,
        completed_modules: completed,
        completion_percentage: total > 0 ? Math.round((completed / total) * 100) : 0,
        average_score: Math.round(avgScore.avg || 0),
        completions: completions.results,
      },
    });
  }
}
