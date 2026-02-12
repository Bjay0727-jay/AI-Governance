/**
 * ForgeAI Govern™ - Local SQLite Adapter
 *
 * Wraps better-sqlite3 to match Cloudflare D1's API surface,
 * so all existing handlers work without modification.
 *
 * D1 API: db.prepare(sql).bind(...args).first() / .all() / .run()
 */

const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const DB_PATH = path.join(__dirname, '..', '..', 'data', 'forgeai.db');

class D1Statement {
  constructor(db, sql) {
    this.db = db;
    this.sql = sql;
    this.params = [];
  }

  bind(...args) {
    this.params = args;
    return this;
  }

  first() {
    try {
      const stmt = this.db.prepare(this.sql);
      return stmt.get(...this.params) || null;
    } catch (err) {
      console.error('DB first() error:', this.sql, err.message);
      throw err;
    }
  }

  all() {
    try {
      const stmt = this.db.prepare(this.sql);
      const rows = stmt.all(...this.params);
      return { results: rows };
    } catch (err) {
      console.error('DB all() error:', this.sql, err.message);
      throw err;
    }
  }

  run() {
    try {
      const stmt = this.db.prepare(this.sql);
      const result = stmt.run(...this.params);
      return { success: true, changes: result.changes };
    } catch (err) {
      console.error('DB run() error:', this.sql, err.message);
      throw err;
    }
  }
}

class D1Adapter {
  constructor(dbPath) {
    const dir = path.dirname(dbPath || DB_PATH);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    this.db = new Database(dbPath || DB_PATH);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');
  }

  prepare(sql) {
    return new D1Statement(this.db, sql);
  }

  async batch(statements) {
    const transaction = this.db.transaction(() => {
      const results = [];
      for (const stmt of statements) {
        // Each stmt is a D1Statement - execute it
        try {
          results.push(stmt.run());
        } catch (err) {
          console.error('Batch error:', err.message);
          throw err;
        }
      }
      return results;
    });
    return transaction();
  }

  exec(sql) {
    this.db.exec(sql);
  }

  close() {
    this.db.close();
  }
}

function createDatabase(dbPath) {
  return new D1Adapter(dbPath);
}

module.exports = { D1Adapter, createDatabase, DB_PATH };
