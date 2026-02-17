/**
 * ForgeAI Govern™ - Database Setup Script
 *
 * Creates the SQLite database and initializes the schema + compliance controls.
 * Run: npm run setup
 */

const fs = require('fs');
const path = require('path');
const { createDatabase } = require('../src/local/db-adapter');

console.log('ForgeAI Govern™ - Database Setup');
console.log('================================\n');

// Remove existing DB for clean setup
const dbPath = path.join(__dirname, '..', 'data', 'forgeai.db');
if (fs.existsSync(dbPath)) {
  fs.unlinkSync(dbPath);
  // Also remove WAL/SHM files if present
  if (fs.existsSync(dbPath + '-wal')) fs.unlinkSync(dbPath + '-wal');
  if (fs.existsSync(dbPath + '-shm')) fs.unlinkSync(dbPath + '-shm');
  console.log('Removed existing database.\n');
}

const db = createDatabase();

// Run schema as a single exec call
console.log('Creating database schema...');
const schema = fs.readFileSync(path.join(__dirname, '..', 'src', 'database', 'schema.sql'), 'utf8');
db.exec(schema);
console.log('  12 tables created.\n');

// Run seed data as a single exec call
console.log('Loading compliance control catalog...');
const seed = fs.readFileSync(path.join(__dirname, '..', 'src', 'database', 'seed.sql'), 'utf8');
db.exec(seed);

// Count controls loaded
const count = db.prepare('SELECT COUNT(*) as c FROM compliance_controls').first();
console.log(`  ${count.c} compliance controls loaded.`);
console.log('  Mapped across: NIST AI RMF, FDA SaMD, ONC HTI-1, HIPAA, State Laws\n');

db.close();
console.log('Database ready at: data/forgeai.db');
console.log('Run "npm run seed" to add demo healthcare AI assets.');
console.log('Run "npm start" to launch the platform.\n');
