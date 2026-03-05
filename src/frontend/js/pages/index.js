/**
 * ForgeAI Govern - Page Renderers (Entry Point)
 *
 * Assembles per-module page renderers into the global Pages object.
 * Built with esbuild into a single bundle for the browser.
 */

import { dashboard } from './dashboard.js';
import { assets } from './assets.js';
import { risk } from './risk.js';
import { impact } from './impact.js';
import { compliance } from './compliance.js';
import { vendors } from './vendors.js';
import { monitoring } from './monitoring.js';
import { governance } from './governance.js';
import { support } from './support.js';
import { knowledge } from './knowledge.js';
import { notifications } from './notifications.js';
import { training } from './training.js';
import { admin } from './admin.js';
import { reports } from './reports.js';
import { help } from './help.js';
import { events } from './events.js';

window.Pages = Object.assign(
  {},
  dashboard,
  assets,
  risk,
  impact,
  compliance,
  vendors,
  monitoring,
  governance,
  support,
  knowledge,
  notifications,
  training,
  admin,
  reports,
  help,
  events,
);
