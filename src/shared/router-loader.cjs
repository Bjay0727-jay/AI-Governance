/**
 * CJS loader for the ESM Workers Router.
 * Uses Node 22's native dynamic import() to load ESM modules.
 * This file is loaded at startup (not in Jest's VM), avoiding the
 * --experimental-vm-modules requirement.
 */

let routerClass = null;
let loadPromise = null;

async function loadRouter() {
  if (routerClass) return routerClass;
  if (loadPromise) return loadPromise;

  loadPromise = import('../api/router.js').then(mod => {
    routerClass = mod.Router;
    return routerClass;
  });

  return loadPromise;
}

module.exports = { loadRouter };
