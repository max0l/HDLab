#!/usr/bin/env node
// Default: query casting only, without connecting to MongoDB.
// Optional HTTP mode creates one simulation using an existing project you own.
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const usage = `Usage:
  node apps/backend/scripts/poc-query-selector.mjs
  HDLAB_TOKEN=<token> node apps/backend/scripts/poc-query-selector.mjs \\
    --url http://localhost:8080 --project-id <owned-project-id>

Default mode requires the backend's installed Mongoose dependency.
HTTP mode needs Node 18+ and creates one simulation; it does not require Mongoose.
Use an existing harmless test project owned by the supplied token's account.
The HTTP selector is restricted to that exact project; no broad $ne query is sent.`;

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i++) {
    const key = argv[i];
    if (key === '--help') return { help: true };
    if (!['--url', '--project-id'].includes(key) || !argv[i + 1] || args[key]) {
      throw new Error(`Invalid or duplicate argument: ${key}\n${usage}`);
    }
    args[key] = argv[++i];
  }
  if (Object.keys(args).length && (!args['--url'] || !args['--project-id'])) {
    throw new Error(`Both --url and --project-id are required.\n${usage}`);
  }
  return args;
}

function offline() {
  const require = createRequire(import.meta.url);
  const mongoose = require('mongoose');
  const Project = mongoose.model('SelectorPocProject', new mongoose.Schema({
    ownerId: mongoose.Schema.Types.ObjectId,
  }));
  const id = '507f1f77bcf86cd799439011';
  console.log(`Mongoose ${mongoose.version}; no database connection.`);
  for (const value of [id, { $ne: null }, { $in: [id] }]) {
    const query = Project.findById(value);
    query.cast(Project);
    const filter = JSON.parse(JSON.stringify(query.getFilter()));
    assert.deepEqual(filter, { _id: value });
    console.log(`${JSON.stringify(value)} -> ${JSON.stringify(filter)}`);
  }
  console.log('CONFIRMED: findById accepts operator objects as query selectors.');
  console.log('This proves query casting, not endpoint access or an ownership bypass.');
}

async function http(args) {
  const id = args['--project-id'];
  if (!/^[0-9a-fA-F]{24}$/.test(id)) throw new Error('Invalid project ID.');
  const token = process.env.HDLAB_TOKEN;
  if (!token) throw new Error('Set HDLAB_TOKEN to your own account token.');
  const base = new URL(args['--url']);
  if (!['http:', 'https:'].includes(base.protocol) || base.username || base.password || base.search || base.hash) {
    throw new Error('Use an HTTP(S) URL without credentials, query, or fragment.');
  }
  const api = `${base.href.replace(/\/+$/, '').replace(/\/api$/, '')}/api`;
  const request = (path, options = {}) => fetch(`${api}${path}`, {
    ...options,
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    redirect: 'error',
    signal: AbortSignal.timeout(15000),
  });

  // The real endpoint only returns projects owned by the authenticated account.
  const owned = await request(`/projects/${id}`);
  if (!owned.ok) throw new Error(`Project ownership preflight failed: HTTP ${owned.status}. No POST sent.`);
  const project = await owned.json();
  if (String(project._id).toLowerCase() !== id.toLowerCase()) {
    throw new Error('Project preflight returned a different ID. No POST sent.');
  }

  const payload = { projectId: { $in: [id] }, testbenchType: 'systemverilog' };
  console.log(`POST ${api}/simulations`);
  console.log(JSON.stringify(payload));
  const res = await request('/simulations', { method: 'POST', body: JSON.stringify(payload) });
  const body = await res.json().catch(() => ({}));
  if (res.status === 201) {
    assert.equal(String(body.projectId).toLowerCase(), id.toLowerCase());
    console.log(`CONFIRMED: object-valued projectId accepted; simulation ${body._id} created.`);
    console.log('Only the specified owned project was selected. No ownership bypass demonstrated.');
  } else if (res.status === 400) {
    console.log(`REJECTED: HTTP 400 (${String(body.error || 'Bad request').slice(0, 300)}).`);
    console.log('Inspect the error: rejection alone does not prove projectId validation was added.');
  } else {
    throw new Error(`INCONCLUSIVE: HTTP ${res.status}. No retry was attempted.`);
  }
}

try {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) console.log(usage);
  else if (args['--url']) await http(args);
  else offline();
} catch (err) {
  console.error(err.message);
  process.exitCode = 1;
}
