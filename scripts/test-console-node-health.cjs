// Copyright 2026 Ratio1
// Licensed under the Apache License, Version 2.0 (the "License").
// SPDX-License-Identifier: Apache-2.0

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const bundle = fs.readFileSync(path.join(__dirname, '../engine/pkg/ui/distoss/assets/bundle.js'), 'utf8');

function consoleHarness(fetchResponse = async () => { throw new Error('unexpected request'); }) {
  const elements = new Map();
  const listeners = new Map();
  const intervals = new Map();
  let nextInterval = 1;
  const element = (id) => {
    if (!elements.has(id)) {
      elements.set(id, {
        innerHTML: '', textContent: '', hidden: false,
        addEventListener() {}, focus() {},
      });
    }
    return elements.get(id);
  };
  const document = {
    hidden: false,
    head: { appendChild() {} },
    createElement: () => ({ textContent: '' }),
    getElementById: element,
    querySelectorAll: () => [],
    querySelector: () => null,
    addEventListener: (name, callback) => listeners.set(name, callback),
  };
  const context = {
    document, sessionStorage: { getItem: () => null, removeItem() {}, setItem() {} },
    fetch: fetchResponse, Headers, URLSearchParams, Date,
    setInterval: (callback, delay) => { const id = nextInterval++; intervals.set(id, { callback, delay }); return id; },
    clearInterval: (id) => intervals.delete(id),
  };
  vm.createContext(context);
  vm.runInContext(bundle.replace(/\n\}\)\(\);\s*$/, '\n  globalThis.healthTest = { state, parseNodeHealth, nodeHealthStatus, renderNodeHealth, refreshNodeHealth, startNodeHealthPolling, stopNodeHealthPolling };\n})();'), context);
  return { ...context.healthTest, document, element, intervals, listeners };
}

test('counts only observed IDs and live liveness, without synthetic rows', () => {
  const { parseNodeHealth } = consoleHarness();
  const snapshot = parseNodeHealth([
    { node_id: 8, liveness_status: 3, updated_at: 1700000000000000000 },
    { node_id: 12, liveness_status: 2, updated_at: 0 },
  ], 4);
  assert.equal(snapshot.configured, 4);
  assert.equal(snapshot.observed, 2);
  assert.equal(snapshot.live, 1);
  assert.equal(snapshot.notObserved, 2);
  assert.deepEqual(Array.from(snapshot.nodes, (node) => node.id), [8, 12]);
});

test('liveness labels distinguish unavailable, dead, draining and unknown', () => {
  const { nodeHealthStatus } = consoleHarness();
  assert.equal(nodeHealthStatus(1), 'Dead');
  assert.equal(nodeHealthStatus(2), 'Unavailable');
  assert.equal(nodeHealthStatus(3), 'Live');
  assert.equal(nodeHealthStatus(6), 'Draining');
  assert.equal(nodeHealthStatus(99), 'Unknown');
});

test('renders a stale snapshot and never invents a Ratio1 address or range zero', () => {
  const harness = consoleHarness();
  harness.state.session = 'session';
  harness.state.nodeHealth.snapshot = harness.parseNodeHealth([{ node_id: 7, liveness_status: 3, updated_at: 0 }], 3);
  harness.state.nodeHealth.lastSuccessAt = Date.now() - 121000;
  harness.renderNodeHealth();
  const html = harness.element('mesh-node-health').innerHTML;
  assert.match(html, /Stale/);
  assert.match(html, /Not observed/);
  assert.match(html, /Unable to assess/);
  assert.match(html, /DB node ID/);
  assert.doesNotMatch(html, /Ratio1 address|roach7/);
});

test('access failure leaves an unavailable state; visibility controls the 60s poll', async () => {
  const harness = consoleHarness(async () => ({ ok: false, status: 403, text: async () => 'forbidden' }));
  harness.state.session = 'session';
  await harness.refreshNodeHealth();
  assert.match(harness.element('mesh-node-health').innerHTML, /Unable to assess/);
  assert.match(harness.element('mesh-node-health').innerHTML, /Stale/);
  harness.startNodeHealthPolling();
  assert.equal(harness.intervals.size, 1);
  assert.equal(Array.from(harness.intervals.values())[0].delay, 60000);
  harness.document.hidden = true;
  harness.listeners.get('visibilitychange')();
  assert.equal(harness.intervals.size, 0);
});

test('loads configured count and paginated observed nodes, then refreshes on tab return', async () => {
  const calls = [];
  const json = (body) => ({ ok: true, status: 200, headers: { get: () => 'application/json' }, json: async () => body });
  const harness = consoleHarness(async (url) => {
    calls.push(url);
    if (url === '/api/v2/r1db/node-config/') return json({ configured_node_count: 3 });
    if (url === '/api/v2/nodes/?limit=500&offset=0') return json({ nodes: [{ node_id: 10, liveness_status: 3, updated_at: 1700000000000000000 }], next: 1 });
    if (url === '/api/v2/nodes/?limit=500&offset=1') return json({ nodes: [{ node_id: 11, liveness_status: 1, updated_at: 0 }] });
    throw new Error(`unexpected request: ${url}`);
  });
  harness.state.session = 'session';
  await harness.refreshNodeHealth();
  assert.equal(harness.state.nodeHealth.snapshot.observed, 2);
  assert.equal(harness.state.nodeHealth.snapshot.notObserved, 1);
  assert.match(harness.element('mesh-node-health').innerHTML, /DB node ID/);
  assert.match(harness.element('mesh-node-health').innerHTML, /Dead/);
  assert.equal(calls.length, 3);
  harness.document.hidden = true;
  harness.listeners.get('visibilitychange')();
  harness.document.hidden = false;
  harness.listeners.get('visibilitychange')();
  await harness.state.nodeHealth.inFlight;
  assert.equal(calls.length, 6);
  assert.equal(harness.intervals.size, 1);
});

test('rejects duplicate status records rather than reporting a false observed count', () => {
  const { parseNodeHealth } = consoleHarness();
  assert.throws(() => parseNodeHealth([{ node_id: 4, liveness_status: 3 }, { node_id: 4, liveness_status: 1 }], 3));
});
