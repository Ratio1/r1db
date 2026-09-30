// Copyright 2026 Ratio1
// Licensed under the Apache License, Version 2.0 (the "License").
// SPDX-License-Identifier: Apache-2.0

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const bundle = fs.readFileSync(path.join(__dirname, '../engine/pkg/ui/distoss/assets/bundle.js'), 'utf8');

function consoleHarness(fetch) {
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) {
      elements.set(id, {
        innerHTML: '', textContent: '', hidden: false, value: '', disabled: false,
        addEventListener() {}, focus() {}, querySelectorAll: () => [], querySelector: () => null,
      });
    }
    return elements.get(id);
  };
  const document = {
    head: { appendChild() {} },
    createElement: () => ({ textContent: '' }),
    getElementById: (id) => id === 'r1db-console-handoff' ? null : element(id),
    querySelector: () => null,
    addEventListener() {},
  };
  const context = {
    document, fetch, Headers, URLSearchParams, Date, performance: { now: () => 10 },
    sessionStorage: { setItem() {}, removeItem() {} },
    location: { search: '' },
  };
  vm.createContext(context);
  vm.runInContext(bundle.replace(/\n\}\)\(\);\s*$/, '\n  globalThis.dashboardTest = { state, renderDataTable, runQuery };\n})();'), context);
  return { ...context.dashboardTest, element };
}

test('successful SQL refreshes the database selector', async () => {
  const calls = [];
  const json = (body) => ({
    ok: true, status: 200, headers: new Headers({ 'content-type': 'application/json' }),
    json: async () => body,
  });
  const harness = consoleHarness(async (url) => {
    calls.push(url);
    if (url === '/api/v2/sql/') return json({ execution: { txn_results: [{ tag: 'DROP DATABASE', rows: [] }] } });
    if (url === '/api/v2/r1db/databases/?limit=500&offset=0') return json({ databases: ['appdb'] });
    throw new Error(`unexpected request: ${url}`);
  });
  harness.state.session = 'session';
  harness.state.database = 'appdb';
  harness.state.databases = ['appdb', 'qa_alpha'];
  harness.state.view = 'sql';
  harness.element('mesh-query').value = 'DROP DATABASE qa_alpha CASCADE';
  await harness.runQuery();
  await new Promise(setImmediate);
  assert.deepEqual(Array.from(harness.state.databases), ['appdb']);
  assert.doesNotMatch(harness.element('mesh-database-select').innerHTML, /qa_alpha/);
  assert.deepEqual(calls, ['/api/v2/sql/', '/api/v2/r1db/databases/?limit=500&offset=0']);
});

test('short result values stay compact without forcing long values onto one line', () => {
  const { renderDataTable } = consoleHarness(async () => { throw new Error('unexpected request'); });
  const html = renderDataTable({ columns: [{ name: 'n' }, { name: 'payload' }], rows: [{ n: 26, payload: 'W'.repeat(300) }] });
  assert.match(html, /class="mesh-code mesh-value-compact"[^>]*>26<\/td>/);
  assert.match(html, /class="mesh-code"[^>]*>W{300}<\/td>/);
  assert.match(bundle, /\.mesh-table td\.mesh-value-compact\s*\{[^}]*white-space: nowrap/);
});
