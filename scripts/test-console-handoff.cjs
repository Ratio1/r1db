// Copyright 2026 Ratio1
// Licensed under the Apache License, Version 2.0 (the "License").
// SPDX-License-Identifier: Apache-2.0

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const bundle = fs.readFileSync(path.join(__dirname, '../engine/pkg/ui/distoss/assets/bundle.js'), 'utf8');

function runHandoff(dataset, storageThrows = false) {
  const stored = [];
  const navigations = [];
  const context = {
    document: { getElementById: (id) => id === 'r1db-console-handoff' ? { dataset } : null },
    sessionStorage: {
      setItem: (key, value) => {
        if (storageThrows) throw new Error('storage disabled');
        stored.push([key, value]);
      },
    },
    location: { replace: (url) => navigations.push(url) },
  };
  vm.runInNewContext(bundle, context);
  return { stored, navigations };
}

test('handoff stores the API session on the console origin before opening Overview', () => {
  const result = runHandoff({ session: 'session-token', username: 'app_user', database: 'appdb' });
  assert.equal(result.stored.length, 1);
  assert.equal(result.stored[0][0], 'r1db-console-session-v1');
  assert.deepEqual(JSON.parse(result.stored[0][1]), {
    session: 'session-token', username: 'app_user', database: 'appdb',
  });
  assert.deepEqual(result.navigations, ['/']);
});

test('incomplete handoffs and blocked storage return to manual login', () => {
  for (const result of [
    runHandoff({ session: '', username: 'app_user', database: 'appdb' }),
    runHandoff({ session: 'token', username: 'app_user', database: 'appdb' }, true),
  ]) {
    assert.equal(result.stored.length, 0);
    assert.deepEqual(result.navigations, ['/?console_login=storage']);
  }
});
