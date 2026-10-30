#!/usr/bin/env node
'use strict';

// Execute the exact quick-settings helpers embedded in app.js with lightweight
// Vue-ref stubs. This tests behavior, not merely source-text patterns.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const source = fs.readFileSync('source/web/app.js', 'utf8');
const start = source.indexOf('    const yamlIndent =');
const end = source.indexOf('    const loadNodeConfig = async () => {', start);
assert(start >= 0 && end > start, 'could not locate quick-settings implementation');

const messages = [];
const context = {
  configYaml: { value: '' },
  configTunEnabled: { value: false },
  configDnsEnabled: { value: false },
  configDnsNameservers: { value: '' },
  selectedConfigNode: { value: { machine_code: 'test-node' } },
  showMsg: (message, type) => messages.push({ message, type }),
};
vm.createContext(context);
vm.runInContext(
  source.slice(start, end) +
  '\nglobalThis.__quick = { applyConfigQuickSettings, syncConfigQuickSettingsFromYaml, readYamlScalar };',
  context,
  { filename: 'source/web/app.js#quick-settings' },
);

const quick = context.__quick;
const baseYaml = [
  'port: 7890',
  'tun:',
  '  enable: false # preserve this comment',
  '  stack: system',
  '  nested:',
  '    enable: false',
  'dns:',
  '  enable: false',
  '  nameserver:',
  '    - "1.1.1.1"',
  '  fallback:',
  '    nameserver:',
  '      - "9.9.9.9"',
  '  fake-ip-range: 198.18.0.1/16',
  'rules:',
  '  - MATCH,DIRECT',
  '',
].join('\n');

context.configYaml.value = baseYaml;
context.configTunEnabled.value = true;
context.configDnsEnabled.value = true;
context.configDnsNameservers.value = '223.5.5.5\n119.29.29.29';
quick.applyConfigQuickSettings();

let yaml = context.configYaml.value;
assert.match(yaml, /^  enable: true # preserve this comment$/m);
assert.match(yaml, /^    enable: false$/m, 'nested tun.enable must remain unchanged');
assert.match(yaml, /^  nameserver:$/m);
assert.match(yaml, /^    - "223\.5\.5\.5"$/m);
assert.match(yaml, /^    - "119\.29\.29\.29"$/m);
assert.match(yaml, /^    nameserver:$/m, 'nested fallback.nameserver must remain');
assert.match(yaml, /^      - "9\.9\.9\.9"$/m, 'nested fallback list must remain');
assert.match(yaml, /^  fake-ip-range: 198\.18\.0\.1\/16$/m);
assert.match(yaml, /^rules:$/m);
assert.doesNotMatch(yaml, /\\n/, 'literal backslash-n must never be emitted');
assert.equal((yaml.match(/^tun:$/gm) || []).length, 1);
assert.equal((yaml.match(/^dns:$/gm) || []).length, 1);

// Ten repeated toggle/apply cycles must remain idempotent: one root section,
// one direct scalar for each toggle, and one direct nameserver list.
for (let i = 0; i < 10; i++) {
  context.configTunEnabled.value = i % 2 === 0;
  context.configDnsEnabled.value = i % 2 !== 0;
  context.configDnsNameservers.value = i % 2 === 0 ? '1.0.0.1\n1.1.1.1' : '8.8.8.8';
  quick.applyConfigQuickSettings();
  yaml = context.configYaml.value;
  assert.equal((yaml.match(/^tun:$/gm) || []).length, 1, 'duplicate tun section after cycle ' + i);
  assert.equal((yaml.match(/^dns:$/gm) || []).length, 1, 'duplicate dns section after cycle ' + i);
  assert.equal((yaml.match(/^  enable: (?:true|false)(?:\s+#.*)?$/gm) || []).length, 2);
  assert.doesNotMatch(yaml, /\\n/, 'literal backslash-n after cycle ' + i);
  assert.match(yaml, /^rules:$/m, 'unrelated root section lost after cycle ' + i);
}

// Read-back synchronization must reflect the YAML model rather than stale UI state.
quick.syncConfigQuickSettingsFromYaml();
assert.equal(context.configTunEnabled.value, false);
assert.equal(context.configDnsEnabled.value, true);
assert.equal(context.configDnsNameservers.value, '8.8.8.8');

// Missing root sections are created exactly once and use actual line breaks.
context.configYaml.value = 'mixed-port: 7890\n';
context.configTunEnabled.value = true;
context.configDnsEnabled.value = false;
context.configDnsNameservers.value = '8.8.4.4';
quick.applyConfigQuickSettings();
yaml = context.configYaml.value;
assert.equal((yaml.match(/^tun:$/gm) || []).length, 1);
assert.equal((yaml.match(/^dns:$/gm) || []).length, 1);
assert.match(yaml, /^  enable: true$/m);
assert.match(yaml, /^  enable: false$/m);
assert.match(yaml, /^    - "8\.8\.4\.4"$/m);
assert.doesNotMatch(yaml, /\\n/);

// Duplicate root sections are rejected without changing the editor contents.
const duplicateYaml = 'tun:\n  enable: false\ntun:\n  enable: true\ndns:\n  enable: false\n';
context.configYaml.value = duplicateYaml;
context.configTunEnabled.value = true;
quick.applyConfigQuickSettings();
assert.equal(context.configYaml.value, duplicateYaml);
assert(messages.some(item => item.type === 'error' && item.message.includes('重复的顶层 tun')));

console.log('PASS: YAML quick settings behavior tests (nested keys, comments, nameserver preservation, 10 toggle cycles, read-back, missing sections, duplicate rejection).');
