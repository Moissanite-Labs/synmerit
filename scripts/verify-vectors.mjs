import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';

const root = new URL('../conformance/', import.meta.url);
// An explicit maintainer-provided local adapter may export async verifyBundle.
// No automatic discovery, package installation, URI fetching, or remote imports.
const adapter = process.argv[2]
  ? await import(pathToFileURL(resolve(process.argv[2])))
  : await import('../src/protocol.mjs');
assert.equal(typeof adapter.verifyBundle, 'function', 'adapter must export verifyBundle');
const manifest = JSON.parse(await readFile(new URL('manifest.json', root), 'utf8'));
assert.equal(manifest.format, 'koinos-conformance-manifest/1');
assert.equal(manifest.protocol, 'koinos/0.1');
assert.ok(Array.isArray(manifest.cases) && manifest.cases.length > 0);
assert.equal(new Set(manifest.cases).size, manifest.cases.length, 'duplicate manifest entry');
const files = (await readdir(new URL('cases/', root))).filter(f => f.endsWith('.json')).map(f => `cases/${f}`).sort();
assert.deepEqual([...manifest.cases].sort(), files, 'manifest must include every case');
let accepted = 0, rejected = 0;
for (const path of manifest.cases) {
  assert.match(path, /^cases\/[a-z0-9-]+\.json$/, 'unsafe fixture path');
  const c = JSON.parse(await readFile(new URL(path, root), 'utf8'));
  assert.equal(c.format, 'koinos-conformance/1');
  assert.equal(path, `cases/${c.id}.json`);
  assert.ok(['accept', 'reject'].includes(c.expected.outcome), `${c.id}: unsupported outcome`);
  let state, error;
  try { state = await adapter.verifyBundle(c.bundle, c.options); }
  catch (e) { error = e; }
  if (c.expected.outcome === 'accept') {
    assert.equal(error, undefined, `${c.id}: unexpectedly rejected: ${error?.message}`);
    assert.deepEqual(state, c.expected.state, `${c.id}: derived state mismatch`);
    accepted++;
  } else {
    assert.ok(error instanceof Error, `${c.id}: unexpectedly accepted`);
    rejected++;
  }
}
console.log(`Portable vectors: ${accepted} accepted with exact state; ${rejected} rejected. No network or settlement evidence.`);
