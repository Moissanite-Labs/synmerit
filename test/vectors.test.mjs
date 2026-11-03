import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createPublicKey, verify } from 'node:crypto';
import { canonicalize, digestBytes, verifyBundle } from '../src/protocol.mjs';
const root = new URL('../conformance/', import.meta.url);
const manifest = JSON.parse(await readFile(new URL('manifest.json', root), 'utf8'));
const cases = await Promise.all(manifest.cases.map(async path => JSON.parse(await readFile(new URL(path, root), 'utf8'))));

test('committed language-neutral vectors match reference outcomes and states', () => {
  const output = execFileSync(process.execPath, [fileURLToPath(new URL('../scripts/verify-vectors.mjs', import.meta.url))], { encoding: 'utf8' });
  assert.match(output, /14 accepted with exact state; 22 rejected/);
});

test('semantic rejection vectors have valid hashes and signatures through the offending event', () => {
  const structural = new Set(['tampered-body', 'bad-signature', 'reordered-history', 'unknown-field', 'unsupported-format']);
  for (const c of cases.filter(c => !structural.has(c.id))) {
    for (const { id, signature, ...unsigned } of c.bundle.records) {
      assert.equal(digestBytes(canonicalize(unsigned)), id, c.id);
      const publicKey = createPublicKey({ format: 'der', type: 'spki', key: Buffer.concat([
        Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(unsigned.actor.slice(15), 'base64url'),
      ]) });
      assert.ok(verify(null, Buffer.from(`koinos/0.1\n${id}`), publicKey, Buffer.from(signature, 'base64url')), c.id);
    }
  }
});

test('semantic failure cases reach the intended rule rather than a preceding error', () => {
  const diagnostics = {
    'principal-review': /independent/, 'agent-review': /Human participant/,
    'non-steward-acceptance': /Steward required/, 'duplicate-consent': /Duplicate consent/,
    'agent-consent': /Human participant/, 'forward-agreement': /Unknown preceding agreement/,
    'expiry-at-acceptance': /Inactive/, 'revoked-acceptance': /Inactive/,
    'wrong-revoker': /Invalid revocation/, 'withdrawn-acceptance': /currently consent/,
    'stale-review': /Exact latest/, 'terminal-dispute': /Exact latest/,
    'noncanonical-time': /canonical timestamp/, 'backward-time': /Backwards/,
  };
  for (const [id, pattern] of Object.entries(diagnostics)) {
    const c = cases.find(c => c.id === id);
    assert.throws(() => verifyBundle(c.bundle, c.options), pattern, id);
  }
});

test('positive state expectations cover every event kind and preserve attribution', () => {
  const positive = cases.filter(c => c.expected.outcome === 'accept');
  const kinds = new Set(positive.flatMap(c => c.bundle.records.map(r => r.kind)));
  assert.equal(kinds.size, 10);
  const byId = Object.fromEntries(positive.map(c => [c.id, c.expected.state]));
  assert.equal(byId['valid-accepted'].contributions[0].status, 'accepted');
  assert.equal(byId['valid-accepted'].contributions[0].principal, byId['valid-accepted'].project.steward);
  assert.equal(byId['valid-revoked'].delegations[0].revoked, true);
  assert.equal(byId['valid-withdrawn'].agreements[0].consents.length, 1);
  assert.equal(byId['valid-reconsented'].contributions[0].status, 'accepted');
  assert.equal(byId['valid-changes-requested'].contributions[0].status, 'changes_requested');
  assert.equal(byId['valid-disputed'].contributions[0].status, 'disputed');
  assert.ok(byId['valid-disputed'].contributions[0].acceptance);
});

test('portable runner fails on expectation drift and an incomplete manifest', async () => {
  const { mkdtemp, cp, mkdir, writeFile, rm } = await import('node:fs/promises');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const temp = await mkdtemp(join(tmpdir(), 'koinos-vectors-'));
  try {
    await mkdir(join(temp, 'scripts'));
    await cp(fileURLToPath(root), join(temp, 'conformance'), { recursive: true });
    await cp(fileURLToPath(new URL('../scripts/verify-vectors.mjs', import.meta.url)), join(temp, 'scripts/verify-vectors.mjs'));
    const run = () => execFileSync(process.execPath, [join(temp, 'scripts/verify-vectors.mjs'), fileURLToPath(new URL('../src/protocol.mjs', import.meta.url))], { encoding: 'utf8', stdio: 'pipe' });
    assert.match(run(), /14 accepted/);
    const target = cases.find(c => c.id === 'valid-accepted');
    const altered = structuredClone(target);
    altered.expected.state.contributions[0].status = 'submitted';
    await writeFile(join(temp, 'conformance/cases/valid-accepted.json'), JSON.stringify(altered));
    assert.throws(run, /derived state mismatch/);
    await writeFile(join(temp, 'conformance/cases/valid-accepted.json'), JSON.stringify(target));
    await writeFile(join(temp, 'conformance/manifest.json'), JSON.stringify({ ...manifest, cases: manifest.cases.slice(1) }));
    assert.throws(run, /manifest must include every case/);
  } finally { await rm(temp, { recursive: true, force: true }); }
});
