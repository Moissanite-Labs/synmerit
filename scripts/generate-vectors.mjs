// Maintainer-only fixture authoring. Generates fresh synthetic identities in memory.
// No private key is written. Regeneration intentionally changes signed fixture bytes.
import { mkdir, writeFile } from 'node:fs/promises';
import { sign } from 'node:crypto';
import { createDemo } from '../src/demo.mjs';
import { canonicalize, digestBytes, verifyBundle } from '../src/protocol.mjs';

const directory = new URL('../conformance/cases/', import.meta.url);
await mkdir(directory, { recursive: true });
const { bundle: accepted, identities } = createDemo();
const { steward, reviewer, agent } = identities;
const prefix = n => ({ format: accepted.format, records: structuredClone(accepted.records.slice(0, n)) });
const agreement = accepted.records[1].id;
const delegation = accepted.records[4].id;
const contribution = accepted.records[5].id;
const review = accepted.records[6].id;
// Bypass createRecord's policy validation to construct correctly signed invalid events.
function append(bundle, who, kind, body, time = '2026-01-01T12:01:00.000Z') {
  const unsigned = { protocol: 'koinos/0.1', project: bundle.records[0].project,
    sequence: bundle.records.length, previous: bundle.records.at(-1).id,
    time, actor: who.id, kind, body };
  const id = digestBytes(canonicalize(unsigned));
  bundle.records.push({ ...unsigned, id,
    signature: sign(null, Buffer.from(`koinos/0.1\n${id}`), who.privateKey).toString('base64url') });
  return bundle;
}
const cases = [];
function add(id, description, bundle, outcome, options = {}, diagnostic = null) {
  const expected = { outcome };
  if (outcome === 'accept') expected.state = verifyBundle(bundle, options);
  else {
    let error;
    try { verifyBundle(bundle, options); } catch (e) { error = e; }
    if (!error || (diagnostic && !error.message.includes(diagnostic)))
      throw new Error(`${id}: expected ${diagnostic}, got ${error?.message ?? 'accept'}`);
  }
  cases.push(id);
  return writeFile(new URL(`${id}.json`, directory), JSON.stringify({
    format: 'koinos-conformance/1', id, description, bundle, options, expected,
  }, null, 2) + '\n');
}
for (const [n, name] of [[1,'genesis'],[2,'agreement'],[4,'consent'],[5,'delegation'],[6,'submission'],[7,'review'],[8,'accepted']])
  await add(`valid-${name}`, `Valid ${name} prefix; unpinned incomplete histories are permitted.`, prefix(n), 'accept');
await add('valid-exact-pins', 'Both trusted pins match exactly.', prefix(8), 'accept', { expectedHead: accepted.records.at(-1).id, expectedProject: accepted.records[0].project });
await add('wrong-head', 'A trusted head pin does not match.', prefix(8), 'reject', { expectedHead: '0'.repeat(64) }, 'Expected head mismatch');
await add('wrong-project', 'A trusted project pin does not match.', prefix(8), 'reject', { expectedProject: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' }, 'Expected project mismatch');
await add('truncated-pinned', 'A valid shorter history is rejected against the accepted head.', prefix(7), 'reject', { expectedHead: accepted.records.at(-1).id }, 'Expected head mismatch');
const acceptBody = { contribution, review };
const reviewBody = { contribution, decision: 'approve', note: 'Synthetic review' };
await add('principal-review', 'A human principal cannot review their agent contribution.', append(prefix(6), steward, 'contribution.reviewed', reviewBody), 'reject', {}, 'independent');
await add('agent-review', 'An agent cannot act as the human reviewer.', append(prefix(6), agent, 'contribution.reviewed', reviewBody), 'reject', {}, 'Human participant');
await add('non-steward-acceptance', 'An independent reviewer is not the steward.', append(prefix(7), reviewer, 'contribution.accepted', acceptBody), 'reject', {}, 'Steward required');
await add('duplicate-consent', 'Active consent cannot be repeated.', append(prefix(4), reviewer, 'agreement.consented', { agreement }), 'reject', {}, 'Duplicate consent');
await add('agent-consent', 'An agent cannot consent as an agreement party.', append(prefix(2), agent, 'agreement.consented', { agreement }), 'reject', {}, 'Human participant');
await add('forward-agreement', 'Consent cannot reference an agreement absent from preceding history.', append(prefix(1), steward, 'agreement.consented', { agreement }), 'reject', {}, 'Unknown preceding agreement');
await add('expiry-at-acceptance', 'Expiry is inclusive at acceptance, even for an earlier valid submission.', append(prefix(7), steward, 'contribution.accepted', acceptBody, '2027-01-01T00:00:00.000Z'), 'reject', {}, 'Inactive');
await add('valid-before-expiry', 'Acceptance one millisecond before expiry is permitted.', append(prefix(7), steward, 'contribution.accepted', acceptBody, '2026-12-31T23:59:59.999Z'), 'accept');
const revoked = append(prefix(7), steward, 'delegation.revoked', { delegation, reason: 'Synthetic revocation' });
await add('valid-revoked', 'Revocation preserves pending contribution evidence.', revoked, 'accept');
await add('revoked-acceptance', 'A revoked grant blocks acceptance of earlier work.', append(structuredClone(revoked), steward, 'contribution.accepted', acceptBody), 'reject', {}, 'Inactive');
await add('wrong-revoker', 'Only the original principal may revoke a grant.', append(prefix(5), reviewer, 'delegation.revoked', { delegation, reason: 'Synthetic attempt' }), 'reject', {}, 'Invalid revocation');
const withdrawn = append(prefix(7), reviewer, 'agreement.withdrawn', { agreement, reason: 'Synthetic withdrawal' });
await add('valid-withdrawn', 'Withdrawal is preserved without deleting earlier review.', withdrawn, 'accept');
await add('withdrawn-acceptance', 'Acceptance requires all current consents.', append(structuredClone(withdrawn), steward, 'contribution.accepted', acceptBody), 'reject', {}, 'currently consent');
const reconsented = append(structuredClone(withdrawn), reviewer, 'agreement.consented', { agreement });
await add('valid-reconsented', 'Explicit renewed consent permits acceptance while the grant is active.', append(reconsented, steward, 'contribution.accepted', acceptBody), 'accept');
const changed = append(prefix(7), reviewer, 'contribution.reviewed', { ...reviewBody, decision: 'request_changes' });
await add('valid-changes-requested', 'A later review supersedes an earlier approval.', changed, 'accept');
await add('stale-review', 'An old approval cannot bypass a newer request for changes.', append(structuredClone(changed), steward, 'contribution.accepted', acceptBody), 'reject', {}, 'Exact latest');
const disputed = append(prefix(8), reviewer, 'contribution.disputed', { contribution, reason: 'Synthetic dispute' });
await add('valid-disputed', 'An accepted contribution may be disputed without erasing acceptance.', disputed, 'accept');
await add('terminal-dispute', 'Disputed contributions cannot be accepted again.', append(structuredClone(disputed), steward, 'contribution.accepted', acceptBody), 'reject', {}, 'Exact latest');
await add('noncanonical-time', 'UTC time without milliseconds is noncanonical even when correctly signed.', append(prefix(7), steward, 'contribution.accepted', acceptBody, '2026-01-01T12:01:00Z'), 'reject', {}, 'canonical timestamp');
await add('backward-time', 'Correctly signed event time must not decrease.', append(prefix(7), steward, 'contribution.accepted', acceptBody, '2025-12-31T23:59:59.999Z'), 'reject', {}, 'Backwards');
for (const [id, description, mutate] of [
  ['tampered-body', 'Changing a signed body invalidates its digest.', b => { b.records[0].body.title = 'tampered'; }],
  ['bad-signature', 'A signature from a different event cannot authenticate this event.', b => { b.records[1].signature = b.records[0].signature; }],
  ['reordered-history', 'Records cannot be reordered.', b => { [b.records[1], b.records[2]] = [b.records[2], b.records[1]]; }],
  ['unknown-field', 'Unknown envelope fields are rejected.', b => { b.records[0].extra = true; }],
  ['unsupported-format', 'Unknown bundle versions are rejected.', b => { b.format = 'koinos-bundle/999'; }],
]) { const b = prefix(8); mutate(b); await add(id, description, b, 'reject'); }
await writeFile(new URL('../conformance/manifest.json', import.meta.url), JSON.stringify({
  format: 'koinos-conformance-manifest/1', protocol: 'koinos/0.1', cases: cases.map(id => `cases/${id}.json`),
}, null, 2) + '\n');
console.log(`Generated ${cases.length} portable cases; private keys stayed in memory.`);
