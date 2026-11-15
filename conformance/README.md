# Portable 0.1 conformance vectors

A bounded interoperability corpus for [issue #14](https://github.com/Moissanite-Labs/synmerit/issues/14), not a new protocol or proof of general conformance. The cases are plain JSON so a second implementation can consume them without executing the reference implementation or JavaScript fixture builders.

## Run

```
node scripts/verify-vectors.mjs
```

This checks all committed files, accept/reject outcomes, and exact derived state for positive cases. It is also run by `npm test`. Existing dynamic checks remain in `npm run conformance`.

For an explicitly selected, trusted local implementation exposing `verifyBundle(bundle, options)` (sync or async):

```
node scripts/verify-vectors.mjs /path/to/local/adapter.mjs
```

An adapter is executable code, not untrusted fixture data. The runner does not discover adapters, install dependencies, or fetch fixture URIs. A maintainer is responsible for selecting trusted adapter code. Other languages should read `manifest.json` and implement the consumer steps below directly.

## Consumer contract

1. Load the manifest with format `koinos-conformance-manifest/1` and protocol `koinos/0.1`. Its `cases` array names every case under `cases/`.
2. Read each UTF-8 JSON file. Its format is `koinos-conformance/1`; `id` is its filename without `.json`; `description` describes the targeted rule.
3. Pass `bundle` unchanged to your verifier with the separate `options` object. Missing pins are absent, not null. Do not add, remove, normalize, repair or re-sign bundle fields.
4. For `expected.outcome: "accept"`, compare the complete returned JSON projection with `expected.state`. Object key order is irrelevant; array order, strings, integers, nulls and field presence are significant.
5. For `expected.outcome: "reject"`, verification must fail. Never treat an invalid record as an ignored event or return a partial successful history.
6. Report each case and mismatch. Passing this corpus is evidence only for these cases, not proof of production safety or live product integration.

These are JSON **values**, not raw parser tests. Whitespace/key ordering in the case file is not signed: record ids bind canonical JSON as specified by the protocol. Duplicate-key source documents, malformed UTF-8 and parser-specific representations are not covered. Diagnostic text is deliberately absent from the portable expectation. Stable error codes remain separate work under #14; local regression tests check current messages only to establish that semantic negative cases reach their intended rule.

## Coverage

36 cases: 14 accepted projections and 22 rejections. Positive histories cover all ten event kinds, including withdrawal/reconsent, revocation, latest review changes and terminal dispute. Negative histories cover principal/agent review, non-steward acceptance, duplicate/agent consent, nonpreceding references, inclusive expiry, revoked or withdrawn acceptance, wrong revoker, stale review, terminal dispute, noncanonical/backward time, exact head/project pins, truncation, digest/signature tampering, reordering, unknown fields and unsupported version.

The expiry pair differs at the exact acceptance boundary: one millisecond before expiry accepts, equality rejects. The forward-reference case refers to an agreement absent from the supplied prefix but present later in the original synthetic lifecycle. Unpinned shorter valid histories intentionally accept; trusted pins belong outside the bundle.

Positive expected states were produced from the reference projection, then checked against Exofab's independent implementation at PR #6 head `9530c806c813ca017feb42c6c048e9f4b0b44f10`. Both implementations agreed on all 36 cases, including exact state on the 14 positives. This is a local source-level comparison, not an installed application, shared service, or venture handoff acceptance test. No sibling source was copied or vendored; the repositories still have no software license grant.

## Fixture authoring

`node scripts/generate-vectors.mjs` intentionally replaces the fixture set with freshly generated synthetic keys and signatures. Private keys exist only in process memory and are never written. This is not a byte-reproducible generator: normal checks consume committed bytes and never regenerate them. Review the data diff and rerun both implementations after intentional regeneration.

Semantic negative cases are correctly signed, constructed without the signer's policy guard, so they exercise verifier state/authority rules rather than incidental signature failures. Tests independently verify their signature envelope with Node crypto and verify the intended rejection point. Positive state assertions additionally check attribution, withdrawal, revocation, acceptance and dispute preservation.

All actors and projects are fictional. URI values are inert evidence references and must not be fetched automatically. Signatures establish no real person's consent, legal ownership, funding, wallet authority or payment settlement.

## Remaining work

This is additive work toward #14, not closure of it. Still missing: stable verifier error codes, exhaustive authority-rule and resource-limit boundary vectors, malformed input/parser vectors, cross-language runners, and the small-order-key suite dependent on #9/#10. No accepted vector uses a small-order key, and the corpus must not imply that the main-branch verifier fixes that open issue. The separate 0.2 graph/ownership proposal in #6 is not covered.
