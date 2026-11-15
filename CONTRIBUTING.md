# Contributing

Koinos is an experimental protocol. A change should make collaboration easier to inspect, carry between tools, or govern by explicit agreement.

Use Node.js 22 or newer. There are no package dependencies to install.

```sh
npm run check
npm test
npm run conformance
```

Start with an issue that describes a concrete missing behavior. For protocol changes, include example records, authority rules, compatibility effects, and failure cases. State what a signature proves and what still depends on people or external evidence. Never add real private keys, personal agreements, or private project records to fixtures.

Keep public keys, private keys, and names distinct. A matching signature proves control of a key. A name or declared participant type is not identity verification. A learned preference is never authorization.

Tests should exercise outcomes: denied actions, preserved history, deliberate consent, and round trips between consumers. A schema match alone is not protocol conformance. Keep the browser receipt verifier independent of the Node signer and verifier.

Changes need independent review before merging. Pin the reviewed commit, run checks on the final tree, and document limitations. Major governance, licensing, identity recovery, and economic choices need an explicit maintainer decision. The repository does not yet grant a software license; do not add one on someone else's behalf.

Portable, language-neutral test cases and local adapter instructions are in [conformance/README.md](conformance/README.md). Keep the committed corpus separate from fixture regeneration; see its explicit coverage limits before claiming conformance.
