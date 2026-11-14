# Koinos

Koinos is a protocol for people and agents to cooperate across independent projects. It records who contributed, what evidence was reviewed, and which agreements and permissions applied. Projects can carry that history between tools without depending on one organization.

This repository is `Moissanite-Labs/synmerit`, renamed from `koinos`; the old address redirects here. The organization profile lists the project as Synmerit. The protocol and its identifiers (`koinos/0.1`, `koinos-bundle/0.1`, `koinos:ed25519:` keys) keep the Koinos name, so records made with this version stay valid.

**Version 0.1 is an experimental reference implementation.** It includes a signed record format, a local command-line tool, and a visual workbench. It does not operate an economic network or transfer money. The [founding vision](docs/vision.md) is preserved in full.

## Try it locally

Requires **Node.js 22 or newer**. No dependencies, account, API key, or package installation is required.

```sh
git clone https://github.com/Moissanite-Labs/synmerit.git
cd synmerit
npm start
```

Open **http://127.0.0.1:4173**. The workbench shows a fictional project moving from an agreement through consent, a scoped agent task, human review, acceptance, and dispute. Select a stage to inspect its records. Import a bundle to check its signatures and protocol rules, or export the current history to another tool.

The sample roles are simulated. Their signatures are demonstration records, not real people's consent. All bundle contents are visible to recipients.

```sh
# Generate a fresh signed example and inspect it.
npm run demo -- /tmp/koinos-example.json
node src/cli.mjs inspect /tmp/koinos-example.json
node src/cli.mjs verify /tmp/koinos-example.json

# Import into a separate local store, preserving signatures and attribution.
node src/cli.mjs import /tmp/koinos-second-store.json /tmp/koinos-example.json
node src/cli.mjs pin /tmp/koinos-second-store.json

# Run the checks.
npm run check
npm test
npm run conformance
```

Output files are created exclusively. Use a new filename when repeating the example. [CLI and SDK examples](examples/README.md) explain authoring with your own keys, importing updates, and retaining a trusted history checkpoint.

## What works

| Capability | Behavior |
| --- | --- |
| Signed project history | Ed25519 signatures, content hashes, ordered links, explicit protocol version, strict validation. |
| Agreement and consent | References to exact terms digests; each party signs its own consent and can record withdrawal. |
| Scoped agent authority | A named agent can submit work for a person under one agreement until revocation or expiry. |
| Contribution provenance | Actor, human principal, artifact digest, agreement, and grant remain linked. |
| Human review and acceptance | Independent review of the exact submission; acceptance references the latest approving review. |
| Visible disagreement | Disputes remain in history and mark the accepted contribution as contested. |
| Portable records | Complete JSON bundles round-trip through the CLI and browser without rewriting signatures. |
| Conflict protection | Local storage rejects a shortened or divergent history instead of replacing accepted records. |
| Independent receipt verification | The browser uses WebCrypto; the conformance consumer independently checks hashes and signatures. |

The same rules apply to people and agents outside the Exo ecosystem. The example illustrates Exofab-style human collaboration and Synbios-style agent work. It does not connect to either service.

## Where trust remains

A signature proves control of a key, not identity, truth, or legal effect. Names and human/agent roles are declarations. Artifact and agreement contents are not fetched or independently checked. Signed times are assertions, not trusted timestamps.

A complete valid history may still omit a later action unknown to the recipient. Keep a trusted project and latest head separately. The reference detects conflicting histories but does not solve distributed consensus. Bundles are not encrypted, and exporting one shares every record. Read the [security and trust model](SECURITY.md) before using personal data.

## Build on it

- [Protocol specification](docs/protocol.md): wire format, signatures, event rules, and compatibility.
- [Architecture](docs/architecture.md): authority, consumers, and transport boundaries.
- [Example and SDK](examples/README.md): a runnable workflow and file exchange.
- [Structural JSON Schema](schemas/bundle-0.1.schema.json): tooling support, used alongside semantic verification.
- [Roadmap](docs/roadmap.md): federation, privacy, key recovery, real adapters, and separately agreed economics.
- [Contributing](CONTRIBUTING.md): tests, review, and protocol changes.

Koinos does not incorporate entities, establish ownership, execute payments, issue a currency or token, or determine legal rights. Economic arrangements remain choices for the participants, with separate agreements and review. Licensing and long-term governance remain open; no software license has been selected for this reference.
