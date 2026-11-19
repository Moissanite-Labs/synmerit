# Koinos 0.1 protocol

This experimental reference implements the [implementation contract](implementation-contract.md). It is a single-project ordered event history with explicit human consent and narrow, revocable agent authority. It does not establish legal identity, legal consent, truth, intellectual-property ownership, or network governance.

## Encoding and verification

A bundle has exactly `format: "koinos-bundle/0.1"` and `records`. Every record contains exactly `protocol`, `project`, `sequence`, `previous`, `time`, `actor`, `kind`, `body`, `id`, and `signature`. Unknown fields and unsupported versions fail closed. Project identifiers are lowercase UUIDs. Genesis is sequence zero with null previous; subsequent records increment sequence and point to the immediately preceding record hash. All references resolve to earlier records in the same project.

Canonical JSON sorts object keys by ECMAScript UTF-16 order. Arrays retain order. Only null, booleans, valid Unicode strings, safe integer numbers, arrays and plain objects are supported. Negative zero, lone surrogates, sparse arrays, accessors, symbol keys, non-enumerable object fields, and prototype-sensitive keys (`__proto__`, `constructor`, `prototype`) are rejected. JSON text import must reject duplicate object keys before parsing if the importing application needs to distinguish duplicate-key source documents; the core takes parsed JSON values and cannot recover source spelling or duplicated keys discarded by a parser.

The record id is SHA-256 of canonical JSON for the envelope excluding `id` and `signature`. An Ed25519 signature covers UTF-8 bytes of `koinos/0.1`, newline, and the lowercase hex record id. Public identity is `koinos:ed25519:` followed by canonical unpadded base64url encoding of the raw 32-byte public key. Signatures use the same encoding for 64 bytes. Noncanonical encodings fail. Keys that encode one of the eight small-order Ed25519 points also fail, in any encoding: a signature for them can be produced without a private key. Private keys use PKCS8 PEM and never belong in a bundle.

Timestamps must be exactly UTC `YYYY-MM-DDTHH:mm:ss.sssZ`, valid calendar dates, and nondecreasing. Delegations expire at their expiry timestamp, not after it. Time is an actor's signed assertion: an offline verifier cannot establish real creation time, prevent backdating, or guarantee that a signed history includes every event.

## Authority and state

Genesis lists immutable participants and declares them human or agent. Its listed human signer becomes steward. A key's declared kind is not verified personhood. Only the steward proposes terms; the terms record fixes a URI, SHA-256 digest and human parties. The software does not fetch terms. Each party signs explicit consent to that precise record. Duplicate active consent fails. A consenting party may withdraw with a reason and later explicitly consent again.

Delegation requires every party's current consent. A human party grants a named agent only `contribution.submit` for a particular agreement, with future expiry. There is no subdelegation. Only the grantor can revoke; revocation is irreversible. An agent's attribution includes both its signing identity and human principal. Human submissions require null delegation. Submission and acceptance require all parties' current consent; agent grants must also remain unrevoked and unexpired at both events.

An independent human party may review a pending contribution; neither submission actor nor principal may review it. A review may approve or request changes. The latest review controls state. Only the steward can accept, citing the exact latest approving review. Accepted contributions cannot be reviewed or accepted again. A human party can dispute an accepted contribution with a reason. Disputed is terminal in 0.1. Withdrawal blocks delegation, submission and acceptance; reviews and disputes remain available so parties can record concerns. Consent must be restored before acceptance. Withdrawal and revocation do not rewrite previous acceptance or erase history.

`verifyBundle` returns derived JSON state; `summarize` is the same verified projection. `createRecord` verifies existing history and the proposed extension before returning it. `createBundle` verifies and returns a detached canonical JSON copy. Optional expected-project and expected-head pins must match exactly; a head pin does not mean “any descendant of this head.” Complete unpinned shorter histories can verify: retain and compare a trusted head outside the bundle to detect rollback. Competing valid extensions are forks requiring human resolution.

## Resource and trust boundaries

Limits: 10,000 records; 16 MiB canonical JSON bytes; 20 recursive levels; 200,000 visited JSON values per canonicalization; 65,536 UTF-16 code units per general string; 10,000 array entries; 1,000 participants. Titles and participant names are limited to 256 code units, ordinary descriptive fields to 8,192, and URIs to 4,096. Text fields must contain non-whitespace characters. URI syntax requires a scheme and non-whitespace remainder; schemes are not an execution allowlist. Consumers must treat URIs and text as untrusted data and never execute or automatically fetch them.

Bounds apply after parsed values reach the core. Importers must bound input bytes before parsing. Appending repeatedly replays complete history; this reference favors simple verification over large-history throughput. There is no encryption or access control: export reveals every record. Partial or redacted bundles are unsupported. Artifact digests bind references; software does not verify external artifact bytes. Protocol signatures prove control of a key, and demonstration keys do not represent real people's consent.
