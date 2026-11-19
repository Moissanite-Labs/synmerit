import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import {
  generateIdentity,
  createRecord,
  createBundle,
  verifyBundle,
  canonicalize,
  digestBytes,
} from "../src/protocol.mjs";
const time = "2026-10-29T00:00:00.000Z";
function fixture() {
  const alice = generateIdentity(),
    bob = generateIdentity(),
    agent = generateIdentity(),
    outsider = generateIdentity();
  let records = [];
  const add = (identity, kind, body, opts = {}) => {
    const r = createRecord({ records, identity, kind, body, time, ...opts });
    records.push(r);
    return r;
  };
  add(alice, "project.created", {
    title: "Project",
    description: "A test",
    participants: [
      { id: alice.id, name: "Alice", kind: "human" },
      { id: bob.id, name: "Bob", kind: "human" },
      { id: agent.id, name: "Agent", kind: "agent" },
    ],
  });
  const agreement = add(alice, "agreement.proposed", {
    title: "Terms",
    uri: "urn:terms:test",
    digest: digestBytes("terms"),
    parties: [alice.id, bob.id],
  }).id;
  const consent = () => {
    add(alice, "agreement.consented", { agreement });
    add(bob, "agreement.consented", { agreement });
  };
  const grant = () =>
    add(alice, "delegation.granted", {
      agent: agent.id,
      agreement,
      scope: ["contribution.submit"],
      expires: "2026-10-30T00:00:00.000Z",
    }).id;
  const submit = (identity = agent, delegation = null) =>
    add(identity, "contribution.submitted", {
      title: "Work",
      summary: "Result",
      artifact: { uri: "urn:artifact:test", digest: digestBytes("result") },
      agreement,
      delegation,
    }).id;
  return {
    alice,
    bob,
    agent,
    outsider,
    records,
    add,
    agreement,
    consent,
    grant,
    submit,
  };
}
test("signed full lifecycle, independent review, acceptance, terminal dispute", () => {
  const f = fixture();
  f.consent();
  const d = f.grant(),
    c = f.submit(f.agent, d);
  const review = f.add(f.bob, "contribution.reviewed", {
    contribution: c,
    decision: "approve",
    note: "Checked",
  }).id;
  f.add(f.alice, "contribution.accepted", { contribution: c, review });
  f.add(f.bob, "contribution.disputed", { contribution: c, reason: "Concern" });
  const s = verifyBundle(createBundle(f.records));
  assert.equal(s.contributions[0].principal, f.alice.id);
  assert.equal(s.contributions[0].status, "disputed");
  assert.throws(() =>
    f.add(f.alice, "contribution.accepted", { contribution: c, review }),
  );
});
test("tampering, signature spoofing, wrong head and project, fork and truncation pins", () => {
  const f = fixture(),
    b = createBundle(f.records);
  for (const mutate of [
    (b) => (b.records[0].body.title = "Changed"),
    (b) => (b.records[1].signature = b.records[0].signature),
    (b) => (b.records[1].actor = f.outsider.id),
    (b) => (b.records[1].extra = true),
    (b) => (b.records[1].sequence = 0),
    (b) => (b.records[1].project = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
  ]) {
    const copy = structuredClone(b);
    mutate(copy);
    assert.throws(() => verifyBundle(copy));
  }
  assert.throws(() => verifyBundle(b, { expectedHead: "0".repeat(64) }));
  assert.throws(() => verifyBundle(b, { expectedProject: "wrong" }));
  assert.throws(() =>
    verifyBundle(createBundle(f.records.slice(0, 1)), {
      expectedHead: b.records.at(-1).id,
    }),
  );
});
test("canonical JSON rejects ambiguous and dangerous representations", () => {
  assert.equal(
    canonicalize({ z: 1, a: [true, null, "x"] }),
    '{"a":[true,null,"x"],"z":1}',
  );
  for (const v of [
    NaN,
    Infinity,
    1.1,
    2 ** 53,
    -0,
    undefined,
    1n,
    new Date(),
    new Array(2),
    "\ud800",
    "\udfff",
    JSON.parse('{"__proto__":1}'),
    JSON.parse('{"constructor":1}'),
    {
      get x() {
        throw Error("getter executed");
      },
    },
    "x".repeat(65537),
  ])
    assert.throws(() => canonicalize(v));
  let deep = {};
  for (let i = 0; i < 22; i++) deep = { deep };
  assert.throws(() => canonicalize(deep));
});
test("unknown event/body fields, bad time, unsupported scope, identity mismatch", () => {
  const f = fixture();
  f.consent();
  for (const [kind, body, opts] of [
    ["unknown", {}, {}],
    ["agreement.consented", { agreement: f.agreement, extra: 1 }, {}],
    [
      "delegation.granted",
      {
        agent: f.agent.id,
        agreement: f.agreement,
        scope: ["everything"],
        expires: "2026-10-30T00:00:00.000Z",
      },
      {},
    ],
    [
      "delegation.granted",
      {
        agent: f.agent.id,
        agreement: f.agreement,
        scope: ["contribution.submit"],
        expires: time,
      },
      {},
    ],
    [
      "agreement.withdrawn",
      { agreement: f.agreement, reason: "x" },
      { time: "2026-10-28T00:00:00.000Z" },
    ],
    [
      "agreement.withdrawn",
      { agreement: f.agreement, reason: "x" },
      { time: "2026-02-30T00:00:00.000Z" },
    ],
  ])
    assert.throws(() => f.add(f.alice, kind, body, opts));
  assert.throws(() =>
    f.add({ ...f.alice, privateKey: f.bob.privateKey }, "agreement.withdrawn", {
      agreement: f.agreement,
      reason: "x",
    }),
  );
});
test("consent blocks delegation and submission; withdrawal blocks acceptance; explicit reconsent restores", () => {
  const f = fixture();
  assert.throws(f.grant);
  f.consent();
  const d = f.grant(),
    c = f.submit(f.agent, d);
  const review = f.add(f.bob, "contribution.reviewed", {
    contribution: c,
    decision: "approve",
    note: "OK",
  }).id;
  f.add(f.bob, "agreement.withdrawn", {
    agreement: f.agreement,
    reason: "Withdraw",
  });
  assert.throws(() => f.submit(f.agent, d));
  assert.throws(() =>
    f.add(f.alice, "contribution.accepted", { contribution: c, review }),
  );
  f.add(f.bob, "agreement.consented", { agreement: f.agreement });
  f.add(f.alice, "contribution.accepted", { contribution: c, review });
});
test("revocation is grantor-only irreversible and blocks existing contribution acceptance", () => {
  const f = fixture();
  f.consent();
  const d = f.grant(),
    c = f.submit(f.agent, d);
  const review = f.add(f.bob, "contribution.reviewed", {
    contribution: c,
    decision: "approve",
    note: "OK",
  }).id;
  assert.throws(() =>
    f.add(f.bob, "delegation.revoked", { delegation: d, reason: "x" }),
  );
  f.add(f.alice, "delegation.revoked", { delegation: d, reason: "x" });
  assert.throws(() =>
    f.add(f.alice, "delegation.revoked", { delegation: d, reason: "x" }),
  );
  assert.throws(() => f.submit(f.agent, d));
  assert.throws(() =>
    f.add(f.alice, "contribution.accepted", { contribution: c, review }),
  );
});
test("expiry is strict at event boundary; time cannot move backwards", () => {
  const f = fixture();
  f.consent();
  const d = f.grant();
  assert.throws(() =>
    f.add(
      f.agent,
      "contribution.submitted",
      {
        title: "x",
        summary: "x",
        artifact: { uri: "urn:x", digest: digestBytes("x") },
        agreement: f.agreement,
        delegation: d,
      },
      { time: "2026-10-30T00:00:00.000Z" },
    ),
  );
});
test("latest independent review controls acceptance and human submissions require null delegation", () => {
  const f = fixture();
  f.consent();
  const c = f.submit(f.alice);
  assert.throws(() =>
    f.add(f.alice, "contribution.reviewed", {
      contribution: c,
      decision: "approve",
      note: "self",
    }),
  );
  const first = f.add(f.bob, "contribution.reviewed", {
    contribution: c,
    decision: "approve",
    note: "OK",
  }).id;
  f.add(f.bob, "contribution.reviewed", {
    contribution: c,
    decision: "request_changes",
    note: "Found issue",
  });
  assert.throws(() =>
    f.add(f.alice, "contribution.accepted", { contribution: c, review: first }),
  );
  const last = f.add(f.bob, "contribution.reviewed", {
    contribution: c,
    decision: "approve",
    note: "Fixed",
  }).id;
  assert.throws(() =>
    f.add(f.alice, "contribution.accepted", { contribution: c, review: first }),
  );
  f.add(f.alice, "contribution.accepted", { contribution: c, review: last });
  assert.throws(() =>
    f.add(f.bob, "contribution.reviewed", {
      contribution: c,
      decision: "approve",
      note: "Late",
    }),
  );
});
test("outsiders, agents, duplicate participants and cross-history references rejected", () => {
  const f = fixture();
  assert.throws(() =>
    f.add(f.outsider, "agreement.consented", { agreement: f.agreement }),
  );
  assert.throws(() =>
    f.add(f.agent, "agreement.consented", { agreement: f.agreement }),
  );
  const other = fixture();
  assert.throws(() =>
    f.add(f.alice, "agreement.consented", { agreement: other.agreement }),
  );
  f.consent();
  assert.throws(() =>
    f.add(f.alice, "agreement.consented", { agreement: f.agreement }),
  );
  assert.throws(() =>
    createRecord({
      records: [],
      identity: f.alice,
      kind: "project.created",
      time,
      body: {
        title: "x",
        description: "x",
        participants: [
          { id: f.alice.id, name: "A", kind: "human" },
          { id: f.alice.id, name: "Again", kind: "human" },
        ],
      },
    }),
  );
});
test("malformed base64 and unsupported bundles fail cleanly", () => {
  const f = fixture();
  for (const signature of [
    "!",
    "A".repeat(86) + "=",
    "A".repeat(85) + "B",
    "",
  ]) {
    const b = createBundle(f.records);
    b.records[0].signature = signature;
    assert.throws(() => verifyBundle(b), Error);
  }
  for (const b of [
    { format: "future", records: f.records },
    { format: "koinos-bundle/0.1", records: [] },
    { format: "koinos-bundle/0.1", records: f.records, secret: "x" },
  ])
    assert.throws(() => verifyBundle(b), Error);
});
test("canonicalization never invokes array accessors or accepts hidden metadata", () => {
  const a = [1];
  Object.defineProperty(a, "0", {
    get() {
      throw Error("executed");
    },
    enumerable: true,
  });
  assert.throws(() => canonicalize(a), /Invalid array property/);
  const b = [1];
  b[Symbol("metadata")] = 2;
  assert.throws(() => canonicalize(b));
  const c = { x: 1 };
  Object.defineProperty(c, "hidden", { value: 2 });
  assert.throws(() => canonicalize(c));
  const d = [];
  d.foo = 1;
  assert.throws(() => canonicalize(d));
});
test("bounded structures, missing histories, forward references and unauthorised proposal rejected", () => {
  assert.throws(() => canonicalize(Array(10001).fill(null)), /oversized array/);
  assert.throws(() =>
    verifyBundle({
      format: "koinos-bundle/0.1",
      records: Array(10001).fill(null),
    }),
  );
  const f = fixture();
  assert.throws(() =>
    f.add(f.bob, "agreement.proposed", {
      title: "Other",
      uri: "urn:other",
      digest: digestBytes("other"),
      parties: [f.bob.id],
    }),
  );
  assert.throws(() =>
    f.add(f.alice, "agreement.consented", { agreement: "f".repeat(64) }),
  );
  assert.throws(() =>
    createRecord({
      records: [],
      identity: f.alice,
      kind: "agreement.consented",
      body: { agreement: f.agreement },
      time,
    }),
  );
});
test("delegation cannot change principal, agent, agreement or introduce human delegation", () => {
  const f = fixture();
  f.consent();
  const d = f.grant();
  assert.throws(() => f.submit(f.alice, d));
  assert.throws(() => f.submit(f.outsider, d));
  const another = f.add(f.alice, "agreement.proposed", {
    title: "New",
    uri: "urn:new",
    digest: digestBytes("new"),
    parties: [f.alice.id],
  }).id;
  f.add(f.alice, "agreement.consented", { agreement: another });
  assert.throws(() =>
    f.add(f.agent, "contribution.submitted", {
      title: "Cross agreement",
      summary: "x",
      artifact: { uri: "urn:x", digest: digestBytes("x") },
      agreement: another,
      delegation: d,
    }),
  );
  const c = f.submit(f.agent, d);
  assert.throws(() =>
    f.add(f.alice, "contribution.reviewed", {
      contribution: c,
      decision: "approve",
      note: "Principal review",
    }),
  );
  assert.throws(() =>
    f.add(f.bob, "contribution.disputed", {
      contribution: c,
      reason: "Too soon",
    }),
  );
});
test("small-order actor keys are rejected before signature verification", async () => {
  const { verifyCryptography } = await import("../web/verify.mjs");
  const p = 2n ** 255n - 19n,
    order8 =
      2707385501144840649318225287225658788936804267575313519463743609750303402022n;
  const encodeY = (y, sign) => {
    const b = Buffer.alloc(32);
    for (let i = 0; i < 32; i++, y >>= 8n) b[i] = Number(y & 255n);
    b[31] |= sign << 7;
    return b;
  };
  // All eight torsion points, both sign bits, and noncanonical y = p, p + 1.
  const weak = [0n, 1n, p - 1n, order8, p - order8, p, p + 1n].flatMap((y) =>
    [0, 1].map((sign) => encodeY(y, sign)),
  );
  // 1, p - 1 and 0 are the y of the order 1, 2 and 4 points. Check the order-8
  // constant algebraically: OpenSSL builds differ on accepting these forgeries.
  const pow = (b, e) => {
    let r = 1n;
    for (b %= p; e; e >>= 1n, b = (b * b) % p) if (e & 1n) r = (r * b) % p;
    return r;
  };
  const d = ((p - 121665n) * pow(121666n, p - 2n)) % p;
  for (const y of [order8, p - order8]) {
    const y2 = (y * y) % p;
    assert.equal((d * y2 * y2 + 2n * y2 - 1n) % p, 0n, "double has y = 0");
    const x2 = ((y2 - 1n) * pow(d * y2 + 1n, p - 2n)) % p;
    assert.equal(pow(x2, (p - 1n) / 2n), 1n, "point is on the curve");
  }
  // R = identity, S = 0 verifies for a small-order key whenever [k]A is the identity.
  const forged = Buffer.concat([encodeY(1n, 0), Buffer.alloc(32)]);
  for (const raw of weak) {
    const actor = "koinos:ed25519:" + raw.toString("base64url");
    const unsigned = {
      protocol: "koinos/0.1",
      project: randomUUID(),
      sequence: 0,
      previous: null,
      time,
      actor,
      kind: "project.created",
      body: {
        title: "Forged",
        description: "No private key",
        participants: [{ id: actor, name: "Anyone", kind: "human" }],
      },
    };
    const id = digestBytes(canonicalize(unsigned));
    const bundle = {
      format: "koinos-bundle/0.1",
      records: [{ ...unsigned, id, signature: forged.toString("base64url") }],
    };
    assert.throws(() => verifyBundle(bundle), /Small-order actor key/);
    await assert.rejects(verifyCryptography(bundle), /Small-order public key/);
    const alice = generateIdentity();
    assert.throws(
      () =>
        createRecord({
          records: [],
          identity: alice,
          kind: "project.created",
          time,
          body: {
            title: "Project",
            description: "Weak participant",
            participants: [
              { id: alice.id, name: "Alice", kind: "human" },
              { id: actor, name: "Weak", kind: "agent" },
            ],
          },
        }),
      /Small-order actor key/,
    );
  }
});
