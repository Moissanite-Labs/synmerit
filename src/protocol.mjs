import {
  generateKeyPairSync,
  createPublicKey,
  createPrivateKey,
  sign,
  verify,
  createHash,
  randomUUID,
} from "node:crypto";

export const LIMITS = Object.freeze({
  records: 10000,
  bytes: 16 * 1024 * 1024,
  depth: 20,
  string: 65536,
  array: 10000,
  participants: 1000,
});
const fail = (message) => {
  throw new Error(message);
};
const plain = (v) =>
  v !== null &&
  typeof v === "object" &&
  (Object.getPrototypeOf(v) === Object.prototype ||
    Object.getPrototypeOf(v) === null);
const unicode = (s) =>
  !/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(
    s,
  );
export function canonicalize(value) {
  let nodes = 0;
  function walk(v, depth) {
    if (++nodes > 200000 || depth > LIMITS.depth)
      fail("Canonical JSON complexity limit exceeded");
    if (v === null || typeof v === "boolean") return JSON.stringify(v);
    if (typeof v === "string") {
      if (v.length > LIMITS.string || !unicode(v))
        fail("Invalid or oversized Unicode string");
      return JSON.stringify(v);
    }
    if (typeof v === "number") {
      if (!Number.isSafeInteger(v) || Object.is(v, -0))
        fail("Only safe integers are allowed");
      return String(v);
    }
    if (Array.isArray(v)) {
      if (v.length > LIMITS.array || Reflect.ownKeys(v).length !== v.length + 1)
        fail("Invalid or oversized array");
      const items = [];
      for (let i = 0; i < v.length; i++) {
        const d = Object.getOwnPropertyDescriptor(v, String(i));
        if (!d || !d.enumerable || !("value" in d))
          fail("Invalid array property");
        items.push(walk(d.value, depth + 1));
      }
      return "[" + items.join(",") + "]";
    }
    if (!plain(v)) fail("Only plain JSON objects are allowed");
    const keys = Reflect.ownKeys(v);
    if (
      keys.some(
        (k) =>
          typeof k !== "string" ||
          ["__proto__", "prototype", "constructor"].includes(k),
      )
    )
      fail("Forbidden object key");
    return (
      "{" +
      keys
        .sort()
        .map((k) => {
          const d = Object.getOwnPropertyDescriptor(v, k);
          if (!d.enumerable || !("value" in d))
            fail("Only enumerable data properties are allowed");
          return walk(k, depth + 1) + ":" + walk(d.value, depth + 1);
        })
        .join(",") +
      "}"
    );
  }
  const result = walk(value, 0);
  if (Buffer.byteLength(result) > LIMITS.bytes)
    fail("JSON byte limit exceeded");
  return result;
}
export function digestBytes(bytes) {
  if (typeof bytes !== "string" && !Buffer.isBuffer(bytes))
    fail("Digest input must be string or Buffer");
  return createHash("sha256").update(bytes).digest("hex");
}
const enc = (b) => b.toString("base64url");
function decode(s, length) {
  if (typeof s !== "string" || !/^[A-Za-z0-9_-]+$/.test(s))
    fail("Invalid base64url");
  const b = Buffer.from(s, "base64url");
  if (b.length !== length || enc(b) !== s) fail("Noncanonical base64url");
  return b;
}
// Ed25519 points of order 1, 2, 4 or 8 verify signatures made without a private
// key. A point and its negation share y, so y (sign bit cleared, reduced mod p)
// identifies all eight: 0, 1, p - 1 and the two order-8 values.
const FIELD = 2n ** 255n - 19n;
const ORDER8_Y =
  2707385501144840649318225287225658788936804267575313519463743609750303402022n;
const SMALL_ORDER_Y = new Set([0n, 1n, FIELD - 1n, ORDER8_Y, FIELD - ORDER8_Y]);
function smallOrder(raw) {
  let y = 0n;
  for (let i = 31; i >= 0; i--)
    y = (y << 8n) | BigInt(i === 31 ? raw[i] & 0x7f : raw[i]);
  return SMALL_ORDER_Y.has(y % FIELD);
}
function publicKey(id) {
  if (typeof id !== "string" || !id.startsWith("koinos:ed25519:"))
    fail("Invalid actor identity");
  const raw = decode(id.slice(15), 32);
  if (smallOrder(raw)) fail("Small-order actor key");
  return createPublicKey({
    key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]),
    format: "der",
    type: "spki",
  });
}
export function generateIdentity() {
  const { publicKey: pub, privateKey } = generateKeyPairSync("ed25519");
  return {
    id:
      "koinos:ed25519:" +
      enc(pub.export({ format: "der", type: "spki" }).subarray(-32)),
    privateKey: privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
  };
}
const hash = (x) => typeof x === "string" && /^[0-9a-f]{64}$/.test(x);
const uuid = (x) =>
  typeof x === "string" &&
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(
    x,
  );
function fields(o, names) {
  if (
    !plain(o) ||
    Object.keys(o).sort().join("|") !== [...names].sort().join("|")
  )
    fail("Unexpected or missing fields");
}
function str(x, label, max = 8192) {
  if (typeof x !== "string" || !x.trim() || x.length > max)
    fail(`Invalid ${label}`);
}
function timestamp(x) {
  if (
    typeof x !== "string" ||
    !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(x) ||
    !Number.isFinite(Date.parse(x)) ||
    new Date(x).toISOString() !== x
  )
    fail("Invalid canonical timestamp");
}
function uri(x) {
  str(x, "URI", 4096);
  if (!/^[A-Za-z][A-Za-z0-9+.-]*:[^\s]+$/.test(x)) fail("Invalid URI");
}
export function verifyBundle(bundle, { expectedHead, expectedProject } = {}) {
  canonicalize(bundle);
  fields(bundle, ["format", "records"]);
  if (bundle.format !== "koinos-bundle/0.1") fail("Unsupported bundle format");
  if (
    !Array.isArray(bundle.records) ||
    bundle.records.length < 1 ||
    bundle.records.length > LIMITS.records
  )
    fail("History must contain 1..10000 records");
  const state = {
    project: null,
    participants: [],
    agreements: [],
    delegations: [],
    contributions: [],
    head: null,
    count: 0,
  };
  const participants = new Map(),
    agreements = new Map(),
    delegations = new Map(),
    contributions = new Map();
  let lastTime = "";
  for (const r of bundle.records) {
    fields(r, [
      "protocol",
      "project",
      "sequence",
      "previous",
      "time",
      "actor",
      "kind",
      "body",
      "id",
      "signature",
    ]);
    if (r.protocol !== "koinos/0.1") fail("Unsupported protocol");
    if (!uuid(r.project) || (state.project && r.project !== state.project.id))
      fail("Invalid or cross-project identifier");
    if (r.sequence !== state.count || r.previous !== state.head)
      fail("Broken sequence or previous link (fork)");
    timestamp(r.time);
    if (r.time < lastTime) fail("Backwards event time");
    const { id, signature, ...unsigned } = r;
    if (!hash(id) || digestBytes(canonicalize(unsigned)) !== id)
      fail("Record digest mismatch");
    if (
      !verify(
        null,
        Buffer.from("koinos/0.1\n" + id),
        publicKey(r.actor),
        decode(signature, 64),
      )
    )
      fail("Invalid signature");
    const b = r.body;
    const person = participants.get(r.actor);
    const human = () => {
      if (!person || person.kind !== "human")
        fail("Human participant required");
    };
    const steward = () => {
      human();
      if (r.actor !== state.project.steward) fail("Steward required");
    };
    const agreement = (id) => {
      const a = agreements.get(id);
      if (!a) fail("Unknown preceding agreement");
      return a;
    };
    const party = (a) => {
      human();
      if (!a.parties.includes(r.actor)) fail("Agreement party required");
    };
    const consented = (a) => {
      if (!a.parties.every((p) => a.consents.includes(p)))
        fail("All parties must currently consent");
    };
    const grantActive = (d, a, actor) => {
      if (
        !d ||
        d.agent !== actor ||
        d.agreement !== a.id ||
        d.revoked ||
        r.time >= d.expires ||
        !a.consents.includes(d.principal) ||
        !d.scope.includes("contribution.submit")
      )
        fail("Inactive or mismatched delegation");
    };
    const contribution = (id) => {
      const c = contributions.get(id);
      if (!c) fail("Unknown preceding contribution");
      return c;
    };
    if (!state.count && r.kind !== "project.created")
      fail("Genesis must create project");
    switch (r.kind) {
      case "project.created": {
        if (state.count) fail("Duplicate project creation");
        fields(b, ["title", "description", "participants"]);
        str(b.title, "title", 256);
        str(b.description, "description");
        if (
          !Array.isArray(b.participants) ||
          !b.participants.length ||
          b.participants.length > LIMITS.participants
        )
          fail("Invalid participants");
        for (const p of b.participants) {
          fields(p, ["id", "name", "kind"]);
          publicKey(p.id);
          str(p.name, "name", 256);
          if (!["human", "agent"].includes(p.kind) || participants.has(p.id))
            fail("Invalid or duplicate participant");
          const copy = { ...p };
          participants.set(p.id, copy);
          state.participants.push(copy);
        }
        if (participants.get(r.actor)?.kind !== "human")
          fail("Genesis actor must be listed human");
        state.project = {
          id: r.project,
          title: b.title,
          description: b.description,
          steward: r.actor,
        };
        break;
      }
      case "agreement.proposed": {
        fields(b, ["title", "uri", "digest", "parties"]);
        steward();
        str(b.title, "title", 256);
        uri(b.uri);
        if (!hash(b.digest)) fail("Invalid terms digest");
        if (
          !Array.isArray(b.parties) ||
          !b.parties.length ||
          new Set(b.parties).size !== b.parties.length ||
          b.parties.some((p) => participants.get(p)?.kind !== "human")
        )
          fail("Invalid human parties");
        const a = { id, ...b, parties: [...b.parties], consents: [] };
        agreements.set(id, a);
        state.agreements.push(a);
        break;
      }
      case "agreement.consented":
      case "agreement.withdrawn": {
        fields(
          b,
          r.kind === "agreement.consented"
            ? ["agreement"]
            : ["agreement", "reason"],
        );
        const a = agreement(b.agreement);
        party(a);
        if (r.kind === "agreement.consented") {
          if (a.consents.includes(r.actor)) fail("Duplicate consent");
          a.consents.push(r.actor);
        } else {
          str(b.reason, "reason");
          if (!a.consents.includes(r.actor))
            fail("No active consent to withdraw");
          a.consents = a.consents.filter((p) => p !== r.actor);
        }
        break;
      }
      case "delegation.granted": {
        fields(b, ["agent", "agreement", "scope", "expires"]);
        const a = agreement(b.agreement);
        party(a);
        consented(a);
        if (participants.get(b.agent)?.kind !== "agent")
          fail("Agent participant required");
        if (
          !Array.isArray(b.scope) ||
          b.scope.length !== 1 ||
          b.scope[0] !== "contribution.submit"
        )
          fail("Unsupported delegation scope");
        timestamp(b.expires);
        if (b.expires <= r.time) fail("Delegation expiry must follow grant");
        const d = {
          id,
          ...b,
          scope: [...b.scope],
          principal: r.actor,
          revoked: false,
        };
        delegations.set(id, d);
        state.delegations.push(d);
        break;
      }
      case "delegation.revoked": {
        fields(b, ["delegation", "reason"]);
        str(b.reason, "reason");
        const d = delegations.get(b.delegation);
        if (!d || d.principal !== r.actor || d.revoked)
          fail("Invalid revocation or grantor");
        d.revoked = true;
        break;
      }
      case "contribution.submitted": {
        fields(b, ["title", "summary", "artifact", "agreement", "delegation"]);
        str(b.title, "title", 256);
        str(b.summary, "summary");
        fields(b.artifact, ["uri", "digest"]);
        uri(b.artifact.uri);
        if (!hash(b.artifact.digest)) fail("Invalid artifact digest");
        const a = agreement(b.agreement);
        consented(a);
        let principal = r.actor;
        if (person?.kind === "human") {
          party(a);
          if (b.delegation !== null)
            fail("Human submission requires null delegation");
        } else {
          const d = delegations.get(b.delegation);
          grantActive(d, a, r.actor);
          principal = d.principal;
        }
        const c = {
          id,
          ...b,
          artifact: { ...b.artifact },
          actor: r.actor,
          principal,
          status: "submitted",
          reviews: [],
          acceptance: null,
          dispute: null,
        };
        contributions.set(id, c);
        state.contributions.push(c);
        break;
      }
      case "contribution.reviewed": {
        fields(b, ["contribution", "decision", "note"]);
        const c = contribution(b.contribution);
        party(agreement(c.agreement));
        str(b.note, "note");
        if (
          !["submitted", "changes_requested", "reviewed"].includes(c.status) ||
          r.actor === c.actor ||
          r.actor === c.principal
        )
          fail("Review must be independent and pending");
        if (!["approve", "request_changes"].includes(b.decision))
          fail("Invalid review decision");
        c.reviews.push({
          id,
          actor: r.actor,
          decision: b.decision,
          note: b.note,
        });
        c.status = b.decision === "approve" ? "reviewed" : "changes_requested";
        break;
      }
      case "contribution.accepted": {
        fields(b, ["contribution", "review"]);
        steward();
        const c = contribution(b.contribution),
          a = agreement(c.agreement);
        consented(a);
        if (
          c.status !== "reviewed" ||
          c.reviews.at(-1)?.id !== b.review ||
          c.reviews.at(-1)?.decision !== "approve"
        )
          fail("Exact latest approving review required");
        if (c.delegation !== null)
          grantActive(delegations.get(c.delegation), a, c.actor);
        c.status = "accepted";
        c.acceptance = { id, actor: r.actor, review: b.review };
        break;
      }
      case "contribution.disputed": {
        fields(b, ["contribution", "reason"]);
        str(b.reason, "reason");
        const c = contribution(b.contribution);
        party(agreement(c.agreement));
        if (c.status !== "accepted")
          fail("Only accepted contribution can be disputed");
        c.status = "disputed";
        c.dispute = { id, actor: r.actor, reason: b.reason };
        break;
      }
      default:
        fail("Unsupported event kind");
    }
    state.head = id;
    state.count++;
    lastTime = r.time;
  }
  if (expectedHead !== undefined && expectedHead !== state.head)
    fail("Expected head mismatch");
  if (expectedProject !== undefined && expectedProject !== state.project.id)
    fail("Expected project mismatch");
  return state;
}
export function createBundle(records) {
  const bundle = { format: "koinos-bundle/0.1", records };
  verifyBundle(bundle);
  return JSON.parse(canonicalize(bundle));
}
export function summarize(bundle) {
  return verifyBundle(bundle);
}
export function createRecord({
  records,
  identity,
  kind,
  body,
  time = new Date().toISOString(),
  project,
}) {
  if (!Array.isArray(records)) fail("Records array required");
  if (records.length) verifyBundle({ format: "koinos-bundle/0.1", records });
  if (!identity || typeof identity.privateKey !== "string")
    fail("Signing identity required");
  const key = createPrivateKey(identity.privateKey);
  if (key.asymmetricKeyType !== "ed25519") fail("Ed25519 private key required");
  const derived =
    "koinos:ed25519:" +
    enc(
      createPublicKey(key)
        .export({ format: "der", type: "spki" })
        .subarray(-32),
    );
  if (derived !== identity.id) fail("Signing identity key mismatch");
  const unsigned = {
    protocol: "koinos/0.1",
    project: project ?? records[0]?.project ?? randomUUID(),
    sequence: records.length,
    previous: records.at(-1)?.id ?? null,
    time,
    actor: identity.id,
    kind,
    body,
  };
  const id = digestBytes(canonicalize(unsigned));
  const record = {
    ...unsigned,
    id,
    signature: enc(sign(null, Buffer.from("koinos/0.1\n" + id), key)),
  };
  verifyBundle({ format: "koinos-bundle/0.1", records: [...records, record] });
  return JSON.parse(canonicalize(record));
}
