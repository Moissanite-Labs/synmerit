// Independent WebCrypto consumer. Does not import the Node protocol implementation.
const enc = new TextEncoder();
function canonical(value) {
  if (value === null || typeof value === "boolean")
    return JSON.stringify(value);
  if (typeof value === "string") {
    for (let i = 0; i < value.length; i++) {
      const c = value.charCodeAt(i);
      if (c >= 0xd800 && c <= 0xdbff) {
        const n = value.charCodeAt(++i);
        if (!(n >= 0xdc00 && n <= 0xdfff)) throw Error("Malformed Unicode");
      } else if (c >= 0xdc00 && c <= 0xdfff) throw Error("Malformed Unicode");
    }
    return JSON.stringify(value);
  }
  if (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    !Object.is(value, -0)
  )
    return String(value);
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  if (value && Object.getPrototypeOf(value) === Object.prototype)
    return (
      "{" +
      Object.keys(value)
        .sort()
        .map((k) => canonical(k) + ":" + canonical(value[k]))
        .join(",") +
      "}"
    );
  throw Error("Unsupported canonical value");
}
function bytes(s) {
  if (!/^[A-Za-z0-9_-]+$/.test(s)) throw Error("Invalid base64url");
  const b = Uint8Array.from(
    atob(s.replace(/-/g, "+").replace(/_/g, "/")),
    (c) => c.charCodeAt(0),
  );
  if (
    btoa(String.fromCharCode(...b))
      .replace(/=/g, "")
      .replace(/\+/g, "-")
      .replace(/\//g, "_") !== s
  )
    throw Error("Noncanonical base64url");
  return b;
}
// Small-order Ed25519 points accept forged signatures. Each is identified by its
// y-coordinate (little-endian, sign bit cleared, reduced mod p).
const p = (1n << 255n) - 19n;
const order8 =
  2707385501144840649318225287225658788936804267575313519463743609750303402022n;
const weakY = [0n, 1n, p - 1n, order8, p - order8];
function weakKey(raw) {
  const big = Array.from(raw).reverse();
  big[0] &= 0x7f;
  const hex = big.map((v) => v.toString(16).padStart(2, "0")).join("");
  return weakY.includes(BigInt("0x" + hex) % p);
}
export async function verifyCryptography(bundle) {
  if (
    bundle?.format !== "koinos-bundle/0.1" ||
    !Array.isArray(bundle.records) ||
    !bundle.records.length
  )
    throw Error("Expected complete nonempty 0.1 bundle");
  let previous = null,
    project,
    time = "";
  for (const [i, r] of bundle.records.entries()) {
    if (
      Object.keys(r).sort().join(",") !==
      "actor,body,id,kind,previous,project,protocol,sequence,signature,time"
    )
      throw Error("Unexpected envelope fields");
    if (
      r.protocol !== "koinos/0.1" ||
      r.sequence !== i ||
      r.previous !== previous
    )
      throw Error(`Broken chain at record ${i}`);
    if (i === 0) project = r.project;
    if (
      r.project !== project ||
      typeof r.time !== "string" ||
      new Date(r.time).toISOString() !== r.time ||
      r.time < time
    )
      throw Error("Project or time inconsistency");
    const { id, signature, ...unsigned } = r;
    const hash = Array.from(
      new Uint8Array(
        await crypto.subtle.digest("SHA-256", enc.encode(canonical(unsigned))),
      ),
      (v) => v.toString(16).padStart(2, "0"),
    ).join("");
    if (id !== hash) throw Error(`Hash mismatch at record ${i}`);
    if (!r.actor.startsWith("koinos:ed25519:")) throw Error("Unknown key type");
    const raw = bytes(r.actor.slice(15));
    if (raw.length !== 32) throw Error("Invalid public key length");
    if (weakKey(raw)) throw Error("Small-order public key");
    const key = await crypto.subtle.importKey(
      "raw",
      raw,
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    const sig = bytes(signature);
    if (
      sig.length !== 64 ||
      !(await crypto.subtle.verify(
        "Ed25519",
        key,
        sig,
        enc.encode("koinos/0.1\n" + id),
      ))
    )
      throw Error(`Invalid signature at record ${i}`);
    previous = id;
    time = r.time;
  }
  return { count: bundle.records.length, head: previous };
}
