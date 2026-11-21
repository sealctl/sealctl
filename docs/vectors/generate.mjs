// Reproduces every test vector in docs/protocol.md.
// Usage: node vectors.mjs <path to BIP39 english.txt>   (Node 20+, no dependencies)
import crypto from "node:crypto";
import fs from "node:fs";

const H = (b) => Buffer.from(b).toString("hex");
const B = (s) => Buffer.from(s, "hex");
const U = (s) => Buffer.from(s, "utf8");
const b64u = (b) => Buffer.from(b).toString("base64url");
const cat = (...xs) => Buffer.concat(xs.map((x) => Buffer.from(x)));
const sha256 = (b) => crypto.createHash("sha256").update(b).digest();
const Z = Buffer.from([0]);
const out = {};
const put = (k, v) => { out[k] = v; console.log(`${k}: ${v}`); };

// ---------- primitives ----------
const hmac = (key, msg) => crypto.createHmac("sha256", key).update(msg).digest();
const hkdfExtract = (salt, ikm) => hmac(salt.length ? salt : Buffer.alloc(32), ikm);
function hkdfExpand(prk, info, L) {
  let t = Buffer.alloc(0), okm = Buffer.alloc(0);
  for (let i = 1; okm.length < L; i++) { t = hmac(prk, cat(t, info, [i])); okm = cat(okm, t); }
  return okm.subarray(0, L);
}
const hkdf = (ikm, info, L, salt = Buffer.alloc(0)) => hkdfExpand(hkdfExtract(salt, ikm), info, L);
// cross-check the hand-written HKDF against node's own
{
  const a = hkdf(U("ikm"), U("info"), 42), b = Buffer.from(crypto.hkdfSync("sha256", U("ikm"), Buffer.alloc(0), U("info"), 42));
  if (!a.equals(b)) throw new Error("hkdf mismatch");
}
const ED_PKCS8 = B("302e020100300506032b657004220420"), ED_SPKI = B("302a300506032b6570032100");
const X_PKCS8 = B("302e020100300506032b656e04220420"), X_SPKI = B("302a300506032b656e032100");
const edPriv = (seed) => crypto.createPrivateKey({ key: cat(ED_PKCS8, seed), format: "der", type: "pkcs8" });
const edPub = (seed) => Buffer.from(crypto.createPublicKey(edPriv(seed)).export({ format: "jwk" }).x, "base64url");
const edSign = (seed, msg) => crypto.sign(null, msg, edPriv(seed));
const edVerify = (pub, msg, sig) => crypto.verify(null, msg, crypto.createPublicKey({ key: cat(ED_SPKI, pub), format: "der", type: "spki" }), sig);
const xPriv = (sk) => crypto.createPrivateKey({ key: cat(X_PKCS8, sk), format: "der", type: "pkcs8" });
const xPub = (sk) => Buffer.from(crypto.createPublicKey(xPriv(sk)).export({ format: "jwk" }).x, "base64url");
const xDH = (sk, pk) => crypto.diffieHellman({ privateKey: xPriv(sk), publicKey: crypto.createPublicKey({ key: cat(X_SPKI, pk), format: "der", type: "spki" }) });
function chachaSeal(key, nonce, aad, pt) {
  const c = crypto.createCipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
  c.setAAD(aad, { plaintextLength: pt.length });
  return cat(c.update(pt), c.final(), c.getAuthTag());
}
function chachaOpen(key, nonce, aad, ct) {
  const d = crypto.createDecipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
  d.setAAD(aad, { plaintextLength: ct.length - 16 });
  d.setAuthTag(ct.subarray(ct.length - 16));
  return cat(d.update(ct.subarray(0, ct.length - 16)), d.final());
}

// ---------- HPKE (RFC 9180), base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305 ----------
const i2osp = (n, w) => { const b = Buffer.alloc(w); b.writeUIntBE(n, 0, w); return b; };
const KEM_ID = cat(U("KEM"), i2osp(0x20, 2));
const HPKE_ID = cat(U("HPKE"), i2osp(0x20, 2), i2osp(1, 2), i2osp(3, 2));
const lExtract = (sid, salt, label, ikm) => hkdfExtract(salt, cat(U("HPKE-v1"), sid, U(label), ikm));
const lExpand = (sid, prk, label, info, L) => hkdfExpand(prk, cat(i2osp(L, 2), U("HPKE-v1"), sid, U(label), info), L);
const deriveKeyPair = (ikm) => { const sk = lExpand(KEM_ID, lExtract(KEM_ID, Buffer.alloc(0), "dkp_prk", ikm), "sk", Buffer.alloc(0), 32); return { sk, pk: xPub(sk) }; };
const eae = (dh, ctx) => lExpand(KEM_ID, lExtract(KEM_ID, Buffer.alloc(0), "eae_prk", dh), "shared_secret", ctx, 32);
function keySchedule(ss, info) {
  const pskId = lExtract(HPKE_ID, Buffer.alloc(0), "psk_id_hash", Buffer.alloc(0));
  const infoHash = lExtract(HPKE_ID, Buffer.alloc(0), "info_hash", info);
  const ksc = cat([0], pskId, infoHash);
  const secret = lExtract(HPKE_ID, ss, "secret", Buffer.alloc(0));
  return { key: lExpand(HPKE_ID, secret, "key", ksc, 32), nonce: lExpand(HPKE_ID, secret, "base_nonce", ksc, 12) };
}
function hpkeSeal(pkR, info, aad, pt, ikmE) {
  const e = deriveKeyPair(ikmE); // fixed ephemeral for test vectors only; real senders use GenerateKeyPair
  const ss = eae(xDH(e.sk, pkR), cat(e.pk, pkR));
  const { key, nonce } = keySchedule(ss, info);
  return { enc: e.pk, ct: chachaSeal(key, nonce, aad, pt), ss };
}
function hpkeOpen(skR, info, aad, enc, ct) {
  const ss = eae(xDH(skR, enc), cat(enc, xPub(skR)));
  const { key, nonce } = keySchedule(ss, info);
  return chachaOpen(key, nonce, aad, ct);
}
// RFC 9180 A.2.1 check
{
  const info = B("4f6465206f6e2061204772656369616e2055726e");
  const r = deriveKeyPair(B("1ac01f181fdf9f352797655161c58b75c656a6cc2716dcb66372da835542e1df"));
  if (H(r.sk) !== "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb") throw new Error("A.2.1 skRm");
  const s = hpkeSeal(r.pk, info, B("436f756e742d30"), B("4265617574792069732074727574682c20747275746820626561757479"),
    B("909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b"));
  if (H(s.enc) !== "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a") throw new Error("A.2.1 enc");
  if (H(s.ss) !== "0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7") throw new Error("A.2.1 shared_secret");
  if (H(s.ct) !== "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28") throw new Error("A.2.1 ct");
  console.log("RFC 9180 A.2.1 sequence 0: OK");
}

// ---------- BIP39 ----------
const WORDS = fs.readFileSync(process.argv[2], "utf8").trim().split("\n");
if (WORDS.length !== 2048 || H(sha256(U(WORDS.join("\n") + "\n"))) !== "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda") throw new Error("wordlist");
function mnemonicFromEntropy(ent) {
  const bits = [...cat(ent, sha256(ent).subarray(0, 1))].map((x) => x.toString(2).padStart(8, "0")).join("");
  const w = [];
  for (let i = 0; i < 24; i++) w.push(WORDS[parseInt(bits.slice(i * 11, i * 11 + 11), 2)]);
  return w.join(" ");
}
const seedOf = (m) => crypto.pbkdf2Sync(U(m.normalize("NFKD")), U("mnemonic"), 2048, 64, "sha512");

// ---------- sealctl derivation ----------
const rootOf = (seed) => hkdf(seed, U("sealctl/v1/root"), 32);
const derive = (root, label, L) => hkdf(root, U("sealctl/v1/" + label), L);
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function fingerprint(root) {
  let n = derive(root, "fingerprint", 8).readBigUInt64BE(0) % (58n ** 4n);
  let s = "";
  for (let i = 0; i < 4; i++) { s = B58[Number(n % 58n)] + s; n /= 58n; }
  return s;
}
const check = (key) => b64u(hkdf(key, U("sealctl/v1/check"), 8));
const CROCK = "0123456789abcdefghjkmnpqrstvwxyz";
function tag(machinePub) {
  const h = sha256(cat(U("sealctl/v1/tag"), Z, machinePub));
  const v = (h[0] << 12) | (h[1] << 4) | (h[2] >> 4); // first 20 bits
  return [15, 10, 5, 0].map((s) => CROCK[(v >> s) & 31]).join("");
}
const uuidBytes = (u) => B(u.replace(/-/g, ""));

function phoneKeys(root) {
  const idSeed = derive(root, "phone:identity", 32);
  const boxSk = derive(root, "phone:box", 32);
  return { idSeed, P: edPub(idSeed), boxSk, BX: xPub(boxSk) };
}

// ---------- vectors ----------
const mA = Array(23).fill("abandon").concat("art").join(" ");
const mB = mnemonicFromEntropy(sha256(U("sealctl test vector B")));
put("A.mnemonic", mA);
put("B.entropy", H(sha256(U("sealctl test vector B"))));
put("B.mnemonic", mB);
const roots = {};
for (const [k, m] of [["A", mA], ["B", mB]]) {
  const seed = seedOf(m), root = rootOf(seed), pk = phoneKeys(root);
  roots[k] = root;
  put(`${k}.seed`, H(seed));
  put(`${k}.root`, H(root));
  put(`${k}.fingerprint`, fingerprint(root));
  put(`${k}.fingerprint_okm`, H(derive(root, "fingerprint", 8)));
  put(`${k}.phone_identity_seed`, H(pk.idSeed));
  put(`${k}.phone_identity_public_b64u`, b64u(pk.P));
  put(`${k}.phone_box_private`, H(pk.boxSk));
  put(`${k}.phone_box_public_b64u`, b64u(pk.BX));
  put(`${k}.state_key`, H(derive(root, "state", 32)));
}
const root = roots.B;
const STORE = "0f8c6d2e-4b1a-4c3d-9e5f-7a6b8c9d0e1f";
const FILE = "3d7e1b9a-2c4f-4a8e-b6d1-5f0e9c2a7b34";
const VOL = "fa5a93d5-28d9-4c08-b608-c2b6f344b4d8";
const REPO = "6c1f0b2e-8d3a-4f7b-a9e4-2b5c7d8e9f01";
const labels = [`secrets:${STORE}`, `secret:${FILE}`, `volume:${VOL}`, `backup:${REPO}`];
const keys = {};
for (const l of labels) {
  const k = derive(root, l, 16);
  keys[l] = k;
  const [pp, ii] = l.split(":");
  put(`B.key ${pp} ${ii}`, H(k));
  put(`B.key_b64u ${pp} ${ii}`, b64u(k));
  put(`B.check ${pp} ${ii}`, check(k));
}

// sealed file (store key, mode 1) and own-approval file (mode 2)
const NAME = "shop/openai-api-key", VALUE = U("test-value-not-a-real-key");
function sealFile(mode, ikmKey, nonce) {
  const fileKey = hkdf(ikmKey, U("sealctl/v1/file:" + FILE), 32);
  const header = cat(U("SCS1"), [mode], U(fingerprint(root)), uuidBytes(FILE), nonce);
  const aad = cat(header, U(STORE), Z, U(NAME));
  const sealed = cat(header, chachaSeal(fileKey, nonce, aad, VALUE));
  if (!chachaOpen(fileKey, nonce, aad, sealed.subarray(37)).equals(VALUE)) throw new Error("sealed roundtrip");
  return { fileKey, sealed };
}
const s1 = sealFile(1, keys[`secrets:${STORE}`], B("000102030405060708090a0b"));
put("B.file_key_mode1", H(s1.fileKey));
put("B.sealed_mode1", H(s1.sealed));
const s2 = sealFile(2, keys[`secret:${FILE}`], B("0c0d0e0f1011121314151617"));
put("B.file_key_mode2", H(s2.fileKey));
put("B.sealed_mode2", H(s2.sealed));

// state blob
{
  const pk = phoneKeys(root);
  const nonce = B("18191a1b1c1d1e1f20212223");
  const pt = U('{"v":1}');
  const aad = cat(U("sealctl/v1/state"), Z, pk.P);
  const blob = cat([1], nonce, chachaSeal(derive(root, "state", 32), nonce, aad, pt));
  put("B.state_blob_b64u", b64u(blob));
}

// machine, pairing link and proof
const mSeed = sha256(U("sealctl test machine"));
const M = edPub(mSeed);
const S = B("000102030405060708090a0b0c0d0e0f");
put("machine.seed", H(mSeed));
put("machine.public_b64u", b64u(M));
put("machine.tag", tag(M));
const MACHINE_ID = "0123456789abcdef0123456789abcdef";
const hint = b64u(sha256(cat(U("sealctl/v1/hint"), Z, U(MACHINE_ID))).subarray(0, 16));
put("machine.hint", hint);
const enc = (s) => encodeURIComponent(s);
const mBoxSk = sha256(U("sealctl test machine box"));
const MX = xPub(mBoxSk);
put("machine.box_private", H(mBoxSk));
put("machine.box_public_b64u", b64u(MX));
const EXPIRES = Date.UTC(2026, 10, 21, 9, 10, 0) / 1000;
const link = `https://sealctl.com/p#v=1&m=${b64u(M)}&x=${b64u(MX)}&s=${b64u(S)}&n=${enc("dev@mbp.example.com")}&o=${enc("macOS 15.2")}&d=${enc("Mac15,3")}&h=${hint}&e=${EXPIRES}`;
put("pair.link", link);
{
  const pk = phoneKeys(root);
  const mac = hmac(S, cat(U("sealctl/v1/pair"), Z, pk.P, pk.BX, M));
  put("pair.hmac", H(mac));
  put("pair.proof", b64u(cat(pk.BX, mac)));
  // move from words A (old) to words B (new)
  const old = phoneKeys(roots.A);
  const msg = cat(U("sealctl/v1/move"), Z, pk.P, pk.BX, M);
  const sig = edSign(old.idSeed, msg);
  if (!edVerify(old.P, msg, sig)) throw new Error("move sig");
  put("move.signature", H(sig));
  put("move.proof", b64u(cat(pk.BX, sig)));
  put("move.proof_length", b64u(cat(pk.BX, sig)).length);
}

// request and reply
{
  const pk = phoneKeys(root);
  const id = b64u(B("303132333435363738393a3b3c3d3e3f"));
  const ot = deriveKeyPair(sha256(U("sealctl test one-time key")));
  const t = Date.UTC(2026, 10, 21, 9, 0, 0);
  put("request.id", id);
  put("request.t", t);
  put("onetime.private", H(ot.sk));
  put("onetime.public_b64u", b64u(ot.pk));
  const body = U(JSON.stringify({
    v: 1, t, why: "open", ot: b64u(ot.pk),
    ctx: {
      agent: "Claude Code", repo: { id: "github.com/acme/shop", name: "acme/shop" }, cmd: "npm test", cwd: "~/src/shop",
      user: "dev@mbp.example.com", subject: { k: "secret", n: NAME }, n: [NAME],
    },
    keys: [{ p: "secrets", i: STORE, w: fingerprint(root), c: check(keys[`secrets:${STORE}`]), o: { k: "store", p: "~/.local/share/sealctl/store/" + STORE, s: 4096 } }],
    uses: [{ a: "Claude Code", r: "github.com/acme/shop", n: [NAME] }],
    work: 0,
  }));
  put("request.body", body.toString("utf8"));
  const reqMsg = cat(U("sealctl/v1/request"), Z, U(id), Z, pk.P, body);
  const reqSig = edSign(mSeed, reqMsg);
  put("request.signature", H(reqSig));
  const aad = cat(U(id), Z, M);
  const r = hpkeSeal(pk.BX, U("sealctl/v1/request"), aad, cat(reqSig, body), sha256(U("sealctl test ephemeral request")));
  const sealedReq = b64u(cat(r.enc, r.ct));
  put("request.enc", H(r.enc));
  put("request.sealed", sealedReq);
  put("request.sealed_length", sealedReq.length);
  // phone side
  const raw = Buffer.from(sealedReq, "base64url");
  const pt = hpkeOpen(pk.boxSk, U("sealctl/v1/request"), aad, raw.subarray(0, 32), raw.subarray(32));
  if (!edVerify(M, cat(U("sealctl/v1/request"), Z, U(id), Z, pk.P, pt.subarray(64)), pt.subarray(0, 64))) throw new Error("req verify");

  const rq = b64u(sha256(body));
  const rbody = U(JSON.stringify({
    v: 1, rq, ok: true, w: fingerprint(root), grant: "session", remember: true,
    place: "trusted", cap: 14400, base: 1800, rate: 120,
    keys: [{ p: "secrets", i: STORE, k: b64u(keys[`secrets:${STORE}`]) }],
  }));
  put("reply.rq", rq);
  put("reply.body", rbody.toString("utf8"));
  const repSig = edSign(pk.idSeed, cat(U("sealctl/v1/reply"), Z, U(id), Z, M, rbody));
  put("reply.signature", H(repSig));
  const rr = hpkeSeal(ot.pk, U("sealctl/v1/reply"), aad, cat(repSig, rbody), sha256(U("sealctl test ephemeral reply")));
  const sealedRep = b64u(cat(rr.enc, rr.ct));
  put("reply.sealed", sealedRep);
  put("reply.sealed_length", sealedRep.length);
  const rraw = Buffer.from(sealedRep, "base64url");
  const rpt = hpkeOpen(ot.sk, U("sealctl/v1/reply"), aad, rraw.subarray(0, 32), rraw.subarray(32));
  if (!edVerify(pk.P, cat(U("sealctl/v1/reply"), Z, U(id), Z, M, rpt.subarray(64)), rpt.subarray(0, 64))) throw new Error("reply verify");
}

// machine status (machine to phone) and machine message (phone to machine)
{
  const pk = phoneKeys(root);
  const t = Date.UTC(2026, 10, 21, 9, 30, 0);
  const sbody = U(JSON.stringify({
    v: 1, t, seq: 1,
    state: { s: "open", left: 13200, stop: Date.UTC(2026, 10, 22, 1, 0, 0), place: "trusted" },
    log: [{ t: Date.UTC(2026, 10, 21, 9, 1, 0), a: "Claude Code", r: "github.com/acme/shop", c: "npm test", n: [NAME], own: false }],
  }));
  put("status.body", sbody.toString("utf8"));
  const ssig = edSign(mSeed, cat(U("sealctl/v1/status"), Z, pk.P, sbody));
  put("status.signature", H(ssig));
  const st = hpkeSeal(pk.BX, U("sealctl/v1/status"), M, cat(ssig, sbody), sha256(U("sealctl test ephemeral status")));
  const sealedSt = b64u(cat(st.enc, st.ct));
  put("status.sealed", sealedSt);
  const sraw = Buffer.from(sealedSt, "base64url");
  const spt = hpkeOpen(pk.boxSk, U("sealctl/v1/status"), M, sraw.subarray(0, 32), sraw.subarray(32));
  if (!edVerify(M, cat(U("sealctl/v1/status"), Z, pk.P, spt.subarray(64)), spt.subarray(0, 64))) throw new Error("status verify");

  const mbody = U(JSON.stringify({ v: 1, t: Date.UTC(2026, 10, 21, 13, 0, 0), seq: 1, type: "lock", reason: "place" }));
  put("message.body", mbody.toString("utf8"));
  const msig = edSign(pk.idSeed, cat(U("sealctl/v1/message"), Z, M, mbody));
  put("message.signature", H(msig));
  const mm = hpkeSeal(MX, U("sealctl/v1/message"), M, cat(msig, mbody), sha256(U("sealctl test ephemeral message")));
  const sealedMsg = b64u(cat(mm.enc, mm.ct));
  put("message.sealed", sealedMsg);
  const mraw = Buffer.from(sealedMsg, "base64url");
  const mpt = hpkeOpen(mBoxSk, U("sealctl/v1/message"), M, mraw.subarray(0, 32), mraw.subarray(32));
  if (!edVerify(pk.P, cat(U("sealctl/v1/message"), Z, M, mpt.subarray(64)), mpt.subarray(0, 64))) throw new Error("message verify");
}

// root backup item (iCloud Keychain / Block Store), words B
{
  const ent = sha256(U("sealctl test vector B"));
  const created = Buffer.alloc(8); created.writeBigUInt64BE(BigInt(Date.UTC(2026, 10, 21, 9, 0, 0)));
  put("backup_item", H(cat([1], ent, U(fingerprint(root)), created)));
}

// relay signature (existing Relay API scheme), machine signing a licence read
{
  const pk = phoneKeys(root);
  const time = String(Date.UTC(2026, 10, 21, 9, 0, 0) / 1000);
  const canonical = `sealctl-relay-v1\nGET\n/v1/phones/${b64u(pk.P)}/licence\n${time}\n${b64u(sha256(Buffer.alloc(0)))}`;
  put("relay.canonical", JSON.stringify(canonical));
  put("relay.signature", b64u(edSign(mSeed, U(canonical))));
}

// relay-signing.json: request signing for the Relay API (shared with the relay's tests)
{
  const phone = phoneKeys(root), oldPhone = phoneKeys(roots.A);
  const P = b64u(phone.P), Mid = b64u(M), time = "1795251600";
  const sign = (seed, method, path, body) => {
    const bodyHash = b64u(sha256(U(body)));
    const canonical = `sealctl-relay-v1\n${method}\n${path}\n${time}\n${bodyHash}`;
    return { method, path, time, body, bodyHash, canonical, key: b64u(edPub(seed)), signature: b64u(edSign(seed, U(canonical))) };
  };
  const pairBody = JSON.stringify({ machine: Mid, name: "dev@mbp.example.com", os: "macOS 15.2", model: "Mac15,3", proof: out["pair.proof"] });
  const moveMsg = `sealctl-licence-move-v1\n${b64u(oldPhone.P)}\n${P}`;
  const relay = {
    scheme: "sealctl-relay-v1",
    note: "Ed25519 seeds are test keys derived from the test words in docs/protocol.md Appendix A. Signatures are deterministic (RFC 8032).",
    keys: {
      machine: { seed: H(mSeed), public: Mid },
      phone: { seed: H(phone.idSeed), public: P, words: "B" },
      oldPhone: { seed: H(oldPhone.idSeed), public: b64u(oldPhone.P), words: "A" },
    },
    vectors: [
      { name: "machine reads the licence", signer: "machine", ...sign(mSeed, "GET", `/v1/phones/${P}/licence`, "") },
      { name: "machine opens a wait socket", signer: "machine", ...sign(mSeed, "GET", `/v1/phones/${P}/wait`, "") },
      { name: "machine looks itself up", signer: "machine", ...sign(mSeed, "GET", `/v1/machines/${Mid}`, "") },
      { name: "phone registers a machine", signer: "phone", ...sign(phone.idSeed, "POST", `/v1/phones/${P}/machines`, pairBody) },
      { name: "phone lists requests with a query", signer: "phone", ...sign(phone.idSeed, "GET", `/v1/phones/${P}/requests?limit=10`, "") },
      { name: "machine unpairs itself", signer: "machine", ...sign(mSeed, "DELETE", `/v1/phones/${P}/machines/${Mid}`, "") },
    ],
    licenceMove: { old: b64u(oldPhone.P), new: P, message: moveMsg, proof: b64u(edSign(phone.idSeed, U(moveMsg))) },
  };
  for (const v of relay.vectors) if (!edVerify(Buffer.from(v.key, "base64url"), U(v.canonical), Buffer.from(v.signature, "base64url"))) throw new Error("relay vector");
  fs.writeFileSync(new URL("./relay-signing.json", import.meta.url), JSON.stringify(relay, null, 2) + "\n");
}

fs.writeFileSync(new URL("./vectors.json", import.meta.url), JSON.stringify(out, null, 2) + "\n");
