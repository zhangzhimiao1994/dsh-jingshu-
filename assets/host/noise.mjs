/**
 * Noise_XK_25519_AESGCM_SHA256 —— DS Bot 中转隧道的端到端加密（docs/RELAY-DESIGN.md §4）。
 *
 * 只用 Node 内置 crypto，零依赖。角色约定：
 *   - initiator = 手机：事先从二维码钉住主机静态公钥（XK 的 "K"），握手里把自己的静态公钥加密发给主机；
 *   - responder = 电脑桥接：握手完成后拿到手机静态公钥，据此判断是否为已登记设备。
 *
 *   XK:
 *     <- s
 *     ...
 *     -> e, es
 *     <- e, ee
 *     -> s, se
 *
 * AESGCM nonce = 4 字节 0 + 8 字节大端计数器（Noise 规范 §12.4）。
 * 所有公钥/私钥对外一律用 32 字节原始值的 base64url 表示。
 */
import crypto from 'node:crypto';

export const PROTOCOL_NAME = 'Noise_XK_25519_AESGCM_SHA256';
export const PROLOGUE = Buffer.from('dsbot-relay-v1', 'utf8');
export const DH_LEN = 32;
export const TAG_LEN = 16;
/** Noise 单条消息上限 65535 字节；减去 tag 后的明文上限。 */
export const MAX_PLAINTEXT = 65535 - TAG_LEN;

const X25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
const EMPTY = Buffer.alloc(0);

// ---------------------------------------------------------------------------
// X25519 原始密钥 <-> KeyObject
// ---------------------------------------------------------------------------

export function privateKeyFromRaw(raw) {
  const buf = toBuf(raw, 'private key');
  return crypto.createPrivateKey({ key: Buffer.concat([X25519_PKCS8_PREFIX, buf]), format: 'der', type: 'pkcs8' });
}

export function publicKeyFromRaw(raw) {
  const buf = toBuf(raw, 'public key');
  return crypto.createPublicKey({ key: Buffer.concat([X25519_SPKI_PREFIX, buf]), format: 'der', type: 'spki' });
}

/** 生成 X25519 密钥对：{ privateKey: Buffer(32), publicKey: Buffer(32) }。 */
export function generateKeyPair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('x25519');
  return {
    privateKey: Buffer.from(privateKey.export({ format: 'jwk' }).d, 'base64url'),
    publicKey: Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url'),
  };
}

/** 由私钥推导公钥。 */
export function publicFromPrivate(raw) {
  const key = crypto.createPublicKey(privateKeyFromRaw(raw));
  return Buffer.from(key.export({ format: 'jwk' }).x, 'base64url');
}

export function dh(privateRaw, publicRaw) {
  return crypto.diffieHellman({ privateKey: privateKeyFromRaw(privateRaw), publicKey: publicKeyFromRaw(publicRaw) });
}

function toBuf(value, label) {
  const buf = typeof value === 'string' ? Buffer.from(value, 'base64url') : Buffer.from(value ?? EMPTY);
  if (buf.length !== DH_LEN) throw new Error(`noise: ${label} 必须是 32 字节`);
  return buf;
}

// ---------------------------------------------------------------------------
// 对称部分
// ---------------------------------------------------------------------------

function sha256(...parts) {
  const hash = crypto.createHash('sha256');
  for (const part of parts) hash.update(part);
  return hash.digest();
}

function hmac(key, ...parts) {
  const mac = crypto.createHmac('sha256', key);
  for (const part of parts) mac.update(part);
  return mac.digest();
}

/** Noise HKDF：返回 2 个 32 字节输出。 */
export function hkdf2(chainingKey, ikm) {
  const temp = hmac(chainingKey, ikm);
  const out1 = hmac(temp, Buffer.from([1]));
  const out2 = hmac(temp, out1, Buffer.from([2]));
  return [out1, out2];
}

function nonceBytes(n) {
  const nonce = Buffer.alloc(12);
  nonce.writeBigUInt64BE(BigInt(n), 4);
  return nonce;
}

export function aeadEncrypt(key, n, ad, plaintext) {
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonceBytes(n));
  cipher.setAAD(ad);
  const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([body, cipher.getAuthTag()]);
}

export function aeadDecrypt(key, n, ad, ciphertext) {
  if (ciphertext.length < TAG_LEN) throw new Error('noise: 密文过短');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonceBytes(n));
  decipher.setAAD(ad);
  decipher.setAuthTag(ciphertext.subarray(ciphertext.length - TAG_LEN));
  return Buffer.concat([decipher.update(ciphertext.subarray(0, ciphertext.length - TAG_LEN)), decipher.final()]);
}

/** 握手完成后的单向加密状态（计数器严格递增，解密失败即视为隧道损坏）。 */
export class CipherState {
  constructor(key) {
    this.k = key;
    this.n = 0n;
  }

  encrypt(plaintext, ad = EMPTY) {
    if (plaintext.length > MAX_PLAINTEXT) throw new Error('noise: 明文超过单帧上限');
    const out = aeadEncrypt(this.k, this.n, ad, plaintext);
    this.n += 1n;
    return out;
  }

  decrypt(ciphertext, ad = EMPTY) {
    const out = aeadDecrypt(this.k, this.n, ad, ciphertext);
    this.n += 1n;
    return out;
  }
}

class SymmetricState {
  constructor() {
    const name = Buffer.from(PROTOCOL_NAME, 'utf8');
    this.h = name.length <= 32 ? Buffer.concat([name, Buffer.alloc(32 - name.length)]) : sha256(name);
    this.ck = Buffer.from(this.h);
    this.k = null;
    this.n = 0n;
  }

  mixHash(data) {
    this.h = sha256(this.h, data);
  }

  mixKey(ikm) {
    const [ck, tempK] = hkdf2(this.ck, ikm);
    this.ck = ck;
    this.k = tempK;
    this.n = 0n;
  }

  encryptAndHash(plaintext) {
    let out = plaintext;
    if (this.k) {
      out = aeadEncrypt(this.k, this.n, this.h, plaintext);
      this.n += 1n;
    }
    this.mixHash(out);
    return out;
  }

  decryptAndHash(ciphertext) {
    let out = ciphertext;
    if (this.k) {
      out = aeadDecrypt(this.k, this.n, this.h, ciphertext);
      this.n += 1n;
    }
    this.mixHash(ciphertext);
    return out;
  }

  split() {
    const [k1, k2] = hkdf2(this.ck, EMPTY);
    return [new CipherState(k1), new CipherState(k2)];
  }
}

// ---------------------------------------------------------------------------
// XK 握手
// ---------------------------------------------------------------------------

/**
 * 发起方（手机）。用法：
 *   const hs = new XKInitiator({ staticKey, remoteStatic });
 *   send(hs.writeMessage1());  hs.readMessage2(msg2);  send(hs.writeMessage3());
 *   const { send: tx, recv: rx } = hs.finish();
 *
 * `ephemeral` 仅供测试向量注入固定临时密钥。
 */
export class XKInitiator {
  constructor({ staticKey, remoteStatic, prologue = PROLOGUE, ephemeral = null }) {
    this.s = { privateKey: toBuf(staticKey.privateKey, 'static private'), publicKey: toBuf(staticKey.publicKey, 'static public') };
    this.rs = toBuf(remoteStatic, 'remote static');
    this.e = ephemeral
      ? { privateKey: toBuf(ephemeral.privateKey, 'ephemeral private'), publicKey: toBuf(ephemeral.publicKey, 'ephemeral public') }
      : generateKeyPair();
    this.ss = new SymmetricState();
    this.ss.mixHash(prologue);
    this.ss.mixHash(this.rs);
    this.step = 0;
  }

  writeMessage1(payload = EMPTY) {
    expectStep(this, 0);
    this.ss.mixHash(this.e.publicKey);
    this.ss.mixKey(dh(this.e.privateKey, this.rs));
    const body = this.ss.encryptAndHash(payload);
    this.step = 1;
    return Buffer.concat([this.e.publicKey, body]);
  }

  readMessage2(message) {
    expectStep(this, 1);
    const msg = Buffer.from(message);
    if (msg.length < DH_LEN + TAG_LEN) throw new Error('noise: 握手消息 2 长度不足');
    this.re = msg.subarray(0, DH_LEN);
    this.ss.mixHash(this.re);
    this.ss.mixKey(dh(this.e.privateKey, this.re));
    const payload = this.ss.decryptAndHash(msg.subarray(DH_LEN));
    this.step = 2;
    return payload;
  }

  writeMessage3(payload = EMPTY) {
    expectStep(this, 2);
    const encS = this.ss.encryptAndHash(this.s.publicKey);
    this.ss.mixKey(dh(this.s.privateKey, this.re));
    const body = this.ss.encryptAndHash(payload);
    this.step = 3;
    return Buffer.concat([encS, body]);
  }

  finish() {
    expectStep(this, 3);
    const [c1, c2] = this.ss.split();
    return { send: c1, recv: c2, handshakeHash: Buffer.from(this.ss.h) };
  }
}

/** 响应方（电脑桥接）。readMessage1 → writeMessage2 → readMessage3 → finish()。 */
export class XKResponder {
  constructor({ staticKey, prologue = PROLOGUE, ephemeral = null }) {
    this.s = { privateKey: toBuf(staticKey.privateKey, 'static private'), publicKey: toBuf(staticKey.publicKey, 'static public') };
    this.e = ephemeral
      ? { privateKey: toBuf(ephemeral.privateKey, 'ephemeral private'), publicKey: toBuf(ephemeral.publicKey, 'ephemeral public') }
      : generateKeyPair();
    this.ss = new SymmetricState();
    this.ss.mixHash(prologue);
    this.ss.mixHash(this.s.publicKey);
    this.step = 0;
    this.rs = null;
  }

  readMessage1(message) {
    expectStep(this, 0);
    const msg = Buffer.from(message);
    if (msg.length < DH_LEN + TAG_LEN) throw new Error('noise: 握手消息 1 长度不足');
    this.re = msg.subarray(0, DH_LEN);
    this.ss.mixHash(this.re);
    this.ss.mixKey(dh(this.s.privateKey, this.re));
    const payload = this.ss.decryptAndHash(msg.subarray(DH_LEN));
    this.step = 1;
    return payload;
  }

  writeMessage2(payload = EMPTY) {
    expectStep(this, 1);
    this.ss.mixHash(this.e.publicKey);
    this.ss.mixKey(dh(this.e.privateKey, this.re));
    const body = this.ss.encryptAndHash(payload);
    this.step = 2;
    return Buffer.concat([this.e.publicKey, body]);
  }

  readMessage3(message) {
    expectStep(this, 2);
    const msg = Buffer.from(message);
    const encLen = DH_LEN + TAG_LEN;
    if (msg.length < encLen + TAG_LEN) throw new Error('noise: 握手消息 3 长度不足');
    this.rs = this.ss.decryptAndHash(msg.subarray(0, encLen));
    this.ss.mixKey(dh(this.e.privateKey, this.rs));
    const payload = this.ss.decryptAndHash(msg.subarray(encLen));
    this.step = 3;
    return payload;
  }

  finish() {
    expectStep(this, 3);
    const [c1, c2] = this.ss.split();
    return { send: c2, recv: c1, handshakeHash: Buffer.from(this.ss.h), remoteStatic: Buffer.from(this.rs) };
  }
}

function expectStep(hs, step) {
  if (hs.step !== step) throw new Error(`noise: 握手步骤错误（当前 ${hs.step}，期望 ${step}）`);
}

// ---------------------------------------------------------------------------
// 隧道内分片：每条 Noise 消息明文 = 1 字节标志（0=最后一片，1=后面还有）+ 数据
// ---------------------------------------------------------------------------

export const FRAG_CHUNK = MAX_PLAINTEXT - 1;
export const MAX_REASSEMBLED = 24 * 1024 * 1024;

/** 把一条应用消息切成若干 Noise 明文片。 */
export function fragment(message) {
  const data = Buffer.from(message);
  const pieces = [];
  for (let offset = 0; offset < data.length || pieces.length === 0; offset += FRAG_CHUNK) {
    const chunk = data.subarray(offset, offset + FRAG_CHUNK);
    const last = offset + FRAG_CHUNK >= data.length;
    pieces.push(Buffer.concat([Buffer.from([last ? 0 : 1]), chunk]));
  }
  return pieces;
}

/** 重组器：push(明文片) → 完整消息或 null。 */
export function createReassembler(limit = MAX_REASSEMBLED) {
  let parts = [];
  let size = 0;
  return {
    push(piece) {
      if (piece.length < 1) throw new Error('noise: 空分片');
      const flag = piece[0];
      if (flag !== 0 && flag !== 1) throw new Error('noise: 分片标志无效');
      size += piece.length - 1;
      if (size > limit) throw new Error('noise: 消息超过上限');
      parts.push(piece.subarray(1));
      if (flag === 1) return null;
      const out = Buffer.concat(parts);
      parts = [];
      size = 0;
      return out;
    },
  };
}
