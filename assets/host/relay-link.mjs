/**
 * 桥接的「中转传输层」（docs/RELAY-DESIGN.md §4–§5）。
 *
 * 桥接主动连到 dsbot-relay，用 Ed25519 认领 hostId 房间；每个手机连进来就是一个 channel，
 * 在 channel 上做 Noise XK 握手（桥接 = responder），之后隧道里跑的 JSON 帧被**原样转成
 * 对本机桥接的 HTTP / WS 请求**（127.0.0.1:<port>）——鉴权、白名单、限流、审计全部复用现有路径，
 * 中转模式不会多出任何绕过白名单的口子。
 *
 * channel 两种模式：
 *   - pairing：手机静态公钥未登记。只允许 GET /dsbot/status 与 POST /dsbot/pair/redeem；
 *              兑换成功后把手机静态公钥绑定到新设备，切到 device 模式。
 *   - device ：静态公钥属于一台未撤销设备。请求里的 device token 必须属于同一台设备。
 *
 * 隧道内帧（加密前的明文 JSON）：
 *   手机→桥接 {"k":"req","id","method","path","headers":{authorization,content-type},"body"}
 *             {"k":"mux-open","mid","token"} {"k":"mux","mid","text"} {"k":"mux-close","mid"} {"k":"ping"}
 *   桥接→手机 {"k":"ready","mode","deviceId"?,"version"} {"k":"res","id","status","body"}
 *             {"k":"mux-opened","mid"} {"k":"mux","mid","text"} {"k":"mux-closed","mid","code"} {"k":"pong"}
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';

import { XKResponder, createReassembler, fragment, generateKeyPair, publicFromPrivate } from './noise.mjs';

export const HOST_KEYS_FILE = 'host-keys.json';
export const HANDSHAKE_TIMEOUT_MS = 30_000;
export const PAIRING_IDLE_MS = 5 * 60_000;
export const MAX_MUX_PER_CHANNEL = 4;
export const MAX_RESPONSE_BYTES = 20 * 1024 * 1024;
export const LOCAL_REQUEST_TIMEOUT_MS = 90_000;
export const REVOKE_SWEEP_MS = 3_000;
export const RECONNECT_MIN_MS = 1_000;
export const RECONNECT_MAX_MS = 30_000;
export const PAIRING_ALLOWED = new Set(['GET /dsbot/status', 'POST /dsbot/pair/redeem']);
export const RELAY_KEY_PATTERN = /^[A-Za-z0-9_-]{43}$/;

const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const SIGN_CONTEXT = 'dsbot-relay-host-v1';

// ---------------------------------------------------------------------------
// 主机密钥
// ---------------------------------------------------------------------------

export function hostIdFromSigningKey(rawPublicKey) {
  return crypto.createHash('sha256').update(Buffer.from(rawPublicKey)).digest('base64url').slice(0, 22);
}

/**
 * 读取或生成 <stateDir>/host-keys.json（0600）：
 *   sign  = Ed25519（向中转证明房间归属）
 *   noise = X25519（Noise 静态密钥，公钥写进二维码供手机钉住）
 */
/**
 * 原子写：tmp(同目录) → fsync → rename，并保留一份 .bak。
 * 主机身份是全仓库最不可再生的数据（signPrivate 丢了 hostId 就变了，所有手机要重扫），
 * 所以这里必须比其它状态文件更严格。
 */
function writeHostKeysAtomic(file, record) {
  const tmp = `${file}.tmp-${process.pid}`;
  const text = `${JSON.stringify(record, null, 2)}\n`;
  const fd = fs.openSync(tmp, 'w', 0o600);
  try {
    fs.writeFileSync(fd, text, 'utf8');
    try { fs.fsyncSync(fd); } catch { /* 部分文件系统不支持，尽力而为 */ }
  } finally {
    fs.closeSync(fd);
  }
  try { fs.chmodSync(tmp, 0o600); } catch { /* Windows 上忽略 */ }
  // 覆盖前先把当前有效文件留一份，供损坏时恢复
  try { if (fs.existsSync(file)) fs.copyFileSync(file, `${file}.bak`); } catch { /* 尽力 */ }
  fs.renameSync(tmp, file);
  // 首次生成时还没有 .bak：把刚写好的文件本身作为第一份备份，
  // 否则「刚装好就损坏」这条路径永远无备份可恢复。
  try { if (!fs.existsSync(`${file}.bak`)) fs.copyFileSync(file, `${file}.bak`); } catch { /* 尽力 */ }
}

/** 读并校验；任何异常都返回 null，由调用方区分「不存在」与「坏了」。 */
function tryReadHostKeys(file) {
  try {
    return normalizeKeys(JSON.parse(fs.readFileSync(file, 'utf8')));
  } catch {
    return null;
  }
}

export function loadOrCreateHostKeys(stateDir, { rotate = false } = {}) {
  const file = path.join(stateDir, HOST_KEYS_FILE);
  const backup = `${file}.bak`;

  if (!rotate) {
    const existing = tryReadHostKeys(file);
    if (existing) return { ...existing, path: file, created: false, recovered: false };

    // 主文件存在但读不出/不合规：先尝试备份，再考虑重建。
    if (fs.existsSync(file)) {
      const fromBackup = tryReadHostKeys(backup);
      if (fromBackup) {
        writeHostKeysAtomic(file, {
          version: 1,
          signPrivate: fromBackup.signPrivate.toString('base64url'),
          signPublic: fromBackup.signPublic.toString('base64url'),
          noisePrivate: fromBackup.noise.privateKey.toString('base64url'),
          noisePublic: fromBackup.noise.publicKey.toString('base64url'),
          createdAt: Date.now(),
        });
        return { ...fromBackup, path: file, created: false, recovered: true };
      }
      // 主文件与备份都不可用：把坏文件留档，绝不静默覆盖丢失证据。
      try { fs.renameSync(file, `${file}.corrupt-${Date.now()}`); } catch { /* 尽力 */ }
      console.warn('[host-keys] 主机身份文件损坏且无可恢复备份，已把坏文件改名留档，正在生成新身份。' +
        '现有手机的配对将全部失效，需要重新扫码。');
    }
  }

  fs.mkdirSync(stateDir, { recursive: true });
  const sign = crypto.generateKeyPairSync('ed25519');
  const noise = generateKeyPair();
  const record = {
    version: 1,
    signPrivate: sign.privateKey.export({ format: 'jwk' }).d,
    signPublic: sign.publicKey.export({ format: 'jwk' }).x,
    noisePrivate: noise.privateKey.toString('base64url'),
    noisePublic: noise.publicKey.toString('base64url'),
    createdAt: Date.now(),
  };
  writeHostKeysAtomic(file, record);
  return { ...normalizeKeys(record), path: file, created: true, recovered: false };
}

function normalizeKeys(raw) {
  if (!raw || raw.version !== 1) return null;
  const signPrivate = Buffer.from(String(raw.signPrivate ?? ''), 'base64url');
  const signPublic = Buffer.from(String(raw.signPublic ?? ''), 'base64url');
  const noisePrivate = Buffer.from(String(raw.noisePrivate ?? ''), 'base64url');
  if (signPrivate.length !== 32 || signPublic.length !== 32 || noisePrivate.length !== 32) return null;
  const noisePublic = publicFromPrivate(noisePrivate);
  return {
    signPrivate,
    signPublic,
    noise: { privateKey: noisePrivate, publicKey: noisePublic },
    hostId: hostIdFromSigningKey(signPublic),
    hpk: noisePublic.toString('base64url'),
  };
}

export function signChallenge(keys, nonce) {
  const key = crypto.createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, keys.signPrivate]),
    format: 'der',
    type: 'pkcs8',
  });
  return crypto.sign(null, Buffer.from(`${SIGN_CONTEXT}\n${nonce}\n${keys.hostId}`, 'utf8'), key).toString('base64url');
}

/** 规整中转地址：只接受 ws:// 或 wss://，去掉末尾斜杠。 */
export function normalizeRelayUrl(raw) {
  const text = String(raw ?? '').trim().replace(/\/+$/, '');
  let url;
  try {
    url = new URL(text);
  } catch {
    throw new Error(`--relay 地址无效：${text}（形如 ws://1.2.3.4:8443 或 wss://relay.example.com）`);
  }
  if (url.protocol !== 'ws:' && url.protocol !== 'wss:') {
    throw new Error(`--relay 只支持 ws:// 或 wss://，收到：${url.protocol}`);
  }
  return text;
}

// ---------------------------------------------------------------------------
// 中转连接
// ---------------------------------------------------------------------------

/**
 * @param {object} options
 *   bridge        已 start() 的桥接（用到 port/bind/lookupDevice/findDeviceByRelayKey/bindRelayKey/audit）
 *   relayUrl      ws(s)://…
 *   keys          loadOrCreateHostKeys() 结果
 *   WebSocketImpl 默认 globalThis.WebSocket（Node ≥ 22）
 */
export function createRelayLink(options) {
  const {
    bridge,
    relayUrl,
    keys,
    WebSocketImpl = globalThis.WebSocket,
    log = () => {},
    handshakeTimeoutMs = HANDSHAKE_TIMEOUT_MS,
    pairingIdleMs = PAIRING_IDLE_MS,
  } = options;
  if (typeof WebSocketImpl !== 'function') throw new Error('当前 Node 没有内置 WebSocket（需要 Node ≥ 22）');

  const channels = new Map();
  let ws = null;
  let stopped = false;
  let online = false;
  let retryMs = RECONNECT_MIN_MS;
  let retryTimer = null;
  let sweepTimer = null;
  const listeners = new Set();

  const emit = (event) => {
    for (const fn of listeners) {
      try {
        fn(event);
      } catch {
        /* ignore */
      }
    }
  };
  const localHost = () => (bridge.bind === '0.0.0.0' || bridge.bind === '::' ? '127.0.0.1' : bridge.bind);

  function sendControl(value) {
    if (ws && ws.readyState === 1) ws.send(JSON.stringify(value));
  }
  function sendToChannel(ch, payload) {
    if (!ws || ws.readyState !== 1) return;
    const head = Buffer.alloc(4);
    head.writeUInt32BE(ch, 0);
    ws.send(Buffer.concat([head, payload]));
  }

  function connect() {
    if (stopped) return;
    const url = `${relayUrl}/v1/host?hostId=${encodeURIComponent(keys.hostId)}`;
    let socket;
    try {
      socket = new WebSocketImpl(url);
    } catch (error) {
      scheduleReconnect(error?.message ?? String(error));
      return;
    }
    socket.binaryType = 'arraybuffer';
    ws = socket;
    socket.addEventListener('message', (event) => {
      if (ws !== socket) return;
      if (typeof event.data === 'string') return onControl(event.data);
      const data = Buffer.from(event.data);
      if (data.length < 4) return;
      const ch = data.readUInt32BE(0);
      channels.get(ch)?.receive(data.subarray(4));
    });
    socket.addEventListener('close', (event) => {
      if (ws !== socket) return;
      ws = null;
      const wasOnline = online;
      online = false;
      for (const channel of channels.values()) channel.dispose('relay-closed');
      channels.clear();
      if (wasOnline) emit({ type: 'offline', code: event.code });
      if (event.code === 4003) log(`[relay] 中转拒绝了主机认证（${event.reason || 'bad signature'}）`);
      scheduleReconnect(event.reason || `code ${event.code}`);
    });
    socket.addEventListener('error', () => {
      /* close 事件会接着到达 */
    });
  }

  function scheduleReconnect(reason) {
    if (stopped) return;
    log(`[relay] 与中转断开（${reason}），${Math.round(retryMs / 1000)} 秒后重连`);
    clearTimeout(retryTimer);
    retryTimer = setTimeout(connect, retryMs);
    retryTimer.unref?.();
    retryMs = Math.min(RECONNECT_MAX_MS, retryMs * 2);
  }

  function onControl(text) {
    let msg;
    try {
      msg = JSON.parse(text);
    } catch {
      return;
    }
    if (msg.t === 'challenge') {
      sendControl({ t: 'hello', pub: keys.signPublic.toString('base64url'), sig: signChallenge(keys, String(msg.nonce)) });
    } else if (msg.t === 'ready') {
      online = true;
      retryMs = RECONNECT_MIN_MS;
      log(`[relay] 已连上中转 ${relayUrl}（hostId ${keys.hostId}）`);
      emit({ type: 'online' });
    } else if (msg.t === 'open') {
      const ch = Number(msg.ch);
      if (!Number.isInteger(ch) || ch <= 0) return;
      channels.get(ch)?.dispose('reopened');
      channels.set(ch, createChannel(ch));
    } else if (msg.t === 'close') {
      const ch = Number(msg.ch);
      channels.get(ch)?.dispose('client-closed');
      channels.delete(ch);
    }
  }

  // -------------------------------------------------------------------------
  // channel：一部手机的一条隧道
  // -------------------------------------------------------------------------

  function createChannel(ch) {
    const hs = new XKResponder({ staticKey: keys.noise });
    let step = 0; // 0 等 msg1，1 等 msg3，2 已建立
    let tx = null;
    let rx = null;
    let mode = '';
    let deviceId = '';
    let relayKey = '';
    let disposed = false;
    let lastActivity = Date.now();
    const reassembler = createReassembler();
    const muxes = new Map();
    const inflight = new Set();

    const handshakeTimer = setTimeout(() => kick('handshake-timeout'), handshakeTimeoutMs);
    handshakeTimer.unref?.();

    const audit = (reason, extra = {}) =>
      bridge.audit({ method: 'RELAY', path: `channel/${ch}`, decision: extra.decision ?? 'allow', reason, status: 0, remoteAddr: `relay:${ch}`, deviceId: deviceId || undefined });

    function kick(reason) {
      if (disposed) return;
      audit(reason, { decision: 'deny' });
      sendControl({ t: 'close-channel', ch, reason });
      channel.dispose(reason);
      channels.delete(ch);
    }

    function send(value) {
      if (disposed || !tx) return;
      const text = Buffer.from(JSON.stringify(value), 'utf8');
      for (const piece of fragment(text)) sendToChannel(ch, tx.encrypt(piece));
    }

    function receive(data) {
      if (disposed) return;
      lastActivity = Date.now();
      try {
        if (step === 0) {
          hs.readMessage1(data);
          sendToChannel(ch, hs.writeMessage2());
          step = 1;
          return;
        }
        if (step === 1) {
          hs.readMessage3(data);
          const result = hs.finish();
          tx = result.send;
          rx = result.recv;
          step = 2;
          clearTimeout(handshakeTimer);
          relayKey = result.remoteStatic.toString('base64url');
          const device = bridge.findDeviceByRelayKey(relayKey);
          if (device && device.revoked !== true) {
            mode = 'device';
            deviceId = device.id;
          } else {
            mode = 'pairing';
          }
          audit(`tunnel-${mode}`);
          send({ k: 'ready', mode, deviceId: deviceId || undefined, version: bridge.version });
          return;
        }
        const piece = rx.decrypt(data);
        const message = reassembler.push(piece);
        if (message) handleMessage(message);
      } catch (error) {
        // 2026-11-23 架构整改：握手失败要能区分责任方，App 才能给出正确动作。
        //  step 0 失败 = 手机用的主机公钥不对（host key 换过 / 扫了旧二维码）
        //  step 1 失败 = 手机自身静态密钥与主机登记不一致（重装、清数据、换机克隆）
        const reason = step < 2
          ? (step === 0 ? 'host-key-mismatch' : 'device-key-mismatch')
          : 'decrypt-failed';
        try { audit(`tunnel-${reason}`, { decision: 'deny', detail: String(error?.message ?? error).slice(0, 120) }); } catch { /* 尽力 */ }
        kick(reason);
      }
    }

    function handleMessage(buf) {
      let msg;
      try {
        msg = JSON.parse(buf.toString('utf8'));
      } catch {
        return kick('bad-frame');
      }
      if (!msg || typeof msg !== 'object') return kick('bad-frame');
      switch (msg.k) {
        case 'ping':
          return send({ k: 'pong' });
        case 'req':
          return void handleRequest(msg);
        case 'mux-open':
          return handleMuxOpen(msg);
        case 'mux': {
          const entry = muxes.get(String(msg.mid));
          if (!entry || typeof msg.text !== 'string') return undefined;
          if (entry.socket.readyState === 1) entry.socket.send(msg.text);
          else entry.queue.push(msg.text);
          return undefined;
        }
        case 'mux-close': {
          const entry = muxes.get(String(msg.mid));
          if (entry) {
            muxes.delete(String(msg.mid));
            try {
              entry.socket.close();
            } catch {
              /* ignore */
            }
          }
          return undefined;
        }
        default:
          return undefined;
      }
    }

    /** device 模式下：请求里的 token 必须属于握手认证出的那台设备。 */
    function tokenMatchesDevice(token) {
      if (mode !== 'device' || !token) return false;
      const device = bridge.lookupDevice(token);
      return Boolean(device && device.id === deviceId);
    }

    async function handleRequest(msg) {
      const id = msg.id;
      const method = String(msg.method ?? 'GET').toUpperCase();
      const reqPath = String(msg.path ?? '/');
      const headers = msg.headers && typeof msg.headers === 'object' ? msg.headers : {};
      const reply = (status, body) => send({ k: 'res', id, status, body });
      const localError = (status, code, message) =>
        reply(status, JSON.stringify({ ok: false, error: { code, message } }));

      if (!reqPath.startsWith('/') || reqPath.startsWith('//')) return localError(400, 'bridge/bad-request', '路径无效');
      const pathname = reqPath.split('?')[0];
      if (mode === 'pairing') {
        if (!PAIRING_ALLOWED.has(`${method} ${pathname}`)) {
          return localError(401, 'bridge/unauthorized', '这台手机还没有登录；请先扫码登录');
        }
      } else {
        const auth = String(headers.authorization ?? '');
        const token = auth.toLowerCase().startsWith('bearer ') ? auth.slice(7).trim() : '';
        // /dsbot/status 与 /dsbot/pair/redeem 无需 token（手机丢了本地登录时要能用新登录码重新登录，
        // 登录码本身就是凭据）；其余请求的 token 必须与隧道设备一致。
        if (!PAIRING_ALLOWED.has(`${method} ${pathname}`) && !tokenMatchesDevice(token)) {
          return localError(401, 'bridge/unauthorized', '设备令牌与本机隧道不匹配');
        }
      }

      const body = typeof msg.body === 'string' ? Buffer.from(msg.body, 'utf8') : null;
      const outHeaders = { 'x-dsbot-relay-channel': String(ch) };
      if (headers.authorization) outHeaders.authorization = String(headers.authorization);
      if (headers['content-type']) outHeaders['content-type'] = String(headers['content-type']);
      if (body) outHeaders['content-length'] = String(body.length);

      const pending = { req: null };
      inflight.add(pending);
      try {
        const { status, text } = await new Promise((resolve, reject) => {
          const req = http.request(
            { host: localHost(), port: bridge.port, method, path: reqPath, headers: outHeaders },
            (res) => {
              const chunks = [];
              let size = 0;
              res.on('data', (chunk) => {
                size += chunk.length;
                if (size > MAX_RESPONSE_BYTES) {
                  req.destroy(new Error('response too large'));
                  return;
                }
                chunks.push(chunk);
              });
              res.on('end', () => resolve({ status: res.statusCode ?? 502, text: Buffer.concat(chunks).toString('utf8') }));
              res.on('error', reject);
            },
          );
          pending.req = req;
          // 桥接到 DSH 本身有 30s 上游超时；这里再兜一层，任何卡住的本地请求都不会永久占着隧道。
          req.setTimeout(LOCAL_REQUEST_TIMEOUT_MS, () => req.destroy(new Error('local request timeout')));
          req.on('error', reject);
          if (body) req.write(body);
          req.end();
        });
        if (disposed) return undefined;
        if (method === 'POST' && pathname === '/dsbot/pair/redeem' && status === 200) {
          try {
            const parsed = JSON.parse(text);
            if (parsed?.ok && typeof parsed.deviceId === 'string') {
              bridge.bindRelayKey(parsed.deviceId, relayKey);
              mode = 'device';
              deviceId = parsed.deviceId;
              audit('tunnel-paired');
            }
          } catch {
            /* 响应不是 JSON：保持 pairing 模式 */
          }
        }
        return reply(status, text);
      } catch {
        if (disposed) return undefined;
        return localError(502, 'bridge/relay-local-failed', '桥接本地转发失败');
      } finally {
        inflight.delete(pending);
      }
    }

    function handleMuxOpen(msg) {
      const mid = String(msg.mid ?? '');
      const token = String(msg.token ?? '');
      const fail = (code) => send({ k: 'mux-closed', mid, code });
      if (!mid || muxes.has(mid)) return fail(4400);
      if (!tokenMatchesDevice(token)) return fail(4401);
      if (muxes.size >= MAX_MUX_PER_CHANNEL) return fail(4429);
      const url = `ws://${localHost()}:${bridge.port}/api/remote.mux?token=${encodeURIComponent(token)}`;
      let socket;
      try {
        socket = new WebSocketImpl(url);
      } catch {
        return fail(4502);
      }
      const entry = { socket, queue: [] };
      muxes.set(mid, entry);
      socket.addEventListener('open', () => {
        if (muxes.get(mid) !== entry) return;
        send({ k: 'mux-opened', mid });
        for (const text of entry.queue.splice(0)) socket.send(text);
      });
      socket.addEventListener('message', (event) => {
        if (muxes.get(mid) !== entry) return;
        const text = typeof event.data === 'string' ? event.data : Buffer.from(event.data).toString('utf8');
        send({ k: 'mux', mid, text });
      });
      socket.addEventListener('close', (event) => {
        if (muxes.get(mid) !== entry) return;
        muxes.delete(mid);
        send({ k: 'mux-closed', mid, code: event.code });
      });
      socket.addEventListener('error', () => {});
      return undefined;
    }

    const channel = {
      receive,
      get mode() {
        return mode;
      },
      get deviceId() {
        return deviceId;
      },
      get relayKey() {
        return relayKey;
      },
      /** 周期检查：设备被撤销 → 断开；pairing 通道闲置太久 → 断开。 */
      sweep(now = Date.now()) {
        if (disposed || step !== 2) return;
        if (mode === 'device') {
          const device = bridge.findDeviceByRelayKey(relayKey);
          if (!device || device.revoked === true || device.id !== deviceId) kick('device-revoked');
        } else if (now - lastActivity > pairingIdleMs) {
          kick('pairing-idle');
        }
      },
      dispose() {
        if (disposed) return;
        disposed = true;
        clearTimeout(handshakeTimer);
        for (const entry of muxes.values()) {
          try {
            entry.socket.close();
          } catch {
            /* ignore */
          }
        }
        muxes.clear();
        for (const pending of inflight) pending.req?.destroy();
        inflight.clear();
      },
    };
    return channel;
  }

  return {
    get hostId() {
      return keys.hostId;
    },
    get hpk() {
      return keys.hpk;
    },
    get relayUrl() {
      return relayUrl;
    },
    get online() {
      return online;
    },
    get channelCount() {
      return channels.size;
    },
    channels() {
      return [...channels.entries()].map(([ch, c]) => ({ ch, mode: c.mode, deviceId: c.deviceId }));
    },
    onEvent(fn) {
      listeners.add(fn);
      return () => listeners.delete(fn);
    },
    start() {
      stopped = false;
      connect();
      sweepTimer = setInterval(() => {
        for (const channel of channels.values()) channel.sweep();
      }, REVOKE_SWEEP_MS);
      sweepTimer.unref?.();
      return this;
    },
    /** 立即检查撤销（撤销设备的 API 调用后可直接调用，不必等定时器）。 */
    sweepNow() {
      for (const channel of channels.values()) channel.sweep();
    },
    async stop() {
      stopped = true;
      clearTimeout(retryTimer);
      clearInterval(sweepTimer);
      for (const channel of channels.values()) channel.dispose('stopped');
      channels.clear();
      const socket = ws;
      ws = null;
      online = false;
      if (socket) {
        try {
          socket.close();
        } catch {
          /* ignore */
        }
      }
    },
  };
}
