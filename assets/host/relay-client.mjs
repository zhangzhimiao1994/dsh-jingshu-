/**
 * 手机端中转隧道的 Node 参考实现（测试与 scripts/e2e-relay.mjs 共用；App 端 Kotlin 实现以它为准）。
 *
 *   const phone = await connectRelayClient({ relay, host, hpk, staticKey });
 *   await phone.ready;                       // {mode:'pairing'|'device', deviceId?}
 *   const res = await phone.request('POST', '/dsbot/pair/redeem', { body: {...} });
 *   const mux = phone.openMux(token);        // mux.send(text) / mux.onMessage / mux.close()
 */
import { XKInitiator, createReassembler, fragment, generateKeyPair } from './noise.mjs';

export function connectRelayClient(options) {
  const {
    relay,
    host,
    hpk,
    staticKey = generateKeyPair(),
    WebSocketImpl = globalThis.WebSocket,
    timeoutMs = 10_000,
  } = options;
  const ws = new WebSocketImpl(`${relay}/v1/client?hostId=${encodeURIComponent(host)}`);
  ws.binaryType = 'arraybuffer';
  const hs = new XKInitiator({ staticKey, remoteStatic: Buffer.from(hpk, 'base64url') });
  let step = 0; // 0 等 host-online，1 等 msg2，2 等 ready，3 已就绪
  let tx = null;
  let rx = null;
  let nextId = 1;
  const pending = new Map();
  const muxes = new Map();
  const reassembler = createReassembler();
  const controls = [];
  let closeInfo = null;

  let resolveReady;
  let rejectReady;
  const ready = new Promise((resolve, reject) => {
    resolveReady = resolve;
    rejectReady = reject;
  });
  ready.catch(() => {});
  const readyTimer = setTimeout(() => rejectReady(new Error('relay client: 等待隧道就绪超时')), timeoutMs);
  readyTimer.unref?.();

  let resolveClosed;
  const closed = new Promise((resolve) => {
    resolveClosed = resolve;
  });

  function sendApp(value) {
    const text = Buffer.from(JSON.stringify(value), 'utf8');
    for (const piece of fragment(text)) ws.send(tx.encrypt(piece));
  }

  ws.addEventListener('message', (event) => {
    if (typeof event.data === 'string') {
      const msg = JSON.parse(event.data);
      controls.push(msg);
      if (msg.t === 'host-online' && step === 0) {
        ws.send(hs.writeMessage1());
        step = 1;
      }
      return;
    }
    const data = Buffer.from(event.data);
    try {
      if (step === 1) {
        hs.readMessage2(data);
        ws.send(hs.writeMessage3());
        const result = hs.finish();
        tx = result.send;
        rx = result.recv;
        step = 2;
        return;
      }
      if (step < 2) return;
      const message = reassembler.push(rx.decrypt(data));
      if (!message) return;
      const msg = JSON.parse(message.toString('utf8'));
      if (msg.k === 'ready') {
        step = 3;
        clearTimeout(readyTimer);
        resolveReady(msg);
      } else if (msg.k === 'res') {
        const entry = pending.get(msg.id);
        if (entry) {
          pending.delete(msg.id);
          let json = null;
          try {
            json = JSON.parse(msg.body);
          } catch {
            json = null;
          }
          entry.resolve({ status: msg.status, body: msg.body, json });
        }
      } else if (msg.k === 'mux-opened' || msg.k === 'mux' || msg.k === 'mux-closed') {
        const mux = muxes.get(msg.mid);
        if (!mux) return;
        if (msg.k === 'mux-opened') mux._opened();
        else if (msg.k === 'mux') mux.onMessage(msg.text);
        else {
          muxes.delete(msg.mid);
          mux._closed(msg.code);
        }
      }
    } catch (error) {
      rejectReady(error);
      ws.close();
    }
  });
  ws.addEventListener('close', (event) => {
    closeInfo = { code: event.code, reason: event.reason };
    clearTimeout(readyTimer);
    rejectReady(new Error(`relay client: 连接关闭 ${event.code} ${event.reason}`));
    for (const entry of pending.values()) entry.reject(new Error(`连接关闭 ${event.code}`));
    pending.clear();
    for (const mux of muxes.values()) mux._closed(event.code);
    muxes.clear();
    resolveClosed(closeInfo);
  });
  ws.addEventListener('error', () => {});

  return {
    ready,
    closed,
    controls,
    staticKey,
    get closeInfo() {
      return closeInfo;
    },
    request(method, path, { token, body, timeout = timeoutMs } = {}) {
      return new Promise((resolve, reject) => {
        if (step !== 3) {
          reject(new Error('隧道未就绪'));
          return;
        }
        const id = nextId;
        nextId += 1;
        const timer = setTimeout(() => {
          pending.delete(id);
          reject(new Error(`请求超时 ${method} ${path}`));
        }, timeout);
        timer.unref?.();
        pending.set(id, {
          resolve: (value) => {
            clearTimeout(timer);
            resolve(value);
          },
          reject: (error) => {
            clearTimeout(timer);
            reject(error);
          },
        });
        const headers = {};
        if (token) headers.authorization = `Bearer ${token}`;
        if (body !== undefined) headers['content-type'] = 'application/json';
        sendApp({
          k: 'req',
          id,
          method,
          path,
          headers,
          body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body),
        });
      });
    },
    openMux(token) {
      const mid = `m${nextId}`;
      nextId += 1;
      let resolveOpen;
      let rejectOpen;
      const opened = new Promise((resolve, reject) => {
        resolveOpen = resolve;
        rejectOpen = reject;
      });
      opened.catch(() => {});
      const mux = {
        mid,
        opened,
        onMessage: () => {},
        onClose: () => {},
        send(text) {
          sendApp({ k: 'mux', mid, text });
        },
        close() {
          sendApp({ k: 'mux-close', mid });
        },
        _opened: () => resolveOpen(mid),
        _closed: (code) => {
          rejectOpen(new Error(`mux closed ${code}`));
          mux.onClose(code);
        },
      };
      muxes.set(mid, mux);
      sendApp({ k: 'mux-open', mid, token });
      return mux;
    },
    send: (value) => sendApp(value),
    close() {
      ws.close();
    },
  };
}
