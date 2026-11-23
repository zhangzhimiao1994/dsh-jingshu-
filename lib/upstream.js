/**
 * dsh-dsbot-host — DSH 上游探测（upstream.js）。
 *
 * 要解决的问题：DSH 每次启动都会换一个随机回环端口，桌面版和 `dsh web` 命令行版都可能
 * 同时存在；桥接必须知道「上游在哪、是哪种形态」。本模块只做这件事：
 *   找出本机正在跑的 DeepSeek Harness Web 后端，并区分
 *     - desktop：桌面版 DSH（Electron，进程名 `DeepSeek Harness`）
 *     - cli    ：`dsh web` 命令行后端（node / dsh）
 *
 * 做法（形态判定思路沿用桥接的 dsh-discover.mjs）：
 *   1. 候选端口 = 常见起步端口（3080 / 53255 / 58235）+ 49000-65000 等距抽样
 *      + 本机监听端口表（只收 DSH 相关进程，或进程名解析不出来的那些）。
 *   2. 每个端口 POST 一次 `/api/session/list`，单端口超时 300ms；
 *      返回 200 且响应体是 JSON → 认定可用（ok:true）。
 *   3. 端口归属进程决定 desktop / cli（Windows: netstat + tasklist；POSIX: lsof）。
 *
 * 约定：
 *   - 只用 Node 内置模块，ESM。
 *   - 端口不通 / 命令失败 / 超时 / 响应不是 JSON 一律静默跳过，**永远不抛异常**。
 *   - 只探测 127.0.0.1。
 *
 * 关于鉴权（实测 2026-11-09）：DSH 的 `/api/*` 需要浏览器会话 cookie，未鉴权请求
 * `POST /api/session/list` 固定回 `401 unauthorized`，此时按定义 ok:false。
 * 若调用方手里有可用凭据（例如桥接自己签的 cookie），可传 `options.headers`
 * （如 `{ cookie: '...' }`），请求带上后才会拿到 200 + JSON。
 * 拿不到凭据又想知道「上游在不在」时，可显式传 `acceptAuthWall: true`：
 * 把 401 且正文恰为 `unauthorized` 的端口也算作「探测到」（默认关闭，不改默认语义）。
 */

import http from 'node:http';
import { execFile } from 'node:child_process';

/* ------------------------------------------------------------------ *
 * 常量
 * ------------------------------------------------------------------ */

/** 桌面版 DSH（Electron）。 */
export const DSH_KIND_DESKTOP = 'desktop';
/** `dsh web` 命令行后端（node / dsh）。 */
export const DSH_KIND_CLI = 'cli';
/** 探测到了服务，但归属进程名解析不出来。 */
export const DSH_KIND_UNKNOWN = 'unknown';

/** 常见起步端口：不做端口枚举也能先试这几个。 */
export const KNOWN_PORTS = Object.freeze([3080, 53255, 58235]);

/** 高速抽样范围（DSH 端口主要由这里出）。 */
export const SWEEP_RANGE = Object.freeze([49000, 65000]);
/** 抽样步长：默认 500，即 49000..65000 取 33 个点。 */
export const DEFAULT_SWEEP_STEP = 500;

/** 单端口探测超时（硬上限，不是 socket 空闲超时）。 */
export const DEFAULT_PROBE_TIMEOUT_MS = 300;
/** 并发探测数；本机监听端口一般几十个。 */
export const DEFAULT_CONCURRENCY = 24;

/** 探测端点：只读的会话列表 RPC。 */
export const PROBE_PATH = '/api/session/list';
/** 单次响应最多读这么多字节，够判定 JSON 即可。 */
const MAX_BODY_BYTES = 32 * 1024;

/* ------------------------------------------------------------------ *
 * 小工具
 * ------------------------------------------------------------------ */

/**
 * 正数兜底。
 * @param {unknown} value
 * @param {number} fallback
 * @returns {number}
 */
function positive(value, fallback) {
  const num = Number(value);
  return Number.isFinite(num) && num > 0 ? num : fallback;
}

/**
 * 简单并发池（结果保持输入顺序）。
 * @template T, R
 * @param {T[]} items
 * @param {number} limit
 * @param {(item: T, index: number) => Promise<R>} worker
 * @returns {Promise<R[]>}
 */
async function mapLimit(items, limit, worker) {
  const results = new Array(items.length);
  let next = 0;
  const size = Math.max(1, Math.min(Math.floor(limit) || 1, items.length || 1));
  const runners = new Array(size).fill(0).map(async () => {
    for (;;) {
      const index = next++;
      if (index >= items.length) return;
      results[index] = await worker(items[index], index);
    }
  });
  await Promise.all(runners);
  return results;
}

/**
 * 跑一条命令拿 stdout。**永不抛异常**，失败返回空串。
 * @param {string} command
 * @param {string[]} args
 * @param {number} [timeoutMs]
 * @returns {Promise<string>}
 */
function runCommand(command, args, timeoutMs = 4000) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      resolve(value);
    };
    try {
      execFile(
        command,
        args,
        { windowsHide: true, timeout: timeoutMs, maxBuffer: 8 * 1024 * 1024, encoding: 'utf8' },
        (error, stdout) => finish(error ? '' : String(stdout ?? '')),
      );
    } catch {
      finish('');
    }
  });
}

/* ------------------------------------------------------------------ *
 * 输出解析：netstat / lsof / tasklist
 * ------------------------------------------------------------------ */

/**
 * 解析 `netstat -ano -p TCP`，返回回环或通配地址上 LISTENING 的 `{port, pid, processName}`。
 * netstat 不给进程名，processName 先留空，由 tasklist 补齐。
 * @param {string} text
 * @returns {{port: number, pid: number, processName: string}[]}
 */
export function parseNetstatEntries(text) {
  const entries = [];
  for (const line of String(text ?? '').split(/\r?\n/)) {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 5) continue;
    if (parts[0].toUpperCase() !== 'TCP' || parts[3].toUpperCase() !== 'LISTENING') continue;
    // DSH 可能绑 127.0.0.1，也可能绑 0.0.0.0 / [::]（桌面版就是）
    const match = /^(?:127\.0\.0\.1|0\.0\.0\.0|\[::\]|\[::1\]):(\d+)$/.exec(parts[1]);
    if (!match) continue;
    const pid = Number(parts[4]);
    entries.push({ port: Number(match[1]), pid: Number.isFinite(pid) ? pid : 0, processName: '' });
  }
  return entries;
}

/**
 * 解析 `tasklist /FO CSV /NH`，返回 Map<pid, 进程名>。
 * 单个 PID 查不到（权限/位宽过滤）时该端口在表里就不出现，上层按「名字未知」处理。
 * @param {string} text
 * @returns {Map<number, string>}
 */
export function parseTasklistMap(text) {
  const map = new Map();
  for (const line of String(text ?? '').split(/\r?\n/)) {
    const cells = line.match(/"([^"]*)"/g)?.map((cell) => cell.slice(1, -1));
    if (!cells || cells.length < 2) continue;
    const pid = Number(cells[1]);
    if (Number.isFinite(pid) && pid > 0) map.set(pid, cells[0]);
  }
  return map;
}

/**
 * 解析 `lsof -nP -iTCP -sTCP:LISTEN -Fpcn`（macOS / Linux），返回 `{port, pid, processName}`。
 * lsof 自带进程名，POSIX 上不用再查进程表。
 * @param {string} text
 * @returns {{port: number, pid: number, processName: string}[]}
 */
export function parseLsofEntries(text) {
  const entries = [];
  let current = { pid: 0, processName: '' };
  let port = 0;
  const pushPort = () => {
    if (port > 0) entries.push({ port, pid: current.pid, processName: current.processName });
    port = 0;
  };
  for (const line of String(text ?? '').split(/\r?\n/)) {
    if (line.startsWith('p')) {
      pushPort();
      current = { pid: Number(line.slice(1)) || 0, processName: '' };
    } else if (line.startsWith('c')) {
      current.processName = line.slice(1);
    } else if (line.startsWith('n')) {
      const match = /^n(?:127\.0\.0\.1|localhost|\*|\[::1?\]):(\d+)$/.exec(line);
      if (match) {
        pushPort();
        port = Number(match[1]);
      }
    }
  }
  pushPort();
  return entries;
}

/* ------------------------------------------------------------------ *
 * 进程身份：只有它能区分 desktop 与 cli
 * ------------------------------------------------------------------ */

/**
 * 是不是「值得问一句」的 DSH 相关进程名（避免打扰本机其它服务）。
 * @param {string} name
 * @returns {boolean}
 */
export function isDshProcessName(name) {
  const n = String(name ?? '').toLowerCase();
  if (!n) return false;
  return (
    n.includes('deepseek harness') ||
    n.startsWith('deepseek') ||
    n === 'dsh' ||
    n === 'dsh.exe' ||
    n === 'node' ||
    n === 'node.exe' ||
    n.includes('electron')
  );
}

/**
 * 按进程名判定 DSH 形态。
 * @param {string} processName
 * @returns {'desktop'|'cli'|'unknown'}
 */
export function classifyProcess(processName) {
  const n = String(processName ?? '').toLowerCase();
  if (n.includes('deepseek harness') || n.includes('electron') || n.startsWith('deepseek')) {
    return DSH_KIND_DESKTOP;
  }
  if (n === 'node' || n === 'node.exe' || n === 'dsh' || n === 'dsh.exe') return DSH_KIND_CLI;
  return DSH_KIND_UNKNOWN;
}

/** 当前进程自己的形态：插件跑在 DSH 里时用它兜底。 */
function selfKind() {
  if (process.versions?.electron) return DSH_KIND_DESKTOP;
  const exe = String(process.execPath ?? '').toLowerCase();
  if (exe.includes('deepseek harness') || exe.includes('electron')) return DSH_KIND_DESKTOP;
  if (/(^|[\\/])node(\.exe)?$/.test(exe) || /(^|[\\/])dsh(\.exe)?$/.test(exe)) return DSH_KIND_CLI;
  return DSH_KIND_UNKNOWN;
}

/**
 * 枚举本机监听端口（Windows: netstat + tasklist；POSIX: lsof）。
 * 命令不可用 / 被沙箱拦 / 超时都返回空表，**不抛异常**。
 * @returns {Promise<{source: string, entries: {port: number, pid: number, processName: string}[]}>}
 */
async function listListeners() {
  try {
    if (process.platform === 'win32') {
      const [netstat, tasklist] = await Promise.all([
        runCommand('netstat', ['-ano', '-p', 'TCP']),
        runCommand('tasklist', ['/FO', 'CSV', '/NH']),
      ]);
      const names = parseTasklistMap(tasklist);
      const entries = parseNetstatEntries(netstat);
      for (const entry of entries) entry.processName = names.get(entry.pid) ?? '';
      return { source: entries.length > 0 ? 'netstat+tasklist' : 'none', entries };
    }
    const lsof = await runCommand('lsof', ['-nP', '-iTCP', '-sTCP:LISTEN', '-Fpcn']);
    const entries = parseLsofEntries(lsof);
    return { source: entries.length > 0 ? 'lsof' : 'none', entries };
  } catch {
    return { source: 'none', entries: [] };
  }
}

/* ------------------------------------------------------------------ *
 * 候选端口
 * ------------------------------------------------------------------ */

/**
 * 49000-65000 等距抽样端口。
 * @param {number} [sampleStep]
 * @returns {number[]}
 */
export function sampleSweepPorts(sampleStep = DEFAULT_SWEEP_STEP) {
  const step = Math.max(1, Math.floor(positive(sampleStep, DEFAULT_SWEEP_STEP)));
  const [from, to] = SWEEP_RANGE;
  const ports = [];
  for (let port = from; port <= to; port += step) ports.push(port);
  return ports;
}

/**
 * 组装候选端口：常见端口 + 抽样（可选）+ 值得问的监听端口。
 * @param {{port: number, pid?: number, processName?: string}[]} listeners
 * @param {{sweep?: boolean, sampleStep?: number}} [options]
 * @returns {{port: number, pid: number, processName: string}[]}
 */
export function buildCandidatePorts(listeners, options = {}) {
  const picked = new Map();
  const add = (port, extra = {}) => {
    const num = Number(port);
    if (!Number.isInteger(num) || num <= 0 || num > 65535) return;
    picked.set(num, { port: num, pid: 0, processName: '', ...picked.get(num), ...extra });
  };

  for (const port of KNOWN_PORTS) add(port);

  const sweep = options.sweep !== false;
  if (sweep) for (const port of sampleSweepPorts(options.sampleStep)) add(port);

  // 监听端口表是「不抽样也能命中」的关键；只留 DSH 相关进程，
  // 进程名解析不出来（拿不到 tasklist）的也留下，宁可多问一句也别漏掉真上游。
  for (const entry of listeners ?? []) {
    if (entry?.processName && !isDshProcessName(entry.processName)) continue;
    add(entry?.port, { pid: Number(entry?.pid) || 0, processName: String(entry?.processName ?? '') });
  }

  return [...picked.values()].sort((a, b) => a.port - b.port);
}

/* ------------------------------------------------------------------ *
 * 探测：POST /api/session/list
 * ------------------------------------------------------------------ */

/**
 * 响应体是不是合法 JSON（空体不算）。
 * @param {string} text
 * @returns {boolean}
 */
export function isJsonText(text) {
  const trimmed = String(text ?? '').trim();
  if (!trimmed) return false;
  try {
    JSON.parse(trimmed);
    return true;
  } catch {
    return false;
  }
}

/**
 * 探测单个端口：`POST /api/session/list`，200 且响应体是 JSON → 可用。
 * 超时 / 连接失败 / 非 200 / 非 JSON 全部解析成 `{ok:false}`，**不抛异常**。
 *
 * @param {number} port
 * @param {{timeoutMs?: number, headers?: Record<string, string>}} [options]
 * @returns {Promise<{port: number, ok: boolean, status: number, reason: string}>}
 */
export function probeSessionList(port, options = {}) {
  const portNum = Number(port);
  if (!Number.isInteger(portNum) || portNum <= 0 || portNum > 65535) {
    return Promise.resolve({ port: 0, ok: false, status: 0, reason: 'bad-port' });
  }

  const timeoutMs = positive(options.timeoutMs, DEFAULT_PROBE_TIMEOUT_MS);
  const body = JSON.stringify({
    type: 'client-request',
    rpcId: `dsbot-upstream-${portNum}`,
    method: 'session/list',
    payload: { args: {} },
  });

  return new Promise((resolve) => {
    let settled = false;
    let req = null;
    let timer = null;

    const done = (ok, reason, status) => {
      if (settled) return;
      settled = true;
      if (timer) { clearTimeout(timer); timer = null; }
      if (req) { try { req.destroy(); } catch { /* ignore */ } }
      resolve({ port: portNum, ok, status: Number(status) || 0, reason });
    };

    // 300ms 是**总**预算：DSH 忙碌时响应可能迟迟不结束，不能只靠 socket 空闲超时
    timer = setTimeout(() => done(false, 'timeout', 0), timeoutMs);

    try {
      req = http.request(
        {
          host: '127.0.0.1',
          port: portNum,
          method: 'POST',
          path: PROBE_PATH,
          agent: false,
          headers: {
            host: `127.0.0.1:${portNum}`,
            connection: 'close',
            'content-type': 'application/json; charset=utf-8',
            'content-length': Buffer.byteLength(body),
            ...(options.headers ?? {}),
          },
        },
        (res) => {
          const status = res.statusCode ?? 0;
          const contentType = String(res.headers['content-type'] ?? '').toLowerCase();
          let text = '';

          res.setEncoding('utf8');
          res.on('data', (chunk) => {
            if (settled) return;
            if (text.length < MAX_BODY_BYTES) text += chunk;
            // 大响应（会话多时 session/list 可上 MB）不必等传完：
            // 200 + JSON content-type + 首个非空字符是 { 或 [，已经满足判定。
            const head = text.trimStart();
            if (status === 200 && contentType.includes('json') && /^[[{]/.test(head)) {
              done(true, 'json', status);
            }
          });
          res.on('end', () => {
            if (settled) return;
            if (status === 401 && text.trim().toLowerCase() === 'unauthorized') {
              // DSH 的 /api 鉴权层固定应答；本身不是「可用」，由 acceptAuthWall 决定怎么算
              return done(false, 'auth-wall', status);
            }
            if (status !== 200) return done(false, `http-${status}`, status);
            return isJsonText(text) ? done(true, 'json', status) : done(false, 'not-json', status);
          });
          res.on('error', () => done(false, 'response-error', status));
        },
      );
      req.on('error', (error) => {
        // 端口没开是最常见的情况，静默跳过
        done(false, error?.code === 'ECONNREFUSED' ? 'refused' : 'network-error', 0);
      });
      req.end(body);
    } catch {
      done(false, 'request-error', 0);
    }
  });
}

/* ------------------------------------------------------------------ *
 * 主入口
 * ------------------------------------------------------------------ */

/**
 * 从存活端口里按形态挑代表（同形态多个实例取端口最小的）。
 * @param {{port: number, kind: string}[]} alive
 * @param {'desktop'|'cli'} kind
 * @returns {{port: number, ok: boolean}|null}
 */
function pickKind(alive, kind) {
  const found = alive.filter((entry) => entry.kind === kind).sort((a, b) => a.port - b.port)[0];
  return found ? { port: found.port, ok: true } : null;
}

/**
 * 探测本机 DSH 上游。
 *
 * @param {{
 *   timeoutMs?: number,
 *   concurrency?: number,
 *   sweep?: boolean,
 *   sampleStep?: number,
 *   headers?: Record<string, string>,
 *   acceptAuthWall?: boolean,
 *   listeners?: {port: number, pid?: number, processName?: string}[],
 *   probe?: (port: number, options: object) => Promise<object>,
 * }} [options] 测试可注入 listeners / probe；headers 用于带鉴权 cookie。
 * @returns {Promise<{
 *   desktop: {port: number, ok: boolean} | null,
 *   cli: {port: number, ok: boolean} | null,
 *   candidates: number[],
 * }>}
 */
export async function discoverUpstream(options = {}) {
  try {
    const timeoutMs = positive(options.timeoutMs, DEFAULT_PROBE_TIMEOUT_MS);
    const concurrency = positive(options.concurrency, DEFAULT_CONCURRENCY);
    const probe = typeof options.probe === 'function' ? options.probe : probeSessionList;

    const listeners = Array.isArray(options.listeners)
      ? options.listeners
        .map((entry) => ({
          port: Number(entry?.port) || 0,
          pid: Number(entry?.pid) || 0,
          processName: String(entry?.processName ?? ''),
        }))
        .filter((entry) => entry.port > 0)
      : (await listListeners()).entries;

    const candidates = buildCandidatePorts(listeners, options);
    const acceptAuthWall = options.acceptAuthWall === true;

    const probed = await mapLimit(candidates, concurrency, async (entry) => {
      let result;
      try {
        result = await probe(entry.port, { timeoutMs, headers: options.headers });
      } catch {
        result = { ok: false };
      }
      const alive = result?.ok === true || (acceptAuthWall && result?.reason === 'auth-wall');
      return { entry, alive };
    });

    const alive = probed
      .filter((item) => item.alive)
      .map((item) => {
        let kind = classifyProcess(item.entry.processName);
        // 插件自己就跑在 DSH 里时，进程名可能拿不到，用自身形态兜底
        if (kind === DSH_KIND_UNKNOWN && item.entry.pid > 0 && item.entry.pid === process.pid) {
          kind = selfKind();
        }
        return { port: item.entry.port, kind };
      })
      .sort((a, b) => a.port - b.port);

    const desktop = pickKind(alive, DSH_KIND_DESKTOP);
    let cli = pickKind(alive, DSH_KIND_CLI);

    // 进程名解析不出来（受限权限下很常见）时，未知形态的实例按端口顺序补到空槽位，
    // 宁可让调用方看见端口，也不要静默报「没找到」。
    if (!cli) {
      const unknown = alive.find((entry) => entry.kind === DSH_KIND_UNKNOWN && entry.port !== desktop?.port);
      if (unknown) cli = { port: unknown.port, ok: true };
    }

    return { desktop, cli, candidates: candidates.map((entry) => entry.port) };
  } catch {
    // 兜底：任何意外都给出「什么都没找到」的合法结构
    return { desktop: null, cli: null, candidates: [] };
  }
}
