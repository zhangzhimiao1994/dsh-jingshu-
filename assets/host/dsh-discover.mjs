/**
 * 自动查找本机所有 DSH Web 后端（DeepSeek Harness 每次启动都会换一个随机端口）。
 *
 * 背景（2026-10-31）：旧实现只按进程镜像名「DeepSeek Harness」过滤端口，只能发现**桌面版**
 * Electron 里的 DSH Web；用户用 `dsh web` 起在终端里的后端是 node.exe，永远发现不了，
 * 于是桥接在「只有 dsh web」或「桌面版重启换端口」时与上游失联，手机侧表现为 502。
 *
 * 新做法：枚举所有本机 127.0.0.1 监听端口（只保留 node / dsh / DeepSeek Harness / Electron
 * 这几类进程，避免扫到无关服务），用桥接自己签的浏览器 cookie 逐个请求只读的 `session/list`，
 * 返回 `server-response` 的就是 DSH Web。返回**全部**实例，并按类型标注：
 *   - desktop：桌面版 DeepSeek Harness（Electron）
 *   - cli    ：`dsh web` 命令行后端（node/dsh）
 *
 * 只探测本机回环地址、只发只读请求；桥接自己的端口因为没有设备 token 会 401，不会被误判。
 */
import { execFile } from 'node:child_process';
import http from 'node:http';

export const DSH_PROCESS_NAME = 'DeepSeek Harness';
/** session/list 可能很大、DSH 忙碌时也慢；单端口探测默认 1.2 秒。 */
export const PROBE_TIMEOUT_MS = Number(process.env.DSBOT_PROBE_TIMEOUT_MS) > 0
  ? Number(process.env.DSBOT_PROBE_TIMEOUT_MS)
  : 6_000;
/** 并发探测数：本机监听端口通常 < 30 个，6 路足够快也够温和。 */
export const PROBE_CONCURRENCY = 6;
/** 类型标签。 */
export const DSH_KIND_DESKTOP = 'desktop';
export const DSH_KIND_CLI = 'cli';
export const DSH_KIND_UNKNOWN = 'unknown';

const KIND_LABELS = {
  [DSH_KIND_DESKTOP]: '桌面版 DeepSeek Harness',
  [DSH_KIND_CLI]: 'dsh web（命令行）',
  [DSH_KIND_UNKNOWN]: 'DSH Web（未知类型）',
};

/** 只有这些进程占用回环端口的候选才值得探测（避免打扰本机其它服务）。 */
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

/** 按进程名判断后端类型。 */
export function classifyDshProcess(processName) {
  const n = String(processName ?? '').toLowerCase();
  if (n.includes('deepseek harness') || n.includes('electron')) return DSH_KIND_DESKTOP;
  if (n === 'node' || n === 'node.exe' || n === 'dsh' || n === 'dsh.exe') return DSH_KIND_CLI;
  return DSH_KIND_UNKNOWN;
}

export function dshKindLabel(kind) {
  return KIND_LABELS[kind] ?? KIND_LABELS[DSH_KIND_UNKNOWN];
}

function run(command, args) {
  return new Promise((resolve) => {
    execFile(command, args, { windowsHide: true, maxBuffer: 8 * 1024 * 1024 }, (error, stdout) => {
      resolve(error ? '' : String(stdout));
    });
  });
}

/** 解析 `tasklist /FO CSV /NH`，返回镜像名包含 [name] 的 PID（兼容旧接口）。 */
export function parseTasklist(text, name = DSH_PROCESS_NAME) {
  const pids = new Set();
  for (const [pid, image] of parseTasklistMap(text)) {
    if (image.toLowerCase().includes(name.toLowerCase())) pids.add(pid);
  }
  return pids;
}

/** 解析 `tasklist /FO CSV /NH`，返回 Map<pid, 镜像名>。 */
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

/** 解析 `netstat -ano -p TCP`，返回 [pids] 在 127.0.0.1 上 LISTENING 的端口（兼容旧接口）。 */
export function parseNetstat(text, pids) {
  return parseNetstatEntries(text)
    .filter((entry) => pids.has(entry.pid))
    .map((entry) => entry.port);
}

/** 解析 `netstat -ano -p TCP`，返回 [{port, pid}]（仅 127.0.0.1 LISTENING）。 */
export function parseNetstatEntries(text) {
  const entries = [];
  for (const line of String(text ?? '').split(/\r?\n/)) {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 5) continue;
    if (parts[0].toUpperCase() !== 'TCP' || parts[3].toUpperCase() !== 'LISTENING') continue;
    // DSH Web 可能绑 0.0.0.0（桌面版就是），不能只认 127.0.0.1
    const match = /^(?:127\.0\.0\.1|0\.0\.0\.0|\[::\]|\[::1\]):(\d+)$/.exec(parts[1]);
    if (!match) continue;
    const pid = Number(parts[4]);
    entries.push({ port: Number(match[1]), pid: Number.isFinite(pid) ? pid : 0 });
  }
  return entries;
}

/** 解析 `lsof -nP -iTCP -sTCP:LISTEN -Fpcn`（macOS/Linux），返回 [{port, pid, command}]。 */
export function parseLsofEntries(text) {
  const byPid = new Map();
  let current = { pid: 0, command: '' };
  for (const line of String(text ?? '').split(/\r?\n/)) {
    if (line.startsWith('p')) {
      current = { pid: Number(line.slice(1)) || 0, command: '' };
      byPid.set(current.pid, current);
    } else if (line.startsWith('c')) {
      current.command = line.slice(1);
    } else if (line.startsWith('n')) {
      const match = /^n(?:127\.0\.0\.1|localhost):(\d+)$/.exec(line);
      if (match) current.port = Number(match[1]);
    }
  }
  const out = [];
  for (const item of byPid.values()) {
    if (item.port) out.push({ port: item.port, pid: item.pid, command: item.command });
  }
  return out;
}

/** 解析 `lsof ... -Fpcn`（兼容旧接口）：只取 DeepSeek Harness 进程的端口。 */
export function parseLsof(text, name = DSH_PROCESS_NAME) {
  return parseLsofEntries(text)
    .filter((entry) => entry.command.toLowerCase().includes(name.toLowerCase()))
    .map((entry) => entry.port);
}

/** 深度合并后的候选端点：[{port, pid, processName, kind, label}]。 */
export async function listDshCandidateEndpoints({ excludePorts = [] } = {}) {
  const excluded = new Set((excludePorts ?? []).map(Number).filter((n) => n > 0));
  if (process.platform === 'win32') {
    const names = parseTasklistMap(await run('tasklist', ['/FO', 'CSV', '/NH']));
    const entries = parseNetstatEntries(await run('netstat', ['-ano', '-p', 'TCP']));
    const out = [];
    for (const entry of entries) {
      if (excluded.has(entry.port)) continue;
      const processName = names.get(entry.pid) ?? '';
      if (!isDshProcessName(processName)) continue;
      const kind = classifyDshProcess(processName);
      out.push({ port: entry.port, pid: entry.pid, processName, kind, label: dshKindLabel(kind) });
    }
    return out;
  }
  const entries = parseLsofEntries(await run('lsof', ['-nP', '-iTCP', '-sTCP:LISTEN', '-Fpcn']));
  const out = [];
  for (const entry of entries) {
    if (excluded.has(entry.port)) continue;
    const processName = entry.command ?? '';
    if (!isDshProcessName(processName)) continue;
    const kind = classifyDshProcess(processName);
    out.push({ port: entry.port, pid: entry.pid, processName, kind, label: dshKindLabel(kind) });
  }
  return out;
}

/**
 * 用只读的 session/list 判断 [authority] 是否是 DSH Web。
 * @param {(authority: string) => string} cookieFor 返回该 authority 的 `name=value` cookie
 * @param {{timeoutMs?: number}} [options]
 */
export function probeDsh(authority, cookieFor, options = {}) {
  const timeoutMs = Number(options.timeoutMs) > 0 ? Number(options.timeoutMs) : PROBE_TIMEOUT_MS;
  const [host, port] = authority.split(':');
  // 用最轻的只读端点做存活探测：`session/modelCatalog` 实测 ~10ms/9KB，
  // 而 `session/list` 在会话多/DSH 忙时要 2.5s~3s 且响应几十 MB 级——
  // 用它探测会让「正在跑的 DSH」被误判为超时，进而扫不到后端（端口漂移就跟不上）。
  const body = JSON.stringify({ type: 'client-request', rpcId: 'dsbot-discover', method: 'session/modelCatalog', payload: { args: {} } });
  return new Promise((resolve) => {
    const req = http.request(
      {
        host,
        port: Number(port),
        method: 'POST',
        path: '/api/session/modelCatalog',
        headers: {
          host: authority,
          origin: `http://${authority}`,
          cookie: cookieFor(authority),
          'content-type': 'application/json',
          'content-length': Buffer.byteLength(body),
        },
        timeout: timeoutMs,
      },
      (res) => {
        let text = '';
        let settled = false;
        const finish = (value) => {
          if (settled) return;
          settled = true;
          resolve(value);
          // 判定成功就立刻断开：session/list 的响应可能有几 MB（忙的时候 3s+），
          // 等它传完才能判定会让探测超时，进而「扫不到正在跑的 DSH」。
          try { req.destroy(); } catch { /* ignore */ }
          try { res.destroy(); } catch { /* ignore */ }
        };
        res.setEncoding('utf8');
        res.on('data', (chunk) => {
          if (settled) return;
          if (text.length < 4096) text += chunk;
          if (text.includes('"server-response"')) finish(res.statusCode === 200);
        });
        res.on('end', () => {
          res.resume();
          finish(res.statusCode === 200 && text.includes('"server-response"'));
        });
        res.on('error', () => finish(false));
      },
    );
    req.on('timeout', () => req.destroy());
    req.on('error', () => resolve(false));
    req.end(body);
  });
}

/** 简单的并发池。 */
async function mapLimit(items, limit, worker) {
  const results = new Array(items.length);
  let next = 0;
  const runners = new Array(Math.min(limit, items.length)).fill(0).map(async () => {
    for (;;) {
      const index = next++;
      if (index >= items.length) return;
      results[index] = await worker(items[index], index);
    }
  });
  await Promise.all(runners);
  return results;
}

function normalizeEndpoint(candidate) {
  if (typeof candidate === 'number') return { port: candidate, pid: 0, processName: '', kind: DSH_KIND_UNKNOWN };
  if (typeof candidate === 'string') {
    const port = Number(candidate.split(':').pop());
    return { port: Number.isFinite(port) ? port : 0, pid: 0, processName: '', kind: DSH_KIND_UNKNOWN };
  }
  const port = Number(candidate?.port);
  const processName = String(candidate?.processName ?? '');
  const kind = candidate?.kind ?? classifyDshProcess(processName);
  return { port: Number.isFinite(port) ? port : 0, pid: Number(candidate?.pid) || 0, processName, kind };
}

/**
 * 返回本机所有可用的 DSH Web 后端：
 * [{key, authority, host, port, pid, processName, kind, label}]
 * 先探测、后标注；桌面版排在前面（保持旧行为的默认优先级）。
 */
export async function discoverDshTargets(cookieFor, options = {}) {
  const {
    listEndpoints = options.listPorts
      ? async () => (await options.listPorts()).map(normalizeEndpoint)
      : listDshCandidateEndpoints,
    probe = probeDsh,
    excludePorts = [],
    timeoutMs = PROBE_TIMEOUT_MS,
    concurrency = PROBE_CONCURRENCY,
  } = options;

  const endpoints = (await listEndpoints({ excludePorts }))
    .map(normalizeEndpoint)
    .filter((entry) => entry.port > 0);
  if (endpoints.length === 0) return [];

  const uniq = new Map();
  for (const entry of endpoints) if (!uniq.has(entry.port)) uniq.set(entry.port, entry);
  const candidates = [...uniq.values()].sort((a, b) => a.port - b.port);

  const probed = await mapLimit(candidates, concurrency, async (entry) => {
    const authority = `127.0.0.1:${entry.port}`;
    const alive = await probe(authority, cookieFor, { timeoutMs });
    return { ...entry, authority, alive };
  });

  const alive = probed.filter((entry) => entry.alive);
  const kindCount = new Map();
  const targets = [];
  for (const entry of alive.sort((a, b) => {
    const rank = (kind) => (kind === DSH_KIND_DESKTOP ? 0 : kind === DSH_KIND_CLI ? 1 : 2);
    return rank(a.kind) - rank(b.kind) || a.port - b.port;
  })) {
    const seen = kindCount.get(entry.kind) ?? 0;
    kindCount.set(entry.kind, seen + 1);
    const key = seen === 0 ? entry.kind : `${entry.kind}@${entry.port}`;
    targets.push({
      key,
      authority: entry.authority,
      host: '127.0.0.1',
      port: entry.port,
      pid: entry.pid,
      processName: entry.processName,
      kind: entry.kind,
      label: dshKindLabel(entry.kind),
    });
  }
  return targets;
}

/** 兼容旧接口：返回第一个 DSH Web 的 `127.0.0.1:<port>`，找不到返回 null。 */
export async function discoverDsh(cookieFor, options = {}) {
  const targets = await discoverDshTargets(cookieFor, options);
  return targets[0]?.authority ?? null;
}

/** 按偏好选择初始后端：优先 preferredKind，其次桌面版，最后第一个。 */
export function pickPreferredTarget(targets, preferredKind = null) {
  if (!Array.isArray(targets) || targets.length === 0) return null;
  // v2：桥接只连桌面版 DSH（Electron 内置后端）。
  //
  // 不再回落到 `dsh web`（cli 类型）：
  //   1. 它需要额外拉起一个 node 进程，受限环境（沙箱/杀软/精简系统）里 spawn 会被拒；
  //   2. 它的端口同样会漂移，跟踪成本不低于桌面版；
  //   3. 手机端走的是同一套 /api 契约，桌面版已经够用。
  // 找不到桌面版时返回 null，由调用方决定是等待还是降级——而不是偷偷连到 cli 上。
  const desktops = targets.filter((target) => target.kind === DSH_KIND_DESKTOP);
  if (desktops.length === 0) return null;
  // 桌面版之间有多个实例时，保留旧 prefer 语义（同 kind 取第一个）。
  return desktops[0];
}
