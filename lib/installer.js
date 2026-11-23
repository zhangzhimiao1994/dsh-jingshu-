/**
 * dsh-dsbot-host — 安装器。
 *
 * 幂等地把「桥接运行所需的全部环境」装到 ~/.dsbot/：
 *   1. 桥接程序（6 个 .mjs + vendor/qrcode.cjs）
 *   2. host-keys.json（主机身份；已有则接管，绝不覆盖）
 *   3. bridge-config.json（端口/relay/上游；已有则合并，保留用户改动）
 *   4. outbox / inbox 目录
 *   5. DSH 上游探测
 *   6. 版本记录（插件版本 / 桥接版本分开记）
 *   7. Node 运行时定位（三级回退）
 *
 * 设计原则：密钥与配置一律复用桥接自己的实现，避免两边算法漂移。
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { fileURLToPath } from 'node:url';

const LIB_DIR = path.dirname(fileURLToPath(import.meta.url));
const PLUGIN_DIR = path.dirname(LIB_DIR);
const ASSETS_HOST = path.join(PLUGIN_DIR, 'assets', 'host');

/** 桥接运行所需的状态目录。 */
export const STATE_DIR = path.join(os.homedir(), '.dsbot');

/** 需要复制到状态目录的桥接文件。 */
const BRIDGE_FILES = [
  'dsbot-bridge.mjs',
  'dsh-discover.mjs',
  'noise.mjs',
  'qr.mjs',
  'relay-client.mjs',
  'relay-link.mjs',
  path.join('vendor', 'qrcode.cjs'),
];

/** 默认桥接配置；用户改过的字段在合并时保留。 */
const DEFAULT_CONFIG = {
  version: 1,
  product: 'dsbot',
  port: 8788,
  portRange: [8788, 8798],
  bind: '0.0.0.0',
  relay: 'ws://39.105.200.88:8443',
  dsh: 'auto',
};

/** 读取插件自己的版本号。 */
function pluginVersion() {
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(PLUGIN_DIR, 'package.json'), 'utf8'));
    return pkg.version ?? '0.0.0';
  } catch {
    return '0.0.0';
  }
}

/**
 * 三级回退定位 Node 运行时。
 * 1) DSH 自带 runtime  2) 当前进程可执行文件  3) PATH 上的 node
 * @returns {{path: string, source: string} | null}
 */
export function findNode() {
  const candidates = [];

  const runtime = path.join(
    os.homedir(), '.dsh', 'dsh-runtimes', 'dsh-primary-runtime',
    'dependencies', 'node', process.platform === 'win32' ? 'bin\\node.exe' : 'bin/node',
  );
  candidates.push({ path: runtime, source: 'dsh-runtime' });

  if (process.execPath && !/electron/i.test(process.execPath)) {
    candidates.push({ path: process.execPath, source: 'process-exec-path' });
  }

  for (const c of candidates) {
    try {
      if (fs.existsSync(c.path) && fs.statSync(c.path).isFile()) return c;
    } catch { /* 继续找 */ }
  }
  return null;
}

/**
 * 检查现状，不做任何修改。
 * @returns {object} 安装状态快照
 */
export function inspect() {
  const state = {
    stateDir: STATE_DIR,
    exists: fs.existsSync(STATE_DIR),
    bridgeInstalled: false,
    hostId: null,
    config: null,
    dirs: { outbox: false, inbox: false },
    versions: null,
    node: findNode(),
  };

  const bridge = path.join(STATE_DIR, 'dsbot-bridge.mjs');
  state.bridgeInstalled = fs.existsSync(bridge);
  state.dirs.outbox = fs.existsSync(path.join(STATE_DIR, 'outbox'));
  state.dirs.inbox = fs.existsSync(path.join(STATE_DIR, 'inbox'));

  try {
    const keys = JSON.parse(fs.readFileSync(path.join(STATE_DIR, 'host-keys.json'), 'utf8'));
    const raw = Buffer.from(keys.signPublic, 'base64url');
    state.hostId = crypto.createHash('sha256')
      .update(raw).digest('base64url').slice(0, 22);
  } catch { /* 没有密钥 */ }

  try {
    state.config = JSON.parse(fs.readFileSync(path.join(STATE_DIR, 'bridge-config.json'), 'utf8'));
  } catch { /* 没有配置 */ }

  try {
    state.versions = JSON.parse(fs.readFileSync(path.join(STATE_DIR, 'installed.json'), 'utf8'));
  } catch { /* 没有版本记录 */ }

  return state;
}

/** 确保状态目录与 outbox/inbox 存在。 */
function ensureDirs() {
  const created = [];
  for (const dir of [STATE_DIR, path.join(STATE_DIR, 'outbox'), path.join(STATE_DIR, 'inbox')]) {
    if (!fs.existsSync(dir)) { fs.mkdirSync(dir, { recursive: true }); created.push(dir); }
  }
  return created;
}

/** 把插件内置的桥接文件复制到状态目录（幂等：内容相同则跳过）。 */
function ensureBridgeFiles() {
  const copied = [];
  for (const rel of BRIDGE_FILES) {
    const src = path.join(ASSETS_HOST, rel);
    const dst = path.join(STATE_DIR, rel);
    if (!fs.existsSync(src)) throw new Error(`插件内置资源缺失：${rel}`);
    fs.mkdirSync(path.dirname(dst), { recursive: true });
    let same = false;
    try { same = fs.readFileSync(src).equals(fs.readFileSync(dst)); } catch { same = false; }
    if (!same) { fs.copyFileSync(src, dst); copied.push(rel); }
  }
  return copied;
}

/**
 * 确保主机身份存在。已有则接管（hostId 不变），没有才生成。
 * 用桥接自己的 loadOrCreateHostKeys，保证算法一致。
 */
async function ensureHostKeys() {
  const mod = await import(pathToFileURL(path.join(STATE_DIR, 'relay-link.mjs')).href);
  const keys = mod.loadOrCreateHostKeys(STATE_DIR);
  return { hostId: keys.hostId, created: keys.created === true };
}

/**
 * 写桥接配置。已有配置保留用户改过的 relay / port / bind。
 */
function ensureConfig(overrides = {}) {
  const file = path.join(STATE_DIR, 'bridge-config.json');
  let existing = {};
  try { existing = JSON.parse(fs.readFileSync(file, 'utf8')); } catch { /* 首次安装 */ }

  const merged = { ...DEFAULT_CONFIG, ...existing, ...overrides, updatedAt: Date.now() };
  // 端口范围跟随端口，避免用户改了端口却留下旧范围
  if (overrides.port && !overrides.portRange) {
    merged.portRange = [merged.port, merged.port + 10];
  }
  fs.writeFileSync(file, JSON.stringify(merged, null, 2) + '\n', 'utf8');
  return merged;
}

/** 配对状态文件：由桥接写入（0600），插件只读。 */
export const PAIR_STATE_FILE = 'pair.json';

/**
 * 读取桥接落盘的配对状态。
 * 桥接的约定是「登录码不出现在任何 HTTP 响应里」，所以这里读的是同机文件，不走网络。
 * @returns {{ok: boolean, code?: string|null, expiresAt?: number, link?: string|null,
 *            lanUrls?: string[], relay?: string|null, hostId?: string|null,
 *            expired?: boolean, updatedAt?: number, error?: string, detail?: string}}
 */
export function readPairState() {
  const file = path.join(STATE_DIR, PAIR_STATE_FILE);
  try {
    const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
    const now = Date.now();
    const expired = !raw.expiresAt || raw.expiresAt <= now;
    return {
      ok: true,
      // 过期就不返回码，避免 UI 展示一个已经不能用的码
      code: expired ? null : (raw.code ?? null),
      expiresAt: raw.expiresAt ?? 0,
      link: expired ? null : (raw.link ?? null),
      lanUrls: Array.isArray(raw.lanUrls) ? raw.lanUrls : [],
      relay: raw.relay ?? null,
      hostId: raw.hostId ?? null,
      expired,
      updatedAt: raw.updatedAt ?? 0,
    };
  } catch (e) {
    return {
      ok: false,
      error: 'pair-state-unavailable',
      detail: String(e?.message ?? e),
    };
  }
}

/** 记录版本，供升级对比。 */
function writeVersions(extra = {}) {
  const file = path.join(STATE_DIR, 'installed.json');
  let prev = {};
  try { prev = JSON.parse(fs.readFileSync(file, 'utf8')); } catch { /* 首次 */ }
  const next = {
    pluginVersion: pluginVersion(),
    bridgeVersion: prev.bridgeVersion ?? null, // 由桥接自身版本文件提供，暂留空
    installedAt: Date.now(),
    lastUpgradeAt: prev.installedAt ? Date.now() : null,
    ...extra,
  };
  fs.writeFileSync(file, JSON.stringify(next, null, 2) + '\n', 'utf8');
  return next;
}

/**
 * 执行安装（幂等，可重复调用）。
 * @param {{relay?: string, port?: number, bind?: string}} options
 */
export async function install(options = {}) {
  const steps = [];
  const fail = (step, error) => {
    steps.push({ step, ok: false, error: String(error?.message ?? error) });
    return { ok: false, steps, error: String(error?.message ?? error) };
  };

  try {
    const node = findNode();
    if (!node) return fail('find-node', new Error('找不到 Node 运行时（DSH runtime / 系统 node 均不可用）'));
    steps.push({ step: 'find-node', ok: true, path: node.path, source: node.source });

    const createdDirs = ensureDirs();
    steps.push({ step: 'ensure-dirs', ok: true, created: createdDirs });

    const copied = ensureBridgeFiles();
    steps.push({ step: 'copy-bridge', ok: true, copied });

    const keys = await ensureHostKeys();
    steps.push({ step: 'host-keys', ok: true, hostId: keys.hostId, created: keys.created });

    const config = ensureConfig(options);
    steps.push({ step: 'config', ok: true, relay: config.relay, port: config.port });

    const versions = writeVersions();
    steps.push({ step: 'versions', ok: true, ...versions });

    return { ok: true, steps, state: inspect() };
  } catch (error) {
    return fail('install', error);
  }
}
