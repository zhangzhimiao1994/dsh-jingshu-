#!/usr/bin/env node
/**
 * 鲸枢电脑端桥接网关（dsbot-bridge）v0.2「DeepSeek 账号主机」
 * ============================================================================
 * 手机 App 不能直连本机 DSH Web（127.0.0.1，且认证靠浏览器 cookie）。本进程是
 * 手机到 DSH 之间唯一的通道，也是整个项目最核心的安全边界。
 *
 * Phase 1 账号模型（Codex 式）：
 *   账号 = 电脑上 DSH 已登录的 DeepSeek 账号；桥接是「账号主机」，电脑上只登录一次，
 *   之后每台手机扫码（一次性 6 位登录码，10 分钟）换取**独立设备凭据**加入同一账号。
 *
 *   配对手机 ≠ 主机管理员   （安全边界不因账号登录放宽）
 *
 * 设计要点（对照 docs/SECURITY.md §2/§4、docs/ACCOUNT-LOGIN.md）：
 *   1. 方法白名单 + 默认拒绝：只反代明确允许的 DSH Remote 方法（会话读写、模型目录、
 *      审批回传、只读文件浏览、流式事件、附件上传、插件管理）；settings/*、credentials/*、
 *      pluginInventory/*、agentPresets/*、dynamicCordisRunner/*、goals/*、subagents/*、
 *      commands/execute、workspace 写操作、mcp/*、connectors/* 等一律 403 并审计。
 *      （v0.6.2 起应用户要求开放 fileUploads/upload 与 pluginManager/*、pluginMarket/*：
 *      装插件 / MCP 等于能在电脑上运行新程序，手机设备凭据因此等同电脑管理员。）
 *   2. 设备注册表（bridge.json v2）：每台手机一个 32 字节 token，**只存 sha256(token)
 *      与末 4 位指纹，不存明文**；支持 Bearer / x-dsbot-token / ?token=；
 *      错误 token 按来源 IP 限速（>5 次/分钟 → 429）。v0.1 单 token 自动迁移为 devices[0]，
 *      旧手机 token 继续有效（用户现有手机不掉线）。
 *   3. 登录码：6 位 `ABC-DEF`（去掉易混字符），10 分钟 TTL，一次性；兑换入口
 *      `POST /dsbot/pair/redeem`；错误尝试 5 次/分钟 → 429 + 审计。
 *   4. `/dsbot/*` 只做账号/设备管理，不反代 DSH，因此不受 DSH cookie 逻辑影响。
 *   5. Cookie 只存在于主机侧：桥接按 DSH 的 authority 规则签名浏览器 cookie 注入上游，
 *      手机的请求头与响应里的 Set-Cookie 都不会带出 cookie。
 *   6. 审计：<state-dir>/audit.log JSONL，允许与拒绝都记；新增 deviceId 字段；
 *      绝不写 token / cookie / 密钥 / 登录码。
 *   7. WS 升级走 TCP 级 pipe（/api/remote.mux），只改写握手头（Host/Origin/Cookie），
 *      并对 mux 的 open 流端点做白名单校验，避免在桥接里重新实现一整套 WebSocket 协议。
 *
 * 依赖：Node 内置模块 + `vendor/qrcode.cjs`（MIT，qrcode-generator 1.4.4，仅用于二维码；
 * 文件缺失时自动降级为只打印登录链接）。
 * 运行：node dsbot-bridge.mjs [--port 8788] [--dsh 127.0.0.1:64005]
 *                            [--state-dir <dir>] [--bind 0.0.0.0] [--reset]
 *                            [--pair] [--devices] [--revoke <deviceId>] [--open]
 * 测试：node --test host/test
 */

import http from 'node:http';
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import https from 'node:https';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawn, execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

import { createQrMatrix, renderAnsiQr, writePairHtmlFile } from './qr.mjs';
import { createRelayLink, loadOrCreateHostKeys, normalizeRelayUrl } from './relay-link.mjs';
import { discoverDshTargets, pickPreferredTarget } from './dsh-discover.mjs';
import {
  CORDIS_PATCH_PATH,
  parseProviders,
  readPatchText,
  removeProvider,
  upsertProvider,
  writePatchText,
  resolveProviderKey,
  fetchRemoteModels,
} from './llm-providers.mjs';

// ---------------------------------------------------------------------------
// 常量
// ---------------------------------------------------------------------------

export const VERSION = '0.2.1';
export const DEFAULT_PORT = 8788;
/** 端口配置/扫描（安装器写入，bridge 启动读取；占用则顺延并回写）。 */
export function bridgeConfigPath(stateDir) {
  return path.join(stateDir, 'bridge-config.json');
}
export function loadBridgeConfig(stateDir) {
  try {
    const text = fs.readFileSync(bridgeConfigPath(stateDir), 'utf8').replace(/^\uFEFF/, '');
    const parsed = JSON.parse(text);
    return parsed && typeof parsed === 'object' ? parsed : null;
  } catch {
    return null;
  }
}
export function saveBridgeConfig(stateDir, config) {
  try {
    fs.mkdirSync(stateDir, { recursive: true });
    const file = bridgeConfigPath(stateDir);
    const tmp = `${file}.tmp-${process.pid}`;
    fs.writeFileSync(tmp, JSON.stringify({ version: 1, ...config, updatedAt: Date.now() }, null, 2), 'utf8');
    fs.renameSync(tmp, file);
  } catch {
    /* 配置写失败不影响运行 */
  }
}
export function isPortFree(port, bind = '0.0.0.0') {
  return new Promise((resolve) => {
    const probe = net.createServer();
    probe.once('error', () => resolve(false));
    probe.once('listening', () => probe.close(() => resolve(true)));
    probe.listen(port, bind);
  });
}
export async function pickBridgePort({ preferred = DEFAULT_PORT, rangeStart = DEFAULT_PORT, rangeEnd = rangeStart + 10, bind = '0.0.0.0' } = {}) {
  if (Number.isInteger(preferred) && preferred > 0 && (await isPortFree(preferred, bind))) return preferred;
  for (let port = Math.max(1, rangeStart); port <= rangeEnd; port += 1) {
    if (port === preferred) continue;
    if (await isPortFree(port, bind)) return port;
  }
  return preferred;
}
export const DEFAULT_DSH = '127.0.0.1:64005';
export const DEFAULT_BIND = '0.0.0.0';
export const DEFAULT_DEVICE_NAME = 'dsbot-device';
export const DEFAULT_STATE_DIR = path.join(os.homedir(), '.dsbot');
export const DEFAULT_CREDENTIALS_PATH = path.join(os.homedir(), '.dsh', '.credentials.yaml');

/** 状态文件名（v0.2 起内部为 version:2 设备注册表；沿用旧名以兼容现有状态目录/冒烟脚本）。 */
export const STATE_FILE_NAME = 'bridge.json';
/** 状态文件版本：1 = v0.1 单 token（会迁移），2 = 多设备注册表（只存 token 哈希）。 */
export const STATE_VERSION = 2;
/** pair.html 写到 <state-dir>/pair.html。 */
export const PAIR_PAGE_FILE = 'pair.html';
/**
 * 配对状态的结构化落盘（0600）。给同机的 DSH 插件读，用来在设置页渲染二维码。
 * 这是本地 IPC，不是 HTTP —— 登录码仍然不出现在任何 HTTP 响应里（见 pairCode getter 的约定）。
 */
export const PAIR_STATE_FILE = 'pair.json';

/**
 * 端点文件：记录本进程实际监听的端口，供同机程序（DSH 插件、运维脚本、App 扫码页）发现。
 * 手机端读不到 PC 文件系统，所以它**不能**替代固定端口；它的作用是让「端口漂移」这件事可被观测，
 * 以及让同机工具不用猜端口。
 */
export const ENDPOINT_FILE = 'bridge-endpoint.json';

/**
 * 原子写端点文件。**失败只告警不致命**：状态目录不可写时桥接仍必须能对外服务。
 * 2026-11-10 实测：沙箱下写 .dsbot 会 EPERM，旧逻辑直接 `启动失败` 退出，导致整台服务下线。
 */
export function writeEndpointFile(stateDir, info) {
  const target = path.join(stateDir, ENDPOINT_FILE);
  const tmp = `${target}.tmp-${process.pid}`;
  try {
    fs.mkdirSync(stateDir, { recursive: true });
    fs.writeFileSync(
      tmp,
      `${JSON.stringify({ ...info, updatedAt: new Date().toISOString() }, null, 2)}\n`,
      { mode: 0o600 },
    );
    fs.renameSync(tmp, target);
    return true;
  } catch (error) {
    try { fs.unlinkSync(tmp); } catch { /* 临时文件可能没建出来 */ }
    console.warn(`[port] 端点文件写入失败（不影响桥接服务）：${error.message}`);
    return false;
  }
}

/**
 * 探测某端口上的监听者是不是我们自己。用于区分「旧桥接实例残留」和「别的程序占用」。
 * 返回 /dsbot/status 的响应体；不是我们的桥接则返回 null。
 */
export async function probeBridgeOwner(port, timeoutMs = 800) {
  try {
    const res = await fetch(`http://127.0.0.1:${port}/dsbot/status`, { signal: AbortSignal.timeout(timeoutMs) });
    if (!res.ok) return null;
    const body = await res.json();
    return body && body.ok === true ? body : null;
  } catch {
    return null;
  }
}

/** 登录码：6 位 ABC-DEF（去掉易混字符 I/O/0/1），10 分钟一次性。 */
export const PAIR_CODE_TTL_MS = 10 * 60 * 1000;
export const PAIR_CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
export const PAIR_CODE_LENGTH = 6;
export const PAIR_CODE_PATTERN = /^[A-HJ-NP-Z2-9]{3}-[A-HJ-NP-Z2-9]{3}$/;
/** 登录码兑换请求体上限（防御性；正常请求 < 1KB）。 */
export const MAX_PAIR_BODY_BYTES = 64 * 1024;
/** 设备名 / 平台字段的长度与格式限制（来自手机的输入必须消毒后落盘）。 */
export const MAX_DEVICE_NAME_LEN = 48;
export const MAX_PLATFORM_LEN = 24;

/** DeepSeek 账号记录键名（%USERPROFILE%\.dsh\.credentials.yaml 的 records 下）。 */
export const ACCOUNT_RECORD_DEFAULT = 'deepseek-account-platform/default';
export const ACCOUNT_RECORD_DEVICE = 'deepseek-account-platform/device';

/** /dsbot/* 路由表：方法 + 是否需要设备 token。 */
export const DSBOT_ROUTES = Object.freeze({
  '/dsbot/status': { methods: ['GET'], auth: false },
  '/dsbot/pair/redeem': { methods: ['POST'], auth: false },
  '/dsbot/account': { methods: ['GET'], auth: true },
  '/dsbot/devices': { methods: ['GET'], auth: true },
  '/dsbot/devices/revoke': { methods: ['POST'], auth: true },
  '/dsbot/devices/remove': { methods: ['POST'], auth: true },
  // 批量清理桥接侧的「已撤销」设备（手机账号页的「清理」按钮用这个）
  '/dsbot/devices/remove-revoked': { methods: ['POST'], auth: true },
  '/dsbot/emergency-stop': { methods: ['POST'], auth: true },
  '/dsbot/emergency-resume': { methods: ['POST'], auth: true },
  '/dsbot/exec': { methods: ['POST'], auth: true },
  '/dsbot/fs/read': { methods: ['POST'], auth: true },
  '/dsbot/fs/write': { methods: ['POST'], auth: true },
  '/dsbot/usage': { methods: ['POST'], auth: true },
  '/dsbot/logout': { methods: ['POST'], auth: true },
  // 生成一个「只有配置」的 MCP 插件包目录，返回它的路径；手机再用 pluginManager/installBundle 装上
  '/dsbot/mcp/bundle': { methods: ['POST'], auth: true },
  // 手机把自己的日志 / 崩溃记录发到电脑：<state-dir>/phone-logs/
  '/dsbot/logs': { methods: ['POST'], auth: true },
  // Bot 发给手机的文件：只读列出 / 取回 outbox 目录（默认 <state-dir>/outbox）里的文件
  '/dsbot/outbox/list': { methods: ['POST'], auth: true },
  '/dsbot/outbox/file': { methods: ['POST'], auth: true },
  '/dsbot/outbox/chunk': { methods: ['POST'], auth: true },
  // 2026-11-12：outbox 只增不减，手机「会话文件」列表会一直变长且删不掉。
  // 单个删除 + 整个清空（都只操作 outbox 目录下的单层普通文件）。
  '/dsbot/outbox/delete': { methods: ['POST'], auth: true },
  '/dsbot/outbox/clear': { methods: ['POST'], auth: true },
  // 手机发给电脑的大文件：分块上传到 inbox 目录（默认 <state-dir>/inbox），Bot 按路径读取
  '/dsbot/inbox/chunk': { methods: ['POST'], auth: true },
  // 连接健康检查：只回一个空 ok（代替每 20 秒拉一次完整会话列表）
  '/dsbot/ping': { methods: ['POST'], auth: true },
  // 电脑上可能同时跑「桌面版 DSH」和「dsh web（命令行）」两套后端；App 里可以查看/切换。
  // 这两个接口只读写桥接自己的后端列表与选择，不碰 DSH 上游。
  // 模型服务商：测试 / 写入 / 删除（不碰 DSH 上游，直接改 cordis.patch.yml）
  '/dsbot/llm/test': { methods: ['POST'], auth: true },
  '/dsbot/llm/provider': { methods: ['POST'], auth: true },
  '/dsbot/llm/provider/delete': { methods: ['POST'], auth: true },
  '/dsbot/llm/providers': { methods: ['GET'], auth: true },
  // 拉取远端模型列表（OpenAI 兼容 /models），供 App 里勾选模型
  '/dsbot/llm/models': { methods: ['POST'], auth: true },
  '/dsbot/upstreams': { methods: ['GET', 'POST'], auth: true },
  '/dsbot/upstream/select': { methods: ['POST'], auth: true },
});

/**
 * outbox：Bot 发给手机的文件，单文件上限 512MB。
 * - 大文件走 /dsbot/outbox/chunk 分块下载：每块 ≤2MB 原始数据（base64 后约 2.7MB，低于中转隧道 20MB 响应上限）；
 * - /dsbot/outbox/file 只给旧版 App 用，限制 10MB（base64 后 <14MB）。
 */
export const MAX_OUTBOX_FILE_BYTES = 512 * 1024 * 1024;
export const MAX_OUTBOX_CHUNK_BYTES = 2 * 1024 * 1024;
export const MAX_OUTBOX_SINGLE_BYTES = 15 * 1024 * 1024;
export const MAX_OUTBOX_LIST = 500;
export const MAX_OUTBOX_BODY_BYTES = 4 * 1024;

/**
 * inbox：手机→电脑的大文件。每块 base64 放在 JSON 里（≤4MB 原始数据），按 offset 追加到
 * <inbox>/.partial/ 下的临时文件；最后一块到齐后改名到 inbox 目录。offset 对不上时回 409 并告诉手机
 * 已收到多少，手机从那里续传。
 */
export const MAX_INBOX_FILE_BYTES = 1024 * 1024 * 1024;
export const MAX_INBOX_CHUNK_BYTES = 4 * 1024 * 1024;
export const MAX_INBOX_BODY_BYTES = Math.ceil((MAX_INBOX_CHUNK_BYTES * 4) / 3) + 4 * 1024;
export const INBOX_PARTIAL_TTL_MS = 24 * 60 * 60 * 1000;

/** MCP 包和手机日志的请求体上限。 */
export const MAX_MCP_BODY_BYTES = 64 * 1024;
export const MAX_LOG_BODY_BYTES = 4 * 1024 * 1024;
/** MCP 服务名：会变成工具名前缀 mcp__<name>__，只允许小写字母数字和 - _。 */
export const MCP_NAME_PATTERN = /^[a-z0-9][a-z0-9_-]{0,39}$/;
/** 生成的 MCP 包都叫 @dsbot-mcp/<name>，方便手机认出来。 */
export const MCP_PACKAGE_SCOPE = '@dsbot-mcp';

/** 单次 HTTP 请求体上限：16MB（白名单里没有上传通道，这个值只是防御性上限）。 */
export const MAX_BODY_BYTES = 16 * 1024 * 1024;
/** 每 token 的普通请求限流窗口与配额。 */
export const REQUEST_WINDOW_MS = 10_000;
export const REQUEST_LIMIT = 120;
/** 错误 token 的来源 IP 限速：窗口内最多 5 次失败，第 6 次起 429。 */
export const AUTH_FAIL_WINDOW_MS = 60_000;
export const AUTH_FAIL_LIMIT = 5;
/** WS 流式多路复用入口（DSH api-gateway 的固定路径）。 */
export const WS_PATH = '/api/remote.mux';

/** 构造一个 server→client 的 WebSocket Close 帧（FIN+opcode 0x8，未掩码）。 */
export function wsCloseFrame(code, reason = '') {
  const text = Buffer.from(String(reason), 'utf8');
  const payload = Buffer.alloc(2 + text.length);
  payload.writeUInt16BE(code, 0);
  if (text.length > 0) text.copy(payload, 2);
  const length = payload.length;
  const header = length < 126 ? Buffer.from([0x88, length]) : Buffer.from([0x88, 126, (length >> 8) & 0xff, length & 0xff]);
  return Buffer.concat([header, payload]);
}
/**
 * /api/remote.mux 上允许打开的**流式**方法白名单。
 *
 * 为什么 WS 也需要白名单：remote.mux 是 DSH 所有 Typert Remote 流的“多路复用口”，
 * 一个物理 WS 里可以 open 任意 stream endpoint（session/follow、$events 之外，
 * 还有 terminal/attach、job/follow、account/watch……）。如果只做 TCP 透传，
 * 手机就能绕过 unary 方法白名单去开 terminal/attach —— 等于拿到交互式终端，
 * 违反 docs/SECURITY.md「配对手机 ≠ 主机管理员」。
 *
 * 因此桥接在客户端→上游方向做**最小的 WS 帧解析**：只看 `type:"open"` 的
 * endpoint，校验通过后把原始帧原样转发；下行仍然纯 pipe。不是“重新实现 WS”，
 * 只拦截多路复用层的授权决定。
 */
export const ALLOWED_STREAM_ENDPOINTS = new Set([
  'session/follow',
  'session/control',
  '$events',
  'workspace/follow',
]);

/** 单条 WS 帧 / 单条 mux 消息的内存上限（防御恶意超大帧）。 */
export const MAX_MUX_FRAME_BYTES = 8 * 1024 * 1024;
export const MAX_MUX_MESSAGE_BYTES = 16 * 1024 * 1024;

/**
 * 允许反代的 DSH Remote 方法（不带 /api/ 前缀）。
 * 只列白名单，未列出的全部拒绝 —— 默认拒绝是安全模型的一部分。
 */
export const ALLOWED_ENDPOINTS = new Set([
  // 会话读写
  'session/list',
  'session/create',
  'session/prompt',
  'session/cancel',
  // 只能编辑 / 删除本会话里自己排队的消息（「停止」时清掉排队，免得取消后立刻又开新一轮）
  'session/updateQueue',
  // 只读：读 inbox 里排队的消息，供「插队」把它们挪进当前这一轮。
  'session/projections',
  'session/rename',
  'session/page',
  'session/modelCatalog',
  'session/selectModel',
  'session/follow',
  'session/control',
  // 审批回传（docs/SECURITY.md §1.6：只回传用户对某一次请求的裁决）
  '$events',
  '$events/result',
  // 只读元数据
  'skills/list',
  'llm/listProviders',
  'fileReferences/list',
  // 只读工作区浏览
  'workspace/follow',
  'workspaceFiles/list',
  'workspaceFiles/read',
  'workspaceFiles/readAll',
  'workspaceFiles/readBytes',
  'workspaceFiles/stat',
  // 附件：把文件存进某个会话的上传区，拿 receiptId 附在 session/prompt 里
  'fileUploads/upload',
  // 插件管理（用户要求手机能装插件 / MCP；MCP 就是一个只有配置的插件包）
  'pluginManager/listBundles',
  'pluginManager/listPlugins',
  'pluginManager/inspect',
  'pluginManager/installBundle',
  'pluginManager/waitForInstall',
  'pluginManager/cancelInstall',
  'pluginManager/removeBundle',
  'pluginManager/setBundleEnabled',
  'pluginManager/registries',
  'pluginMarket/listIndexes',
  'pluginMarket/setIndexes',
  'pluginMarket/search',
]);

/** 可能跑很久的方法（pnpm 安装）：上游等待时间放宽，手机端拿 requestId 轮询 waitForInstall。 */
export const SLOW_ENDPOINTS = new Set([
  'pluginManager/installBundle',
  'pluginManager/waitForInstall',
  'pluginManager/inspect',
  'pluginManager/removeBundle',
  'pluginManager/setBundleEnabled',
  'pluginMarket/search',
]);
export const SLOW_UPSTREAM_TIMEOUT_MS = 50_000;
export const UPSTREAM_TIMEOUT_MS = 30_000;

/**
 * 明确禁止的方法前缀。默认拒绝已经覆盖它们，这里单独列出只为了：
 *   a) 审计里给出更清楚的 reason（forbidden-method 而不是 unknown-method）；
 *   b) 让 review 时能一眼对照 docs/SECURITY.md。
 */
export const FORBIDDEN_PREFIXES = [
  'settings/',
  'credentials/',
  'pluginInventory/',
  'agentPresets/',
  'dynamicCordisRunner/',
  'goals/',
  'subagents/',
  'commands/execute',
  'mcp/',
  'connectors/',
  'account/',
  'terminal/',
  'job/',
  'schedule/',
  'permissionPresets/',
  'productAnalytics/',
  'messageFeedback/',
  'sessionFeedback/',
  'userQuestions/',
  'sessionReferenceResolver/',
  'directoryPicker/',
  'officeToPdf/',
  'workspace/create',
  'workspace/delete',
  'workspace/rename',
  'workspace/archiveSession',
  'workspace/unarchiveSession',
  'workspace/insertBefore',
  'workspace/insertSessionBefore',
  'workspace/pinSession',
  'workspace/unpinSession',
  'workspace/initializeDefault',
  'session/fork',
  'session/attachment',
  'session/search',
  'session/openWorkspacePath',
  'session/canOpenWorkspacePath',
  'session/workspacePathApplications',
  'workspaceFiles/changes',
];

/** bridge.json 里声明的设备能力（仅做展示与审计参考，真正的边界是白名单）。 */
export const DEVICE_SCOPES = Object.freeze([
  'session:read',
  'session:write',
  'session:stream',
  'approval:respond',
  'files:read',
  'models:read',
  'skills:read',
]);

const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'expect',
]);

/** 从手机发往上游时必须丢弃的头部：认证/隐私相关，由桥接重建。 */
const CLIENT_HEADERS_DROP = new Set([
  'host',
  'origin',
  'referer',
  'cookie',
  'authorization',
  'x-dsbot-token',
  'forwarded',
  'x-forwarded-for',
  'x-forwarded-host',
  'x-forwarded-proto',
  'x-real-ip',
  'accept-encoding',
  'content-length',
]);

const SAFE_ENDPOINT_PATTERN = /^[A-Za-z0-9_$]+(?:\/[A-Za-z0-9_$]+)*$/;
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const COOKIE_TTL_MS = 7 * 24 * 60 * 60 * 1000;
/**
 * DSH 拒绝 issuedAt 晚于它自己 Date.now() 的 cookie；DeepSeek Harness 是 Electron，在 Windows 上
 * 时钟可能比本进程慢十几毫秒，刚签的 cookie 会被当成「未来的」而 401。签发时往回拨 1 分钟。
 */
export const COOKIE_CLOCK_SKEW_MS = 60 * 1000;
/** 客户端与上游 socket 的 TCP keepalive 起始空闲时间（探测死掉的半开连接）。 */
export const TCP_KEEPALIVE_MS = 30 * 1000;
/**
 * WS 代理半关后的强制销毁上限。
 * dsh 重启时上游只发 FIN 不再回包，两端 end() 后连接会停在 CLOSE_WAIT/FIN_WAIT2；
 * 超过这个时间还没关干净就直接 destroy，避免失效连接一直挂在 netstat 里。
 */
export const HALF_CLOSE_GRACE_MS = 5 * 1000;

const STATUS_TEXT = {
  400: 'Bad Request',
  401: 'Unauthorized',
  403: 'Forbidden',
  404: 'Not Found',
  405: 'Method Not Allowed',
  413: 'Payload Too Large',
  429: 'Too Many Requests',
  502: 'Bad Gateway',
  504: 'Gateway Timeout',
};

// ---------------------------------------------------------------------------
// 基础工具
// ---------------------------------------------------------------------------

const nowMs = () => Date.now();

/** base64url 编码（无填充），Node 16+ 原生支持。 */
export function base64url(input) {
  return Buffer.from(input).toString('base64url');
}

/** sha256 十六进制摘要。 */
export function sha256Hex(value) {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

/** 设备 token 指纹：sha256 前 8 位（App“设置 → 安全”页展示用，不泄露 token）。 */
export function tokenFingerprint(token) {
  return sha256Hex(String(token)).slice(0, 8);
}

/**
 * 设备 token 尾部指纹：末 4 位（设备列表核对用）。
 * state 里只存 sha256(token) 与它，绝不存明文 token。
 */
export function tokenTail(token) {
  return String(token ?? '').slice(-4);
}

/** 把 “host:port” 解析成上游连接信息；authority 同时用于 cookie 绑定与 Host 头。 */
export function parseAuthority(raw) {
  const text = String(raw ?? '').trim();
  if (!text) throw new Error('上游地址不能为空');
  let host;
  let portText = '80';
  if (text.startsWith('[')) {
    const end = text.indexOf(']');
    if (end < 0) throw new Error(`上游地址格式错误：${text}`);
    host = text.slice(1, end);
    const rest = text.slice(end + 1);
    if (rest.startsWith(':')) portText = rest.slice(1);
  } else {
    const idx = text.lastIndexOf(':');
    if (idx < 0) {
      host = text;
    } else if (text.indexOf(':') !== idx) {
      throw new Error(`上游地址格式错误（IPv6 请加方括号）：${text}`);
    } else {
      host = text.slice(0, idx);
      portText = text.slice(idx + 1);
    }
  }
  host = host.trim();
  if (!host) throw new Error(`上游地址缺少主机名：${text}`);
  // DSH 在本机以 127.0.0.1 绑定，cookie 的 authority 必须与实际的 Host 一致。
  if (host.toLowerCase() === 'localhost') host = '127.0.0.1';
  const port = Number(portText);
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error(`上游端口无效：${portText || '(空)'}`);
  }
  const authority = host.includes(':') ? `[${host}]:${port}` : `${host}:${port}`;
  return { authority, host, port, origin: `http://${authority}` };
}

/** DSH 浏览器会话 cookie 名：dsh-auth-<base64url(sha256(authority))>。 */
export function computeCookieName(authority) {
  return 'dsh-auth-' + crypto.createHash('sha256').update(String(authority), 'utf8').digest('base64url');
}

/**
 * 按 DSH 的规则签发一次性的浏览器会话 cookie。
 * payload = {version:1, authority, issuedAt, expiresAt: issuedAt+7d}
 * value   = "v1." + base64url(JSON(payload)) + "." + base64url(HMAC-SHA256(secret, body))
 */
export function signCookie(secret, authority, issuedAt = nowMs()) {
  const payload = {
    version: 1,
    authority,
    issuedAt,
    expiresAt: issuedAt + COOKIE_TTL_MS,
  };
  const body = base64url(JSON.stringify(payload));
  const sig = crypto.createHmac('sha256', secret).update(body, 'utf8').digest('base64url');
  return `v1.${body}.${sig}`;
}

/**
 * 从 DSH 凭据文件里取 `client-connection/browser-session` 记录的 secret。
 * 只做足够用的行解析，不引入 YAML 依赖。返回 32 字节 Buffer。
 */
export function loadCookieSecret(credentialsPath = DEFAULT_CREDENTIALS_PATH) {
  const envSecret = process.env.DSBOT_DSH_SECRET;
  if (typeof envSecret === 'string' && envSecret.trim() !== '') {
    const decoded = decodeSecretToken(envSecret.trim(), 'DSBOT_DSH_SECRET');
    if (decoded) return decoded;
  }
  let text;
  try {
    text = fs.readFileSync(credentialsPath, 'utf8');
  } catch (error) {
    throw new Error(
      `无法读取 DSH 凭据文件：${credentialsPath}\n` +
        `  请先在本机启动一次 DSH Web（dsh web），或确认当前 Windows 用户与 DSH 一致。\n` +
        `  原始错误：${error?.code ?? error?.message ?? error}`,
    );
  }
  const lines = text.split(/\r?\n/);
  let inRecord = false;
  let indentOfRecord = 0;
  for (const line of lines) {
    if (/^\s*$/.test(line) || /^\s*#/.test(line)) continue;
    const indent = line.match(/^[ \t]*/)?.[0].length ?? 0;
    const trimmed = line.trim();
    if (/^client-connection\/browser-session:\s*$/.test(trimmed)) {
      inRecord = true;
      indentOfRecord = indent;
      continue;
    }
    if (inRecord) {
      if (indent <= indentOfRecord) break; // 进入下一条记录
      const match = trimmed.match(/^secret:\s*(.+)$/);
      if (match) {
        const decoded = decodeSecretToken(match[1], credentialsPath);
        if (decoded) return decoded;
        throw new Error(
          `DSH 凭据里的 secret 不是合法的 32 字节 base64url：${credentialsPath}\n` +
            '  你可以用 DSBOT_DSH_SECRET 环境变量手动指定（同样要求 base64url 编码的 32 字节）。',
        );
      }
    }
  }
  throw new Error(
    `DSH 凭据文件里没有 client-connection/browser-session.payload.secret：${credentialsPath}\n` +
      '  请先在本机打开一次 DSH Web 完成浏览器会话初始化，然后重启桥接。',
  );
}

function decodeSecretToken(rawValue, label) {
  let value = String(rawValue ?? '').trim();
  if (
    (value.startsWith('"') && value.endsWith('"') && value.length >= 2) ||
    (value.startsWith("'") && value.endsWith("'") && value.length >= 2)
  ) {
    value = value.slice(1, -1);
  }
  if (!value) return null;
  let bytes = null;
  try {
    bytes = Buffer.from(value, 'base64url');
  } catch {
    bytes = null;
  }
  if (!bytes || bytes.length !== 32) {
    try {
      const fallback = Buffer.from(value, 'base64');
      if (fallback.length === 32) bytes = fallback;
    } catch {
      /* ignore */
    }
  }
  if (!bytes || bytes.length !== 32) {
    throw new Error(`${label}: secret 不是 32 字节（实际 ${bytes ? bytes.length : '无法解析'} 字节）`);
  }
  return bytes;
}

// ---------------------------------------------------------------------------
// DeepSeek 账号（电脑端 DSH 已登录的账号）
// ---------------------------------------------------------------------------

/**
 * 极简 YAML 子集解析：只解析 `records:` 下的一层「记录名 + 记录内标量字段」。
 * 真实 `%USERPROFILE%\.dsh\.credentials.yaml` 形状：
 *
 *   records:
 *     client-connection/browser-session:
 *       payload:
 *         secret: <base64url>
 *     deepseek-account-platform/device:
 *       payload:
 *         id: <uuid>
 *     deepseek-account-platform/default:
 *       payload:
 *         token: <...>
 *         issuer: https://platform.deepseek.com
 *
 * 不引入 YAML 依赖；解析失败/字段缺失由调用方降级（账号显示为未登录）。
 * @returns {Map<string, Map<string,string>>} 记录名 → 字段表（payload 层级被拍平）
 */
export function parseCredentialRecords(text) {
  const records = new Map();
  let inRecords = false;
  let current = null;
  let currentIndent = -1;
  for (const rawLine of String(text ?? '').split(/\r?\n/)) {
    if (/^\s*$/.test(rawLine) || /^\s*#/.test(rawLine)) continue;
    const indent = rawLine.match(/^[ \t]*/)?.[0].length ?? 0;
    const trimmed = rawLine.trim();
    if (indent === 0) {
      inRecords = trimmed === 'records:';
      current = null;
      currentIndent = -1;
      continue;
    }
    if (!inRecords) continue;
    if (current && indent <= currentIndent) {
      current = null;
      currentIndent = -1;
    }
    const match = trimmed.match(/^([A-Za-z0-9_./-]+):\s*(.*)$/);
    if (!match) continue;
    const [, key, restRaw] = match;
    let value = restRaw.trim();
    if (!current) {
      // records 下的记录名：必须有值且为空（`name:` 形式），缩进通常为 2。
      if (value === '' && indent >= 2) {
        current = new Map();
        currentIndent = indent;
        records.set(key, current);
      }
      continue;
    }
    if (value === '') continue; // 例如嵌套的 `payload:`
    if (
      (value.startsWith('"') && value.endsWith('"') && value.length >= 2) ||
      (value.startsWith("'") && value.endsWith("'") && value.length >= 2)
    ) {
      value = value.slice(1, -1);
    }
    current.set(key, value);
  }
  return records;
}

/**
 * 从 DSH 凭据文件读取 DeepSeek 账号信息（只读，只提取 id/issuer 与「是否已登录」，
 * **token 永远不出现在返回值里**）。
 *
 * @returns {{loggedIn:boolean, provider:string, displayName:string|null,
 *            deviceId:string|null, issuer:string|null, source:string}}
 *   displayName 取不到昵称时用 `DeepSeek 账号（设备 <id前8位>）`（与 App 端展示一致）。
 */
export function loadAccountInfo(credentialsPath = DEFAULT_CREDENTIALS_PATH, options = {}) {
  const unavailable = {
    loggedIn: false,
    provider: 'deepseek',
    displayName: null,
    deviceId: null,
    issuer: null,
    source: 'unavailable',
  };
  let text;
  try {
    text = fs.readFileSync(credentialsPath, 'utf8');
  } catch {
    return unavailable;
  }
  const records = parseCredentialRecords(text);
  const deviceRecord = records.get(ACCOUNT_RECORD_DEVICE);
  const accountRecord = records.get(ACCOUNT_RECORD_DEFAULT);
  const deviceId = typeof deviceRecord?.get('id') === 'string' ? deviceRecord.get('id').trim() || null : null;
  const issuer = typeof accountRecord?.get('issuer') === 'string' ? accountRecord.get('issuer').trim() || null : null;
  const loggedIn = Boolean(accountRecord?.get('token'));
  const explicitName =
    typeof options.displayName === 'string' && options.displayName.trim() ? options.displayName.trim() : null;
  const generatedName = deviceId
    ? `DeepSeek 账号（设备 ${deviceId.slice(0, 8)}）`
    : loggedIn
      ? 'DeepSeek 账号'
      : null;
  return {
    loggedIn,
    provider: 'deepseek',
    displayName: explicitName ?? generatedName,
    deviceId,
    issuer,
    source: loggedIn || deviceId ? 'credentials' : 'partial',
  };
}

/** 账号信息的公开投影：显式白名单字段，避免把内部/凭据字段带进 HTTP 响应。 */
export function publicAccount(account) {
  if (!account) {
    return { loggedIn: false, provider: 'deepseek', displayName: null, deviceId: null, issuer: null };
  }
  return {
    loggedIn: account.loggedIn === true,
    provider: account.provider ?? 'deepseek',
    displayName: account.displayName ?? null,
    deviceId: account.deviceId ?? null,
    issuer: account.issuer ?? null,
  };
}

/** 常量时间比较两个 token（先 sha256 再 timingSafeEqual，长度不同也安全）。 */
export function tokensMatch(candidate, expected) {
  if (typeof candidate !== 'string' || typeof expected !== 'string') return false;
  const a = crypto.createHash('sha256').update(candidate, 'utf8').digest();
  const b = crypto.createHash('sha256').update(expected, 'utf8').digest();
  const equal = crypto.timingSafeEqual(a, b);
  return equal && candidate.length === expected.length;
}

// ---------------------------------------------------------------------------
// 设备注册表（bridge.json v2）
// ---------------------------------------------------------------------------

/** 生成一台设备的条目 + 明文 token（明文 token 只交给手机一次，state 里只落哈希）。 */
export function createDeviceEntry(options = {}) {
  const {
    name,
    platform,
    token,
    now = nowMs,
    random = crypto.randomBytes,
    createdAt = null,
  } = options;
  const rawToken = typeof token === 'string' && token !== '' ? token : random(32).toString('base64url');
  const created = Number.isFinite(createdAt) ? createdAt : now();
  return {
    entry: {
      id: random(8).toString('hex'),
      name: normalizeDeviceName(name),
      platform: normalizePlatform(platform),
      tokenHash: sha256Hex(rawToken),
      tokenTail: tokenTail(rawToken),
      createdAt: created,
      lastSeenAt: created,
      revoked: false,
    },
    token: rawToken,
  };
}

/** 设备名消毒：去掉控制字符、限长；空值回退到默认名。 */
export function normalizeDeviceName(name, fallback = DEFAULT_DEVICE_NAME) {
  const text = String(name ?? '')
    .replace(/[\r\n\t\u0000-\u001f\u007f]/g, ' ')
    .trim();
  if (!text) return fallback;
  return text.slice(0, MAX_DEVICE_NAME_LEN);
}

/** 设备平台消毒：去掉控制字符、折叠空白、限长；空值记为 unknown（仅展示用途）。 */
export function normalizePlatform(platform) {
  const text = String(platform ?? '')
    .replace(/[\r\n\t\u0000-\u001f\u007f]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  if (!text) return 'unknown';
  return text.slice(0, MAX_PLATFORM_LEN);
}

/**
 * 在设备注册表里按 token 查找设备（常量时间比较 sha256）。
 * 返回已撤销设备（调用方据此区分「无效 token」与「设备已撤销」）。
 */
export function findDeviceByToken(devices, token) {
  if (typeof token !== 'string' || token === '' || !Array.isArray(devices)) return null;
  const candidate = Buffer.from(sha256Hex(token), 'hex');
  for (const device of devices) {
    const expected = typeof device?.tokenHash === 'string' ? device.tokenHash : '';
    if (!/^[0-9a-f]{64}$/.test(expected)) continue;
    let equal = false;
    try {
      equal = crypto.timingSafeEqual(candidate, Buffer.from(expected, 'hex'));
    } catch {
      equal = false;
    }
    if (equal) return device;
  }
  return null;
}

/** 把磁盘上读到的 v2 状态消毒/规整（坏条目丢弃，保证后续逻辑断言可直接信任）。 */
function sanitizeStateV2(raw, now) {
  const devices = [];
  const usedIds = new Set();
  for (const item of Array.isArray(raw?.devices) ? raw.devices : []) {
    if (!item || typeof item !== 'object') continue;
    const id = typeof item.id === 'string' ? item.id.trim().slice(0, 64) : '';
    const tokenHash = typeof item.tokenHash === 'string' ? item.tokenHash.toLowerCase() : '';
    if (!id || usedIds.has(id) || !/^[0-9a-f]{64}$/.test(tokenHash)) continue;
    usedIds.add(id);
    const createdAt = Number.isFinite(item.createdAt) ? item.createdAt : now();
    const entry = {
      id,
      name: normalizeDeviceName(item.name),
      platform: normalizePlatform(item.platform),
      tokenHash,
      tokenTail: typeof item.tokenTail === 'string' ? item.tokenTail.slice(-4) : '',
      createdAt,
      lastSeenAt: Number.isFinite(item.lastSeenAt) ? item.lastSeenAt : createdAt,
      revoked: item.revoked === true,
    };
    if (Number.isFinite(item.revokedAt)) entry.revokedAt = item.revokedAt;
    if (typeof item.relayKey === 'string' && /^[A-Za-z0-9_-]{43}$/.test(item.relayKey)) entry.relayKey = item.relayKey;
    devices.push(entry);
  }
  return { version: STATE_VERSION, devices };
}

/** v0.1 的单 token 状态迁移为 devices[0]：哈希后立刻丢弃明文，旧 token 继续有效。 */
function migrateLegacyState(existing, now) {
  if (!existing || existing.version !== 1) return null;
  if (typeof existing.token !== 'string' || !TOKEN_PATTERN.test(existing.token)) return null;
  const createdAt = Number.isFinite(existing.createdAt) ? existing.createdAt : now();
  const { entry } = createDeviceEntry({
    name: existing.deviceName,
    platform: 'pc',
    token: existing.token,
    now,
    createdAt,
  });
  // id 由哈希派生，保证迁移后重启仍然稳定。
  entry.id = `legacy-${entry.tokenHash.slice(0, 8)}`;
  entry.lastSeenAt = now();
  return entry;
}

/**
 * 失效设备清理策略。
 *
 * 背景：`bridge.json` 里的设备只会新增、永不删除，长时间跑下来会积累一堆
 * 「已撤销」和「装了又不用」的条目（实测 16 台里 8 台是已撤销的废条目）。
 * 它们不影响安全（已撤销=token 哈希作废），但会拖慢每次状态读写、让排障时看不清真正在用的设备。
 *
 * 阈值刻意保守：撤销后仍保留 7 天（便于排查"某台是不是被误撤销"），
 * 未撤销但 90 天没露面的才删（避免误删长期不用但还会用的设备）。
 */
export const STALE_REVOKED_MS = 7 * 24 * 60 * 60 * 1000;
export const STALE_UNUSED_MS = 90 * 24 * 60 * 60 * 1000;

/**
 * 从状态里剔除失效设备，返回保留下来的列表与被删清单（供审计）。
 *
 * @returns {{keep: object[], removed: Array<{id:string,name:string,reason:string,idleDays:number}>}}
 */
export function pruneDevices(state, now = nowMs()) {
  const devices = Array.isArray(state?.devices) ? state.devices : [];
  const keep = [];
  const removed = [];
  for (const device of devices) {
    const lastName = device?.lastSeenAt ?? device?.createdAt ?? 0;
    const idleMs = lastName > 0 ? now - lastName : Number.POSITIVE_INFINITY;
    if (device?.revoked === true && idleMs >= STALE_REVOKED_MS) {
      removed.push({ id: device.id, name: device.name ?? '', reason: 'revoked-stale', idleDays: Math.floor(idleMs / 86400000) });
      continue;
    }
    if (device?.revoked !== true && idleMs >= STALE_UNUSED_MS) {
      removed.push({ id: device.id, name: device.name ?? '', reason: 'unused-stale', idleDays: Math.floor(idleMs / 86400000) });
      continue;
    }
    keep.push(device);
  }
  return { keep, removed };
}

/**
 * 读取/创建状态文件（<state-dir>/bridge.json, version 2）。
 * - v1 单 token 自动迁移为 devices[0]（旧 token 继续可用）；
 * - 损坏文件不阻塞启动，替换为空注册表并打 replacedCorrupt；
 * - --reset 清空所有设备。
 *
 * @returns {{path:string, state:{version:number, devices:object[]}, resetPerformed:boolean,
 *            replacedCorrupt:boolean, migratedFromV1:boolean}}
 */
export function loadOrCreateState(options = {}) {
  const {
    stateDir = DEFAULT_STATE_DIR,
    reset = false,
    now = nowMs,
    stateFileName = STATE_FILE_NAME,
  } = options;
  fs.mkdirSync(stateDir, { recursive: true });
  const statePath = path.join(stateDir, stateFileName);
  let existing = null;
  let corrupt = false;
  let recoveredFromBackup = false;
  try {
    existing = JSON.parse(fs.readFileSync(statePath, 'utf8'));
  } catch (error) {
    if (error?.code !== 'ENOENT') {
      // 先尝试从备份恢复：一次半截 JSON / EBUSY 不该让所有设备失效
      try {
        existing = JSON.parse(fs.readFileSync(`${statePath}.bak`, 'utf8'));
        recoveredFromBackup = true;
      } catch {
        corrupt = true;
      }
    }
  }
  // 主文件与备份都读不出来：把坏文件留档，绝不静默覆盖丢证据。
  if (corrupt && fs.existsSync(statePath)) {
    const stamp = Date.now();
    try {
      fs.renameSync(statePath, `${statePath}.corrupt-${stamp}`);
      console.warn(`[state] bridge 状态文件损坏且无可恢复备份，已留档 ${statePath}.corrupt-${stamp}；` +
        '设备表将重建，现有手机需要重新配对。');
    } catch {
      /* 改名失败也要继续，避免桥接完全起不来 */
    }
  }
  const fresh = () => ({ version: STATE_VERSION, devices: [] });
  if (reset) {
    const state = fresh();
    writeStateFile(statePath, state);
    return { path: statePath, state, resetPerformed: existing !== null, replacedCorrupt: corrupt, migratedFromV1: false, recoveredFromBackup };
  }
  if (existing && existing.version === STATE_VERSION) {
    const state = sanitizeStateV2(existing, now);
    writeStateFile(statePath, state);
    return { path: statePath, state, resetPerformed: false, replacedCorrupt: corrupt, migratedFromV1: false, recoveredFromBackup };
  }
  const legacyDevice = migrateLegacyState(existing, now);
  if (legacyDevice) {
    const state = fresh();
    state.devices.push(legacyDevice);
    writeStateFile(statePath, state);
    return { path: statePath, state, resetPerformed: false, replacedCorrupt: false, migratedFromV1: true, recoveredFromBackup };
  }
  const state = fresh();
  writeStateFile(statePath, state);
  return {
    path: statePath,
    state,
    resetPerformed: false,
    replacedCorrupt: corrupt || existing !== null,
    migratedFromV1: false,
    recoveredFromBackup,
  };
}

/** 原子性足够（单进程写小 JSON）：先写临时文件再 rename，避免崩溃留下半截 JSON。 */
export function writeStateFile(statePath, state) {
  const serialized = JSON.stringify(state, null, 2) + '\n';
  const tempPath = `${statePath}.tmp-${process.pid}`;
  fs.writeFileSync(tempPath, serialized, { mode: 0o600 });
  try {
    fs.chmodSync(tempPath, 0o600); // Windows 上只是尽力而为，POSIX 上真正生效
  } catch {
    /* Windows 不完整支持 chmod，忽略 */
  }
  // 覆盖前留一份：设备表是整个桥接最不可再生的数据之一（丢了所有手机要重扫）
  try {
    if (fs.existsSync(statePath)) fs.copyFileSync(statePath, `${statePath}.bak`);
  } catch {
    /* 备份失败不阻塞主流程 */
  }
  fs.renameSync(tempPath, statePath);
  // 首次写入时没有旧文件，把刚写的本身作为首份备份
  try {
    if (!fs.existsSync(`${statePath}.bak`)) fs.copyFileSync(statePath, `${statePath}.bak`);
  } catch {
    /* 尽力而为 */
  }
}

// ---------------------------------------------------------------------------
// 登录码（一次性 6 位，10 分钟）
// ---------------------------------------------------------------------------

/** 生成 `ABC-DEF` 形式的登录码；字母表已去掉 I/O/0/1 等易混字符。 */
export function generatePairCode(random = crypto.randomBytes) {
  const bytes = random(PAIR_CODE_LENGTH);
  let raw = '';
  for (let index = 0; index < PAIR_CODE_LENGTH; index += 1) {
    raw += PAIR_CODE_ALPHABET[bytes[index] % PAIR_CODE_ALPHABET.length];
  }
  return `${raw.slice(0, 3)}-${raw.slice(3)}`;
}

/**
 * 归一化用户输入的登录码：大小写/空格/短横线位置不敏感
 * （与 App 端一致：`code.replace(/[^A-Za-z0-9]/g,'').toUpperCase()`）。
 * @returns {string|null} `ABC-DEF`，非法时 null
 */
export function normalizePairCode(input) {
  const compact = String(input ?? '')
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, '');
  if (compact.length !== PAIR_CODE_LENGTH) return null;
  for (const ch of compact) {
    if (!PAIR_CODE_ALPHABET.includes(ch)) return null;
  }
  return `${compact.slice(0, 3)}-${compact.slice(3)}`;
}

/** 新建一份登录码状态（内存态；不落盘，重启即失效）。 */
export function createPairingState(now = nowMs, ttlMs = PAIR_CODE_TTL_MS) {
  const createdAt = now();
  return {
    code: generatePairCode(),
    createdAt,
    expiresAt: createdAt + Math.max(1000, ttlMs),
    redeemedAt: 0,
  };
}

/** 登录码是否仍可用（未兑换且未过期）。 */
export function pairingIsActive(pairing, now = nowMs) {
  return Boolean(pairing && pairing.code && !pairing.redeemedAt && now() < pairing.expiresAt);
}

// ---------------------------------------------------------------------------
// 限流器（固定窗口）
// ---------------------------------------------------------------------------

export function createWindowLimiter({ limit, windowMs, now = nowMs }) {
  if (!Number.isFinite(limit) || limit <= 0) throw new Error('limit 必须为正数');
  if (!Number.isFinite(windowMs) || windowMs <= 0) throw new Error('windowMs 必须为正数');
  const buckets = new Map();
  const get = (key, create) => {
    const t = now();
    let bucket = buckets.get(key);
    if (!bucket || t - bucket.start >= windowMs) {
      if (!create) return null;
      bucket = { start: t, count: 0 };
      buckets.set(key, bucket);
    }
    return bucket;
  };
  return {
    /** 记一次请求；返回 {allowed, retryAfterSec}。 */
    consume(key) {
      const bucket = get(key, true);
      bucket.count += 1;
      if (bucket.count > limit) {
        return { allowed: false, retryAfterSec: Math.max(1, Math.ceil((bucket.start + windowMs - now()) / 1000)) };
      }
      return { allowed: true, retryAfterSec: 0 };
    },
    /** 记一次失败（认证失败），返回当前窗口内的失败次数。 */
    recordFailure(key) {
      const bucket = get(key, true);
      bucket.count += 1;
      return bucket.count;
    },
    /** 该 key 是否已经被限速（失败次数达到阈值）。 */
    isBlocked(key) {
      const bucket = get(key, false);
      return Boolean(bucket && bucket.count >= limit);
    },
    retryAfterSec(key) {
      const bucket = get(key, false);
      if (!bucket) return 1;
      return Math.max(1, Math.ceil((bucket.start + windowMs - now()) / 1000));
    },
    clear(key) {
      buckets.delete(key);
    },
    prune() {
      const t = now();
      for (const [key, bucket] of buckets) if (t - bucket.start >= windowMs) buckets.delete(key);
    },
    get size() {
      return buckets.size;
    },
  };
}

// ---------------------------------------------------------------------------
// 审计日志
// ---------------------------------------------------------------------------

/** JSONL 审计：允许与拒绝都记录；绝不包含 token/cookie/密钥/登录码。 */
export function createAuditLog(filePath, now = nowMs) {
  let failed = false;
  return {
    path: filePath,
    write(entry) {
      if (failed) return;
      const line = {
        ts: new Date(now()).toISOString(),
        method: sanitizeField(entry.method),
        path: sanitizeField(entry.path),
        decision: entry.decision === 'allow' ? 'allow' : 'deny',
        reason: sanitizeField(entry.reason ?? ''),
        status: Number.isInteger(entry.status) ? entry.status : 0,
        ms: Number.isFinite(entry.ms) ? Math.max(0, Math.round(entry.ms)) : 0,
        bytes: Number.isFinite(entry.bytes) ? Math.max(0, Math.round(entry.bytes)) : 0,
        remoteAddr: sanitizeField(entry.remoteAddr ?? ''),
        upgrade: entry.upgrade === true,
      };
      // 账号主机：审计必须能回答「哪台设备做了什么」，但绝不能写 token/登录码。
      if (entry.deviceId) line.deviceId = sanitizeField(entry.deviceId);
      if (entry.targetDeviceId) line.targetDeviceId = sanitizeField(entry.targetDeviceId);
      // outbox 下载：记下手机取走了哪个文件。
      if (entry.file) line.file = sanitizeField(entry.file);
      try {
        fs.appendFileSync(filePath, JSON.stringify(line) + '\n');
      } catch {
        failed = true; // 审计写失败不拖垮桥接，但只提示一次
      }
    },
  };
}

function sanitizeField(value) {
  return String(value ?? '')
    .replace(/[\r\n\t\u0000-\u001f\u007f]/g, '?')
    .slice(0, 256);
}

function normalizeRemote(address) {
  const text = String(address ?? '');
  return text.startsWith('::ffff:') ? text.slice(7) : text;
}

// ---------------------------------------------------------------------------
// 请求分类（白名单）
// ---------------------------------------------------------------------------

/**
 * 判断一个 HTTP 请求是否可被转发。
 * @returns {{allowed:boolean, kind:'health'|'api'|'other', endpoint?:string, reason:string}}
 */
export function classifyRequest(method, pathname) {
  const upper = String(method ?? '').toUpperCase();
  if (pathname === '/healthz') {
    if (upper === 'GET' || upper === 'POST') return { allowed: true, kind: 'health', reason: 'ok' };
    return { allowed: false, kind: 'health', reason: 'http-method-not-allowed' };
  }
  if (!pathname.startsWith('/api/')) {
    return { allowed: false, kind: 'other', reason: 'non-api-path' };
  }
  const endpoint = pathname.slice('/api/'.length);
  if (!SAFE_ENDPOINT_PATTERN.test(endpoint)) {
    return { allowed: false, kind: 'api', endpoint, reason: 'malformed-endpoint' };
  }
  if (upper !== 'POST') {
    return { allowed: false, kind: 'api', endpoint, reason: 'http-method-not-allowed' };
  }
  if (ALLOWED_ENDPOINTS.has(endpoint)) {
    return { allowed: true, kind: 'api', endpoint, reason: 'ok' };
  }
  const forbidden = FORBIDDEN_PREFIXES.some(
    (prefix) => endpoint === prefix || endpoint.startsWith(prefix.endsWith('/') ? prefix : prefix + '/'),
  );
  return {
    allowed: false,
    kind: 'api',
    endpoint,
    reason: forbidden ? 'forbidden-method' : 'unknown-method',
  };
}

/** 从请求里取设备 token：Authorization: Bearer > x-dsbot-token > ?token=。 */
export function extractToken(headers, searchParams) {
  const authorization = headers?.authorization;
  if (typeof authorization === 'string') {
    const match = authorization.match(/^\s*Bearer\s+(.+?)\s*$/i);
    if (match) return match[1];
  }
  const custom = headers?.['x-dsbot-token'];
  if (typeof custom === 'string' && custom.trim() !== '') return custom.trim();
  const queryToken = searchParams?.get?.('token');
  if (typeof queryToken === 'string' && queryToken.trim() !== '') return queryToken.trim();
  return '';
}

/** 尽量安全地解析请求 URL；失败时退回一个只有 pathname 的构造。 */
function safeParseRequestUrl(rawUrl) {
  const raw = typeof rawUrl === 'string' && rawUrl.startsWith('/') ? rawUrl : '/';
  const url = new URL(raw, 'http://bridge.invalid');
  return url;
}

// ---------------------------------------------------------------------------
// 多上游 DSH（桌面版 + dsh web 命令行）目标列表与选择偏好
// ---------------------------------------------------------------------------

/** 用户选择的后端偏好存这里（按 kind 记录，端口变了也能跟回来）。 */
export const UPSTREAM_PREFERENCE_FILE = 'upstream.json';

const TARGET_KIND_LABELS = {
  desktop: '桌面版 DeepSeek Harness',
  cli: 'dsh web（命令行）',
  manual: 'DSH Web（手动指定）',
  unknown: 'DSH Web',
};

function targetLabel(kind, label) {
  if (typeof label === 'string' && label.trim() !== '') return label.trim();
  return TARGET_KIND_LABELS[kind] ?? kind ?? 'DSH Web';
}

/**
 * 把发现结果/手工地址统一成桥接内部的后端目标：
 * [{key, authority, host, port, kind, label, pid, processName, alive}]
 * 入参可以是字符串（`127.0.0.1:49563`）或发现模块返回的对象。
 */
export function normalizeDshTargets(rawTargets, fallbackAuthority = null) {
  const raw = Array.isArray(rawTargets) && rawTargets.length > 0 ? rawTargets : fallbackAuthority ? [fallbackAuthority] : [];
  const targets = [];
  const usedKeys = new Set();
  const seenAuthority = new Set();
  for (const item of raw) {
    const isObject = item !== null && typeof item === 'object';
    const authorityText = isObject ? String(item.authority ?? item.key ?? '') : String(item ?? '');
    let parsed;
    try {
      parsed = parseAuthority(authorityText);
    } catch {
      continue;
    }
    if (seenAuthority.has(parsed.authority)) continue;
    seenAuthority.add(parsed.authority);
    const kind = isObject && item.kind ? String(item.kind) : fallbackAuthority ? 'manual' : 'unknown';
    let key = isObject && item.key ? String(item.key) : kind;
    if (usedKeys.has(key)) {
      let suffix = 2;
      while (usedKeys.has(`${key}-${suffix}`)) suffix += 1;
      key = `${key}-${suffix}`;
    }
    usedKeys.add(key);
    targets.push({
      key,
      authority: parsed.authority,
      host: parsed.host,
      port: parsed.port,
      kind,
      label: targetLabel(kind, isObject ? item.label : ''),
      pid: isObject && Number(item.pid) ? Number(item.pid) : 0,
      processName: isObject && typeof item.processName === 'string' ? item.processName : '',
      alive: !(isObject && item.alive === false),
    });
  }
  return targets;
}

/** 启动时选中的后端：优先命令行显式地址，其次持久化偏好，最后第一个。 */
export function selectInitialTarget(targets, authority = '', preferredKind = null) {
  if (!Array.isArray(targets) || targets.length === 0) return null;
  if (authority) {
    try {
      const parsed = parseAuthority(authority);
      const exact = targets.find((target) => target.authority === parsed.authority);
      if (exact) return exact;
    } catch {
      /* ignore */
    }
  }
  if (preferredKind) {
    const preferred = targets.find((target) => target.kind === preferredKind && target.alive !== false);
    if (preferred) return preferred;
  }
  return targets[0];
}

/** 读取 `--dsh auto` 的后端偏好（按 kind，端口变换不影响）。 */
export function loadUpstreamPreference(stateDir = DEFAULT_STATE_DIR) {
  try {
    const parsed = JSON.parse(fs.readFileSync(path.join(stateDir, UPSTREAM_PREFERENCE_FILE), 'utf8'));
    const kind = typeof parsed?.kind === 'string' && parsed.kind.trim() !== '' ? parsed.kind.trim() : '';
    if (!kind) return null;
    return { kind, key: typeof parsed?.key === 'string' ? parsed.key : '', updatedAt: Number(parsed?.updatedAt) || 0 };
  } catch {
    return null;
  }
}

/** 保存后端偏好；写失败不影响当前会话（下次启动回到默认选择）。 */
export function saveUpstreamPreference(stateDir = DEFAULT_STATE_DIR, preference = {}) {
  const kind = typeof preference.kind === 'string' ? preference.kind.trim() : '';
  if (!kind) return null;
  const payload = { version: 1, kind, key: typeof preference.key === 'string' ? preference.key : '', updatedAt: Date.now() };
  try {
    fs.mkdirSync(stateDir, { recursive: true });
    fs.writeFileSync(path.join(stateDir, UPSTREAM_PREFERENCE_FILE), JSON.stringify(payload), 'utf8');
  } catch {
    return null;
  }
  return payload;
}

/** 探测本机 TCP 端口是否可连（dsh web 自启等待用）。 */
export function probePort(host, port, timeoutMs = 500) {
  return new Promise((resolve) => {
    const socket = net.connect({ host, port });
    let done = false;
    const finish = (value) => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve(value);
    };
    socket.setTimeout(timeoutMs, () => finish(false));
    socket.once('connect', () => finish(true));
    socket.once('error', () => finish(false));
  });
}

/** 找本机的 dsh CLI（WinGet 全局安装 / npm 全局 / DSBOT_DSH_BIN）。 */
export function findDshCliBin() {
  const candidates = [];
  if (process.env.DSBOT_DSH_BIN) candidates.push(process.env.DSBOT_DSH_BIN);
  const local = process.env.LOCALAPPDATA;
  if (local) {
    const packages = path.join(local, 'Microsoft', 'WinGet', 'Packages');
    try {
      for (const name of fs.readdirSync(packages)) {
        if (!name.startsWith('OpenJS.NodeJS')) continue;
        const root = path.join(packages, name);
        for (const dir of fs.readdirSync(root)) {
          if (!dir.startsWith('node-')) continue;
          candidates.push(path.join(root, dir, 'node_modules', '@deepseek-ai', 'dsh', 'lib', 'bin.js'));
        }
      }
    } catch {
      /* ignore */
    }
  }
  if (process.env.APPDATA) {
    candidates.push(path.join(process.env.APPDATA, 'npm', 'node_modules', '@deepseek-ai', 'dsh', 'lib', 'bin.js'));
  }
  if (process.platform !== 'win32') {
    const home = process.env.HOME ?? '';
    const roots = [
      '/opt/homebrew/lib/node_modules',
      '/usr/local/lib/node_modules',
      '/usr/lib/node_modules',
      home ? path.join(home, '.npm-global', 'lib', 'node_modules') : '',
      home ? path.join(home, '.local', 'lib', 'node_modules') : '',
    ].filter(Boolean);
    for (const root of roots) {
      candidates.push(path.join(root, '@deepseek-ai', 'dsh', 'lib', 'bin.js'));
    }
  }
  return candidates.find((item) => {
    try {
      return fs.existsSync(item);
    } catch {
      return false;
    }
  }) ?? null;
}

/**
 * 确保本机 dsh web 在跑：已在监听直接返回；否则用全局 dsh CLI 起一个（隐藏窗口、日志进 logPath）。
 * 只在“切到 Web 端”时调用，不影响桌面版。
 */
export async function startDshWeb({ port = 3080, logPath, timeoutMs = 12000, nodeExe } = {}) {
  if (await probePort('127.0.0.1', port, 500)) return { ok: true, already: true, port };
  const bin = findDshCliBin();
  if (!bin) return { ok: false, message: '找不到 dsh CLI（可设 DSBOT_DSH_BIN 指向 .../dsh/lib/bin.js）' };
  const prefix = bin.split(`${path.sep}node_modules${path.sep}`)[0];
  const exe = nodeExe || (fs.existsSync(path.join(prefix, 'node.exe')) ? path.join(prefix, 'node.exe') : process.execPath);
  let fd = 'ignore';
  if (logPath) {
    try {
      fd = fs.openSync(logPath, 'a');
    } catch {
      fd = 'ignore';
    }
  }
  const child = spawn(exe, [bin, 'web', '--port', String(port), '--no-open'], {
    detached: true,
    stdio: ['ignore', fd, fd],
    windowsHide: true,
  });
  child.unref();
  if (typeof fd === 'number') {
    try {
      fs.closeSync(fd);
    } catch {
      /* ignore */
    }
  }
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 500));
    if (await probePort('127.0.0.1', port, 400)) return { ok: true, started: true, port, pid: child.pid, logPath };
  }
  return { ok: false, message: `dsh web 启动超时（${timeoutMs}ms）`, logPath, pid: child.pid };
}

// ---------------------------------------------------------------------------
// 桥接实例
// ---------------------------------------------------------------------------

/**
 * 创建一个桥接实例（不自动监听，方便测试）。
 * @param {object} options
 * @param {number} [options.port]
 * @param {string} [options.bind]
 * @param {string} [options.dsh] 上游 DSH “host:port”
 * @param {string} [options.stateDir]
 * @param {string} [options.credentialsPath]
 * @param {boolean} [options.reset] 清空所有设备（v0.1 兼容：重置单 token 状态）
 * @param {boolean} [options.forceNewPair] 启动时强制生成新登录码（--pair）
 * @param {string|null} [options.revokeOnStart] 启动时先撤销指定设备（--revoke）
 * @param {number} [options.pairingTtlMs] 登录码有效期（测试用）
 * @param {object} [options.limits] 测试用限流覆盖
 * @param {() => number} [options.now]
 * @param {Array|string[]} [options.dshTargets] 可用后端列表（--dsh auto 发现的结果）
 * @param {string|null} [options.preferredKind] 后端偏好（desktop / cli）
 * @param {(cookieFor: (authority:string)=>string) => Promise<object[]>} [options.discoverTargets]
 *        运行期重新发现后端（端口变化/后端启停时用）；缺省用 dsh-discover 的实现
 */
export function createBridge(options = {}) {
  const {
    port = DEFAULT_PORT,
    bind = DEFAULT_BIND,
    dsh = DEFAULT_DSH,
    stateDir = DEFAULT_STATE_DIR,
    outboxDir = '',
    inboxDir = '',
    credentialsPath = DEFAULT_CREDENTIALS_PATH,
    reset = false,
    forceNewPair = false,
    revokeOnStart = null,
    relayInfo = null,
    autoDiscover = false,
    pairingTtlMs = PAIR_CODE_TTL_MS,
    limits = {},
    now = nowMs,
    dshTargets = null,
    preferredKind = null,
    discoverTargets = null,
  } = options;

  // 多上游：桌面版 DSH 与 dsh web 可能同时存在；activeTarget 指向当前代理的后端。
  let targets = normalizeDshTargets(dshTargets, dsh);
  let activeTarget = selectInitialTarget(targets, dsh, preferredKind);
  let preferred = preferredKind ? String(preferredKind) : null;
  if (!activeTarget) throw new Error('没有可用的上游 DSH 地址');
  let upstream = parseAuthority(activeTarget.authority);
  const secret = loadCookieSecret(credentialsPath);
  const startWeb = options.startDshWeb ?? startDshWeb;
  let cookieName = computeCookieName(upstream.authority);
  /** 活跃的 /api/remote.mux 客户端 socket；上游切换时用 1012 关闭，让客户端自动重连。 */
  const activeMuxSockets = new Set();
  const account = loadAccountInfo(credentialsPath);
  const stateInfo = loadOrCreateState({ stateDir, reset, now });
  const state = stateInfo.state;
  const statePath = stateInfo.path;
  const audit = createAuditLog(path.join(stateDir, 'audit.log'), now);

  // 启动时清理一次失效设备：已撤销超 7 天、或未撤销但 90 天没露面的。
  // 设备表只增不删会越积越多（实测 16 台里 8 台是彻底失效的条目），既拖慢读写也让排障看不清。
  try {
    const pruned = pruneDevices(state, now());
    if (pruned.removed.length > 0) {
      state.devices = pruned.keep;
      writeStateFile(statePath, state);
      for (const item of pruned.removed) {
        audit.write({ method: 'DEVICE', path: item.id, decision: 'prune', reason: item.reason, status: 0, remoteAddr: '' });
      }
      console.log(`[state] 已清理 ${pruned.removed.length} 台失效设备（撤销超 7 天 / 90 天未使用）`);
    }
  } catch (error) {
    // 清理失败不该影响启动，但必须留痕——静默吞掉会让"为什么没清理"无从查起。
    console.warn(`[state] 清理失效设备失败（继续启动）：${error?.message ?? error}`);
  }

  const lim = {
    requestLimit: limits.requestLimit ?? REQUEST_LIMIT,
    requestWindowMs: limits.requestWindowMs ?? REQUEST_WINDOW_MS,
    authFailLimit: limits.authFailLimit ?? AUTH_FAIL_LIMIT,
    authFailWindowMs: limits.authFailWindowMs ?? AUTH_FAIL_WINDOW_MS,
    pairFailLimit: limits.pairFailLimit ?? AUTH_FAIL_LIMIT,
    pairFailWindowMs: limits.pairFailWindowMs ?? AUTH_FAIL_WINDOW_MS,
  };
  const requestLimiter = createWindowLimiter({
    limit: lim.requestLimit,
    windowMs: lim.requestWindowMs,
    now,
  });
  const authFailLimiter = createWindowLimiter({
    limit: lim.authFailLimit,
    windowMs: lim.authFailWindowMs,
    now,
  });
  const pairFailLimiter = createWindowLimiter({
    limit: lim.pairFailLimit,
    windowMs: lim.pairFailWindowMs,
    now,
  });

  // 登录码只存在内存里：重启即作废，避免把 6 位码落盘后被离线暴力猜测。
  let pairing = createPairingState(now, pairingTtlMs);
  if (forceNewPair) pairing = createPairingState(now, pairingTtlMs);
  let lastPersistAt = now();
  const persistState = () => {
    writeStateFile(statePath, state);
    lastPersistAt = now();
  };

  const sockets = new Set();
  let server = null;
  let portActual = port;
  let startedAt = 0;
  let pruneTimer = null;
  let pairPagePath = '';
  let pairLink = '';
  let lanUrls = [];

  // --revoke <deviceId>：启动时撤销指定设备（撤销结果会打印在启动报告里）。
  let rediscovering = false;
  let lastRediscoverAt = 0;
  /** 上游连续失败次数（dsh 重启会连击，用来加快 failover）。 */
  let upstreamFailureStreak = 0;
  /** 上游探活定时器。 */
  let upstreamWatchdog = null;
  let startupRevocation = null;
  if (typeof revokeOnStart === 'string' && revokeOnStart.trim() !== '') {
    const requestedId = revokeOnStart.trim();
    const target = state.devices.find((device) => device.id === requestedId);
    const wasRevoked = target?.revoked === true;
    if (target && !wasRevoked) {
      target.revoked = true;
      target.revokedAt = now();
      persistState();
    }
    startupRevocation = { deviceId: requestedId, found: Boolean(target), alreadyRevoked: wasRevoked };
  }

  // ---- 多上游辅助：切换 / 刷新 / 失败转移 -------------------------------
  const viewTarget = (target) => ({
    key: target.key,
    kind: target.kind,
    label: target.label,
    authority: target.authority,
    pid: target.pid || 0,
    processName: target.processName || '',
    alive: target.alive !== false,
  });

  const applyTarget = (target) => {
    const next = parseAuthority(target.authority);
    const changed = upstream.authority !== next.authority;
    activeTarget = target;
    upstream = next;
    cookieName = computeCookieName(upstream.authority);
    // 上游变了：主动关闭所有 mux，让客户端按 1012（Service Restart）重连到新上游。
    if (changed && activeMuxSockets.size > 0) {
      for (const socket of activeMuxSockets) {
        try {
          socket.write(wsCloseFrame(1012, 'upstream switched'));
          socket.end();
        } catch {
          /* ignore */
        }
        activeMuxSockets.delete(socket);
      }
      audit.write({ method: 'DSH', path: upstream.authority, decision: 'allow', reason: 'mux-closed-on-switch', status: 0, remoteAddr: '' });
    }
  };

  const findTargetByKey = (key) => {
    const wanted = String(key ?? '').trim();
    if (!wanted) return null;
    // 规格：key | kind | authority 任一匹配即可（App 会同时带 key/kind/authority）。
    return (
      targets.find((target) => target.key === wanted) ??
      targets.find((target) => target.kind === wanted) ??
      targets.find((target) => target.authority === wanted) ??
      null
    );
  };

  /** 运行期重新发现（端口变化/后端启停）。返回后端数组；失败时返回空数组。 */
  const discoverLatestTargets = async () => {
    const provider =
      typeof discoverTargets === 'function'
        ? discoverTargets
        : (cookieFor) => discoverDshTargets(cookieFor, { excludePorts: [portActual] });
    try {
      const discovered = await provider((authority) => bridge.cookieFor(authority));
      return normalizeDshTargets(discovered, null).map((target) => ({ ...target, alive: true }));
    } catch {
      return [];
    }
  };

  /** 把发现结果合并进 targets：同 authority 保留旧 key，当前后端消失时保留一条 alive:false 供 App 展示。 */
  const mergeDiscovered = (discovered) => {
    const currentAuthority = activeTarget?.authority ?? '';
    const merged = discovered.map((target) => {
      const same = targets.find((item) => item.authority === target.authority);
      return same ? { ...target, key: same.key } : target;
    });
    if (currentAuthority && activeTarget && !merged.some((target) => target.authority === currentAuthority)) {
      merged.push({ ...activeTarget, alive: false });
    }
    targets = merged;
    return targets;
  };

  const buildUpstreamsView = () => {
    const list = targets.map((target) => ({
      ...viewTarget(target),
      active: target.authority === upstream.authority,
    }));
    if (!list.some((item) => item.active) && activeTarget) {
      list.unshift({ ...viewTarget({ ...activeTarget, alive: false }), active: true });
    }
    return {
      activeKey: activeTarget?.key ?? '',
      activeAuthority: upstream.authority,
      preferredKind: preferred,
      targets: list,
    };
  };

  /** 上游不可用时的自动转移：同 kind 跟端口 > 偏好 kind > 第一个可用。 */
  const failoverIfNeeded = async () => {
    const discovered = await discoverLatestTargets();
    if (discovered.length === 0) return;
    const previous = activeTarget;
    const next = discovered.map((target) => {
      const same = targets.find((item) => item.authority === target.authority);
      return same ? { ...target, key: same.key } : target;
    });
    const exact = next.find((target) => target.authority === previous?.authority);
    if (exact) {
      targets = next;
      activeTarget = exact;
      return;
    }
    const sameKind = previous ? next.find((target) => target.kind === previous.kind) : null;
    if (!sameKind) {
      // 手动切换语义：另一种后端不自动顶替；保留当前（标记离线），等用户在 App 里手动切。
      //
      // 例外：显式 `--dsh host:port` / App 手动填的地址（kind=manual）本身就代表「这台 DSH」，
      // 它的端口漂移（dsh 重启换端口）没有同 kind 的目标可跟随，必须允许改连到发现到的存活后端，
      // 否则桥接会永远抱着一个死端口。
      const manualFallback = previous && previous.kind === 'manual'
        ? next.find((target) => target.alive !== false)
        : null;
      if (manualFallback) {
        targets = next;
        const previousAuthority = previous?.authority ?? '';
        applyTarget(manualFallback);
        audit.write({ method: 'DSH', path: manualFallback.authority, decision: 'allow', reason: 'upstream-rediscovered-manual', status: 0, remoteAddr: '' });
        if (typeof options.onUpstreamChange === 'function') options.onUpstreamChange(previousAuthority, manualFallback.authority, viewTarget(manualFallback));
        return;
      }
      if (previous) next.push({ ...previous, alive: false });
      targets = next;
      return;
    }
    targets = next;
    const previousAuthority = previous?.authority ?? '';
    applyTarget(sameKind);
    audit.write({ method: 'DSH', path: sameKind.authority, decision: 'allow', reason: 'upstream-rediscovered', status: 0, remoteAddr: '' });
    if (typeof options.onUpstreamChange === 'function') options.onUpstreamChange(previousAuthority, sameKind.authority, viewTarget(sameKind));
  };

  const BLOCKED_EXEC_PATTERNS = [/rm\s+-rf/i, /\bmkfs\b/i, /\bformat\b/i, /\bshutdown\b/i, /\breboot\b/i, /dd\s+if=/i, />\s*\/dev\/sd/i];
  const CONTROL_ROOTS = [stateDir, outboxDir, inboxDir].filter(Boolean).map((item) => path.resolve(item));
  const controlPathAllowed = (raw) => {
    const target = path.resolve(String(raw || ''));
    return CONTROL_ROOTS.some((root) => target === root || target.startsWith(root + path.sep));
  };
  const controlExecAllowed = (argv) => {
    const source = Array.isArray(argv) ? argv.join(' ') : String(argv || '');
    return !BLOCKED_EXEC_PATTERNS.some((pattern) => pattern.test(source));
  };

  const controlLockPath = path.join(stateDir, 'control-lock.json');
  let controlLocked = false;
  try { controlLocked = JSON.parse(fs.readFileSync(controlLockPath, 'utf8')).locked === true; } catch { /* absent */ }
  const persistControlLock = () => {
    try { fs.writeFileSync(controlLockPath, JSON.stringify({ locked: controlLocked, updatedAt: Date.now() })); } catch { /* ignore */ }
  };
  const activeChildren = new Map();
  const killTree = (pid) => {
    try {
      if (process.platform === 'win32') execFileSync('taskkill', ['/PID', String(pid), '/T', '/F'], { stdio: 'ignore' });
      else process.kill(-pid, 'SIGKILL');
      return true;
    } catch {
      try { process.kill(pid, 'SIGKILL'); return true; } catch { return false; }
    }
  };
  const rpcUpstream = (method, args) => new Promise((resolve, reject) => {
    const body = JSON.stringify({ type: 'client-request', rpcId: 'emergency-' + Date.now(), method, payload: { args } });
    const req = http.request({
      host: upstream.host,
      port: Number(upstream.port),
      path: '/api/' + method,
      method: 'POST',
      headers: {
        host: upstream.authority,
        origin: 'http://' + upstream.authority,
        cookie: cookieName + '=' + signCookie(secret, upstream.authority, Date.now() - COOKIE_CLOCK_SKEW_MS),
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(body),
      },
      timeout: 5000,
    }, (res) => {
      let text = '';
      res.on('data', (chunk) => { text += chunk; });
      res.on('end', () => { try { resolve(JSON.parse(text)); } catch (error) { reject(error); } });
    });
    req.on('timeout', () => req.destroy(new Error('upstream timeout')));
    req.on('error', reject);
    req.end(body);
  });
  const listChildPids = () => {
    try {
      let lines;
      if (process.platform === 'win32') {
        const out = execFileSync('powershell', ['-NoProfile', '-Command',
          'Get-CimInstance Win32_Process | ForEach-Object { "$($_.ProcessId) $($_.ParentProcessId)" }'], { encoding: 'utf8' });
        lines = out.trim().split(/\r?\n/);
      } else {
        const out = execFileSync('ps', ['-eo', 'pid=,ppid='], { encoding: 'utf8' });
        lines = out.trim().split(/\n/);
      }
      const pairs = lines.map((line) => line.trim().split(/\s+/).map(Number)).filter((a) => a.length === 2 && a.every(Number.isFinite));
      const children = new Map();
      for (const [pid, ppid] of pairs) {
        if (!children.has(ppid)) children.set(ppid, []);
        children.get(ppid).push(pid);
      }
      const result = [];
      const walk = (pid) => { for (const child of children.get(pid) || []) { result.push(child); walk(child); } };
      walk(process.pid);
      return result;
    } catch {
      return [];
    }
  };
  const killPids = (pids) => {
    const killed = [];
    const failed = [];
    for (const pid of pids) {
      try {
        if (process.platform === 'win32') execFileSync('taskkill', ['/PID', String(pid), '/T', '/F'], { stdio: 'ignore' });
        else process.kill(pid, 'SIGKILL');
        killed.push(pid);
      } catch {
        failed.push(pid);
      }
    }
    return { killed, failed };
  };

  const bridge = {
    version: VERSION,
    get upstream() {
      return upstream;
    },
    get cookieName() {
      return cookieName;
    },
    /** 活跃 mux 连接数（测试/诊断用）。 */
    get activeMuxCount() {
      return activeMuxSockets.size;
    },
    trackMuxSocket(socket) {
      activeMuxSockets.add(socket);
    },
    untrackMuxSocket(socket) {
      activeMuxSockets.delete(socket);
    },
    /** --dsh auto：DeepSeek Harness 重启换了端口时，上游连接失败会触发重新查找。 */
    autoDiscover,
    /** 给任意 DSH authority 签 `name=value` cookie（端口探测用）。 */
    cookieFor(authority) {
      return `${computeCookieName(authority)}=${signCookie(secret, authority, now() - COOKIE_CLOCK_SKEW_MS)}`;
    },
    /** 兼容旧接口：直接切到某个 authority（不在列表里就补一个 manual 目标）。 */
    setUpstream(authority) {
      const parsed = parseAuthority(authority);
      let target = targets.find((item) => item.authority === parsed.authority);
      if (!target) {
        target = {
          key: 'manual',
          authority: parsed.authority,
          host: parsed.host,
          port: parsed.port,
          kind: 'manual',
          label: TARGET_KIND_LABELS.manual,
          pid: 0,
          processName: '',
          alive: true,
        };
        targets = [...targets, target];
      }
      applyTarget(target);
    },
    /** 当前可用后端列表（App「设置 → DSH 后端」用）。 */
    upstreamsView() {
      return buildUpstreamsView();
    },
    /** 重新发现后端并返回列表（不动当前选择；端口变化由 noteUpstreamFailure 处理）。 */
    async refreshTargets() {
      const discovered = await discoverLatestTargets();
      if (discovered.length > 0) mergeDiscovered(discovered);
      return buildUpstreamsView();
    },
    /**
     * App 里切换后端：先刷新列表再按 key/kind 查找；切换成功会记住偏好（按 kind，端口变了也能跟回）。
     * @returns {{ok:true,changed:boolean,active:object,view:object}|{ok:false,status:number,code:string,message:string,reason:string}}
     */
    async selectUpstream(key) {
      const wanted = String(key ?? '').trim();
      if (!wanted) {
        return { ok: false, status: 400, code: 'bridge/bad-request', message: '缺少后端标识', reason: 'missing-upstream' };
      }
      // 「自动」= 清掉固定偏好，恢复自动发现/自动转移（App 里第三选项）。
      if (wanted === 'auto') {
        preferred = null;
        try {
          fs.rmSync(path.join(stateDir, UPSTREAM_PREFERENCE_FILE), { force: true });
        } catch {
          /* ignore */
        }
        const discovered = await discoverLatestTargets();
        if (discovered.length > 0) mergeDiscovered(discovered);
        if (!activeTarget || activeTarget.alive === false) {
          const fallback = targets.find((item) => item.alive !== false) ?? targets[0];
          if (fallback) applyTarget(fallback);
        }
        return { ok: true, changed: false, auto: true, active: viewTarget(activeTarget), view: buildUpstreamsView() };
      }
      let target = findTargetByKey(wanted);
      if (!target || target.alive === false) {
        const discovered = await discoverLatestTargets();
        if (discovered.length > 0) mergeDiscovered(discovered);
        target = findTargetByKey(wanted);
      }
      // v2：不再自动拉起 `dsh web`（3080）。
      //
      // 那是一个额外进程 + 额外端口：受限环境里 spawn 会被拒（曾导致桥接直接起不来），
      // 端口漂移的跟踪成本也不比桌面版低，而手机端走的是同一套 /api 契约。
      // 切后端时若没有可用的桌面版实例，直接报「没有可用后端」，不再偷偷起一个。
      if (!target) {
        audit.write({ method: 'DSH', path: 'upstream', decision: 'deny', reason: 'no-desktop-backend', status: 503, remoteAddr: '' });
        return {
          ok: false,
          status: 503,
          code: 'bridge/no-desktop-backend',
          message: '没有可用的 DSH 桌面版后端（v2 不再使用 dsh web / 3080）',
          reason: 'no-desktop-backend',
        };
      }
      if (!target) {
        return {
          ok: false,
          status: 404,
          code: 'bridge/upstream-not-found',
          message: '这个 DSH 后端不在线了（检查电脑上是否还开着，或刷新列表）',
          reason: 'upstream-not-found',
        };
      }
      const previousAuthority = upstream.authority;
      const changed = previousAuthority !== target.authority;
      applyTarget(target);
      preferred = target.kind;
      saveUpstreamPreference(stateDir, { kind: target.kind, key: target.key });
      if (changed) {
        audit.write({ method: 'DSH', path: target.authority, decision: 'allow', reason: 'upstream-selected', status: 0, remoteAddr: '' });
        if (typeof options.onUpstreamChange === 'function') options.onUpstreamChange(previousAuthority, target.authority, viewTarget(target));
      }
      return { ok: true, changed, active: viewTarget(target), view: buildUpstreamsView() };
    },
    /**
     * 上游连接失败：自动模式下重新查找 DSH，端口变了就自动切换。
     * 连续失败（dsh 重启时会出现一串）时把节流从 5s 降到 1s，
     * 让桥接在重启后 1~2 秒内就重新找到后端，而不是干等 5 秒。
     */
    noteUpstreamFailure() {
      upstreamFailureStreak += 1;
      if (!autoDiscover || rediscovering) return;
      const throttle = upstreamFailureStreak >= 2 ? 1000 : 5000;
      if (now() - lastRediscoverAt < throttle) return;
      rediscovering = true;
      lastRediscoverAt = now();
      failoverIfNeeded()
        .catch(() => {})
        .finally(() => {
          rediscovering = false;
        });
    },
    /** 任意一次成功请求/探测后清零连续失败计数。 */
    noteUpstreamHealthy() {
      upstreamFailureStreak = 0;
    },
    get upstreamFailureStreak() {
      return upstreamFailureStreak;
    },
    /**
     * dsh 重启后主动重连：每 [intervalMs] 对当前上游做一次 TCP 探活，
     * 连续失败 2 次就重新发现后端；若仍然连不上且允许自动发现，
     * 直接尝试拉起一次 `dsh web` 并切过去——不再依赖「手机下一次请求撞上」才知道。
     */
    startUpstreamWatchdog(intervalMs = 30_000) {
      if (upstreamWatchdog) return;
      upstreamWatchdog = setInterval(() => {
        void (async () => {
          if (rediscovering) return;
          const alive = await probePort(upstream.host, Number(upstream.port), 1500);
          if (alive) {
            upstreamFailureStreak = 0;
            if (activeTarget && activeTarget.alive === false) activeTarget.alive = true;
            return;
          }
          upstreamFailureStreak += 1;
          if (upstreamFailureStreak < 2) return;
          rediscovering = true;
          try {
            await failoverIfNeeded();
            if (await probePort(upstream.host, Number(upstream.port), 1500)) {
              upstreamFailureStreak = 0;
              return;
            }
            if (!autoDiscover) return;
            // v2：探活失败只做后端切换（failoverIfNeeded 已尝试），不再自动拉起 `dsh web`。
            // 找不到新的桌面版实例就继续返回 502，不偷偷起额外进程——
            // 那正是「spawn 被拒导致桥接起不来」的来源。
          } catch {
            /* 探活失败不影响代理，下一次再试 */
          } finally {
            rediscovering = false;
          }
        })();
      }, intervalMs);
      upstreamWatchdog.unref?.();
    },
    stopUpstreamWatchdog() {
      if (!upstreamWatchdog) return;
      clearInterval(upstreamWatchdog);
      upstreamWatchdog = null;
    },
    /** 诊断用：当前上游地址与连续失败次数。 */
    get upstreamHealth() {
      return { authority: upstream.authority, streak: upstreamFailureStreak, autoDiscover };
    },
    stateDir,
    /** Bot 放给手机下载的文件目录（--outbox；默认 <state-dir>/outbox）。 */
    outboxDir: outboxDir ? path.resolve(outboxDir) : path.join(stateDir, 'outbox'),
    /** 手机发来的大文件放这里（--inbox；默认 <state-dir>/inbox）。 */
    inboxDir: inboxDir ? path.resolve(inboxDir) : path.join(stateDir, 'inbox'),
    credentialsPath,
    auditPath: audit.path,
    state,
    account,
    limits: lim,
    resetPerformed: stateInfo.resetPerformed,
    replacedCorrupt: stateInfo.replacedCorrupt,
    migratedFromV1: stateInfo.migratedFromV1,
    startupRevocation,
    scopes: [...DEVICE_SCOPES],
    /** 中转参数 {relay, host, hpk}（--relay 时由 main 注入；写进登录链接与二维码）。 */
    relayInfo,
    get controlLocked() { return controlLocked; },
    async emergencyStop() {
      controlLocked = true;
      persistControlLock();
      const cancelled = []; const failed = [];
      try {
        const listing = await rpcUpstream('session/list', { _request: {} });
        const items = listing?.result?.value?.items ?? [];
        for (const item of items) {
          if (item?.running !== true) continue;
          try { await rpcUpstream('session/cancel', { request: { sessionId: item.sessionId } }); cancelled.push(item.sessionId); }
          catch (e) { failed.push({ sessionId: item.sessionId, error: e.message }); }
        }
      } catch (e) { failed.push({ stage: 'session/list', error: e.message }); }
      const pids = [...activeChildren.keys()];
      const proc = killPids(pids);
      return { locked: true, killed: proc.killed, failed: [...failed, ...proc.failed.map((pid) => ({ pid, stage: 'kill' }))], cancelled };
    },
    async exec(argv, cwd, timeoutMs) {
      const child = spawn(argv[0], argv.slice(1), {
        cwd,
        shell: false,
        windowsHide: true,
        detached: process.platform !== 'win32',
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      const pid = child.pid;
      activeChildren.set(pid, { pid, argv, startedAt: now() });
      let stdout = '';
      let stderr = '';
      let timedOut = false;
      const cap = 200 * 1024;
      child.stdout?.on('data', (chunk) => { if (stdout.length < cap) stdout += chunk.toString('utf8'); });
      child.stderr?.on('data', (chunk) => { if (stderr.length < cap) stderr += chunk.toString('utf8'); });
      const timer = setTimeout(() => {
        timedOut = true;
        killTree(pid);
      }, Math.min(Math.max(Number(timeoutMs) || 30000, 1000), 120000));
      return await new Promise((resolve) => {
        child.on('error', (error) => {
          clearTimeout(timer);
          activeChildren.delete(pid);
          resolve({ code: null, signal: null, stdout, stderr: stderr + '\n' + error.message, timedOut, pid });
        });
        child.on('close', (code, signal) => {
          clearTimeout(timer);
          activeChildren.delete(pid);
          resolve({ code, signal, stdout, stderr, timedOut, pid });
        });
      });
    },
    async deepseekUsage() {
      const file = path.join(os.homedir(), '.dsh', '.credentials.yaml');
      const text = fs.readFileSync(file, 'utf8');
      const match = text.match(/DEEPSEEK_API_KEY:\s*([^\s#]+)/);
      if (!match) throw new Error('credentials 中找不到 DEEPSEEK_API_KEY');
      const apiKey = match[1].replace(/^["']|["']$/g, '');
      const response = await new Promise((resolve, reject) => {
        const req = https.request({
          host: 'api.deepseek.com',
          path: '/user/balance',
          method: 'GET',
          headers: { authorization: 'Bearer ' + apiKey, accept: 'application/json' },
          timeout: 8000,
        }, (res) => {
          let data = '';
          res.on('data', (chunk) => { data += chunk; });
          res.on('end', () => {
            try { resolve({ status: res.statusCode, json: JSON.parse(data) }); }
            catch (error) { reject(error); }
          });
        });
        req.on('timeout', () => req.destroy(new Error('deepseek timeout')));
        req.on('error', reject);
        req.end();
      });
      if (response.status < 200 || response.status >= 300) throw new Error('DeepSeek HTTP ' + response.status);
      const info = Array.isArray(response.json?.balance_infos) ? response.json.balance_infos[0] : null;
      return {
        available: response.json?.is_available === true,
        currency: info?.currency ?? 'CNY',
        totalBalance: info?.total_balance ?? null,
        grantedBalance: info?.granted_balance ?? null,
        toppedUpBalance: info?.topped_up_balance ?? null,
        fetchedAt: Date.now(),
      };
    },
    resumeControl() { controlLocked = false; persistControlLock(); return { locked: false }; },
    get port() {
      return portActual;
    },
    get bind() {
      return bind;
    },
    get startedAt() {
      return startedAt;
    },
    get uptimeSec() {
      return startedAt ? Math.floor((now() - startedAt) / 1000) : 0;
    },
    get auditLogPath() {
      return audit.path;
    },
    get statePath() {
      return statePath;
    },
    get pairingPagePath() {
      return pairPagePath;
    },
    get pairingLink() {
      return pairLink;
    },
    get lanUrls() {
      return lanUrls.map((item) => ({ ...item }));
    },
    get relayUrl() {
      return options.relay ?? null;
    },
    /** 当前有效登录码（只给本机终端/测试用；HTTP 响应里永远不返回它）。 */
    get pairCode() {
      return pairingIsActive(pairing, now) ? pairing.code : null;
    },
    get pairingCode() {
      return this.pairCode;
    },
    get pairingExpiresAt() {
      return pairingIsActive(pairing, now) ? pairing.expiresAt : 0;
    },
    /** 本轮请求注入的 cookie 值（仅用于启动诊断/测试断言，不写日志、不回给手机）。 */
    currentCookie() {
      return signCookie(secret, upstream.authority, now() - COOKIE_CLOCK_SKEW_MS);
    },
    /** 写一条审计（JSONL；内部字段白名单，绝不会写 token/cookie/登录码）。 */
    audit(entry) {
      audit.write(entry);
    },
    /** v0.1 兼容：token 是否属于一台未撤销的设备。 */
    verifyToken(candidate) {
      const device = findDeviceByToken(state.devices, candidate);
      return Boolean(device && device.revoked !== true);
    },
    /** 按 token 找设备（含已撤销设备，便于区分 401 原因）。 */
    lookupDevice(candidate) {
      return findDeviceByToken(state.devices, candidate);
    },
    /** 中转隧道：按手机 Noise 静态公钥找设备（含已撤销设备）。 */
    findDeviceByRelayKey(relayKey) {
      if (typeof relayKey !== 'string' || relayKey === '') return null;
      return state.devices.find((device) => device.relayKey === relayKey) ?? null;
    },
    /** 中转配对成功：把手机静态公钥绑定到新设备（同一公钥只属于一台设备）。 */
    bindRelayKey(deviceId, relayKey) {
      const target = state.devices.find((device) => device.id === deviceId);
      if (!target || typeof relayKey !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(relayKey)) return false;
      for (const device of state.devices) {
        if (device !== target && device.relayKey === relayKey) delete device.relayKey;
      }
      target.relayKey = relayKey;
      persistState();
      return true;
    },
    /** 对外设备列表（/dsbot/devices 与 --devices 共用）：不包含 tokenHash/tokenTail。 */
    devicesView(currentDeviceId = '') {
      return state.devices.map((device) => ({
        id: device.id,
        name: device.name,
        platform: device.platform,
        createdAt: device.createdAt,
        lastSeenAt: device.lastSeenAt,
        current: device.id === currentDeviceId,
        revoked: device.revoked === true,
      }));
    },
    activeDeviceCount() {
      return state.devices.filter((device) => device.revoked !== true).length;
    },
    /** 已认证请求：刷新 lastSeenAt（按 5 秒节流落盘，避免每请求写文件）。 */
    touchDevice(device) {
      if (!device) return;
      device.lastSeenAt = now();
      if (now() - lastPersistAt >= 5000) persistState();
    },
    authBlocked(addr) {
      return authFailLimiter.isBlocked(addr);
    },
    authRetryAfter(addr) {
      return authFailLimiter.retryAfterSec(addr);
    },
    recordAuthFailure(addr) {
      authFailLimiter.recordFailure(addr);
    },
    clearAuthFailures(addr) {
      authFailLimiter.clear(addr);
    },
    consumeRequestQuota(device) {
      return requestLimiter.consume(`device:${device?.id ?? 'unknown'}`);
    },
    pairBlocked(addr) {
      return pairFailLimiter.isBlocked(addr);
    },
    pairRetryAfter(addr) {
      return pairFailLimiter.retryAfterSec(addr);
    },
    pairRecordFailure(addr) {
      pairFailLimiter.recordFailure(addr);
    },
    pairClear(addr) {
      pairFailLimiter.clear(addr);
    },
    /** 公开配对状态（不含登录码明文）。 */
    pairingStatus() {
      const active = pairingIsActive(pairing, now);
      return { active, expiresAt: active ? pairing.expiresAt : 0 };
    },
    /** 生成新登录码（终端 `--pair` 用；旧码立即作废）。 */
    regeneratePairing() {
      pairing = createPairingState(now, pairingTtlMs);
      try {
        bridge.writePairingPage();
      } catch {
        pairPagePath = '';
      }
      return pairing.code;
    },
    /**
     * 过期即自动换新码，不返回任何登录码文本。
     *
     * 背景：以前登录码只在启动时生成一次，过期后 `pair.json` / `pair.html` 一直是死码，
     * 用户想看新码只能重启桥接（每次断线十几秒）。而且一旦配对过设备，
     * 旧逻辑的「续期」分支直接 return，`pair.json` 从此再也不会更新。
     *
     * 现在由调用方按固定间隔轮询本方法：过期 → 生成新码 → 重写 pair.json / pair.html。
     * 换码不会踢掉已配对设备（设备凭据与登录码无关）。
     *
     * @returns {boolean} 本次是否发生了刷新
     */
    refreshPairingIfExpired() {
      // pairingIsActive 的第二个参数是「时钟函数」，不是时间戳。
      // 曾误传 now()（数字）→ 每次轮询抛 now is not a function，被外层空 catch 吞掉，
      // 登录码过期后永远不换新（已配对设备时尤其明显：第二条续期路径会主动跳过）。
      if (pairingIsActive(pairing, now)) return false;
      pairing = createPairingState(now, pairingTtlMs);
      try {
        bridge.writePairingPage();
      } catch {
        pairPagePath = '';
      }
      return true;
    },
    /**
     * 用登录码兑换设备凭据：一次性、10 分钟 TTL，成功后立即作废登录码。
     * 返回的 deviceToken 只出现在这一次 HTTP 响应里，不落盘、不入审计。
     */
    redeemPairCode(code, meta = {}) {
      const at = now();
      if (!pairing || !pairing.code) {
        return {
          ok: false,
          status: 401,
          code: 'bridge/pair-unavailable',
          message: '当前没有可用的登录码；请在电脑上重新生成（--pair）',
          reason: 'pair-unavailable',
        };
      }
      if (pairing.redeemedAt) {
        return {
          ok: false,
          status: 401,
          code: 'bridge/pair-used',
          message: '登录码已被使用；请在电脑上重新生成一个',
          reason: 'pair-code-used',
        };
      }
      if (at >= pairing.expiresAt) {
        return {
          ok: false,
          status: 401,
          code: 'bridge/pair-expired',
          message: '登录码已过期（10 分钟内有效）；请在电脑上重新生成一个',
          reason: 'pair-code-expired',
        };
      }
      if (!tokensMatch(code, pairing.code)) {
        return {
          ok: false,
          status: 401,
          code: 'bridge/invalid-pair-code',
          message: '登录码不正确',
          reason: 'invalid-pair-code',
        };
      }
      const { entry, token } = createDeviceEntry({
        name: meta.deviceName,
        platform: meta.platform,
        now,
      });
      state.devices.push(entry);
      pairing.redeemedAt = at;
      persistState();
      return { ok: true, device: entry, deviceToken: token, account: publicAccount(account) };
    },
    /** 撤销任意设备（不能撤销当前设备；重复撤销幂等）。 */
    revokeDeviceById(targetId, actorDeviceId = null) {
      const target = state.devices.find((device) => device.id === targetId);
      if (!target) {
        return {
          ok: false,
          status: 404,
          code: 'bridge/unknown-device',
          message: '设备不存在（可能已被移除）；在电脑上运行 --devices 查看设备列表',
          reason: 'unknown-device',
        };
      }
      if (actorDeviceId && target.id === actorDeviceId) {
        return {
          ok: false,
          status: 400,
          code: 'bridge/cannot-revoke-self',
          message: '不能撤销当前设备，请使用「退出登录」',
          reason: 'cannot-revoke-self',
        };
      }
      if (target.revoked) return { ok: true, device: target, alreadyRevoked: true };
      target.revoked = true;
      target.revokedAt = now();
      persistState();
      return { ok: true, device: target, alreadyRevoked: false };
    },
    /** 删除一条设备记录：只能删「已撤销」的，且不能删当前设备；列表立即少一条，别的设备不受影响。 */
    removeDeviceById(targetId, actorDeviceId = null) {
      const index = state.devices.findIndex((device) => device.id === targetId);
      if (index < 0) {
        return {
          ok: false,
          status: 404,
          code: 'bridge/unknown-device',
          message: '设备不存在（可能已被删除）',
          reason: 'unknown-device',
        };
      }
      const target = state.devices[index];
      if (actorDeviceId && target.id === actorDeviceId) {
        return {
          ok: false,
          status: 400,
          code: 'bridge/cannot-remove-self',
          message: '不能删除当前设备，请使用「退出登录」',
          reason: 'cannot-remove-self',
        };
      }
      if (!target.revoked) {
        return {
          ok: false,
          status: 409,
          code: 'bridge/device-active',
          message: '这台设备仍有效，请先撤销再删除',
          reason: 'device-active',
        };
      }
      state.devices.splice(index, 1);
      persistState();
      return { ok: true, device: target };
    },
    /** 退出登录 = 撤销当前设备凭据（之后该 token 一律 401）。 */
    logoutDevice(device) {
      if (!device) return null;
      device.revoked = true;
      device.revokedAt = now();
      persistState();
      return device;
    },
    /** 写 <state-dir>/pair.html（自包含 SVG；vendor 缺失时自动降级为文字链接）。 */
    writePairingPage() {
      lanUrls = computeLanUrls({ bind, port: portActual });
      const primaryUrl = lanUrls[0]?.url ?? `http://127.0.0.1:${portActual}`;
      pairLink = buildLoginLink(primaryUrl, pairing.code, bridge.relayInfo);
      pairPagePath = path.join(stateDir, PAIR_PAGE_FILE);
      try {
        writePairHtmlFile(pairPagePath, {
          accountLabel: account.displayName ?? 'DeepSeek 账号',
          code: pairing.code,
          url: primaryUrl,
          link: pairLink,
          expiresAt: pairing.expiresAt,
          version: VERSION,
        });
      } catch {
        pairPagePath = '';
      }
      // 同机 IPC：把配对状态写成结构化文件，供 DSH 插件在设置页读取。
      // 与 pair.html 同目录、同样 0600；登录码仍不出现在任何 HTTP 响应里。
      try {
        fs.writeFileSync(
          path.join(stateDir, PAIR_STATE_FILE),
          JSON.stringify({
            version: 1,
            code: pairing.code,
            expiresAt: pairing.expiresAt,
            link: pairLink,
            lanUrls: lanUrls.map((item) => item.url),
            relay: bridge.relayInfo?.relay ?? null,
            hostId: bridge.relayInfo?.host ?? null,
            updatedAt: Date.now(),
          }, null, 2),
          { mode: 0o600 },
        );
      } catch {
        /* 写不了不影响配对页，插件会读到旧值或空 */
      }
      return pairPagePath;
    },
    async start() {
      if (server) return bridge;
      server = http.createServer((req, res) => {
        handleHttpRequest(bridge, req, res).catch((error) => {
          if (process.env.DSBOT_DEBUG) console.error('[bridge] internal error:', error);
          if (!res.headersSent) {
            sendJson(res, 500, 'bridge/internal-error', '桥接内部错误');
          } else {
            try {
              res.destroy();
            } catch {
              /* ignore */
            }
          }
          bridge.audit({ method: req.method, path: '/', decision: 'deny', reason: 'internal-error', status: 500, remoteAddr: normalizeRemote(req.socket?.remoteAddress) });
        });
      });
      // 上游可能长时间不返回（prompt 等），桥接不能替手机超时；只限制建连。
      server.requestTimeout = 0;
      server.headersTimeout = 60_000;
      server.keepAliveTimeout = 65_000;
      server.timeout = 0;
      server.on('connection', (socket) => {
        sockets.add(socket);
        // 手机断网/切网时连接常常不发 FIN，留下半开 socket，长时间占着到 DSH 的上游流。
        // TCP keepalive 让系统在 ~30s 空闲后探测对端，死连接会报错关闭，代理随之拆掉两端。
        socket.setKeepAlive(true, TCP_KEEPALIVE_MS);
        socket.on('close', () => sockets.delete(socket));
        socket.on('error', () => {});
      });
      server.on('upgrade', (req, socket, head) => {
        try {
          handleUpgrade(bridge, req, socket, head);
        } catch {
          try {
            socket.destroy();
          } catch {
            /* ignore */
          }
        }
      });
      server.on('clientError', (error, socket) => {
        if (!socket.destroyed) {
          try {
            socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
          } catch {
            socket.destroy();
          }
        }
        void error;
      });
      await new Promise((resolve, reject) => {
        const onError = (error) => {
          server?.off('listening', onListening);
          if (error?.code === 'EADDRINUSE') {
            reject(new Error(`端口 ${port} 已被占用。换一个端口：--port ${port + 1}`));
          } else if (error?.code === 'EACCES') {
            reject(new Error(`没有权限监听端口 ${port}（小于 1024 需要管理员权限）。`));
          } else {
            reject(new Error(`监听 ${bind}:${port} 失败：${error?.message ?? error}`));
          }
        };
        const onListening = () => {
          server?.off('error', onError);
          resolve();
        };
        server.once('error', onError);
        server.once('listening', onListening);
        try {
          server.listen(port, bind);
        } catch (error) {
          server.off('listening', onListening);
          onError(error);
        }
      });
      const address = server.address();
      portActual = typeof address === 'object' && address ? address.port : port;
      startedAt = now();
      try {
        bridge.writePairingPage();
      } catch {
        pairPagePath = '';
      }
      pruneTimer = setInterval(() => {
        requestLimiter.prune();
        authFailLimiter.prune();
        pairFailLimiter.prune();
      }, 60_000);
      pruneTimer.unref?.();
      audit.write({ method: 'START', path: 'bridge', decision: 'allow', reason: 'listening', status: 0, remoteAddr: '' });
      return bridge;
    },
    async stop() {
      if (pruneTimer) {
        clearInterval(pruneTimer);
        pruneTimer = null;
      }
      try {
        persistState();
      } catch {
        /* 落盘失败不阻塞退出 */
      }
      if (!server) return;
      const closing = server;
      server = null;
      await new Promise((resolve) => {
        let done = false;
        const finish = () => {
          if (done) return;
          done = true;
          resolve();
        };
        closing.close(finish);
        for (const socket of sockets) {
          try {
            socket.destroy();
          } catch {
            /* ignore */
          }
        }
        sockets.clear();
        setTimeout(finish, 1500).unref?.();
      });
      audit.write({ method: 'STOP', path: 'bridge', decision: 'allow', reason: 'stopped', status: 0, remoteAddr: '' });
    },
  };
  return bridge;
}

// ---------------------------------------------------------------------------
// HTTP 请求处理
// ---------------------------------------------------------------------------

async function handleHttpRequest(bridge, req, res) {
  const started = nowMs();
  const remoteAddr = normalizeRemote(req.socket?.remoteAddress);
  const parsedUrl = safeParseRequestUrl(req.url);
  const pathname = parsedUrl.pathname;
  const base = { method: req.method ?? '', path: pathname, remoteAddr, upgrade: false };

  const deny = (status, code, message, reason, extraHeaders = {}) => {
    const bytes = sendJson(res, status, code, message, extraHeaders);
    bridge.audit({ ...base, decision: 'deny', reason, status, ms: nowMs() - started, bytes });
    return { denied: true };
  };

  // 0) /dsbot/*：账号/设备管理入口（桥接本地实现，不反代 DSH）。
  if (pathname === '/dsbot' || pathname.startsWith('/dsbot/')) {
    return handleDsbotRequest(bridge, req, res, parsedUrl, base, started);
  }

  // 1) 认证：无 token / token 错误 / 设备已撤销 —— 都先挡在权限判断之前。
  const token = extractToken(req.headers, parsedUrl.searchParams);
  if (!token) {
    return deny(401, 'bridge/unauthorized', '缺少设备令牌：请在请求头 Authorization: Bearer <token> 或 ?token= 中提供', 'missing-token');
  }
  if (bridge.authBlocked(remoteAddr)) {
    return deny(429, 'bridge/rate-limited', '认证失败次数过多，请稍后再试', 'auth-rate-limited', {
      'retry-after': String(bridge.authRetryAfter(remoteAddr)),
    });
  }
  const device = bridge.lookupDevice(token);
  if (!device) {
    bridge.recordAuthFailure(remoteAddr);
    return deny(401, 'bridge/unauthorized', '设备令牌无效', 'invalid-token');
  }
  base.deviceId = device.id;
  bridge.clearAuthFailures(remoteAddr);
  if (device.revoked === true) {
    return deny(401, 'bridge/device-revoked', '该设备已被撤销，请在手机上重新扫码登录', 'revoked-token');
  }
  bridge.touchDevice(device);

  // 2) 每设备的普通请求限流。
  const quota = bridge.consumeRequestQuota(device);
  if (!quota.allowed) {
    return deny(429, 'bridge/rate-limited', '请求过于频繁，请稍后再试', 'rate-limited', {
      'retry-after': String(quota.retryAfterSec),
    });
  }

  // 3) 白名单/路由判断（默认拒绝）。
  const route = classifyRequest(req.method, pathname);
  if (!route.allowed) {
    return deny(403, 'bridge/forbidden', forbiddenMessage(route), route.reason);
  }

  // 4) /healthz：只读健康信息（需要设备 token；不回传任何 token 明文）。
  if (route.kind === 'health') {
    const payload = {
      ok: true,
      upstream: bridge.upstream.authority,
      version: bridge.version,
      deviceId: device.id,
      deviceName: device.name,
      tokenFingerprint: sha256Hex(token).slice(0, 8),
      account: publicAccount(bridge.account),
      devices: bridge.activeDeviceCount(),
      uptimeSec: bridge.uptimeSec,
    };
    const body = Buffer.from(JSON.stringify(payload));
    res.writeHead(200, baseHeaders(body.length));
    res.end(body);
    bridge.audit({ ...base, decision: 'allow', reason: 'health', status: 200, ms: nowMs() - started, bytes: body.length });
    return { denied: false };
  }

  // 5) 反代。
  return proxyHttpRequest(bridge, req, res, parsedUrl, base, started);
}

// ---------------------------------------------------------------------------
// 账号主机 /dsbot/* 接口（docs/ACCOUNT-LOGIN.md §3）
// ---------------------------------------------------------------------------

/**
 * 写一个只有配置的 MCP 插件包（DSH 官方做法：bundle 的 cordis.patch.yml 插入一条
 * @deepseek-ai/dsh-mcp-client 配置），返回 {name, spec}；spec 是目录绝对路径，
 * 交给 pluginManager/installBundle 安装。同名再写一次就是改配置（版本号递增，重装生效）。
 *
 * spec: {serverName, transport:'stdio'|'streamable-http', command?, args?[], env?{}, cwd?, url?, headers?{}, title?}
 */
export function writeMcpBundle(rootDir, spec) {
  const serverName = String(spec?.serverName ?? '').trim();
  if (!MCP_NAME_PATTERN.test(serverName)) {
    throw new Error('MCP 名称只能用小写字母、数字、- 和 _（不超过 40 个字符），例如 github');
  }
  const transport = spec.transport === 'streamable-http' ? 'streamable-http' : spec.transport === 'stdio' ? 'stdio' : '';
  if (!transport) throw new Error('transport 只能是 stdio 或 streamable-http');
  const strings = (value, label) => {
    if (value == null) return [];
    if (!Array.isArray(value) || value.some((item) => typeof item !== 'string')) throw new Error(`${label} 必须是字符串数组`);
    return value;
  };
  const dict = (value, label) => {
    if (value == null) return {};
    if (typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} 必须是键值对`);
    const out = {};
    for (const [key, item] of Object.entries(value)) {
      if (!/^[A-Za-z_][A-Za-z0-9_.-]*$/.test(key)) throw new Error(`${label} 的键名不合法：${key}`);
      if (typeof item !== 'string') throw new Error(`${label}.${key} 必须是字符串`);
      out[key] = item;
    }
    return out;
  };
  const config = { serverName, transport };
  if (transport === 'stdio') {
    const command = String(spec.command ?? '').trim();
    if (!command) throw new Error('stdio 方式需要填写启动命令（command），例如 npx');
    config.command = command;
    const args = strings(spec.args, 'args');
    if (args.length) config.args = args;
    const env = dict(spec.env, 'env');
    if (Object.keys(env).length) config.env = env;
    if (typeof spec.cwd === 'string' && spec.cwd.trim()) config.cwd = spec.cwd.trim();
  } else {
    const url = String(spec.url ?? '').trim();
    if (!/^https?:\/\//i.test(url)) throw new Error('streamable-http 方式需要填写 http(s) 地址');
    config.url = url;
    const headers = dict(spec.headers, 'headers');
    if (Object.keys(headers).length) config.headers = headers;
  }
  const name = `${MCP_PACKAGE_SCOPE}/${serverName}`;
  const dir = path.join(rootDir, serverName);
  fs.mkdirSync(dir, { recursive: true });
  // 同名重写 = 改配置：版本号递增，pnpm 才会当作新包重新安装。
  let version = '1.0.0';
  try {
    const previous = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8'));
    const [major, minor, patch] = String(previous.version ?? '1.0.0').split('.').map((n) => Number(n) || 0);
    version = `${major}.${minor}.${patch + 1}`;
  } catch {
    /* 第一次写 */
  }
  const title = typeof spec.title === 'string' && spec.title.trim() ? spec.title.trim().slice(0, 60) : `MCP · ${serverName}`;
  const pkg = {
    name,
    version,
    private: true,
    type: 'module',
    description: `DeepSeek 远控台添加的 MCP 服务 ${serverName}`,
    exports: { './locale/*.json': './locale/*.json' },
    files: ['cordis.patch.yml', 'locale/*.json'],
    dsh: { bundle: { patch: './cordis.patch.yml' } },
  };
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify(pkg, null, 2) + '\n', 'utf8');
  fs.mkdirSync(path.join(dir, 'locale'), { recursive: true });
  const meta = { meta: { title, description: `把 MCP 服务「${serverName}」的工具接给 Bot（工具名 mcp__${serverName}__*）。` } };
  fs.writeFileSync(path.join(dir, 'locale', 'en.json'), JSON.stringify(meta, null, 2) + '\n', 'utf8');
  fs.writeFileSync(path.join(dir, 'locale', 'zh.json'), JSON.stringify(meta, null, 2) + '\n', 'utf8');
  // YAML 是 JSON 的超集：配置用 JSON 写进去，免得手写 YAML 转义。
  const patch = [
    '# 由 DeepSeek 远控台生成：手机上「插件 → 添加 MCP」',
    '- insert:',
    `    - id: dsbot-mcp-${serverName}`,
    "      name: '@deepseek-ai/dsh-mcp-client'",
    `      config: ${JSON.stringify(config)}`,
    '',
  ].join('\n');
  fs.writeFileSync(path.join(dir, 'cordis.patch.yml'), patch, 'utf8');
  return { name, spec: dir, version, config };
}

/** /dsbot/* 成功响应统一 {ok:true, ...payload}。 */
function sendOk(res, payload = {}) {
  const body = Buffer.from(JSON.stringify({ ok: true, ...payload }));
  if (!res.headersSent && !res.writableEnded) {
    res.writeHead(200, baseHeaders(body.length));
    res.end(body);
  }
  return body.length;
}

/** 读取 JSON 对象请求体；失败时返回 {ok:false,status,reason,message}。 */
async function readJsonObject(req, limit = MAX_PAIR_BODY_BYTES) {
  let raw;
  try {
    raw = await readRequestBody(req, limit);
  } catch (error) {
    const tooLarge = error?.code === 'body-too-large';
    if (tooLarge) req.resume();
    return {
      ok: false,
      status: tooLarge ? 413 : 400,
      reason: tooLarge ? 'body-too-large' : 'bad-request',
      message: tooLarge ? '请求体超过上限' : '无法读取请求体',
    };
  }
  if (raw.length === 0) return { ok: true, value: {} };
  let value;
  try {
    value = JSON.parse(raw.toString('utf8'));
  } catch {
    return { ok: false, status: 400, reason: 'invalid-json', message: '请求体必须是合法 JSON' };
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return { ok: false, status: 400, reason: 'invalid-json', message: '请求体必须是 JSON 对象' };
  }
  return { ok: true, value };
}

/** outbox 里允许取回的文件名：单层文件名，不能带路径分隔符、不能以点开头（隐藏文件 / `..`）。 */
export function isSafeOutboxName(name) {
  return (
    typeof name === 'string' &&
    name.length > 0 &&
    name.length <= 200 &&
    !name.startsWith('.') &&
    !/[\\/:*?"<>|\u0000-\u001f]/.test(name) &&
    path.basename(name) === name
  );
}

/** 列出 outbox 目录下的普通文件（不跟随符号链接、不进子目录），最新的在前。目录不存在 = 空列表。 */
export function listOutbox(dir) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return [];
  }
  const files = [];
  for (const entry of entries) {
    if (!entry.isFile() || !isSafeOutboxName(entry.name)) continue;
    try {
      const stat = fs.lstatSync(path.join(dir, entry.name));
      if (!stat.isFile()) continue;
      files.push({ name: entry.name, size: stat.size, mtime: Math.floor(stat.mtimeMs) });
    } catch {
      /* 刚被删掉：跳过 */
    }
  }
  files.sort((a, b) => b.mtime - a.mtime || a.name.localeCompare(b.name));
  return files.slice(0, MAX_OUTBOX_LIST);
}

/** 读 outbox 里的一个文件：名字校验 + 必须是目录下的普通文件 + 大小上限。 */
export function readOutboxFile(dir, name) {
  const fail = (status, code, message, reason) => ({ ok: false, status, code, message, reason });
  if (!isSafeOutboxName(name)) return fail(400, 'bridge/bad-request', '文件名无效', 'outbox-bad-name');
  const root = path.resolve(dir);
  const full = path.resolve(root, name);
  if (path.dirname(full) !== root) return fail(400, 'bridge/bad-request', '文件名无效', 'outbox-bad-name');
  let stat;
  try {
    stat = fs.lstatSync(full);
  } catch {
    return fail(404, 'bridge/outbox-missing', '文件不存在（可能已被删除）', 'outbox-missing');
  }
  if (!stat.isFile()) return fail(404, 'bridge/outbox-missing', '文件不存在（可能已被删除）', 'outbox-not-file');
  if (stat.size > MAX_OUTBOX_SINGLE_BYTES) {
    return fail(413, 'bridge/outbox-too-large', `单次下载接口最多 ${MAX_OUTBOX_SINGLE_BYTES / 1024 / 1024}MB，请用分块下载`, 'outbox-too-large');
  }
  const data = fs.readFileSync(full);
  return { ok: true, file: { name, size: data.length, mtime: Math.floor(stat.mtimeMs), data } };
}

/** 分块读取 outbox 文件：返回本块数据、文件总大小、下一块 offset、是否最后一块。 */
export function readOutboxChunk(dir, name, offset, length) {
  const fail = (status, code, message, reason) => ({ ok: false, status, code, message, reason });
  if (!isSafeOutboxName(name)) return fail(400, 'bridge/bad-request', '文件名无效', 'outbox-bad-name');
  if (!Number.isSafeInteger(offset) || offset < 0) return fail(400, 'bridge/bad-request', 'offset 无效', 'outbox-bad-offset');
  const root = path.resolve(dir);
  const full = path.resolve(root, name);
  if (path.dirname(full) !== root) return fail(400, 'bridge/bad-request', '文件名无效', 'outbox-bad-name');
  let stat;
  try {
    stat = fs.lstatSync(full);
  } catch {
    return fail(404, 'bridge/outbox-missing', '文件不存在（可能已被删除）', 'outbox-missing');
  }
  if (!stat.isFile()) return fail(404, 'bridge/outbox-missing', '文件不存在（可能已被删除）', 'outbox-not-file');
  if (stat.size > MAX_OUTBOX_FILE_BYTES) {
    return fail(413, 'bridge/outbox-too-large', `文件超过 ${MAX_OUTBOX_FILE_BYTES / 1024 / 1024}MB`, 'outbox-too-large');
  }
  const size = stat.size;
  if (offset >= size) return { ok: true, name, size, next: size, done: true, data: Buffer.alloc(0) };
  const want = Math.min(
    Number.isSafeInteger(length) && length > 0 ? length : MAX_OUTBOX_CHUNK_BYTES,
    MAX_OUTBOX_CHUNK_BYTES,
  );
  const take = Math.min(want, size - offset);
  const data = Buffer.alloc(take);
  const fd = fs.openSync(full, 'r');
  try {
    fs.readSync(fd, data, 0, take, offset);
  } finally {
    fs.closeSync(fd);
  }
  const next = offset + take;
  return { ok: true, name, size, next, done: next >= size, data };
}

/** 目录里没有同名文件的名字：报告.pdf → 报告 (1).pdf → 报告 (2).pdf … */
function uniqueFileName(dir, name) {
  const ext = path.extname(name);
  const stem = name.slice(0, name.length - ext.length);
  let candidate = name;
  for (let i = 1; fs.existsSync(path.join(dir, candidate)); i++) candidate = `${stem} (${i})${ext}`;
  return candidate;
}

/** 删掉一天前没传完的临时文件。 */
function sweepInboxPartials(partialDir, now = Date.now()) {
  let entries;
  try {
    entries = fs.readdirSync(partialDir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    if (!entry.isFile()) continue;
    const full = path.join(partialDir, entry.name);
    try {
      if (now - fs.statSync(full).mtimeMs > INBOX_PARTIAL_TTL_MS) fs.rmSync(full, { force: true });
    } catch {
      /* ignore */
    }
  }
}

/**
 * 写入一块上传数据：{uploadId, name, offset, total, data(base64)}。
 * 返回 {ok:true, done:false, received} 或 {ok:true, done:true, path, name, size}；失败 {ok:false,status,code,message,reason,received?}。
 */
export function writeInboxChunk(dir, deviceId, body) {
  const fail = (status, code, message, reason, extra = {}) => ({ ok: false, status, code, message, reason, ...extra });
  const { uploadId, name, offset, total, data } = body ?? {};
  if (typeof uploadId !== 'string' || !/^[A-Za-z0-9_-]{8,64}$/.test(uploadId)) {
    return fail(400, 'bridge/bad-request', 'uploadId 无效', 'inbox-bad-id');
  }
  if (!isSafeOutboxName(name)) return fail(400, 'bridge/bad-request', '文件名无效', 'inbox-bad-name');
  if (!Number.isSafeInteger(total) || total < 0 || total > MAX_INBOX_FILE_BYTES) {
    return fail(413, 'bridge/inbox-too-large', `文件超过 ${MAX_INBOX_FILE_BYTES / 1024 / 1024}MB`, 'inbox-too-large');
  }
  if (!Number.isSafeInteger(offset) || offset < 0) return fail(400, 'bridge/bad-request', 'offset 无效', 'inbox-bad-offset');
  if (typeof data !== 'string') return fail(400, 'bridge/bad-request', '缺少数据', 'inbox-no-data');
  const chunk = Buffer.from(data, 'base64');
  if (chunk.length > MAX_INBOX_CHUNK_BYTES) return fail(413, 'bridge/bad-request', '单块数据过大', 'inbox-chunk-too-large');

  const root = path.resolve(dir);
  const partialDir = path.join(root, '.partial');
  fs.mkdirSync(partialDir, { recursive: true });
  if (offset === 0) sweepInboxPartials(partialDir);
  const partial = path.join(partialDir, `${String(deviceId).slice(0, 16)}-${uploadId}`);
  let received = 0;
  try {
    received = fs.statSync(partial).size;
  } catch {
    received = 0;
  }
  if (offset === 0 && received > 0) {
    // 重新从头传：丢掉旧的半截。
    fs.rmSync(partial, { force: true });
    received = 0;
  }
  if (offset !== received) {
    return fail(409, 'bridge/inbox-offset', '分块顺序不对，请从已收到的位置续传', 'inbox-offset', { received });
  }
  if (offset + chunk.length > total) return fail(400, 'bridge/bad-request', '数据超过声明的大小', 'inbox-overflow');
  fs.appendFileSync(partial, chunk);
  received += chunk.length;
  if (received < total) return { ok: true, done: false, received };

  const finalName = uniqueFileName(root, name);
  const target = path.join(root, finalName);
  fs.renameSync(partial, target);
  return { ok: true, done: true, path: target, name: finalName, size: received };
}

/**
 * /dsbot/* 请求处理入口。
 * 与 /api/* 是两套路由：这里不反代 DSH，只做账号信息、设备注册表、登录码兑换。
 */
async function handleDsbotRequest(bridge, req, res, parsedUrl, base, started) {
  const method = String(req.method ?? '').toUpperCase();
  const pathname = parsedUrl.pathname;
  const route = DSBOT_ROUTES[pathname];

  const deny = (status, code, message, reason, options = {}) => {
    const { headers = {}, deviceId = '', targetDeviceId = '' } = options;
    const bytes = sendJson(res, status, code, message, headers);
    bridge.audit({
      ...base,
      ...(deviceId ? { deviceId } : {}),
      ...(targetDeviceId ? { targetDeviceId } : {}),
      decision: 'deny',
      reason,
      status,
      ms: nowMs() - started,
      bytes,
    });
    return { denied: true };
  };

  if (!route) return deny(404, 'bridge/not-found', '未知的 /dsbot 接口', 'unknown-dsbot-endpoint');
  if (!route.methods.includes(method)) {
    return deny(405, 'bridge/method-not-allowed', `该接口只接受 ${route.methods.join('/')} 请求`, 'http-method-not-allowed');
  }

  const remoteAddr = base.remoteAddr;
  let device = null;
  if (route.auth) {
    const token = extractToken(req.headers, parsedUrl.searchParams);
    if (!token) {
      return deny(401, 'bridge/unauthorized', '缺少设备令牌：请在请求头 Authorization: Bearer <token> 或 ?token= 中提供', 'missing-token');
    }
    if (bridge.authBlocked(remoteAddr)) {
      return deny(429, 'bridge/rate-limited', '认证失败次数过多，请稍后再试', 'auth-rate-limited', {
        headers: { 'retry-after': String(bridge.authRetryAfter(remoteAddr)) },
      });
    }
    device = bridge.lookupDevice(token);
    if (!device) {
      bridge.recordAuthFailure(remoteAddr);
      return deny(401, 'bridge/unauthorized', '设备令牌无效', 'invalid-token');
    }
    base.deviceId = device.id;
    bridge.clearAuthFailures(remoteAddr);
    if (device.revoked === true) {
      return deny(401, 'bridge/device-revoked', '该设备已被撤销，请在手机上重新扫码登录', 'revoked-token');
    }
    bridge.touchDevice(device);
    const quota = bridge.consumeRequestQuota(device);
    if (!quota.allowed) {
      return deny(429, 'bridge/rate-limited', '请求过于频繁，请稍后再试', 'rate-limited', {
        headers: { 'retry-after': String(quota.retryAfterSec) },
      });
    }
  }

  switch (pathname) {
    case '/dsbot/status': {
      const bytes = sendOk(res, {
        version: bridge.version,
        account: publicAccount(bridge.account),
        pairing: bridge.pairingStatus(),
        server: {
          port: bridge.port,
          lanUrls: bridge.lanUrls.map((item) => item.url),
          relay: bridge.relayUrl,
        },
      });
      bridge.audit({ ...base, decision: 'allow', reason: 'account-status', status: 200, ms: nowMs() - started, bytes });
      return { denied: false };
    }

// ---------------------------------------------------------------------------
// 模型服务商（LLM provider）
//
// 目标：让手机端能配置「OpenAI 兼容中转站 / Claude / Gemini」，并存进 DSH 的
// cordis.patch.yml。DSH 的 @deepseek-ai/dsh-llm-pi-ai 适配器按 providers 字典
// 路由请求，配置变更在下一个请求生效，无需重启。
// ---------------------------------------------------------------------------

/** 把 HTTP 状态码翻译成用户能看懂的中文。 */
function explainLlmHttpError(status, bodyText) {
  const snippet = String(bodyText || '').slice(0, 200);
  switch (status) {
    case 400: return { code: 'BAD_REQUEST', message: '请求格式被拒绝：检查协议类型（OpenAI 兼容 vs Claude）', detail: snippet };
    case 401: return { code: 'INVALID_KEY', message: 'API Key 无效或已过期', detail: snippet };
    case 402: return { code: 'NO_BALANCE', message: '账户余额不足', detail: snippet };
    case 403: return { code: 'FORBIDDEN', message: 'API Key 没有访问该资源的权限', detail: snippet };
    case 404: return { code: 'NOT_FOUND', message: '地址或模型不存在：很多中转站需要 baseURL 带 /v1', detail: snippet };
    case 429: return { code: 'RATE_LIMIT', message: '请求太频繁或额度已用尽', detail: snippet };
    case 500: case 502: case 503: case 504:
      return { code: 'UPSTREAM_ERROR', message: '服务端错误（' + status + '），稍后再试', detail: snippet };
    default: return { code: 'HTTP_' + status, message: '服务返回 ' + status, detail: snippet };
  }
}

/** 把网络异常翻译成中文。 */
function explainLlmNetworkError(err) {
  const code = err && err.code ? String(err.code) : '';
  const msg = err && err.message ? String(err.message) : String(err);
  if (code === 'ENOTFOUND' || code === 'EAI_AGAIN') {
    return { code: 'DNS_FAILED', message: '地址解析失败：检查 baseURL 域名是否拼错', detail: msg };
  }
  if (code === 'ECONNREFUSED') {
    return { code: 'CONN_REFUSED', message: '连接被拒绝：端口不对或服务没启动', detail: msg };
  }
  if (code === 'ETIMEDOUT' || code === 'UND_ERR_CONNECT_TIMEOUT') {
    return { code: 'TIMEOUT', message: '连接超时：网络不通或被墙', detail: msg };
  }
  if (code === 'CERT_HAS_EXPIRED' || msg.includes('certificate') || msg.includes('self-signed')) {
    return { code: 'TLS_ERROR', message: 'HTTPS 证书有问题：检查地址协议是否正确', detail: msg };
  }
  return { code: 'NETWORK_ERROR', message: '网络请求失败：' + msg, detail: msg };
}

/** 规范化 baseURL：去掉末尾斜杠。 */
function normalizeLlmBaseUrl(raw) {
  return String(raw || '').trim().replace(/\/+$/, '');
}

/**
 * 测试 provider 连通性。
 *
 * 分两级：
 *   1. GET {baseURL}/models —— 轻量，验证地址 + Key
 *   2. 可选 model 参数时，再发一次最小对话 —— 验证模型可用
 */
async function testLlmProvider({ baseUrl, apiKey, api, model, timeoutMs = 15000 }) {
  const base = normalizeLlmBaseUrl(baseUrl);
  if (!base) return { ok: false, code: 'BAD_INPUT', message: '地址不能为空' };
  if (!/^https?:\/\//i.test(base)) return { ok: false, code: 'BAD_INPUT', message: '地址必须以 http:// 或 https:// 开头' };
  if (!apiKey) return { ok: false, code: 'BAD_INPUT', message: 'API Key 不能为空' };

  const started = Date.now();
  const isAnthropic = api === 'anthropic-messages';

  // ---------- 第一级：列模型 ----------
  const listUrl = isAnthropic ? (base + '/v1/models?limit=1000') : (base + '/models');
  const headers = isAnthropic
    ? { 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' }
    : { authorization: 'Bearer ' + apiKey };

  let models = [];
  try {
    const res = await fetch(listUrl, { method: 'GET', headers, signal: AbortSignal.timeout(timeoutMs) });
    const text = await res.text();
    if (!res.ok) {
      const e = explainLlmHttpError(res.status, text);
      return { ok: false, ...e, stage: 'list-models', elapsedMs: Date.now() - started, url: listUrl };
    }
    let parsed = null;
    try { parsed = JSON.parse(text); } catch { /* 有些中转站返回非 JSON */ }
    if (parsed) {
      const arr = Array.isArray(parsed.data) ? parsed.data : (Array.isArray(parsed.models) ? parsed.models : []);
      models = arr.map((m) => ({
        id: String(m.id || m.name || ''),
        name: String(m.display_name || m.displayName || m.name || m.id || ''),
        contextWindow: Number(m.context_length || m.context_window || m.max_input_tokens || 0) || null,
      })).filter((m) => m.id);
    }
  } catch (err) {
    const e = explainLlmNetworkError(err);
    return { ok: false, ...e, stage: 'list-models', elapsedMs: Date.now() - started, url: listUrl };
  }

  const result = {
    ok: true,
    stage: 'list-models',
    modelCount: models.length,
    models: models.slice(0, 200),
    elapsedMs: Date.now() - started,
    url: listUrl,
    message: models.length > 0 ? ('连接成功，发现 ' + models.length + ' 个模型') : '连接成功，但没列出模型（部分中转站不支持）',
  };

  // ---------- 第二级：最小对话（可选） ----------
  if (model) {
    const chatStarted = Date.now();
    const chatUrl = isAnthropic ? (base + '/v1/messages') : (base + '/chat/completions');
    const chatHeaders = isAnthropic
      ? { 'x-api-key': apiKey, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' }
      : { authorization: 'Bearer ' + apiKey, 'content-type': 'application/json' };
    const body = isAnthropic
      ? { model, max_tokens: 8, messages: [{ role: 'user', content: 'hi' }] }
      : { model, max_tokens: 8, messages: [{ role: 'user', content: 'hi' }] };
    try {
      const res = await fetch(chatUrl, {
        method: 'POST',
        headers: chatHeaders,
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(timeoutMs),
      });
      const text = await res.text();
      if (!res.ok) {
        const e = explainLlmHttpError(res.status, text);
        return { ...result, ok: false, stage: 'chat', ...e, chatElapsedMs: Date.now() - chatStarted, chatUrl };
      }
      let reply = '';
      try {
        const parsed = JSON.parse(text);
        if (isAnthropic) {
          reply = (parsed.content && parsed.content[0] && parsed.content[0].text) || '';
        } else {
          reply = (parsed.choices && parsed.choices[0] && parsed.choices[0].message && parsed.choices[0].message.content) || '';
        }
      } catch { /* 忽略 */ }
      return {
        ...result,
        stage: 'chat',
        chatOk: true,
        chatReply: String(reply).slice(0, 80),
        chatElapsedMs: Date.now() - chatStarted,
        chatUrl,
        message: '连接成功，模型可用',
      };
    } catch (err) {
      const e = explainLlmNetworkError(err);
      return { ...result, ok: false, stage: 'chat', ...e, chatElapsedMs: Date.now() - chatStarted, chatUrl };
    }
  }

  return result;
}

    case '/dsbot/llm/test': {
      const parsed = await readJsonObject(req);
      if (!parsed.ok) { return deny(parsed.status || 400, 'bridge/bad-request', parsed.message || '请求体不是合法 JSON', 'llm-test', { deviceId: device.id }); }
      const body = parsed.value || {};
      const r = await testLlmProvider({
        baseUrl: body.baseUrl,
        apiKey: body.apiKey,
        api: body.api,
        model: body.model,
        timeoutMs: Math.min(60000, Math.max(3000, Number(body.timeoutMs) || 15000)),
      });
      return sendOk(res, r);
    }

    case '/dsbot/llm/providers': {
      // 读 DSH 的 provider 配置（不改上游，只读文件）。
      const providers = parseProviders(readPatchText());
      const bytes = sendOk(res, { providers, path: CORDIS_PATCH_PATH });
      bridge.audit({ ...base, decision: 'allow', reason: 'llm-providers', status: 200, ms: nowMs() - started, bytes, deviceId: device.id });
      return { denied: false };
    }

    case '/dsbot/llm/provider': {
      // 新增/更新一个 provider，写回 cordis.patch.yml。写盘后不自动重启 DSH。
      const parsed = await readJsonObject(req);
      if (!parsed.ok) {
        req.resume();
        return deny(400, 'bridge/bad-request', parsed.message || '请求体不是合法 JSON', 'llm-provider', { deviceId: device.id });
      }
      const body = parsed.value || {};
      const id = String(body.id || '').trim();
      if (!/^[a-z0-9][a-z0-9_.-]{0,40}$/.test(id)) {
        return deny(400, 'bridge/bad-request', 'provider 标识只能用小写字母、数字和 _ . -', 'llm-provider', { deviceId: device.id });
      }
      const provider = {
        id,
        displayName: String(body.displayName || id).trim().slice(0, 40),
        api: String(body.api || 'openai-completions').trim(),
        baseURL: String(body.baseURL || '').trim().slice(0, 300),
        apiKey: String(body.apiKey || '').trim().slice(0, 500),
        apiKeyEnv: String(body.apiKeyEnv || '').trim().slice(0, 80),
        models: Array.isArray(body.models)
          ? body.models.map((item) => String(item).trim()).filter(Boolean).slice(0, 200)
          : [],
      };
      if (!provider.baseURL && !provider.apiKeyEnv) {
        return deny(400, 'bridge/bad-request', '需要 baseURL 或 apiKeyEnv 其中一项', 'llm-provider', { deviceId: device.id });
      }
      try {
        writePatchText(upsertProvider(readPatchText(), provider));
      } catch (error) {
        return deny(500, 'bridge/config-write-failed', `写配置失败：${error?.message ?? error}`, 'llm-provider', { deviceId: device.id });
      }
      const bytes = sendOk(res, { ok: true, provider: { ...provider, apiKey: provider.apiKey ? '***' : '' }, needsRestart: true });
      bridge.audit({ ...base, decision: 'allow', reason: 'llm-provider-saved', provider: id, status: 200, ms: nowMs() - started, bytes, deviceId: device.id });
      return { denied: false };
    }

    case '/dsbot/llm/provider/delete': {
      const parsed = await readJsonObject(req);
      if (!parsed.ok) {
        req.resume();
        return deny(400, 'bridge/bad-request', parsed.message || '请求体不是合法 JSON', 'llm-provider-delete', { deviceId: device.id });
      }
      const id = String(parsed.value?.id || '').trim();
      if (!id) return deny(400, 'bridge/bad-request', '缺少 provider 标识', 'llm-provider-delete', { deviceId: device.id });
      const result = removeProvider(readPatchText(), id);
      if (!result.removed) return deny(404, 'bridge/not-found', `配置里没有 ${id}`, 'llm-provider-delete', { deviceId: device.id });
      try {
        writePatchText(result.text);
      } catch (error) {
        return deny(500, 'bridge/config-write-failed', `写配置失败：${error?.message ?? error}`, 'llm-provider-delete', { deviceId: device.id });
      }
      const bytes = sendOk(res, { ok: true, needsRestart: true });
      bridge.audit({ ...base, decision: 'allow', reason: 'llm-provider-deleted', provider: id, status: 200, ms: nowMs() - started, bytes, deviceId: device.id });
      return { denied: false };
    }

    case '/dsbot/llm/models': {
      // 拉远端模型列表：传 provider（用配置里的 key）或直接传 baseUrl+apiKey。
      const parsed = await readJsonObject(req);
      if (!parsed.ok) {
        req.resume();
        return deny(400, 'bridge/bad-request', parsed.message || '请求体不是合法 JSON', 'llm-models', { deviceId: device.id });
      }
      const body = parsed.value || {};
      let baseUrl = String(body.baseUrl || '').trim();
      let apiKey = String(body.apiKey || '').trim();
      const providerId = String(body.provider || '').trim();
      if (providerId) {
        const provider = parseProviders(readPatchText()).find((item) => item.id === providerId);
        if (!provider) return deny(404, 'bridge/not-found', `配置里没有 ${providerId}`, 'llm-models', { deviceId: device.id });
        baseUrl = baseUrl || provider.baseURL;
        apiKey = apiKey || resolveProviderKey(provider);
      }
      const result = await fetchRemoteModels({ baseUrl, apiKey });
      const bytes = sendOk(res, result);
      bridge.audit({ ...base, decision: 'allow', reason: result.ok ? 'llm-models' : 'llm-models-failed', status: 200, ms: nowMs() - started, bytes, deviceId: device.id });
      return { denied: false };
    }

    case '/dsbot/upstreams': {
      // POST 时默认先重新发现一次（App 打开「DSH 后端」页时用）；GET 直接回缓存列表。
      if (req.method === 'POST') {
        const parsed = await readJsonObject(req);
        if (parsed.ok && parsed.value.refresh !== false) {
          await bridge.refreshTargets();
        } else if (!parsed.ok) {
          req.resume();
        }
      }
      const view = bridge.upstreamsView();
      const bytes = sendOk(res, view);
      bridge.audit({
        ...base,
        decision: 'allow',
        reason: 'upstream-list',
        status: 200,
        ms: nowMs() - started,
        bytes,
        deviceId: device.id,
      });
      return { denied: false };
    }
    case '/dsbot/upstream/select': {
      const parsed = await readJsonObject(req);
      if (!parsed.ok) {
        req.resume();
        return deny(parsed.status, 'bridge/bad-request', parsed.message, parsed.reason, { deviceId: device.id });
      }
      const key = parsed.value.key ?? parsed.value.kind ?? parsed.value.authority;
      const outcome = await bridge.selectUpstream(typeof key === 'string' ? key : '');
      if (!outcome.ok) {
        return deny(outcome.status, outcome.code, outcome.message, outcome.reason, { deviceId: device.id });
      }
      const bytes = sendOk(res, outcome.view);
      bridge.audit({
        ...base,
        path: outcome.active.authority,
        decision: 'allow',
        reason: outcome.changed ? 'upstream-selected' : 'upstream-unchanged',
        requested: typeof key === 'string' ? key : '',
        status: 200,
        ms: nowMs() - started,
        bytes,
        deviceId: device.id,
      });
      return { denied: false };
    }
    case '/dsbot/pair/redeem':
      return handlePairRedeem(bridge, req, res, base, started);
    case '/dsbot/account': {
      const bytes = sendOk(res, {
        account: publicAccount(bridge.account),
        server: { version: bridge.version, lanUrls: bridge.lanUrls.map((item) => item.url) },
        device: { id: device.id, name: device.name, createdAt: device.createdAt },
      });
      bridge.audit({ ...base, decision: 'allow', reason: 'account-info', status: 200, ms: nowMs() - started, bytes });
      return { denied: false };
    }
    case '/dsbot/devices': {
      const bytes = sendOk(res, { devices: bridge.devicesView(device.id) });
      bridge.audit({ ...base, decision: 'allow', reason: 'device-list', status: 200, ms: nowMs() - started, bytes });
      return { denied: false };
    }
    case '/dsbot/devices/revoke': {
      const parsed = await readJsonObject(req);
      if (!parsed.ok) {
        req.resume();
        return deny(parsed.status, 'bridge/bad-request', parsed.message, parsed.reason, { deviceId: device.id });
      }
      const targetDeviceId = typeof parsed.value.deviceId === 'string' ? parsed.value.deviceId.trim() : '';
      if (!targetDeviceId) {
        return deny(400, 'bridge/bad-request', '缺少 deviceId', 'missing-device-id', { deviceId: device.id });
      }
      const outcome = bridge.revokeDeviceById(targetDeviceId, device.id);
      if (!outcome.ok) {
        return deny(outcome.status, outcome.code, outcome.message, outcome.reason, {
          deviceId: device.id,
          targetDeviceId,
        });
      }
      const bytes = sendOk(res);
      bridge.audit({
        ...base,
        targetDeviceId,
        decision: 'allow',
        reason: outcome.alreadyRevoked ? 'device-already-revoked' : 'device-revoked',
        status: 200,
        ms: nowMs() - started,
        bytes,
      });
      return { denied: false };
    }
    case '/dsbot/devices/remove': {
      const parsed = await readJsonObject(req);
      if (!parsed.ok) {
        req.resume();
        return deny(parsed.status, 'bridge/bad-request', parsed.message, parsed.reason, { deviceId: device.id });
      }
      const targetDeviceId = typeof parsed.value.deviceId === 'string' ? parsed.value.deviceId.trim() : '';
      if (!targetDeviceId) {
        return deny(400, 'bridge/bad-request', '缺少 deviceId', 'missing-device-id', { deviceId: device.id });
      }
      const outcome = bridge.removeDeviceById(targetDeviceId, device.id);
      if (!outcome.ok) {
        return deny(outcome.status, outcome.code, outcome.message, outcome.reason, {
          deviceId: device.id,
          targetDeviceId,
        });
      }
      const bytes = sendOk(res);
      bridge.audit({
        ...base,
        targetDeviceId,
        decision: 'allow',
        reason: 'device-removed',
        status: 200,
        ms: nowMs() - started,
        bytes,
      });
      return { denied: false };
    }
    case '/dsbot/devices/remove-revoked': {
      // 2026-11-12：手机「账号 → 清理」原本打的是产品账号服务
      // （DELETE /v1/me/devices/revoked），但那份列表其实是**桥接设备表**，
      // 两者是不同的数据源，所以永远「已清理 0 条」。这里给桥接侧补一个批量清理。
      req.resume();
      const revoked = (state.devices || []).filter((d) => d.revoked === true && d.id !== device.id);
      let removed = 0;
      for (const target of revoked) {
        const outcome = bridge.removeDeviceById(target.id, device.id);
        if (outcome.ok) removed += 1;
      }
      const bytes = sendOk(res, { removed });
      bridge.audit({
        ...base,
        removed,
        decision: 'allow',
        reason: 'device-removed-revoked',
        status: 200,
        ms: nowMs() - started,
        bytes,
      });
      return { denied: false };
    }
    case '/dsbot/emergency-stop': {
      req.resume();
      const result = await bridge.emergencyStop();
      const bytes = sendOk(res, result);
      bridge.audit({ ...base, decision: 'allow', reason: 'emergency-stop', status: 200, ms: nowMs() - started, bytes });
      return { denied: false };
    }
    case '/dsbot/emergency-resume': {
      req.resume();
      const result = bridge.resumeControl();
      const bytes = sendOk(res, result);
      bridge.audit({ ...base, decision: 'allow', reason: 'emergency-resume', status: 200, ms: nowMs() - started, bytes });
      return { denied: false };
    }
    case '/dsbot/exec':
    case '/dsbot/fs/read':
    case '/dsbot/fs/write': {
      if (bridge.controlLocked) {
        return deny(403, 'control/locked', '紧急中断已锁定，所有执行/文件操作被拒绝；请先解除锁定', 'control-locked', { deviceId: device.id });
      }
      const parsed = await readJsonObject(req);
      if (!parsed.ok) {
        req.resume();
        return deny(parsed.status, 'bridge/bad-request', parsed.message, parsed.reason, { deviceId: device.id });
      }
      const blockedPatterns = [/rm\s+-rf/i, /\bmkfs\b/i, /\bformat\b/i, /\bshutdown\b/i, /\breboot\b/i, /dd\s+if=/i, />\s*\/dev\/sd/i];
      const allowedRoots = [bridge.stateDir, bridge.outboxDir, bridge.inboxDir]
        .filter(Boolean)
        .map((item) => {
          try { return fs.realpathSync.native(item); } catch { return path.resolve(item); }
        });
      const resolveAllowed = (raw) => {
        const value = String(raw || '');
        const candidate = path.isAbsolute(value) ? value : path.join(bridge.stateDir, value);
        let real;
        try { real = fs.realpathSync.native(candidate); } catch { return null; }
        const compare = process.platform === 'win32' ? real.toLowerCase() : real;
        const ok = allowedRoots.some((root) => {
          const base = process.platform === 'win32' ? root.toLowerCase() : root;
          return compare === base || compare.startsWith(base + path.sep);
        });
        return ok ? real : null;
      };
      if (base.path === '/dsbot/exec') {
        if (!Array.isArray(parsed.value.argv) || parsed.value.argv.length === 0) {
          return deny(400, 'control/bad-argv', 'exec 需要 argv 数组（不允许 shell 字符串）', 'bad-argv', { deviceId: device.id });
        }
        const source = parsed.value.argv.join(' ');
        if (blockedPatterns.some((pattern) => pattern.test(source))) {
          return deny(400, 'control/blocked-command', '命令命中危险模式黑名单', 'blocked-command', { deviceId: device.id });
        }
        const cwd = String(parsed.value.cwd || bridge.stateDir);
        if (!resolveAllowed(cwd)) {
          return deny(403, 'control/path-denied', '工作目录不在允许目录内', 'path-denied', { deviceId: device.id });
        }
        const timeoutMs = Number(parsed.value.timeoutMs) || 30_000;
        const result = await bridge.exec(parsed.value.argv, cwd, timeoutMs);
        const bytes = sendOk(res, result);
        bridge.audit({ ...base, decision: 'allow', reason: 'exec', argv: parsed.value.argv, cwd, status: 200, ms: nowMs() - started, bytes });
        return { denied: false };
      }
      const target = parsed.value.path ?? parsed.value.file;
      const real = resolveAllowed(target);
      if (!real) {
        return deny(403, 'control/path-denied', '路径不在允许目录内', 'path-denied', { deviceId: device.id });
      }
      if (base.path === '/dsbot/fs/read') {
        let stat;
        try { stat = fs.statSync(real); } catch (error) {
          return deny(400, 'control/read-failed', '读取失败：' + error.message, 'read-failed', { deviceId: device.id });
        }
        if (!stat.isFile()) {
          return deny(400, 'control/not-a-file', '目标不是普通文件', 'not-a-file', { deviceId: device.id });
        }
        if (stat.size > 10 * 1024 * 1024) {
          return deny(413, 'control/too-large', '文件超过 10MB 上限', 'too-large', { deviceId: device.id });
        }
        const data = fs.readFileSync(real).toString('base64');
        const bytes = sendOk(res, { path: real, name: path.basename(real), size: stat.size, mtimeMs: stat.mtimeMs, data });
        bridge.audit({ ...base, decision: 'allow', reason: 'fs-read', file: real, status: 200, ms: nowMs() - started, bytes });
        return { denied: false };
      }
      return deny(501, 'control/not-implemented', 'fs/write 尚未实现', 'not-implemented', { deviceId: device.id });
    }
    case '/dsbot/usage': {
      try {
        const usage = await bridge.deepseekUsage();
        const bytes = sendOk(res, usage);
        bridge.audit({ ...base, decision: 'allow', reason: 'usage', status: 200, ms: nowMs() - started, bytes });
        return { denied: false };
      } catch (error) {
        return deny(502, 'usage/failed', '查询 DeepSeek 余额失败：' + error.message, 'usage-failed', { deviceId: device.id });
      }
    }
    case '/dsbot/logout': {
      // 客户端可能带 `{}` 的 JSON body：读完/排空，避免 keep-alive 连接残留未消费数据。
      req.resume();
      bridge.logoutDevice(device);
      const bytes = sendOk(res);
      bridge.audit({ ...base, decision: 'allow', reason: 'device-logout', status: 200, ms: nowMs() - started, bytes });
      return { denied: false };
    }
    case '/dsbot/mcp/bundle': {
      const parsed = await readJsonObject(req, MAX_MCP_BODY_BYTES);
      if (!parsed.ok) {
        req.resume();
        return deny(parsed.status, 'bridge/bad-request', parsed.message, parsed.reason, { deviceId: device.id });
      }
      let bundle;
      try {
        bundle = writeMcpBundle(path.join(bridge.stateDir, 'mcp-bundles'), parsed.value);
      } catch (error) {
        return deny(400, 'bridge/invalid-mcp', error.message, 'invalid-mcp', { deviceId: device.id });
      }
      const bytes = sendOk(res, bundle);
      bridge.audit({ ...base, decision: 'allow', reason: 'mcp-bundle', mcp: bundle.name, status: 200, ms: nowMs() - started, bytes });
      return { denied: false };
    }
    case '/dsbot/logs': {
      const parsed = await readJsonObject(req, MAX_LOG_BODY_BYTES);
      if (!parsed.ok) {
        req.resume();
        return deny(parsed.status, 'bridge/bad-request', parsed.message, parsed.reason, { deviceId: device.id });
      }
      const text = typeof parsed.value.text === 'string' ? parsed.value.text : '';
      if (!text) return deny(400, 'bridge/bad-request', '缺少日志内容', 'missing-log', { deviceId: device.id });
      const dir = path.join(bridge.stateDir, 'phone-logs');
      fs.mkdirSync(dir, { recursive: true });
      const stamp = new Date().toISOString().replace(/[:.]/g, '-');
      const file = path.join(dir, `${stamp}-${device.id.slice(0, 8)}.log`);
      fs.writeFileSync(file, text, 'utf8');
      const bytes = sendOk(res, { file });
      bridge.audit({ ...base, decision: 'allow', reason: 'phone-log', status: 200, ms: nowMs() - started, bytes });
      return { denied: false };
    }
    case '/dsbot/outbox/list': {
      req.resume();
      const files = listOutbox(bridge.outboxDir);
      const bytes = sendOk(res, { dir: bridge.outboxDir, files });
      bridge.audit({ ...base, decision: 'allow', reason: 'outbox-list', status: 200, ms: nowMs() - started, bytes });
      return { denied: false };
    }
    case '/dsbot/outbox/delete': {
      const parsed = await readJsonObject(req, MAX_OUTBOX_BODY_BYTES);
      if (!parsed.ok) {
        req.resume();
        return deny(parsed.status, 'bridge/bad-request', parsed.message, parsed.reason, { deviceId: device.id });
      }
      const name = typeof parsed.value.name === 'string' ? parsed.value.name.trim() : '';
      if (!isSafeOutboxName(name)) {
        return deny(400, 'bridge/bad-request', '文件名无效', 'outbox-bad-name', { deviceId: device.id });
      }
      let removed = 0;
      try {
        const target = path.join(bridge.outboxDir, name);
        const stat = fs.lstatSync(target);
        if (stat.isFile()) {
          fs.unlinkSync(target);
          removed = 1;
        }
      } catch {
        /* 已经不存在：removed=0，不报错，前端刷新即可 */
      }
      const bytes = sendOk(res, { removed, name });
      bridge.audit({ ...base, decision: 'allow', reason: 'outbox-delete', file: name, status: 200, ms: nowMs() - started, bytes });
      return { denied: false };
    }
    case '/dsbot/outbox/clear': {
      req.resume();
      let removed = 0;
      for (const file of listOutbox(bridge.outboxDir)) {
        try {
          fs.unlinkSync(path.join(bridge.outboxDir, file.name));
          removed += 1;
        } catch {
          /* 跳过删不掉的（权限/并发） */
        }
      }
      const bytes = sendOk(res, { removed });
      bridge.audit({ ...base, decision: 'allow', reason: 'outbox-clear', status: 200, ms: nowMs() - started, bytes });
      return { denied: false };
    }
    case '/dsbot/outbox/chunk': {
      const parsed = await readJsonObject(req, MAX_OUTBOX_BODY_BYTES);
      if (!parsed.ok) {
        req.resume();
        return deny(parsed.status, 'bridge/bad-request', parsed.message, parsed.reason, { deviceId: device.id });
      }
      const outcome = readOutboxChunk(bridge.outboxDir, parsed.value.name, parsed.value.offset, parsed.value.length);
      if (!outcome.ok) {
        return deny(outcome.status, outcome.code, outcome.message, outcome.reason, { deviceId: device.id });
      }
      const bytes = sendOk(res, {
        name: outcome.name,
        size: outcome.size,
        offset: outcome.next,
        done: outcome.done,
        data: outcome.data.toString('base64'),
      });
      bridge.audit({ ...base, decision: 'allow', reason: 'outbox-chunk', file: outcome.name, status: 200, ms: nowMs() - started, bytes });
      return { denied: false };
    }
    case '/dsbot/outbox/file': {
      const parsed = await readJsonObject(req, MAX_OUTBOX_BODY_BYTES);
      if (!parsed.ok) {
        req.resume();
        return deny(parsed.status, 'bridge/bad-request', parsed.message, parsed.reason, { deviceId: device.id });
      }
      const outcome = readOutboxFile(bridge.outboxDir, parsed.value.name);
      if (!outcome.ok) {
        return deny(outcome.status, outcome.code, outcome.message, outcome.reason, { deviceId: device.id });
      }
      const { file } = outcome;
      const bytes = sendOk(res, { name: file.name, size: file.size, mtime: file.mtime, data: file.data.toString('base64') });
      bridge.audit({ ...base, decision: 'allow', reason: 'outbox-file', file: file.name, status: 200, ms: nowMs() - started, bytes });
      return { denied: false };
    }
    case '/dsbot/inbox/chunk': {
      const parsed = await readJsonObject(req, MAX_INBOX_BODY_BYTES);
      if (!parsed.ok) {
        req.resume();
        return deny(parsed.status, 'bridge/bad-request', parsed.message, parsed.reason, { deviceId: device.id });
      }
      let outcome;
      try {
        outcome = writeInboxChunk(bridge.inboxDir, device.id, parsed.value);
      } catch (error) {
        return deny(500, 'bridge/inbox-write-failed', `保存文件失败：${error.message}`, 'inbox-write-failed', { deviceId: device.id });
      }
      if (!outcome.ok) {
        if (outcome.status === 409) {
          // 续传位置对不上不是错误：不记审计，告诉手机已收到多少，手机从那里接着传。
          sendOk(res, { done: false, received: outcome.received, resync: true });
          return { denied: false };
        }
        return deny(outcome.status, outcome.code, outcome.message, outcome.reason, { deviceId: device.id });
      }
      if (!outcome.done) {
        sendOk(res, { done: false, received: outcome.received });
        return { denied: false };
      }
      const bytes = sendOk(res, { done: true, path: outcome.path, name: outcome.name, size: outcome.size });
      bridge.audit({ ...base, decision: 'allow', reason: 'inbox-file', file: outcome.name, status: 200, ms: nowMs() - started, bytes });
      return { denied: false };
    }
    case '/dsbot/ping': {
      req.resume();
      sendOk(res, {});
      return { denied: false };
    }
    default:
      return deny(404, 'bridge/not-found', '未知的 /dsbot 接口', 'unknown-dsbot-endpoint');
  }
}

/** 登录码兑换（公开接口）：失败按来源 IP 限速；成功后登录码立即作废。 */
async function handlePairRedeem(bridge, req, res, base, started) {
  const remoteAddr = base.remoteAddr;
  const deny = (status, code, message, reason, options = {}) => {
    const { headers = {}, deviceId = '' } = options;
    const bytes = sendJson(res, status, code, message, headers);
    bridge.audit({
      ...base,
      ...(deviceId ? { deviceId } : {}),
      decision: 'deny',
      reason,
      status,
      ms: nowMs() - started,
      bytes,
    });
    return { denied: true };
  };

  if (bridge.pairBlocked(remoteAddr)) {
    return deny(429, 'bridge/rate-limited', '登录码错误次数过多，请稍后再试', 'pair-rate-limited', {
      headers: { 'retry-after': String(bridge.pairRetryAfter(remoteAddr)) },
    });
  }
  const parsed = await readJsonObject(req, MAX_PAIR_BODY_BYTES);
  if (!parsed.ok) {
    req.resume();
    return deny(parsed.status, 'bridge/bad-request', parsed.message, parsed.reason);
  }
  const code = normalizePairCode(parsed.value.code);
  if (!code) {
    bridge.pairRecordFailure(remoteAddr);
    return deny(400, 'bridge/invalid-pair-code', '登录码格式不正确（形如 ABC-DEF）', 'invalid-pair-code-format');
  }
  const outcome = bridge.redeemPairCode(code, {
    deviceName: parsed.value.deviceName,
    platform: parsed.value.platform,
  });
  if (!outcome.ok) {
    bridge.pairRecordFailure(remoteAddr);
    return deny(outcome.status, outcome.code, outcome.message, outcome.reason);
  }
  bridge.pairClear(remoteAddr);
  const bytes = sendOk(res, {
    deviceId: outcome.device.id,
    deviceToken: outcome.deviceToken,
    account: outcome.account,
  });
  bridge.audit({ ...base, deviceId: outcome.device.id, decision: 'allow', reason: 'pair-redeem', status: 200, ms: nowMs() - started, bytes });
  return { denied: false };
}

function forbiddenMessage(route) {
  if (route.kind === 'other') return '桥接只暴露 /api 白名单接口与 /healthz';
  if (route.reason === 'malformed-endpoint') return '接口路径不合法';
  if (route.reason === 'http-method-not-allowed') return '该接口只接受 POST 请求';
  if (route.reason === 'forbidden-method') return `该接口不允许手机访问：${route.endpoint}`;
  return `未知接口，默认拒绝：${route.endpoint ?? ''}`;
}

function baseHeaders(contentLength, extra = {}) {
  return {
    'content-type': 'application/json; charset=utf-8',
    'content-length': String(contentLength),
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    ...extra,
  };
}

function sendJson(res, status, code, message, extraHeaders = {}) {
  const body = Buffer.from(JSON.stringify({ ok: false, error: { code, message } }));
  if (res.headersSent || res.writableEnded) return body.length;
  res.writeHead(status, baseHeaders(body.length, extraHeaders));
  res.end(body);
  return body.length;
}

async function readRequestBody(req, limit) {
  return await new Promise((resolve, reject) => {
    const declared = Number(req.headers['content-length']);
    if (Number.isFinite(declared) && declared > limit) {
      const error = new Error('请求体超过上限');
      error.code = 'body-too-large';
      reject(error);
      return;
    }
    const chunks = [];
    let size = 0;
    let settled = false;
    const fail = (error) => {
      if (settled) return;
      settled = true;
      reject(error);
    };
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > limit) {
        const error = new Error('请求体超过上限');
        error.code = 'body-too-large';
        fail(error);
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (settled) return;
      settled = true;
      resolve(Buffer.concat(chunks));
    });
    req.on('error', fail);
    req.on('aborted', () => fail(Object.assign(new Error('客户端中止了请求'), { code: 'client-aborted' })));
  });
}

function buildUpstreamHeaders(bridge, incomingHeaders, body) {
  const headers = {};
  for (const [name, value] of Object.entries(incomingHeaders ?? {})) {
    const lower = name.toLowerCase();
    if (HOP_BY_HOP.has(lower) || CLIENT_HEADERS_DROP.has(lower)) continue;
    if (value === undefined) continue;
    headers[lower] = value;
  }
  headers.host = bridge.upstream.authority;
  headers.origin = bridge.upstream.origin;
  headers.cookie = `${bridge.cookieName}=${bridge.currentCookie()}`;
  // 强制上游返回未压缩内容：桥接只做透传，不替手机解压，审计字节数也更直观。
  headers['accept-encoding'] = 'identity';
  if (body && body.length > 0) headers['content-length'] = String(body.length);
  else if (body) headers['content-length'] = '0';
  return headers;
}

/** 去掉查询串里的 token（设备令牌绝不能转发给上游或落上游日志）。 */
function upstreamPath(rawUrl) {
  const url = safeParseRequestUrl(rawUrl);
  url.searchParams.delete('token');
  return url.pathname + url.search;
}

async function proxyHttpRequest(bridge, req, res, parsedUrl, base, started) {
  let body;
  try {
    body = await readRequestBody(req, MAX_BODY_BYTES);
  } catch (error) {
    const tooLarge = error?.code === 'body-too-large';
    const status = tooLarge ? 413 : 400;
    const code = tooLarge ? 'bridge/body-too-large' : 'bridge/bad-request';
    const message = tooLarge ? '请求体超过 16MB 上限' : '无法读取请求体';
    // 请求体没读完就回错误：告知连接即将关闭，并把残余数据排空，避免客户端卡在写。
    const bytes = sendJson(res, status, code, message, tooLarge ? { connection: 'close' } : {});
    bridge.audit({ ...base, decision: 'deny', reason: tooLarge ? 'body-too-large' : 'bad-request', status, ms: nowMs() - started, bytes });
    req.on('error', () => {});
    req.resume();
    return { denied: true };
  }

  const targetPath = upstreamPath(req.url);
  const headers = buildUpstreamHeaders(bridge, req.headers, body);
  const auditBase = { ...base, path: parsedUrl.pathname };
  const finished = { value: false };
  const finish = (outcome) => {
    if (finished.value) return;
    finished.value = true;
    bridge.audit({ ...auditBase, ms: nowMs() - started, ...outcome });
  };

  const upstreamReq = http.request({
    host: bridge.upstream.host,
    port: bridge.upstream.port,
    method: req.method,
    path: targetPath,
    headers,
    agent: false,
  });
  let responded = false;
  const endpoint = parsedUrl.pathname.replace(/^\/api\//, '');
  upstreamReq.setTimeout(SLOW_ENDPOINTS.has(endpoint) ? SLOW_UPSTREAM_TIMEOUT_MS : UPSTREAM_TIMEOUT_MS, () => {
    if (!responded) upstreamReq.destroy(Object.assign(new Error('上游连接超时'), { code: 'upstream-timeout' }));
  });
  upstreamReq.on('error', (error) => {
    if (res.headersSent || res.writableEnded) {
      try {
        res.destroy();
      } catch {
        /* ignore */
      }
      finish({ decision: 'allow', reason: 'upstream-error', status: 502, bytes: 0 });
      return;
    }
    const timeout = error?.code === 'upstream-timeout';
    if (!timeout) bridge.noteUpstreamFailure();
    const bytes = sendJson(
      res,
      timeout ? 504 : 502,
      timeout ? 'bridge/upstream-timeout' : 'bridge/upstream-unreachable',
      timeout ? `上游 DSH 无响应：${bridge.upstream.authority}` : `无法连接上游 DSH：${bridge.upstream.authority}`,
    );
    finish({ decision: 'allow', reason: timeout ? 'upstream-timeout' : 'upstream-error', status: timeout ? 504 : 502, bytes });
  });
  upstreamReq.on('response', (upstreamRes) => {
    responded = true;
    upstreamReq.setTimeout(0);
    // DSH 拒绝的是桥接的 cookie，不是手机的设备凭据：绝不能把 401/403 原样透给手机，
    // 否则 App 会以为自己被撤销而退出登录。改成 502 bridge/upstream-auth-failed。
    if (upstreamRes.statusCode === 401 || upstreamRes.statusCode === 403) {
      upstreamRes.resume();
      const bytes = sendJson(res, 502, 'bridge/upstream-auth-failed', '电脑上的 DeepSeek Harness 拒绝了桥接的认证，请稍后重试或重启桥接');
      finish({ decision: 'allow', reason: 'upstream-auth-failed', status: 502, bytes });
      return;
    }
    const responseHeaders = {};
    for (const [name, value] of Object.entries(upstreamRes.headers)) {
      const lower = name.toLowerCase();
      if (HOP_BY_HOP.has(lower)) continue;
      // 手机永远拿不到 DSH 浏览器 cookie。
      if (lower === 'set-cookie') continue;
      responseHeaders[name] = value;
    }
    const status = upstreamRes.statusCode ?? 502;
    res.writeHead(status, responseHeaders);
    let bytes = 0;
    upstreamRes.on('data', (chunk) => {
      bytes += chunk.length;
    });
    upstreamRes.on('end', () => {
      finish({ decision: 'allow', reason: 'proxied', status, bytes });
    });
    upstreamRes.on('error', () => {
      try {
        res.destroy();
      } catch {
        /* ignore */
      }
      finish({ decision: 'allow', reason: 'upstream-stream-error', status, bytes });
    });
    res.on('close', () => {
      if (!res.writableFinished) {
        upstreamRes.destroy();
        finish({ decision: 'allow', reason: 'client-aborted', status, bytes });
      }
    });
    upstreamRes.pipe(res);
  });
  upstreamReq.end(body);
  return { denied: false };
}

// ---------------------------------------------------------------------------
// WebSocket 升级：TCP 级 pipe
// ---------------------------------------------------------------------------

function handleUpgrade(bridge, req, socket, head) {
  const started = nowMs();
  const remoteAddr = normalizeRemote(socket.remoteAddress);
  const parsedUrl = safeParseRequestUrl(req.url);
  const base = { method: 'GET', path: parsedUrl.pathname, remoteAddr, upgrade: true, ms: 0 };

  socket.on('error', () => {});
  socket.setNoDelay?.(true);

  const reject = (status, code, message, reason) => {
    const body = JSON.stringify({ ok: false, error: { code, message } });
    const headText =
      `HTTP/1.1 ${status} ${STATUS_TEXT[status] ?? 'Error'}\r\n` +
      'content-type: application/json; charset=utf-8\r\n' +
      `content-length: ${Buffer.byteLength(body)}\r\n` +
      'cache-control: no-store\r\n' +
      'connection: close\r\n\r\n';
    try {
      socket.end(headText + body);
    } catch {
      try {
        socket.destroy();
      } catch {
        /* ignore */
      }
    }
    bridge.audit({ ...base, decision: 'deny', reason, status, ms: nowMs() - started, bytes: Buffer.byteLength(body) });
  };

  // 1) 认证（浏览器 WS 不能自定义头，所以 ?token= 是主要方式；原生客户端也可用头）。
  const token = extractToken(req.headers, parsedUrl.searchParams);
  if (!token) return reject(401, 'bridge/unauthorized', '缺少设备令牌：WS 连接请使用 ?token=<token>', 'missing-token');
  if (bridge.authBlocked(remoteAddr)) {
    return reject(429, 'bridge/rate-limited', '认证失败次数过多，请稍后再试', 'auth-rate-limited');
  }
  const device = bridge.lookupDevice(token);
  if (!device) {
    bridge.recordAuthFailure(remoteAddr);
    return reject(401, 'bridge/unauthorized', '设备令牌无效', 'invalid-token');
  }
  base.deviceId = device.id;
  bridge.clearAuthFailures(remoteAddr);
  if (device.revoked === true) {
    return reject(401, 'bridge/device-revoked', '该设备已被撤销，请在手机上重新扫码登录', 'revoked-token');
  }
  bridge.touchDevice(device);

  // 2) 普通请求限流（按设备）。
  const quota = bridge.consumeRequestQuota(device);
  if (!quota.allowed) {
    return reject(429, 'bridge/rate-limited', '连接过于频繁，请稍后再试', 'rate-limited');
  }

  // 3) 只允许流式多路复用入口，且必须是合法 WS 握手。
  if (parsedUrl.pathname !== WS_PATH) {
    return reject(403, 'bridge/forbidden', `WS 只允许 ${WS_PATH}，其他流式入口默认拒绝`, 'forbidden-ws-path');
  }
  const clientKey = req.headers['sec-websocket-key'];
  const protocolHeader = req.headers['sec-websocket-protocol'];
  if (typeof clientKey !== 'string' || clientKey.trim() === '') {
    return reject(400, 'bridge/bad-request', 'WS 握手缺少 Sec-WebSocket-Key', 'bad-ws-handshake');
  }

  // 4) 连接上游，改写握手头（Host/Origin/Cookie），其余保持原始 WS 语义。
  const upstreamSocket = net.connect({ host: bridge.upstream.host, port: bridge.upstream.port });
  let settled = false;
  let buffered = Buffer.alloc(0);
  let bytesUp = 0;
  let bytesDown = 0;
  const dispose = () => {
    try {
      socket.destroy();
    } catch {
      /* ignore */
    }
    try {
      upstreamSocket.destroy();
    } catch {
      /* ignore */
    }
  };
  const finishAudit = (outcome) => {
    if (settled) return;
    settled = true;
    bridge.audit({ ...base, ms: nowMs() - started, ...outcome });
  };
  const failUpstream = (reason, status, code, message) => {
    if (settled) return;
    finishAudit({ decision: 'allow', reason, status, bytes: bytesDown });
    if (!upstreamSocket.destroyed) {
      const body = JSON.stringify({ ok: false, error: { code, message } });
      const text =
        `HTTP/1.1 ${status} ${STATUS_TEXT[status] ?? 'Error'}\r\n` +
        'content-type: application/json; charset=utf-8\r\n' +
        `content-length: ${Buffer.byteLength(body)}\r\nconnection: close\r\n\r\n`;
      try {
        socket.end(text + body);
      } catch {
        /* ignore */
      }
    }
    dispose();
  };

  upstreamSocket.setTimeout(10_000, () => {
    upstreamSocket.destroy(Object.assign(new Error('上游握手超时'), { code: 'upstream-timeout' }));
  });
  upstreamSocket.on('error', () => {
    bridge.noteUpstreamFailure();
    failUpstream('upstream-error', 502, 'bridge/upstream-unreachable', `无法连接上游 DSH：${bridge.upstream.authority}`);
  });
  upstreamSocket.on('connect', () => {
    const lines = [
      `GET ${WS_PATH} HTTP/1.1`,
      `Host: ${bridge.upstream.authority}`,
      `Origin: ${bridge.upstream.origin}`,
      `Cookie: ${bridge.cookieName}=${bridge.currentCookie()}`,
      'Upgrade: websocket',
      'Connection: Upgrade',
      `Sec-WebSocket-Key: ${clientKey.trim()}`,
      `Sec-WebSocket-Version: ${req.headers['sec-websocket-version'] ?? '13'}`,
    ];
    // 只转发协议子协商（DSH 目前不使用，但保留语义）；不转发扩展，避免透传压缩协商。
    if (typeof protocolHeader === 'string' && protocolHeader !== '') {
      lines.push(`Sec-WebSocket-Protocol: ${protocolHeader}`);
    }
    lines.push('User-Agent: dsbot-bridge/' + VERSION, '', '');
    upstreamSocket.write(lines.join('\r\n'));
  });
  upstreamSocket.on('data', (chunk) => {
    if (settled) return;
    if (buffered.length === 0) {
      buffered = Buffer.from(chunk);
    } else {
      buffered = Buffer.concat([buffered, chunk]);
    }
    const headerEnd = buffered.indexOf('\r\n\r\n');
    if (headerEnd < 0) {
      if (buffered.length > 64 * 1024) failUpstream('upstream-bad-handshake', 502, 'bridge/upstream-error', '上游握手响应异常');
      return;
    }
    const headText = buffered.subarray(0, headerEnd + 4).toString('latin1');
    const rest = buffered.subarray(headerEnd + 4);
    const statusLine = headText.split('\r\n', 1)[0] ?? '';
    const statusMatch = statusLine.match(/^HTTP\/1\.[01]\s+(\d{3})/);
    const status = statusMatch ? Number(statusMatch[1]) : 502;
    if (status !== 101) {
      // 上游拒绝升级：把它的响应还给客户端，然后断开。401/403 是 DSH 拒绝桥接的 cookie，
      // 改成 502，避免手机误以为设备凭据失效而退出登录。
      finishAudit({ decision: 'allow', reason: 'upstream-rejected-ws', status, bytes: buffered.length });
      settled = true;
      let reply = buffered;
      if (status === 401 || status === 403) {
        const body = JSON.stringify({ ok: false, error: { code: 'bridge/upstream-auth-failed', message: '电脑上的 DeepSeek Harness 拒绝了桥接的认证' } });
        reply = Buffer.from(
          'HTTP/1.1 502 Bad Gateway\r\ncontent-type: application/json; charset=utf-8\r\n' +
            `content-length: ${Buffer.byteLength(body)}\r\nconnection: close\r\n\r\n${body}`,
        );
      }
      try {
        socket.end(reply);
      } catch {
        /* ignore */
      }
      dispose();
      return;
    }
    // 握手成功：把上游 101 响应（含可能已经捎带的数据）转给客户端。
    settled = true;
    upstreamSocket.setTimeout(0);
    bridge.trackMuxSocket(socket);
    socket.once('close', () => bridge.untrackMuxSocket(socket));
    try {
      socket.write(buffered);
    } catch {
      dispose();
      return;
    }
    bytesDown += rest.length;
    upstreamSocket.on('data', (upChunk) => {
      bytesDown += upChunk.length;
    });

    let closedAudited = false;
    let violated = false;
    const complete = () => {
      if (closedAudited) return;
      closedAudited = true;
      dispose();
      if (violated) return; // 违规已按 deny 审计过了
      bridge.audit({ ...base, decision: 'allow', reason: 'ws-proxied', status: 101, ms: nowMs() - started, bytes: bytesDown });
    };
    const violation = (detail) => {
      if (closedAudited) return;
      violated = true;
      closedAudited = true;
      bridge.audit({
        ...base,
        decision: 'deny',
        reason: 'mux-violation',
        status: 403,
        ms: nowMs() - started,
        bytes: bytesDown,
      });
      // 给客户端回一个标准 WS Close 帧（1008 = policy violation），再断开两端。
      try {
        socket.write(Buffer.from([0x88, 0x02, 0x03, 0xf0]));
      } catch {
        /* ignore */
      }
      try {
        socket.end();
      } catch {
        /* ignore */
      }
      try {
        upstreamSocket.destroy();
      } catch {
        /* ignore */
      }
      if (process.env.DSBOT_DEBUG) console.error('[bridge] mux violation:', detail);
    };

    // 客户端 → 上游：只解析 mux 层的 open/item/end/cancel 帧，做流式端点白名单校验；
    // 校验通过的帧按原字节转发（不做任何改写），下行继续纯 pipe。
    const muxFilter = createMuxClientFilter({
      write(frame) {
        if (upstreamSocket.destroyed) return;
        if (!upstreamSocket.write(frame)) {
          try {
            socket.pause();
          } catch {
            /* ignore */
          }
        }
      },
      onViolation: violation,
    });
    upstreamSocket.on('drain', () => {
      if (!socket.destroyed) socket.resume();
    });
    socket.on('data', (clientChunk) => {
      bytesUp += clientChunk.length;
      muxFilter.push(clientChunk);
    });
    if (head && head.length > 0) {
      bytesUp += head.length;
      muxFilter.push(head);
    }
    upstreamSocket.pipe(socket, { end: true });
    // 双端半开兜底：HTTP server 升级出来的 socket 是 allowHalfOpen=true，读到 FIN 后不会
    // 自动关闭写方向。两端都显式 end()，保证对端断线后能尽快 close 并写审计。
    //
    // dsh 重启时上游只发 FIN、不再回包：两端 end() 之后连接会停在 CLOSE_WAIT/FIN_WAIT2
    // （netstat 里那条 CloseWait 就是它）。这里加一个 5s 的强制销毁上限，
    // 半关后迟迟等不到对端关闭就自己 destroy，绝不让失效连接活过下一次重启。
    let halfCloseTimer = null;
    const armHalfCloseDispose = () => {
      if (halfCloseTimer) return;
      halfCloseTimer = setTimeout(() => {
        try {
          socket.destroy();
        } catch {
          /* ignore */
        }
        dispose();
        complete();
      }, HALF_CLOSE_GRACE_MS);
      halfCloseTimer.unref?.();
    };
    socket.on('end', () => {
      try {
        upstreamSocket.end();
      } catch {
        /* ignore */
      }
      try {
        socket.end();
      } catch {
        /* ignore */
      }
      armHalfCloseDispose();
    });
    upstreamSocket.on('end', () => {
      try {
        socket.end();
      } catch {
        /* ignore */
      }
      try {
        upstreamSocket.end();
      } catch {
        /* ignore */
      }
      armHalfCloseDispose();
    });
    socket.on('close', complete);
    socket.on('error', complete);
    upstreamSocket.on('error', complete);
    upstreamSocket.on('close', () => {
      try {
        socket.end();
      } catch {
        /* ignore */
      }
      complete();
    });
  });
}

/**
 * 最小 WS 帧过滤器（只处理客户端→上游方向）。
 *
 * 目的：/api/remote.mux 把 DSH 全部 Typert Remote 流复用在一条 WS 上，纯 TCP 透传
 * 会让手机绕过 unary 白名单打开 terminal/attach 这类危险流。这里只解析出完整的
 * 文本帧、看 `{type:"open", endpoint}` 是否在 ALLOWED_STREAM_ENDPOINTS 里：
 *   - 通过：把收到的原始帧字节按序转发（完全不改写，压缩/掩码/扩展都原样）；
 *   - 违规：不转发该消息，回调 onViolation（审计 + Close 1008 断连）。
 * 非文本帧、二进制帧、未知帧类型一律按违规处理（默认拒绝）。
 */
export function createMuxClientFilter({ write, onViolation }) {
  let buffer = Buffer.alloc(0);
  let closed = false;
  let message = null; // { opcode, payloads, raws, size }
  const fail = (detail) => {
    closed = true;
    onViolation(detail);
  };
  const inspectTextPayload = (payload) => {
    let parsed;
    try {
      parsed = JSON.parse(payload.toString('utf8'));
    } catch {
      return 'invalid-json-frame';
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return 'invalid-mux-frame';
    if (parsed.type === 'open') {
      const endpoint = parsed.endpoint;
      if (typeof endpoint !== 'string' || endpoint === '') return 'invalid-stream-endpoint';
      if (!ALLOWED_STREAM_ENDPOINTS.has(endpoint)) return `forbidden-stream-endpoint:${endpoint}`;
      return null;
    }
    if (parsed.type === 'item' || parsed.type === 'end' || parsed.type === 'cancel') return null;
    return `unknown-mux-frame:${String(parsed.type)}`;
  };
  const handleFrame = (fin, opcode, payload, raw) => {
    // 控制帧：原样转发（ping/pong/close 不影响 mux 授权）。
    if (opcode === 0x8) {
      write(raw);
      closed = true;
      return null;
    }
    if (opcode === 0x9 || opcode === 0xa) {
      write(raw);
      return null;
    }
    if (opcode === 0x1 || opcode === 0x2) {
      message = { opcode, payloads: [payload], raws: [raw], size: payload.length };
    } else if (opcode === 0x0) {
      if (!message) return 'unexpected-continuation';
      message.payloads.push(payload);
      message.raws.push(raw);
      message.size += payload.length;
      if (message.size > MAX_MUX_MESSAGE_BYTES) return 'mux-message-too-large';
    } else {
      return `unsupported-opcode:${opcode}`;
    }
    if (!fin) return null;
    const finished = message;
    message = null;
    if (finished.opcode === 0x2) return 'binary-mux-frame';
    const detail = inspectTextPayload(Buffer.concat(finished.payloads));
    if (detail) return detail;
    for (const frame of finished.raws) write(frame);
    return null;
  };
  return {
    push(chunk) {
      if (closed || chunk.length === 0) return;
      buffer = buffer.length === 0 ? chunk : Buffer.concat([buffer, chunk]);
      let detail = null;
      while (!closed && buffer.length >= 2) {
        const fin = (buffer[0] & 0x80) !== 0;
        const opcode = buffer[0] & 0x0f;
        const masked = (buffer[1] & 0x80) !== 0;
        let length = buffer[1] & 0x7f;
        let offset = 2;
        if (length === 126) {
          if (buffer.length < 4) return;
          length = buffer.readUInt16BE(2);
          offset = 4;
        } else if (length === 127) {
          if (buffer.length < 10) return;
          const big = buffer.readBigUInt64BE(2);
          if (big > BigInt(MAX_MUX_FRAME_BYTES)) {
            detail = 'mux-frame-too-large';
            break;
          }
          length = Number(big);
          offset = 10;
        }
        if (length > MAX_MUX_FRAME_BYTES) {
          detail = 'mux-frame-too-large';
          break;
        }
        const maskLength = masked ? 4 : 0;
        const total = offset + maskLength + length;
        if (buffer.length < total) return;
        const raw = Buffer.from(buffer.subarray(0, total));
        const payload = Buffer.from(buffer.subarray(offset + maskLength, total));
        if (masked) {
          const mask = buffer.subarray(offset, offset + 4);
          for (let index = 0; index < payload.length; index += 1) payload[index] ^= mask[index & 3];
        }
        buffer = buffer.subarray(total);
        detail = handleFrame(fin, opcode, payload, raw);
        if (detail) break;
      }
      if (detail) fail(detail);
    },
  };
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

export function parseArgs(argv) {
  const options = {
    port: DEFAULT_PORT,
    bind: DEFAULT_BIND,
    dsh: 'auto',
    stateDir: DEFAULT_STATE_DIR,
    credentialsPath: DEFAULT_CREDENTIALS_PATH,
    reset: false,
    pair: false,
    devices: false,
    revoke: null,
    open: false,
    help: false,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    const readValue = (name) => {
      const eq = arg.indexOf('=');
      if (eq >= 0) return arg.slice(eq + 1);
      index += 1;
      if (index >= argv.length) throw new Error(`参数 ${name} 缺少值`);
      return argv[index];
    };
    const name = arg.includes('=') ? arg.slice(0, arg.indexOf('=')) : arg;
    if (name === '--help' || name === '-h') options.help = true;
    else if (name === '--reset') options.reset = true;
    else if (name === '--pair') options.pair = true;
    else if (name === '--devices') options.devices = true;
    else if (name === '--open') options.open = true;
    else if (name === '--wait-dsh') options.waitDsh = true;
    else if (name === '--relay') options.relay = requireText(readValue('--relay'), '--relay');
    else if (name === '--rotate-host-key') options.rotateHostKey = true;
    else if (name === '--revoke') options.revoke = requireDeviceId(readValue('--revoke'));
    else if (name === '--port') {
      const value = Number(readValue('--port'));
      if (!Number.isInteger(value) || value <= 0 || value > 65535) throw new Error(`--port 必须是 1-65535 的整数，收到：${value}`);
      options.port = value;
      options.portExplicit = true;
    } else if (name === '--bind') options.bind = requireText(readValue('--bind'), '--bind');
    // 调试用：缩短登录码有效期，用于验证「过期自动换新」整条链路（生产不要设置）。
    else if (name === '--pair-ttl-ms') {
      const ttl = Number(readValue('--pair-ttl-ms'));
      if (!Number.isInteger(ttl) || ttl <= 0) throw new Error('--pair-ttl-ms 必须是正整数毫秒');
      options.pairingTtlMs = ttl;
    }
    else if (name === '--dsh') options.dsh = requireText(readValue('--dsh'), '--dsh');
    else if (name === '--state-dir') options.stateDir = path.resolve(requireText(readValue('--state-dir'), '--state-dir'));
    else if (name === '--outbox') options.outboxDir = path.resolve(requireText(readValue('--outbox'), '--outbox'));
    else if (name === '--inbox') options.inboxDir = path.resolve(requireText(readValue('--inbox'), '--inbox'));
    else if (name === '--credentials') options.credentialsPath = path.resolve(requireText(readValue('--credentials'), '--credentials'));
    else if (name === '--version' || name === '-v') {
      options.version = true;
    } else throw new Error(`未知参数：${arg}（用 --help 查看用法）`);
  }
  return options;
}

function requireText(value, name) {
  const text = String(value ?? '').trim();
  if (!text) throw new Error(`${name} 不能为空`);
  return text;
}

function requireDeviceId(value) {
  const text = String(value ?? '').trim();
  if (!text) throw new Error('--revoke 缺少设备 ID（用 --devices 查看）');
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(text)) {
    throw new Error(`--revoke 设备 ID 格式不正确：${text}（用 --devices 查看）`);
  }
  return text;
}

export function lanIPv4Addresses(interfaces = os.networkInterfaces()) {
  const result = [];
  for (const [name, addresses] of Object.entries(interfaces)) {
    for (const address of addresses ?? []) {
      if (address.family === 'IPv4' && !address.internal) result.push({ name, address: address.address });
    }
  }
  return result;
}

export function computeLanUrls({ bind = DEFAULT_BIND, port = DEFAULT_PORT, interfaces } = {}) {
  const urls = [];
  const seen = new Set();
  const add = (host, name) => {
    if (!host || seen.has(host)) return;
    seen.add(host);
    urls.push({ host, name: name ?? '', url: `http://${host}:${port}` });
  };
  if (isLoopbackBind(bind)) {
    add('127.0.0.1', 'loopback');
    return urls;
  }
  if (bind !== '0.0.0.0' && bind !== '::') add(bind, 'bind');
  for (const item of rankLanAddresses(lanIPv4Addresses(interfaces))) add(item.address, item.name);
  if (urls.length === 0) add('127.0.0.1', 'loopback');
  return urls;
}

/**
 * 给局域网网卡排序：物理网卡（WLAN/以太网）与常见家用私网段优先，
 * 虚拟网卡（singbox/VPN/Hyper-V/Docker 等）排后 —— 手机扫码要连的通常是第一个。
 */
const PHYSICAL_LAN_HINTS = /(wlan|wi-?fi|ethernet|以太网|无线|本地连接)/i;
const VIRTUAL_LAN_HINTS = /(tun|tap|vpn|virtual|vmware|vbox|hyper-v|vethernet|docker|singbox|tailscale|zerotier|loopback|wsl)/i;

export function lanAddressScore(item) {
  const name = String(item?.name ?? '');
  const address = String(item?.address ?? '');
  let score = 0;
  if (VIRTUAL_LAN_HINTS.test(name)) score -= 10;
  if (PHYSICAL_LAN_HINTS.test(name)) score += 5;
  if (/^192\.168\./.test(address)) score += 4;
  else if (/^10\./.test(address)) score += 3;
  else if (/^172\.(1[6-9]|2\d|3[01])\./.test(address)) score += 2;
  if (/^169\.254\./.test(address)) score -= 5;
  return score;
}

export function rankLanAddresses(items) {
  return [...items].sort((a, b) => lanAddressScore(b) - lanAddressScore(a));
}

function isLoopbackBind(bind) {
  return bind === '127.0.0.1' || bind === 'localhost' || bind === '::1';
}

/** 登录链接格式：dsbot://login?url=http://<ip>:<port>&code=ABC-DEF（docs/ACCOUNT-LOGIN.md §1）。 */
export function buildLoginLink(baseUrl, code, relayInfo = null) {
  const url = String(baseUrl ?? '').replace(/\/+$/, '');
  let link = `dsbot://login?url=${url}&code=${code}`;
  // 中转参数（docs/RELAY-DESIGN.md §4.2）：旧版 App 会忽略多余参数，继续走局域网。
  if (relayInfo?.relay && relayInfo?.host && relayInfo?.hpk) {
    link += `&relay=${encodeURIComponent(relayInfo.relay)}&host=${relayInfo.host}&hpk=${relayInfo.hpk}`;
  }
  return link;
}

/**
 * 用系统默认浏览器/查看器打开文件（Windows 按约定用 PowerShell 的 Start-Process）。
 * 只是“尽力而为”：失败返回 false，绝不让桥接因为打不开浏览器而退出。
 */
export function openPathWithDefaultBrowser(filePath) {
  if (!filePath) return false;
  try {
    let command;
    let args;
    if (process.platform === 'win32') {
      const escaped = String(filePath).replace(/'/g, "''");
      command = 'powershell.exe';
      args = ['-NoProfile', '-NonInteractive', '-Command', `Start-Process -LiteralPath '${escaped}'`];
    } else if (process.platform === 'darwin') {
      command = 'open';
      args = [filePath];
    } else {
      command = 'xdg-open';
      args = [filePath];
    }
    const child = spawn(command, args, { detached: true, stdio: 'ignore' });
    child.on('error', () => {});
    child.unref();
    return true;
  } catch {
    return false;
  }
}

function formatTimestamp(ms) {
  if (!Number.isFinite(ms) || ms <= 0) return '—';
  const date = new Date(ms);
  const pad = (value) => String(value).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ` +
    `${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

export function formatStartupReport(bridge, options = {}) {
  const { port = bridge.port, bind = bridge.bind } = options;
  const showDevices = options.devices === true;
  const account = publicAccount(bridge.account);
  const pairing = bridge.pairingStatus();
  const lan = rankLanAddresses(lanIPv4Addresses());
  const urls = bridge.lanUrls.length > 0 ? bridge.lanUrls : computeLanUrls({ bind, port });
  const lines = [];
  lines.push('============================================================');
  lines.push(`  DeepSeek 远控台 主机桥接网关 v${bridge.version}`);
  lines.push('  DeepSeek 账号主机：电脑登录一次账号，多台手机扫码加入同一账号');
  lines.push('============================================================');
  // 账号信息打码输出：deviceId 只展示前 8 位；token/secret 永不进入输出。
  if (account.loggedIn) {
    lines.push(`DeepSeek 账号 : ${account.displayName ?? 'DeepSeek 账号'}  [已登录]`);
  } else {
    lines.push('DeepSeek 账号 : 未检测到（电脑端 DSH 可能未登录 DeepSeek；手机仍可扫码加入）');
  }
  lines.push(
    `provider      : ${account.provider}    账号设备 ID: ` +
      (account.deviceId ? `${account.deviceId.slice(0, 8)}…（已打码）` : '（未知）'),
  );
  if (account.issuer) lines.push(`issuer        : ${account.issuer}`);
  const cookieHint = `${bridge.cookieName.slice(0, 'dsh-auth-'.length + 8)}…`;
  lines.push(`上游 DSH 地址 : http://${bridge.upstream.authority}${bridge.autoDiscover ? '（自动查找）' : ''}  (cookie: 已签名 ${cookieHint})`);
  if (bridge.autoDiscover) {
    const view = bridge.upstreamsView();
    const items = view.targets.map((target) => `${target.label} ${target.authority}${target.active ? '（当前）' : ''}`);
    lines.push(`可用 DSH 后端 : ${items.length > 0 ? items.join('；') : '（未发现）'}`);
    lines.push('后端切换      : 手机「设置 → DSH 后端」里切换（仅桌面版；v2 已移除 dsh web）');
  }
  lines.push(`桥接监听      : ${bind}:${port}${bind === '0.0.0.0' ? '（所有网卡）' : ''}`);
  lines.push(`状态目录      : ${bridge.stateDir}`);
  lines.push(`审计日志      : ${bridge.auditPath}`);
  lines.push(`发给手机的文件: ${bridge.outboxDir}（放进这里，手机「设置 → 收到的文件」下载）`);
  lines.push(`手机发来的大文件: ${bridge.inboxDir}`);
  lines.push(
    `已登记设备    : ${bridge.state.devices.length} 台（${bridge.activeDeviceCount()} 台可用）` +
      (showDevices ? '' : '；--devices 查看列表'),
  );
  if (bridge.migratedFromV1) {
    const legacy = bridge.state.devices[0];
    lines.push('');
    lines.push(`ℹ 已从 v0.1 单 token 迁移为设备 ${legacy?.id ?? ''}：旧手机 token 继续有效，无需重新配对。`);
  }
  if (bridge.resetPerformed) {
    lines.push('');
    lines.push('⚠ 已按 --reset 清空全部设备：所有手机都需要重新扫码登录。');
  }
  if (bridge.replacedCorrupt) {
    lines.push('');
    lines.push('⚠ 原 bridge.json 损坏或格式不对，已重建设备注册表（所有手机需重新扫码）。');
  }
  if (bridge.startupRevocation) {
    const revocation = bridge.startupRevocation;
    lines.push('');
    if (!revocation.found) {
      lines.push(`⚠ --revoke 指定的设备不存在：${revocation.deviceId}（用 --devices 查看设备 ID）。`);
    } else if (revocation.alreadyRevoked) {
      lines.push(`ℹ 设备 ${revocation.deviceId} 此前已被撤销。`);
    } else {
      lines.push(`✔ 已按 --revoke 撤销设备 ${revocation.deviceId}。`);
    }
  }
  if (bridge.relayInfo) {
    lines.push(`中转服务      : ${bridge.relayInfo.relay}（不在同一网络时手机经中转连接，端到端加密）`);
    lines.push(`主机 ID       : ${bridge.relayInfo.host}`);
    lines.push(`主机公钥指纹  : ${sha256Hex(bridge.relayInfo.hpk).slice(0, 16)}`);
  }
  lines.push('');
  if (lan.length === 0) {
    lines.push('本机局域网 IPv4 地址：（没有检测到局域网 IPv4 网卡；手机可能连不上，请检查 Wi-Fi / 网线连接）');
  } else {
    lines.push('本机局域网 IPv4 地址（手机必须与电脑在同一可信局域网）：');
    for (const item of lan) lines.push(`  - ${item.address}  (${item.name})`);
  }
  lines.push('');
  lines.push('登录码（一次性，10 分钟内有效；--pair 可重新生成）：');
  if (pairing.active && bridge.pairCode) {
    lines.push(`  ${bridge.pairCode}`);
    lines.push('');
    lines.push('登录链接（手机 App 可直接打开；扫码/粘贴均可）：');
    for (const item of urls) lines.push(`  ${buildLoginLink(item.url, bridge.pairCode, bridge.relayInfo)}`);
    lines.push('');
    if (isLoopbackBind(bind)) {
      lines.push('⚠ 当前只绑定了回环地址，手机无法访问；要手机扫码请用 --bind 0.0.0.0。');
      lines.push('');
    }
    if (bridge.pairingPagePath) {
      lines.push(`二维码网页      : ${bridge.pairingPagePath}（双击打开后用手机相机扫码；--open 自动打开）`);
    }
    lines.push('');
    lines.push('登录二维码（终端 ANSI 块，手机相机可直接扫）：');
    const matrix = createQrMatrix(bridge.pairingLink || buildLoginLink(urls[0]?.url ?? '', bridge.pairCode, bridge.relayInfo));
    const ansi = matrix ? renderAnsiQr(matrix) : null;
    if (ansi) lines.push(ansi);
    else {
      lines.push('  （缺少 host/vendor/qrcode.cjs，无法在终端画二维码；');
      lines.push('    请用上面的登录链接，或打开 pair.html 里的文字版链接）');
    }
  } else {
    lines.push('  （当前没有有效登录码：已兑换或已过期；重跑桥接或加 --pair 重新生成）');
  }
  if (showDevices) {
    lines.push('');
    lines.push('已登记设备列表（--devices）：');
    const devices = bridge.devicesView('');
    if (devices.length === 0) {
      lines.push('  （还没有设备；用上面的登录码在手机上扫码加入）');
    } else {
      for (const device of devices) {
        lines.push(
          `  - ${device.id}  ${device.name}  [${device.platform}]  ` +
            `${device.revoked ? '已撤销' : '可用'}  最近活跃 ${formatTimestamp(device.lastSeenAt)}`,
        );
      }
    }
  }
  lines.push('');
  lines.push('安全提示（务必阅读）：');
  lines.push('  1. 只在你信任的局域网里使用。桥接是 HTTP 明文传输（DSH 本身也不带 TLS），');
  lines.push('     公共 Wi-Fi/不可信网络请先自建 TLS 或 VPN 隧道，绝不要把端口直接暴露到公网。');
  lines.push('  2. 手机扫码加入 ≠ 主机管理员：手机只能做会话读写、模型目录、审批回传、只读文件浏览；');
  lines.push('     修改设置、读写密钥、安装插件、执行命令等请求会被桥接 403 并记入审计。');
  lines.push('  3. 每台手机有独立设备凭据（桥接只存 sha256 哈希，不存明文）；可在手机「账号 → 设备」里');
  lines.push('     撤销其他设备，或在本机运行：node host/dsbot-bridge.mjs --revoke <deviceId>（--devices 查看 ID）。');
  lines.push('  4. 手机丢失/凭据泄露：Ctrl+C 停止桥接后运行 --reset 清空全部设备，再重新扫码登录。');
  lines.push('  5. 审计日志（JSONL，允许/拒绝都记；含 deviceId，不含 token/cookie/登录码）：');
  lines.push(`         ${bridge.auditPath}`);
  lines.push('  6. 本终端输出包含一次性登录码与二维码，请勿截图/转发；关闭窗口后重跑命令会生成新码。');
  lines.push('');
  lines.push('已就绪，等待手机扫码登录…（Ctrl+C 停止）');
  return lines.join('\n');
}

export function formatHelp() {
  return [
    'DeepSeek 远控台 主机桥接网关（DeepSeek 账号主机：电脑登录一次，多台手机扫码加入）',
    '',
    '用法：',
    '  node host/dsbot-bridge.mjs [选项]',
    '',
    '选项：',
    `  --port <端口>          桥接监听端口（默认 ${DEFAULT_PORT}）`,
    '  --dsh <host:port|auto> 上游 DSH Web 地址（默认 auto：自动发现本机桌面版 DSH；重启换端口自动跟随。v2 不再使用 dsh web / 3080）',
    `  --bind <地址>          监听地址（默认 ${DEFAULT_BIND}；只允许本机访问用 127.0.0.1）`,
    '  --state-dir <目录>     状态目录（默认 %USERPROFILE%\\.dsbot；bridge.json + audit.log + pair.html）',
    '  --credentials <文件>   DSH 凭据文件（默认 %USERPROFILE%\\.dsh\\.credentials.yaml）',
    '  --outbox <目录>        Bot 发给手机的文件放这里，手机在「收到的文件」里下载（默认 <状态目录>\\outbox）',
    '  --inbox <目录>         手机发来的大文件存这里（默认 <状态目录>\\inbox）',
    '  --pair                 启动时重新生成一次性登录码（每次启动默认都会生成新码）',
    '  --devices              启动输出打印已登记设备列表',
    '  --revoke <deviceId>    启动时撤销指定设备（用 --devices 查看设备 ID）',
    '  --open                 启动后用默认浏览器打开 pair.html（Windows 用 Start-Process）',
    '  --wait-dsh             DeepSeek Harness 没打开时一直等待，不退出（开机自启用）',
    '  --reset                清空全部设备，所有手机需重新扫码登录',
    '  --relay <ws(s)://…>    经中转服务连接（手机不在同一网络时可用；内容端到端加密）',
    '  --rotate-host-key      重新生成主机密钥（配合 --relay；所有手机需重新扫码）',
    '  --version              打印版本号',
    '  --help                 显示本帮助',
    '',
    '示例：',
    '  node host/dsbot-bridge.mjs',
    '  node host/dsbot-bridge.mjs --port 8788 --dsh 127.0.0.1:64005',
    '  node host/dsbot-bridge.mjs --devices',
    '  node host/dsbot-bridge.mjs --revoke 3f2a9c0d1b4e6a8c',
    '  node host/dsbot-bridge.mjs --reset',
    '',
    '安全模型：默认拒绝的方法白名单；每台手机独立设备 token（state 只存 sha256+末4位）；',
    '登录码 10 分钟一次性；错误 token/登录码限速；审计 JSONL 含 deviceId；手机拿不到 DSH cookie。',
  ].join('\n');
}

async function main() {
  let options;
  try {
    options = parseArgs(process.argv.slice(2));
  } catch (error) {
    console.error(`参数错误：${error.message}`);
    process.exitCode = 1;
    return;
  }
  if (options.help) {
    console.log(formatHelp());
    return;
  }
  if (options.version) {
    console.log(VERSION);
    return;
  }
  let dsh = options.dsh;
  // 两个概念分开：
  //  - autoDiscover：桥接**始终**允许自动发现/跟随端口漂移（探活看门狗、失败重发现都以此为准）；
  //  - autoPick：启动时是否由发现结果直接决定上游（仅 `--dsh auto`）。
  // 以前 `--dsh 127.0.0.1:3080` 会把 autoDiscover 置 false，dsh 一换端口就永远连死地址。
  const autoDiscover = true;
  const autoPick = dsh === 'auto';
  let dshTargets = null;
  let preferredKind = null;
  if (autoPick) dsh = null;
  if (autoPick) {
    try {
      const secret = loadCookieSecret(options.credentialsPath);
      const cookieFor = (authority) => `${computeCookieName(authority)}=${signCookie(secret, authority, Date.now() - COOKIE_CLOCK_SKEW_MS)}`;
      const preference = loadUpstreamPreference(options.stateDir);
      preferredKind = preference?.kind ?? null;
      // DSH 忙（正在跑 Bot）时探测可能超时：最多试 3 次。桌面版和 dsh web 同时发现。
      for (let attempt = 0; attempt < 3 && (!dshTargets || dshTargets.length === 0); attempt += 1) {
        if (attempt > 0) await new Promise((resolve) => setTimeout(resolve, 2000));
        dshTargets = await discoverDshTargets(cookieFor);
      }
      // --wait-dsh（开机自启用）：DSH 还没打开就一直等，不退出——手机那边的登录不受影响。
      if ((!dshTargets || dshTargets.length === 0) && options.waitDsh) {
        console.log('等待 DSH 桌面版启动…（打开 DeepSeek Harness 桌面版后会继续）');
        while (!dshTargets || dshTargets.length === 0) {
          await new Promise((resolve) => setTimeout(resolve, 5000));
          dshTargets = await discoverDshTargets(cookieFor);
        }
      }
      if (dshTargets && dshTargets.length > 0) {
        const chosen = pickPreferredTarget(dshTargets, preferredKind);
        dsh = chosen.authority;
        preferredKind = preferredKind ?? chosen.kind;
      }
    } catch (error) {
      // 发现失败不该阻断启动：探测依赖系统命令（netstat / tasklist），
      // 在受限环境（沙箱、杀软拦截、精简系统）可能直接被拒。
      // 降级为「暂未发现」，由运行期自动发现与探活看门狗接管。
      console.warn(`[dsh] 自动发现失败（${error.message}），先启动，稍后继续查找后端`);
      dshTargets = null;
    }
    if (!dsh) {
      // 降级而非退出：探测手段被系统限制（或 DSH 稍后才启动）时，
      // 不该把桥接挡在门外——先以占位上游启动，运行期自动发现会切到真实后端。
      dsh = DEFAULT_DSH;
      console.warn(
        `[dsh] 暂未发现正在运行的 DSH 后端，先以 ${dsh} 启动；` +
          '打开 DeepSeek Harness 桌面版后会自动接管（v2 不再使用 dsh web / 3080）。',
      );
    }
  }

  // 显式 --dsh 也可能过期（dsh 重启换了端口）：连不通就立刻扫一遍本机 DSH，
  // 把发现结果当作新上游，而不是抱着死端口启动。发现失败才退回原地址（运行期看门狗还会重试）。
  if (!autoPick && dsh) {
    const [explicitHost, explicitPort] = String(dsh).split(':');
    const reachable = await probePort(explicitHost, Number(explicitPort), 1200);
    if (!reachable) {
      try {
        const secret = loadCookieSecret(options.credentialsPath);
        const cookieFor = (authority) => `${computeCookieName(authority)}=${signCookie(secret, authority, Date.now() - COOKIE_CLOCK_SKEW_MS)}`;
        for (let attempt = 0; attempt < 2 && (!dshTargets || dshTargets.length === 0); attempt += 1) {
          if (attempt > 0) await new Promise((resolve) => setTimeout(resolve, 1500));
          dshTargets = await discoverDshTargets(cookieFor);
        }
        if (dshTargets && dshTargets.length > 0) {
          const chosen = pickPreferredTarget(dshTargets, preferredKind);
          console.log(`[upstream] --dsh ${dsh} 连不上（dsh 可能重启换了端口），自动改连 ${chosen.authority}（${chosen.label}）`);
          dsh = chosen.authority;
          preferredKind = chosen.kind;
        } else {
          console.log(`[upstream] --dsh ${dsh} 连不上，也没扫到其他 DSH；先用原地址启动，运行期会继续探活重发现。`);
        }
      } catch {
        /* 发现失败不阻塞启动 */
      }
    }
  }
  let relayInfo = null;
  let hostKeys = null;
  if (options.relay) {
    try {
      const relay = normalizeRelayUrl(options.relay);
      hostKeys = loadOrCreateHostKeys(options.stateDir, { rotate: options.rotateHostKey === true });
      relayInfo = { relay, host: hostKeys.hostId, hpk: hostKeys.hpk };
    } catch (error) {
      console.error(`启动失败：${error.message}`);
      process.exitCode = 1;
      return;
    }
  }
  let bridge;
  // 2026-11-23 事故：两个桥接进程在 1 秒内同时启动，端口探测都还没就绪，
  // 第二个回退到 8789 并连上中转，导致同一 host 出现两条连接、手机 Noise 握手被互抢
  // 表现为 channel/N deny handshake-failed。这里加一把单实例锁，先占锁再探测端口。
  const instanceLock = acquireSingleInstanceLock(options.stateDir);
  if (!instanceLock.ok) {
    console.log(`[lock] 已有一个桥接实例在运行（pid ${instanceLock.pid}），本进程退出，避免抢占设备表与中转。`);
    process.exitCode = 0;
    return;
  }
  const releaseLock = () => { try { instanceLock.release(); } catch { /* 尽力 */ } };
  process.on('exit', releaseLock);
  process.on('SIGINT', () => { releaseLock(); process.exit(0); });
  process.on('SIGTERM', () => { releaseLock(); process.exit(0); });

  const bridgeCfg = loadBridgeConfig(options.stateDir);
  const rangeStart = Number(bridgeCfg?.portRange?.[0]) || DEFAULT_PORT;
  const rangeEnd = Number(bridgeCfg?.portRange?.[1]) || rangeStart + 10;
  const preferredPort = options.portExplicit
    ? options.port
    : (Number(process.env.DSBOT_PORT) || Number(bridgeCfg?.port) || DEFAULT_PORT);
  const chosenPort = await pickBridgePort({ preferred: preferredPort, rangeStart, rangeEnd, bind: options.bind });
  if (chosenPort !== options.port) {
    const owner = await probeBridgeOwner(options.port);
    // 2026-11-23 架构决策：端口不再自动漂移。
    // 漂移会让手机里的固定地址失效，也会让「两个实例」变得难以察觉。
    // 未显式 --port 时，端口被占就直接退出并说明占用者。
    if (!options.portExplicit) {
      if (owner) {
        console.log(
          `[port] ${options.port} 已被本机另一个桥接占用（${owner.account?.displayName ?? '未知账号'}），` +
          '本进程退出（桥接不支持多实例，--port 也不能绕过单实例锁）。',
        );
        process.exitCode = 0;
        return;
      }
      console.log(
        `[port] ${options.port} 被其他程序占用，端口固定策略下不自动漂移，本进程退出。` +
        `请释放该端口，或用 --port 显式指定别的端口。`,
      );
      process.exitCode = 2;
      return;
    }
    console.log(
      owner
        ? `[port] ${options.port} 被本机另一个桥接实例占用，改用 ${chosenPort}（旧实例仍在服务，手机可能连的是它）`
        : `[port] ${options.port} 被其它程序占用，改用 ${chosenPort}`,
    );
    console.warn(`[port] 端口已漂移：手机固定地址连不上，新端口已记入 ${path.join(options.stateDir, ENDPOINT_FILE)}`);
  }
  options.port = chosenPort;
  try {
    bridge = createBridge({
      port: options.port,
      bind: options.bind,
      pairingTtlMs: options.pairingTtlMs,
      dsh,
      dshTargets,
      preferredKind,
      autoDiscover,
      discoverTargets: autoDiscover
        ? (cookieFor) => discoverDshTargets(cookieFor, { excludePorts: [options.port] })
        : null,
      onUpstreamChange: (from, to) => console.log(`[dsh] 已切换 DSH 后端：${from} → ${to}`),
      stateDir: options.stateDir,
      outboxDir: options.outboxDir,
      inboxDir: options.inboxDir,
      credentialsPath: options.credentialsPath,
      reset: options.reset,
      forceNewPair: options.pair,
      revokeOnStart: options.revoke,
      relayInfo,
    });
  } catch (error) {
    console.error(`启动失败：${error.message}`);
    if (/EPERM|EACCES/.test(String(error.code || error.message))) {
      console.error(
        `状态目录不可写：${options.stateDir}\n` +
        '  桥接需要写设备表/登录码/审计日志。若是沙箱或受限账户导致的权限拒绝，\n' +
        '  请用正常权限启动（不要在工作区沙箱里跑桥接），或用 --state-dir 指定可写目录。',
      );
    }
    process.exitCode = 1;
    return;
  }
  try {
    await bridge.start();
    // 端点文件：让端口漂移可观测。写失败不影响服务（沙箱下写 .dsbot 会 EPERM）。
    writeEndpointFile(options.stateDir, {
      port: bridge.port,
      bind: options.bind,
      pid: process.pid,
      startedAt: new Date().toISOString(),
    });
    // dsh 重启（换端口或同端口重启）后主动重连：30s 探活一次，连续失败就重新发现/拉起。
    bridge.startUpstreamWatchdog();
    // 登录码过期自动换新：以前只能重启桥接才能拿到新码（每次断线十几秒），
    // 而且一旦配对过设备，旧逻辑的续期分支直接 return，pair.json 从此再也不会更新。
    const pairRefreshTimer = setInterval(() => {
      try {
        if (bridge.refreshPairingIfExpired()) {
          console.log(`[pair] 登录码已过期，已自动换新（见 ${path.join(options.stateDir, PAIR_STATE_FILE)} 或 pair.html）`);
        }
      } catch {
        /* 刷新失败不影响桥接本体 */
      }
    }, 30_000);
    pairRefreshTimer.unref?.();
    fs.mkdirSync(bridge.outboxDir, { recursive: true });
    fs.mkdirSync(bridge.inboxDir, { recursive: true });
    saveBridgeConfig(options.stateDir, {
      product: process.env.DSBOT_PRODUCT || 'dsbot',
      port: bridge.port,
      portRange: [rangeStart, rangeEnd],
      bind: options.bind,
      relay: options.relay ?? null,
      dsh: options.dsh ?? 'auto',
    });
  } catch (error) {
    console.error(`启动失败：${error.message}`);
    process.exitCode = 1;
    return;
  }
  console.log(formatStartupReport(bridge, options));

  // 登录码自动续期：过期后自动生成新码并重写 pair.html。
  // 用户不用重启 bridge —— pair.html 每 30 秒自动刷新就能看到新码。
  // 已有可用设备时不续（避免无意义地换码）。
  const PAIR_RENEW_CHECK_MS = 30 * 1000;
  const pairRenewTimer = setInterval(() => {
    try {
      if (bridge.pairingStatus().active) return;
      const devices = bridge.devicesView ? bridge.devicesView("") : [];
      const anyLive = Array.isArray(devices) && devices.some((d) => d && d.revoked !== true);
      if (anyLive) return;
      const code = bridge.regeneratePairing();
      console.log(`\n[配对] 登录码已自动续期：${code}（pair.html 已更新）`);
    } catch {
      /* 续期失败不影响主流程 */
    }
  }, PAIR_RENEW_CHECK_MS);
  if (typeof pairRenewTimer.unref === 'function') pairRenewTimer.unref();
  let relayLink = null;
  if (relayInfo) {
    relayLink = createRelayLink({
      bridge,
      relayUrl: relayInfo.relay,
      keys: hostKeys,
      log: (line) => console.log(line),
    });
    relayLink.start();
  }
  if (options.open) {
    const opened = openPathWithDefaultBrowser(bridge.pairingPagePath);
    console.log(
      opened
        ? `已用默认浏览器打开二维码网页：${bridge.pairingPagePath}`
        : '⚠ 无法自动打开浏览器；请手动双击上面的 pair.html 路径。',
    );
  }
  const shutdown = async (signal) => {
    console.log(`\n收到 ${signal}，正在关闭桥接…`);
    try {
      await relayLink?.stop();
      bridge.stopUpstreamWatchdog();
      await bridge.stop();
    } catch {
      /* ignore */
    }
    console.log('桥接已关闭。');
    process.exit(0);
  };
  process.on('SIGINT', () => void shutdown('SIGINT'));
  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGBREAK', () => void shutdown('SIGBREAK'));
  process.on('uncaughtException', (error) => {
    console.error('未捕获异常（桥接继续运行）：', error);
  });
  process.on('unhandledRejection', (reason) => {
    console.error('未处理的 Promise 拒绝（桥接继续运行）：', reason);
  });
}

// 只在被直接运行时启动 CLI，import 时保持纯库语义（测试会 import）。
const invokedDirectly =
  typeof process.argv[1] === 'string' && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (invokedDirectly) {
  void main();
}

/**
 * 单实例锁：在 stateDir 下用 pid 文件做互斥。
 * 规则：
 *  - 用 wx 独占创建，已存在则读取其中 pid；
 *  - pid 仍存活 → 判定已有实例，返回 ok:false；
 *  - pid 已死（崩溃/被杀）→ 删掉旧锁并重建。
 * 这样无论看门狗、开机自启还是手动启动撞在一起，都只会留下一个实例。
 */
function acquireSingleInstanceLock(stateDir) {
  const lockPath = path.join(stateDir, 'bridge.lock');
  const write = () => {
    const fd = fs.openSync(lockPath, 'wx');
    fs.writeSync(fd, String(process.pid));
    fs.closeSync(fd);
  };
  const alive = (pid) => {
    if (!Number.isInteger(pid) || pid <= 0) return false;
    try { process.kill(pid, 0); return true; } catch { return false; }
  };
  try {
    fs.mkdirSync(stateDir, { recursive: true });
    write();
  } catch (error) {
    if (error?.code !== 'EEXIST') throw error;
    let pid = 0;
    try { pid = Number(fs.readFileSync(lockPath, 'utf8').trim()) || 0; } catch { /* 读不到当作失效 */ }
    if (alive(pid) && pid !== process.pid) {
      return { ok: false, pid };
    }
    try { fs.unlinkSync(lockPath); } catch { /* 尽力 */ }
    try { write(); } catch (retryError) {
      if (retryError?.code === 'EEXIST') return { ok: false, pid };
      throw retryError;
    }
  }
  return {
    ok: true,
    pid: process.pid,
    release() {
      try {
        const held = Number(fs.readFileSync(lockPath, 'utf8').trim()) || 0;
        if (held === process.pid) fs.unlinkSync(lockPath);
      } catch { /* 尽力 */ }
    },
  };
}