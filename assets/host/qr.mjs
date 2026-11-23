/**
 * 登录二维码渲染（终端 ANSI / 自包含 SVG / pair.html）。
 * ============================================================================
 * QR 编码器本身 vendor 自 MIT 的 qrcode-generator 1.4.4（`host/vendor/qrcode.cjs`，
 * 由 Lead 引入，不要在此文件里修改 vendor 内容）。这里只做三件事：
 *   1. 把文本编码成模块矩阵（带安静区），供终端与网页共用；
 *   2. 终端 ANSI 二维码：用背景色的两格宽方块凑成近似正方形模块（多数等宽字体下可扫）；
 *   3. pair.html：把同一矩阵画成内嵌 SVG（不联网、直接双击可开）。
 *
 * 设计约束：vendor 文件缺失时**不能**让桥接启动失败 —— `createQrMatrix` 返回 null，
 * 调用方退化为“只打印登录链接 + pair.html 里放文字版链接”。这样源码目录即使没有
 * vendor 也能跑测试/启动。
 */

import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);

/** vendor 的默认位置（相对本文件，避免依赖 cwd）。 */
export const DEFAULT_QR_VENDOR_PATH = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  'vendor',
  'qrcode.cjs',
);

/** 终端二维码的安静区（模块数）；QR 规范建议 4。 */
export const DEFAULT_QUIET_ZONE = 4;

let cachedFactory = null;
let cachedFactoryPath = '';

/**
 * 加载 QR 编码器工厂（qrcode-generator 导出的 `qrcode(typeNumber, errorCorrectionLevel)`）。
 * 文件不存在 / 不是合法 UMD 模块时返回 null（调用方走文字降级路径）。
 */
export function loadQrEncoder(vendorPath = DEFAULT_QR_VENDOR_PATH) {
  const resolved = path.resolve(String(vendorPath));
  if (cachedFactory && cachedFactoryPath === resolved) return cachedFactory;
  let factory = null;
  try {
    const mod = require(resolved);
    if (typeof mod === 'function') factory = mod;
    else if (typeof mod?.default === 'function') factory = mod.default;
    else if (typeof mod?.qrcode === 'function') factory = mod.qrcode;
  } catch {
    factory = null;
  }
  if (!factory) return null;
  cachedFactory = factory;
  cachedFactoryPath = resolved;
  return factory;
}

/** vendor QR 编码器是否可用（启动报告里据此决定打印二维码还是链接）。 */
export function isQrAvailable(vendorPath = DEFAULT_QR_VENDOR_PATH) {
  return loadQrEncoder(vendorPath) !== null;
}

/**
 * 把一段文本编码为 QR 矩阵（含安静区）。
 * @returns {{size:number, moduleCount:number, quietZone:number, modules:boolean[][]}|null}
 *          modules[r][c] === true 表示深色模块（要画的点）；行/列均含 quietZone 边距。
 */
export function createQrMatrix(text, options = {}) {
  const {
    vendorPath = DEFAULT_QR_VENDOR_PATH,
    ecc = 'M',
    quietZone = DEFAULT_QUIET_ZONE,
    typeNumber = 0,
  } = options;
  const factory = loadQrEncoder(vendorPath);
  if (!factory) return null;
  const payload = String(text ?? '');
  if (!payload) return null;
  const qr = factory(typeNumber, ecc);
  qr.addData(payload);
  qr.make();
  const count = qr.getModuleCount();
  const margin = Math.max(0, Math.floor(Number(quietZone) || 0));
  const size = count + margin * 2;
  const modules = new Array(size);
  for (let row = 0; row < size; row += 1) {
    const line = new Array(size);
    for (let col = 0; col < size; col += 1) {
      const inCode = row >= margin && row < margin + count && col >= margin && col < margin + count;
      line[col] = inCode ? qr.isDark(row - margin, col - margin) === true : false;
    }
    modules[row] = line;
  }
  return { size, moduleCount: count, quietZone: margin, modules };
}

/**
 * 终端 ANSI 二维码：每模块两个空格宽（近似正方形），深色模块用黑色背景、
 * 浅色模块用白色背景；每行结束复位，兼容深色/浅色终端。
 * @returns {string|null} 多行文本；矩阵非法时返回 null。
 */
export function renderAnsiQr(matrix, options = {}) {
  const {
    dark = '\x1b[40m  ',
    light = '\x1b[47m  ',
    reset = '\x1b[0m',
  } = options;
  if (!matrix || !Array.isArray(matrix.modules) || matrix.modules.length === 0) return null;
  const lines = [];
  for (const row of matrix.modules) {
    let line = '';
    for (const isDark of row) line += isDark ? dark : light;
    lines.push(line + reset);
  }
  return lines.join('\n');
}

/** 把矩阵画成内嵌 SVG（白底黑块，crispEdges 保证扫码边缘清晰）。 */
export function renderSvgQr(matrix, options = {}) {
  const { dark = '#111111', light = '#ffffff', label = '登录二维码' } = options;
  if (!matrix || !Array.isArray(matrix.modules) || matrix.modules.length === 0) return null;
  const size = matrix.size;
  const parts = [
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" ` +
      `shape-rendering="crispEdges" role="img" aria-label="${escapeHtml(label)}">`,
    `<rect width="${size}" height="${size}" fill="${light}"/>`,
  ];
  const pathParts = [];
  for (let row = 0; row < size; row += 1) {
    for (let col = 0; col < size; col += 1) {
      if (matrix.modules[row][col]) pathParts.push(`M${col} ${row}h1v1h-1z`);
    }
  }
  parts.push(`<path d="${pathParts.join('')}" fill="${dark}"/>`);
  parts.push('</svg>');
  return parts.join('');
}

/** HTML 文本转义（pair.html 里的所有动态文本都经过这里）。 */
export function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (ch) => {
    switch (ch) {
      case '&':
        return '&amp;';
      case '<':
        return '&lt;';
      case '>':
        return '&gt;';
      case '"':
        return '&quot;';
      default:
        return '&#39;';
    }
  });
}

function formatExpiresText(expiresAt) {
  if (!Number.isFinite(expiresAt) || expiresAt <= 0) return '10 分钟内有效';
  const date = new Date(expiresAt);
  const pad = (n) => String(n).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ` +
    `${pad(date.getHours())}:${pad(date.getMinutes())} 前有效`;
}

/**
 * 生成自包含的 pair.html（无外部资源、可离线双击打开）。
 * 有 QR 矩阵时内嵌 SVG；没有时只显示可点击/可长按复制的登录链接（文字降级）。
 */
export function buildPairHtml(options = {}) {
  const {
    accountLabel = 'DeepSeek 账号',
    code = '',
    url = '',
    link = '',
    expiresAt = 0,
    qrSvg = null,
    qrAvailable = Boolean(qrSvg),
    version = '',
  } = options;
  const safeCode = escapeHtml(code);
  const safeLink = escapeHtml(link);
  const safeUrl = escapeHtml(url);
  const safeAccount = escapeHtml(accountLabel);
  const expiresText = escapeHtml(formatExpiresText(expiresAt));
  const qrBlock = qrSvg
    ? `<div class="qr" aria-label="登录二维码">${qrSvg}</div>`
    : `<div class="qr-fallback">
        <p>当前没有可用的二维码编码器，请直接在手机浏览器/App 中打开下面的链接：</p>
        <p class="link"><a href="${safeLink}">${safeLink}</a></p>
      </div>`;
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<!-- 每 30 秒自动刷新：登录码过期后 bridge 会自动续期，刷新即可看到新码 -->
<meta http-equiv="refresh" content="30">
<title>DeepSeek 远控台 扫码登录</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
    background: #151517; color: #dde2e8;
    font-family: "Segoe UI", "Microsoft YaHei", system-ui, -apple-system, sans-serif;
  }
  main { width: min(92vw, 560px); padding: 28px 24px; }
  h1 { font-size: 20px; margin: 0 0 4px; font-weight: 600; }
  .sub { color: #9aa4b2; font-size: 13px; margin: 0 0 20px; line-height: 1.6; }
  .account { font-size: 14px; color: #658eff; margin-bottom: 18px; word-break: break-all; }
  .qr { background: #fff; border-radius: 16px; padding: 14px; width: max-content; margin: 0 auto 18px; }
  .qr svg { display: block; width: min(76vw, 320px); height: auto; }
  .qr-fallback { background: #2c2c2e; border-radius: 16px; padding: 16px; margin-bottom: 18px; line-height: 1.7; font-size: 13px; }
  .code {
    direction: ltr; text-align: center; font-family: Consolas, "Cascadia Mono", monospace;
    font-size: 34px; letter-spacing: 4px; font-weight: 700; color: #fff;
    background: #2c2c2e; border-radius: 16px; padding: 16px 8px; margin: 0 0 10px;
    user-select: all;
  }
  .expires { text-align: center; color: #9aa4b2; font-size: 12px; margin: 0 0 18px; }
  .link { word-break: break-all; text-align: center; font-size: 12px; color: #9aa4b2; line-height: 1.7; }
  .link a { color: #658eff; }
  .warn { border-top: 1px solid #2c2c2e; margin-top: 20px; padding-top: 14px; color: #9aa4b2; font-size: 12px; line-height: 1.8; }
  .warn b { color: #ea2d2e; font-weight: 600; }
  code { font-family: Consolas, "Cascadia Mono", monospace; }
</style>
</head>
<body>
<main>
  <h1>DeepSeek 远控台 扫码登录</h1>
  <p class="sub">电脑上的 DSH 已登录 DeepSeek 账号。用手机扫描下方二维码，即可把该手机加入同一账号（可多台设备）。</p>
  <div class="account">${safeAccount}</div>
  ${qrBlock}
  <div class="code">${safeCode}</div>
  <p class="expires">登录码 ${expiresText}，一次性使用</p>
  <p class="link">登录链接<br><a href="${safeLink}">${safeLink}</a></p>
  <p class="link">桥接地址：<code>${safeUrl}</code></p>
  <div class="warn">
    <b>请勿截图或分享本页面</b>：登录码等同于一次性密码，拿到它的人可以把设备加入你的账号。<br>
    安全提示：手机与电脑需在同一可信局域网；桥接为明文 HTTP（DSH 本身也不带 TLS）。<br>
    设备凭据只保存在手机上（Keystore），桥接只存 sha256 哈希；电脑端 <code>--reset</code> 可一键清空全部设备。
  </div>
  <p class="link">dsbot-bridge${version ? ' v' + escapeHtml(version) : ''}</p>
</main>
</body>
</html>
`;
}

/** 把 pair.html 写到磁盘（传入矩阵时内嵌 SVG，否则自动降级为文字链接）。 */
export function writePairHtmlFile(filePath, options = {}) {
  const matrix = options.matrix ?? (options.link ? createQrMatrix(options.link, options.qrOptions ?? {}) : null);
  const html = buildPairHtml({ ...options, qrSvg: matrix ? renderSvgQr(matrix) : null, qrAvailable: Boolean(matrix) });
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, html, 'utf8');
  return filePath;
}
