/**
 * dsh-jingshu — 鲸枢手机连接宿主插件（host 半）。
 *
 * 职责只有两块：
 *   1. 常驻 API：`/jingshu-host/*`，给设置页 UI 查状态、触发安装、取配对码
 *   2. 安装逻辑：由 API 调用，幂等地把桥接运行所需的环境装好（见 installer.js）
 *
 * 不负责：进程保活（外层守护负责）、请求转发（桥接负责）、崩溃重启（外层守护负责）。
 *
 * 鉴权：复用 DSH 的浏览器会话校验 `connection.requestRejection(req)`，
 * 与 dsh-remote-pair 同一套请求策略，不自建 token。
 */

import fs from 'node:fs'
import net from 'node:net'
import os from 'node:os'
import path from 'node:path'
import { pathToFileURL } from 'node:url'

import { install, inspect, readPairState } from './installer.js'
import { startBridgeSupervisor } from './supervisor.js'

/** Stable plugin name (must match cordis.patch.yml 的 name). */
export const name = 'jingshu-host'

/** 路由与鉴权需要 Web 服务器与 DSH 连接服务。 */
export const inject = ['webServer', 'connection']

/** 本插件独占的通道前缀。 */
const CHANNEL_PATH = '/jingshu-host'

/** 插件版本，与 package.json 同步维护。 */
const PLUGIN_VERSION = '0.0.3'

/** 请求体上限：安装参数只有几个字段。 */
const MAX_BODY_BYTES = 64 * 1024

/**
 * 写 JSON 响应。
 * @param {import('node:http').ServerResponse} res
 * @param {number} status
 * @param {unknown} body
 */
function json(res, status, body) {
  const payload = JSON.stringify(body)
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(payload),
    'cache-control': 'no-store',
  })
  res.end(payload)
}

/**
 * 读取请求体，超过上限直接拒绝。
 * @param {import('node:http').IncomingMessage} req
 * @param {number} limit
 * @returns {Promise<string>}
 */
function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    let size = 0
    /** @type {Buffer[]} */
    const chunks = []
    req.on('data', (chunk) => {
      size += chunk.length
      if (size > limit) {
        reject(new Error(`请求体超过 ${limit} 字节`))
        req.destroy()
        return
      }
      chunks.push(chunk)
    })
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
    req.on('error', reject)
  })
}

/**
 * 探测桥接是否在本机监听（默认 8788，读 bridge-config.json）。
 *
 * 用真实 TCP 连接判断，而不是查进程命令行：受限环境里进程查询会 Access denied，
 * 造成「明明在跑却认为没跑」；而 bridge-endpoint.json 是历史落盘文件，桥接崩了它还在，
 * 单看文件会把死的当活的。连得上 = 活着。
 * @returns {Promise<{up: boolean, port: number, checkedAt: number}>}
 */
async function bridgeStatus() {
  const port = (() => {
    try {
      const cfg = JSON.parse(
        fs.readFileSync(path.join(os.homedir(), '.dsbot', 'bridge-config.json'), 'utf8'),
      )
      return Number.isInteger(cfg.port) ? cfg.port : 8788
    } catch {
      return 8788
    }
  })()
  return { up: await isPortListening(port), port, checkedAt: Date.now() }
}

/**
 * 尝试建立一次 TCP 连接，超时或出错即视为没有监听者。
 * @param {number} port
 * @returns {Promise<boolean>}
 */
function isPortListening(port) {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host: '127.0.0.1', port })
    let settled = false
    const done = (value) => {
      if (settled) return
      settled = true
      socket.destroy()
      resolve(value)
    }
    socket.setTimeout(600, () => done(false))
    socket.once('connect', () => done(true))
    socket.once('error', () => done(false))
  })
}

/**
 * 生成可执行提示，避免界面只显示空白。
 * @param {ReturnType<typeof readPairState>} state
 * @param {ReturnType<typeof bridgeStatus>} bridge
 * @returns {string}
 */
function pairHint(state, bridge) {
  const staleAfterMs = 15 * 60 * 1000
  const stale = state.updatedAt ? Date.now() - state.updatedAt > staleAfterMs : true

  if (!state.ok) {
    return '读不到登录码：桥接还没在本机生成过 pair.json。重启 DSH 即可，插件会自动拉起桥接。'
  }
  if (stale) {
    return '登录码早已停止更新：桥接进程多半已经退出。重启 DSH 即可，插件会自动拉起桥接。'
  }
  if (state.expired) {
    return bridge.up
      ? '登录码刚过期，桥接会在 30 秒内自动换新，稍后重试即可。'
      : '登录码已过期且桥接未运行，不会再自动换新。请先恢复桥接。'
  }
  return '登录码有效，可直接扫码登录。'
}

/**
 * 懒加载桥接自带的二维码模块（~/.dsbot/qr.mjs）。
 *
 * 不 import 插件的 assets/host/qr.mjs，是因为真正被使用、且一定带 vendor 的是
 * 桥接安装目录那一份；插件 assets 里的副本只用于首次安装时铺文件。
 * @returns {Promise<typeof import('../../host/qr.mjs')>}
 */
let qrModulePromise = null
function loadQrModule() {
  const file = path.join(os.homedir(), '.dsbot', 'qr.mjs')
  if (!qrModulePromise) {
    qrModulePromise = import(pathToFileURL(file).href)
  }
  return qrModulePromise
}

/**
 * Activate the host half.
 * @param {object} ctx - Cordis plugin context (webServer + connection injected).
 */
export function apply(ctx) {
  const logger = ctx.logger('jingshu-host')
  const connection = ctx.connection

  /**
   * 分发一次请求。
   * @param {import('node:http').IncomingMessage} req
   * @param {import('node:http').ServerResponse} res
   */
  const handler = async (req, res) => {
    // 与 DSH 浏览器鉴权同一套策略；不带会话的请求一律拒绝。
    const rejection = connection.requestRejection(req)
    if (rejection !== undefined) {
      res.writeHead(rejection, { 'content-type': 'text/plain; charset=utf-8' })
      res.end(rejection === 401 ? 'unauthorized' : 'forbidden')
      return
    }

    const pathname = new URL(req.url ?? '/', 'http://dsh.invalid').pathname
    const endpoint = pathname.slice(`${CHANNEL_PATH}/`.length)

    // GET /jingshu-host/status —— 插件与安装状态快照
    if (endpoint === 'status' && req.method === 'GET') {
      let state = null
      let error = null
      try { state = inspect() } catch (e) { error = String(e?.message ?? e) }
      json(res, 200, { ok: true, plugin: 'dsh-jingshu', version: PLUGIN_VERSION, state, error })
      return
    }

    // GET /jingshu-host/pair —— 当前配对码与连接参数（读桥接落盘的同机文件）
    // 说明：登录码由桥接写 %USERPROFILE%\.dsbot\pair.json，10 分钟过期后桥接自己换新。
    // 因此「读不到码」只有两种原因，必须分开报，否则界面上就是一片空白：
    //   1) 桥接进程没在跑 → pair.json 停更 → 码过期后再也不会刷新
    //   2) 桥接在跑但刚好在换码窗口 → 30 秒内自愈
    if (endpoint === 'pair' && req.method === 'GET') {
      const state = readPairState()
      const bridge = await bridgeStatus()
      json(res, 200, {
        ...state,
        bridge,
        hint: pairHint(state, bridge),
      })
      return
    }

    // POST /jingshu-host/install —— 幂等安装；body 可带 { relay, port, bind }
    if (endpoint === 'install' && req.method === 'POST') {
      let options = {}
      try {
        const raw = await readBody(req, MAX_BODY_BYTES)
        if (raw.trim()) {
          const parsed = JSON.parse(raw)
          if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) options = parsed
        }
      } catch (e) {
        json(res, 400, { ok: false, error: 'bad-request', detail: String(e?.message ?? e) })
        return
      }
      // 只接受安装器认识的字段，避免把任意对象写进配置
      const safe = {}
      if (typeof options.relay === 'string' && options.relay.trim()) safe.relay = options.relay.trim()
      if (Number.isInteger(options.port) && options.port > 0 && options.port < 65536) safe.port = options.port
      if (typeof options.bind === 'string' && options.bind.trim()) safe.bind = options.bind.trim()

      try {
        const result = await install(safe)
        json(res, result.ok ? 200 : 500, result)
      } catch (e) {
        logger.error(`安装失败：${String(e?.message ?? e)}`)
        json(res, 500, { ok: false, error: 'install-failed', detail: String(e?.message ?? e) })
      }
      return
    }

    // GET /jingshu-host/qr.svg —— 当前登录码的二维码（SVG，前端 <img> 直接用）
    // 用桥接自带的同款编码器（~/.dsbot/qr.mjs + vendor/qrcode.cjs），
    // 保证「设置页看到的码」和「pair.html 里的码」是同一套编码，不会一边扫不动。
    if (endpoint === 'qr.svg' && req.method === 'GET') {
      const state = readPairState()
      if (!state.ok || !state.code) {
        res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' })
        res.end('no-active-code')
        return
      }
      try {
        const qr = await loadQrModule()
        const matrix = qr.createQrMatrix(state.link || state.code)
        const svg = qr.renderSvgQr(matrix, { label: `登录码 ${state.code}` })
        if (!svg) throw new Error('二维码编码器不可用')
        res.writeHead(200, {
          'content-type': 'image/svg+xml; charset=utf-8',
          'cache-control': 'no-store',
        })
        res.end(svg)
      } catch (e) {
        logger.error(`生成二维码失败：${String(e?.message ?? e)}`)
        res.writeHead(500, { 'content-type': 'text/plain; charset=utf-8' })
        res.end('qr-unavailable')
      }
      return
    }

    json(res, 404, { ok: false, error: 'not-found', endpoint })
  }

  // 两处都是必须的，缺一就会 "webserver: duplicate undefined route"：
  //   1. kind 必须显式给。register 用 kind 选表（exact / prefix），漏传时 path 落进
  //      prefixes 表但报错文案把它叫成 undefined，排查时极具误导性。
  //   2. 返回值是 disposer，必须交给 ctx.effect。cordis 重载插件会先 dispose 再 apply，
  //      旧代码直接 register 不持有 disposer，旧路由永远留在表里，第二次同路径注册即抛错，
  //      插件随即被判定 failed（include:jingshu-host fiberPhase=failed）。
  ctx.effect(() => ctx.webServer.register({ kind: 'prefix', path: CHANNEL_PATH, handler }))

  // 2026-11-23：插件对「桥接在不在跑」负责。
  // 只做“确保在跑”（端口在听 / lock pid 活着就什么都不做），不抢单实例、不重复拉起。
  // 这样用户装完插件就可用，不再需要额外的计划任务或脚本。
  ctx.effect(() => {
    const supervisor = startBridgeSupervisor({ logger })
    return () => supervisor.stop()
  })
  logger.info(`jingshu-host ${PLUGIN_VERSION} 已加载，通道 ${CHANNEL_PATH}（prefix）`)
}
