/**
 * dsh-jingshu —— 桥接进程守护（插件内置）
 *
 * 为什么放在插件里：用户装的是 DSH 插件，不是我们的安装器。
 * 以前插件只把桥接文件拷到 ~/.dsbot 就撒手不管，用户还得手动跑脚本/计划任务，
 * 于是「装了插件但还是连不上」。现在插件对「桥接在不在跑」负责。
 *
 * 设计约束（2026-11-23 事故后定的三条）：
 *   1. 只允许一个守护：起之前先看端口是否在听、再看 bridge.lock 里的 pid 是否活着，
 *      任一成立就不动手（桥接自己也有单实例锁，双保险）。
 *   2. 不做静默成功：起完等端口真正 listen，最多 20 秒；起不来写日志并继续重试。
 *   3. 插件卸载/重载要能停掉循环：返回 disposer，避免热重载叠加多个守护。
 */
import { spawn } from 'node:child_process'
import fs from 'node:fs'
import net from 'node:net'
import os from 'node:os'
import path from 'node:path'

const STATE_DIR = path.join(os.homedir(), '.dsbot')
const ENTRY = path.join(STATE_DIR, 'dsbot-bridge.mjs')
const LOCK = path.join(STATE_DIR, 'bridge.lock')
const CONFIG = path.join(STATE_DIR, 'bridge-config.json')
const LOG = path.join(STATE_DIR, 'bridge-console.log')

const DEFAULT_PORT = 8788
const DEFAULT_RELAY = 'ws://39.105.200.88:8443'
const START_TIMEOUT_MS = 20_000
const RETRY_MIN_MS = 3_000
const RETRY_MAX_MS = 60_000

function readConfig() {
  let port = DEFAULT_PORT
  let relay = DEFAULT_RELAY
  let bind = '0.0.0.0'
  try {
    const raw = JSON.parse(fs.readFileSync(CONFIG, 'utf8'))
    if (Number.isInteger(raw.port) && raw.port > 0 && raw.port < 65536) port = raw.port
    if (typeof raw.relay === 'string' && raw.relay.trim()) relay = raw.relay.trim()
    if (typeof raw.bind === 'string' && raw.bind.trim()) bind = raw.bind.trim()
  } catch {
    /* 首次运行没有配置文件：用默认值 */
  }
  return { port, relay, bind }
}

function portListening(port, timeoutMs = 1_200) {
  return new Promise((resolve) => {
    const socket = net.connect({ host: '127.0.0.1', port })
    let settled = false
    const done = (value) => {
      if (settled) return
      settled = true
      socket.destroy()
      resolve(value)
    }
    socket.setTimeout(timeoutMs)
    socket.on('connect', () => done(true))
    socket.on('timeout', () => done(false))
    socket.on('error', () => done(false))
  })
}

function lockPidAlive() {
  try {
    const pid = Number(fs.readFileSync(LOCK, 'utf8').trim())
    if (!Number.isInteger(pid) || pid <= 0) return false
    process.kill(pid, 0)
    return true
  } catch {
    return false
  }
}

/**
 * @param {{ logger?: { info?: Function, warn?: Function, error?: Function } }} [options]
 */
export function startBridgeSupervisor(options = {}) {
  const logger = options.logger ?? {}
  const info = (m) => (logger.info ? logger.info(m) : undefined)
  const warn = (m) => (logger.warn ? logger.warn(m) : undefined)

  const cfg = readConfig()
  let stopped = false
  let child = null
  let retryMs = RETRY_MIN_MS
  let timer = null
  let lastState = 'init'

  function log(line) {
    try {
      fs.appendFileSync(LOG, `[plugin-supervisor] ${new Date().toISOString()} ${line}\n`)
    } catch {
      /* 日志失败不影响主流程 */
    }
  }

  async function ensureOnce() {
    if (stopped) return
    lastState = 'checking'
    if (await portListening(cfg.port)) {
      lastState = 'running'
      retryMs = RETRY_MIN_MS
      return
    }
    if (lockPidAlive()) {
      lastState = 'starting'
      return
    }
    if (!fs.existsSync(ENTRY)) {
      lastState = 'missing-entry'
      warn(`桥接入口不存在：${ENTRY}（请先调用 /jingshu-host/install 安装）`)
      return
    }

    log(`spawn ${ENTRY} --port ${cfg.port}`)
    try {
      child = spawn(process.execPath, [ENTRY, '--relay', cfg.relay, '--port', String(cfg.port), '--bind', cfg.bind], {
        cwd: os.homedir(),
        stdio: 'ignore',
        windowsHide: true,
        detached: false,
      })
    } catch (e) {
      log(`spawn 失败：${String(e?.message ?? e)}`)
      return
    }
    child.on('exit', (code, signal) => {
      log(`桥接退出 code=${code} signal=${signal ?? ''}`)
      child = null
      if (stopped) return
      scheduleRetry()
    })

    const deadline = Date.now() + START_TIMEOUT_MS
    while (!stopped && Date.now() < deadline) {
      if (await portListening(cfg.port, 800)) {
        lastState = 'running'
        retryMs = RETRY_MIN_MS
        log(`桥接已监听 ${cfg.port}`)
        return
      }
      await new Promise((r) => setTimeout(r, 1_000))
    }
    lastState = 'start-timeout'
    log(`桥接 ${START_TIMEOUT_MS / 1000}s 内未监听 ${cfg.port}`)
  }

  function scheduleRetry() {
    if (stopped) return
    const delay = retryMs
    retryMs = Math.min(retryMs * 2, RETRY_MAX_MS)
    timer = setTimeout(() => {
      timer = null
      void ensureOnce()
    }, delay)
  }

  info(`桥接守护已启动（port=${cfg.port} relay=${cfg.relay}）`)
  void ensureOnce()

  // 每 30 秒巡检一次：端口掉了就重新拉起（不依赖计划任务）
  const tick = setInterval(() => {
    void ensureOnce()
  }, 30_000)
  if (typeof tick.unref === 'function') tick.unref()

  return {
    stop() {
      stopped = true
      if (timer) clearTimeout(timer)
      clearInterval(tick)
      // 不杀桥接进程：它要跟着机器活下去，插件重载不该把手机断线
      child = null
      log('守护已停止（桥接进程保留）')
    },
    status() {
      return { state: lastState, port: cfg.port, relay: cfg.relay }
    },
  }
}
