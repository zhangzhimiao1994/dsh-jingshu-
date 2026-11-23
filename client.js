/**
 * dsh-jingshu —— 客户端半。
 *
 * 提供两个入口：
 *   1. 侧边栏「更多」列表里一个「鲸枢配对」项（slot: sidebar.panellist）
 *      → 点开是整页面板（slot: main，key 与 panellist 的 id 相同）
 *   2. 设置 → 通用 里一行同样的状态面板（slot: settings.general.item）
 *
 * 数据来自同机接口，不新增对外暴露面：
 *   GET /jingshu-host/pair    状态 + 登录码 + 可执行提示（需 DSH 会话）
 *   GET /jingshu-host/qr.svg  当前登录码的二维码
 */
window.__ModuleLoader__.load({
  id: 'dsh-jingshu',
  factory(require) {
    const React = require('react')
    const h = React.createElement
    const { useState, useEffect, useCallback } = React

    const PANEL_ID = 'jingshu-pair'
    const PANEL_LABEL = '鲸枢配对'
    const REFRESH_MS = 20000

    const styles = {
      wrap: { display: 'flex', flexDirection: 'column', gap: '12px' },
      head: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px' },
      title: { fontSize: '14px', lineHeight: '20px', fontWeight: 500 },
      hint: { fontSize: '12px', lineHeight: '18px', color: 'var(--dsw-alias-label-secondary)' },
      body: { display: 'flex', gap: '16px', alignItems: 'flex-start', flexWrap: 'wrap' },
      qrBox: {
        width: '184px',
        height: '184px',
        padding: '8px',
        borderRadius: '8px',
        background: '#ffffff',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        flex: '0 0 auto',
      },
      qr: { width: '168px', height: '168px', display: 'block' },
      qrEmpty: {
        width: '168px',
        height: '168px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        textAlign: 'center',
        fontSize: '12px',
        lineHeight: '18px',
        color: '#666666',
        whiteSpace: 'pre-line',
      },
      meta: { display: 'flex', flexDirection: 'column', gap: '6px', minWidth: '220px', flex: '1 1 220px' },
      code: {
        fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
        fontSize: '24px',
        letterSpacing: '2px',
        lineHeight: '30px',
      },
      row: { fontSize: '12px', lineHeight: '18px', color: 'var(--dsw-alias-label-secondary)' },
      actions: { display: 'flex', gap: '8px', flexWrap: 'wrap', marginTop: '4px' },
      button: {
        fontSize: '12px',
        lineHeight: '18px',
        padding: '4px 10px',
        borderRadius: '6px',
        border: '0.5px solid var(--dsw-alias-border-l2)',
        background: 'transparent',
        color: 'inherit',
        cursor: 'pointer',
      },
      page: { padding: '24px 20px', maxWidth: '720px' },
    }

    function Row({ label, value }) {
      return h('div', { style: styles.row }, label + '：' + value)
    }

    function usePairState() {
      const [state, setState] = useState({ loading: true, data: null, error: null })

      const load = useCallback(async () => {
        try {
          const res = await fetch('/jingshu-host/pair', { credentials: 'same-origin' })
          if (!res.ok) throw new Error('HTTP ' + res.status)
          const data = await res.json()
          setState({ loading: false, data, error: null })
        } catch (e) {
          setState({ loading: false, data: null, error: String((e && e.message) || e) })
        }
      }, [])

      useEffect(() => {
        let disposed = false
        const run = () => {
          if (!disposed) void load()
        }
        run()
        const timer = setInterval(run, REFRESH_MS)
        return () => {
          disposed = true
          clearInterval(timer)
        }
      }, [load])

      return { state, load }
    }

    function PairCard() {
      const { state, load } = usePairState()
      const [copied, setCopied] = useState(false)

      const copyLink = useCallback(async () => {
        const link = state.data && state.data.link
        if (!link) return
        try {
          await navigator.clipboard.writeText(link)
          setCopied(true)
          setTimeout(() => setCopied(false), 1500)
        } catch {
          setCopied(false)
        }
      }, [state.data])

      const data = state.data
      const hasCode = Boolean(data && data.ok && data.code)
      const bridgeUp = Boolean(data && data.bridge && data.bridge.up)
      const version = hasCode ? '?v=' + (data.updatedAt || 0) : ''

      return h(
        'div',
        { style: styles.wrap },
        h(
          'div',
          { style: styles.head },
          h('div', { style: styles.title }, '鲸枢手机连接'),
          h(
            'button',
            { type: 'button', style: styles.button, onClick: () => void load() },
            state.loading ? '刷新中…' : '刷新',
          ),
        ),
        h(
          'div',
          { style: styles.hint },
          state.error ? '读取失败：' + state.error : (data && data.hint) || '正在读取本机登录码…',
        ),
        h(
          'div',
          { style: styles.body },
          h(
            'div',
            { style: styles.qrBox },
            hasCode
              ? h('img', {
                  style: styles.qr,
                  src: '/jingshu-host/qr.svg' + version,
                  alt: '登录码 ' + data.code + ' 的二维码',
                })
              : h(
                  'div',
                  { style: styles.qrEmpty },
                  bridgeUp ? '暂无可用登录码\n稍等 30 秒后点刷新' : '桥接未运行\n先恢复桥接再刷新',
                ),
          ),
          h(
            'div',
            { style: styles.meta },
            h('div', { style: styles.code }, hasCode ? data.code : '——'),
            h(Row, {
              label: '桥接',
              value: bridgeUp ? '运行中（端口 ' + data.bridge.port + '）' : '未运行',
            }),
            hasCode
              ? h(Row, {
                  label: '有效期',
                  value: new Date(data.expiresAt).toLocaleTimeString('zh-CN', { hour12: false }),
                })
              : null,
            h(Row, { label: '主机 ID', value: (data && data.hostId) || '未知' }),
            hasCode
              ? h(Row, {
                  label: '局域网',
                  value: (data.lanUrls && data.lanUrls[0]) || '未知',
                })
              : null,
            h(
              'div',
              { style: styles.actions },
              h(
                'button',
                {
                  type: 'button',
                  style: styles.button,
                  disabled: !hasCode,
                  onClick: () => void copyLink(),
                },
                copied ? '已复制' : '复制登录链接',
              ),
            ),
            h('div', { style: styles.row }, '二维码页：%USERPROFILE%\\.dsbot\\pair.html（30 秒自动刷新）'),
            h('div', { style: styles.row }, '桥接停了：重启 DSH 即可恢复并换新码'),
          ),
        ),
      )
    }

    /** 侧边栏「更多」里的图标（与 IG5 一样用 16×16 currentColor SVG）。 */
    function PairIcon() {
      return h(
        'svg',
        { width: 16, height: 16, viewBox: '0 0 16 16', fill: 'currentColor', 'aria-hidden': true },
        h('rect', { x: '3', y: '1.5', width: '10', height: '13', rx: '2' }),
        h('rect', { x: '5', y: '3.5', width: '6', height: '7', rx: '1', fill: 'var(--dsw-alias-bg-layer-1)' }),
        h('circle', { cx: '8', cy: '12.5', r: '0.9', fill: 'var(--dsw-alias-bg-layer-1)' }),
      )
    }

    return {
      inject: ['slots'],
      apply(ctx) {
        // 1) 「更多」菜单项
        try {
          ctx.slots.inject('sidebar.panellist', () =>
            ctx.slots.register(
              {
                name: 'sidebar.panellist',
                id: PANEL_ID,
                order: 56,
                label: () => PANEL_LABEL,
              },
              PairIcon,
            ),
          )
        } catch {}

        // 2) 点开后整页面板：key 与 panellist 的 id 对应
        try {
          ctx.slots.inject('main', () =>
            ctx.slots.register({ name: 'main', key: PANEL_ID }, () =>
              h('div', { style: styles.page }, h(PairCard)),
            ),
          )
        } catch {}

        // 3) 设置 → 通用 也放一份
        try {
          ctx.slots.inject('settings.general.item', () =>
            ctx.slots.register(
              { name: 'settings.general.item', id: 'jingshu-pair-settings', order: 60 },
              PairCard,
            ),
          )
        } catch {}
      },
    }
  },
})
