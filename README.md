# dsh-jingshu 插件（鲸枢手机连接）

让 **DeepSeek Harness（DSH）** 具备“手机遥控电脑”的能力：手机装「DSH鲸枢控制台」，
电脑装本插件，扫码即可在手机上收发会话、下发任务、接收文件。

- 插件名：`dsh-dsbot-host`
- 版本：`0.0.1`
- 平台：Windows + DSH 桌面版

## 它做了什么

1. 把桥接程序安装到 `%USERPROFILE%\.dsbot`
2. 由插件负责“确保桥接在跑”（端口探测 + 单实例锁，绝不重复拉起）
3. 在 DSH 侧边栏「更多」里提供 **鲸枢配对** 面板：二维码、6 位登录码
4. 手机扫码后，桥接把 DSH 的会话/文件在手机上呈现

## 安装方式一：npm 包名（推荐）

在 DSH「插件」页安装，填：

```
dsh-dsbot-host
```

装完重启 DSH，侧边栏出现「鲸枢配对」即成功。

## 安装方式二：GitHub Release 直链

在 DSH「插件」页安装，填下面这个地址（DSH 支持远程 tarball）：

```
https://github.com/zhangzhimiao1994/dsh-jingshu-/raw/main/dsh-dsbot-host-0.0.1.tgz
```

或下载该 tgz 后填本地路径。

## 装完之后

1. 重启 DSH
2. 侧边栏「更多」→ **鲸枢配对** → 手机扫码（或输入 6 位登录码）
3. 登录码一次性、10 分钟有效，过期面板自动换新

## 常见问题

| 现象 | 处理 |
|---|---|
| 侧边栏没有「鲸枢配对」 | 插件没装上或 DSH 没重启 |
| 面板提示桥接没起来 | 8788 端口被占；关掉占用者，重启 DSH，插件会自动重试 |
| 手机提示「电脑拒绝了这台手机」 | 电脑上有旧桥接实例，重启 DSH 即可（插件保证单实例） |

## 结构

```
client.js            侧边栏/设置页 UI（鲸枢配对面板）
lib/index.js         插件入口与 /dsbot-host/* 接口
lib/installer.js     幂等安装：目录、桥接文件、host-keys、配置
lib/supervisor.js    桥接进程守护（端口/锁探测 + 重试）
lib/upstream.js      DSH 后端发现与切换
assets/host/         桥接实现（dsbot-bridge.mjs 等）
locale/              中英文案
```

## 许可

MIT
