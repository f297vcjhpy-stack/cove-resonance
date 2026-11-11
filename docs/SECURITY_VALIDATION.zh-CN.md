# 安全补丁验证记录

日期：2026-11-11。原始提交：`e63cfa5f29730b2fa9d90406fc882a6eba8d22e1`。

## 已通过

- Node.js 22.23.4：92/92 tests passed（原有 78 项 + 14 项认证 / QR 隔离测试）。
- TypeScript build 和 `git diff --check`。
- 编译后的网关 + 实际未登录 Bridge 私有子进程：OAuth `/token` PKCE 交换成功，Bearer-authenticated `initialize` / realtime-status 调用成功；匿名调用 401。
- 测试覆盖：匿名双入口拒绝、OAuth metadata、DCR 不可信回调拒绝、管理登录与 CSRF、明确授权、PKCE / client / redirect / resource 绑定、单次授权码、access expiry、refresh rotation / replay family revocation、QR 结果不序列化 Cookie、登出时取消在途扫码、断开时撤销 grants、请求体限制、管理页脚本语法。
- QR 请求运行在单独 IPC 子进程，SDK 的 stdout/stderr 被丢弃；测试确认网关密钥不会传入扫码进程，异常不会携带上游内容返回。

## 未通过或未执行

- 本执行环境对 `interface.music.163.com` 返回 DNS `EAI_AGAIN`，实际 QR 生成未成功；不得声称真实扫码登录已验收。
- 未绑定任何真实网易云账号，未执行一起听房间 / NIM / 双向消息端到端测试。
- 新网关尚未部署公网；当前公开测试服务仍为上游原版的未登录实例。
- 本环境无 Docker，未执行 `Dockerfile.secure` 镜像构建。TypeScript 与无账号实际子进程测试不能替代原生 NIM 的生产验收。
- 未做独立渗透测试或完整依赖可达性审计。

## 依赖扫描

升级 MCP SDK 至 1.32.2、Zod 至 4.6.7，并更新兼容的间接依赖后，npm audit 从 19 项降到 **8 项（1 critical、5 high、2 moderate）**。

剩余包：`decompress`（critical）、`basic-ftp`、`get-uri`、`music-metadata`、`NeteaseCloudMusicApi`、`node-nim`、`pac-proxy-agent`、`file-type`。

`decompress` 由原生 SDK 下载 / 解压安装脚本使用；媒体解析和 FTP 相关依赖来自网易云 API 的更宽泛功能集，并非此网关直接暴露的上传接口。这不等于相关风险已消除。未使用 `npm audit fix --force` 降级网易云 / NIM 主版本，以免破坏一起听协议。

绑定真实账号前，应在目标 Linux 环境进一步核对这些依赖的影响并完成安全验收。此补丁不附带“全部漏洞已修复”的保证。

## 上线所需输入

1. 可写的自有 GitHub Fork / 仓库，用于保存补丁和构建。
2. 所有者在 Render 安全界面自行设置 `COVE_ADMIN_SECRET`，不经过聊天或助手。
3. 新服务无账号公网验收 → 用户确认 OAuth → 用户亲自扫码 → 实际一起听验收。
