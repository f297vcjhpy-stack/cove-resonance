# 个人专用安全部署补丁

本补丁基于 upstream `e63cfa5f29730b2fa9d90406fc882a6eba8d22e1`。
它增加单所有者 OAuth 网关和仅管理页可用的网易云扫码登录，不改变原有 Bridge Queue、ACK、reply 或 NIM 协议。

## 现状与边界

- OAuth 使用 MCP SDK 的标准路由：发现、动态客户端注册、S256 PKCE、authorization code、refresh、revoke。
- `/mcp/music` 和兼容 `/mcp` 均要求该服务签发的 Bearer token。固定 audience 为公开 origin 的 `/mcp/music`。
- 授权必须先登录管理页并明确同意。默认回调 origin 仅允许 `https://chatgpt.com` 和 `https://chat.openai.com`，精确匹配已注册 redirect URI。
- 管理页登录使用你在 Render 自行设置的 `COVE_ADMIN_SECRET`。必须至少 32 字符，建议密码管理器生成随机值。
- 管理页使用 Secure / HttpOnly / SameSite=Lax Cookie；修改操作必须通过同源 Origin 和 CSRF 检查。
- 网易云只提供扫码流程。不通过聊天、MCP 工具或表单收集网易云密码 / Cookie。
- QR key 仅保留服务器内存；成功 Cookie 不返回给浏览器或模型，只传给绑定在 `127.0.0.1` 的私有子进程。
- 网关不转发 `/events` 或其他任意后端路径。Listener 维持原有短期、单次 session token。
- OAuth 客户端注册信息采用 AES-256-GCM 加密认证封装在 client_id 中，用现有管理密钥派生、绑定本 MCP 资源的专用密钥校验；有效期 30 天，不需要数据库。服务重启后仍可识别注册过的客户端。它不是访问令牌，不能代替所有者确认、PKCE 或客户端认证。
- 账号登录、管理会话、OAuth access/refresh tokens、队列仍在内存。**服务休眠 / 重启后需重新扫码，并重新完成 ChatGPT OAuth 授权；不再因注册信息丢失而必须重建插件。** 管理密钥轮换、域名改变或注册到期需要重新注册客户端。
- 升级前已经丢失的旧随机 client_id 无法安全恢复，需一次新建连接以获得新格式的注册信息。不能为了兼容旧 ID 而接受未知客户端。
- 管理页“断开网易云”停止本机连接、清除内存凭据并撤销 MCP grants；不等于在网易云官方撤销已签发的登录会话。官方撤销请在网易云账号安全设置中完成。
- 原生 SDK 与网易云 API 为上游依赖；仍有未修复的供应链依赖告警，见验收记录。不建议视为已完成独立安全审计。

## Render 配置

先把改动保存到你自己的 GitHub 仓库，不要提交 `.env`、Cookie 或管理密钥。
现有测试实例从作者仓库构建，不会自动包含这些改动。

推荐新建一个 Free Web Service 用于受保护版本，原有未登录测试实例可保留到验收结束。不要自动升级付费计划。

| 配置 | 值 |
| --- | --- |
| Runtime | Docker |
| Dockerfile | `Dockerfile.secure` |
| Compute plan | `free` |
| Auto-deploy | Off，后续更新先审查 |
| `NODE_ENV` | `production` |
| `COVE_ADMIN_SECRET` | 在 Render 的 Environment 页面自行生成并填写，勿发给助手 |
| `BRIDGE_PUBLIC_ORIGIN` | 可不填，自动读取 Render 的 `RENDER_EXTERNAL_URL` |
| `NETEASE_COOKIE` | 不要设置；若存在需移除 |

可先不设置 `COVE_ADMIN_SECRET` 部署以验证匿名拒绝和 OAuth metadata。
此时管理页返回 503 提示待配置，所有管理操作被锁定，访客无法抢先注册所有者或绑定账号。
由所有者在 Render 页面填写密钥后，选择保存并重新部署即可启用管理页。

原生 Node runtime 也可：Node 22.23.4；Build Command `npm ci --include=dev && npm test && npm run build`；Start Command `npm run start:secure`。
Docker 镜像在构建期会从网易云官方服务下载 `node-nim` 的原生 runtime，必须允许该出站请求。镜像采用 Debian/glibc，避免 Alpine/musl。

Free 实例会休眠，适合验证；若将来希望长期保留内存态，不应依赖 ping 绕过休眠。持久化与常驻费用需要单独决定。

## 上线后验收顺序

1. 公网 `/` 返回 `{ok:true,service:"cove-secure-gateway"}`。
2. 无令牌 POST `/mcp/music` 和 `/mcp` 必须 401；`WWW-Authenticate` 指向 protected-resource metadata。
3. 读取 `/.well-known/oauth-protected-resource/mcp/music` 和 `/.well-known/oauth-authorization-server`。
4. 无管理会话访问 `/admin/qr/start` 必须失败；`/events` 必须 404。
5. 在 ChatGPT 网页重新添加自定义 MCP server，选择 OAuth / 动态注册；不用提供网易云凭据。完成管理页登录和明确授权。
6. 先调用状态工具；应显示未登录、未启用网易云实时连接。
7. 由你亲自打开服务器 `/admin`，输入管理密钥，生成二维码，用网易云官方 App 扫码并确认。
8. 回 ChatGPT 查询实时状态；只有实际进入一起听房间并建立 NIM 后才能称为一起听连接成功。
9. 明确开启 Long-wait，发送一条测试消息并核验双向回复；不要同时开启 Widget Listener。

不要仅凭“二维码已生成”“HTTP 200”或“登录成功”就声称已完成一起听端到端测试。

## 本地验证

```
npm ci --ignore-scripts
npm test
npm run build
git diff --check
```

`--ignore-scripts` 仅适用于无账号单测，不会安装原生 NIM runtime，不代表真实一起听可用。
生产构建使用普通 `npm ci --include=dev`。
