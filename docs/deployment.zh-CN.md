# 部署指南：Windows、HTTPS 与云端 MCP

首次连接用**临时测试目录**，例如在 Windows 用户目录下新建 `mcp-test`、放一份无敏感内容的文本。不要先开放整块盘。首次用“请求批准”；只有能准确解释审批行为后，再给特定工作区选更宽的权限。停止小助手或让 Windows 休眠会中断连接。

## 1. 准备本机

1. 用普通 Windows 用户解压源码，安装带 Tcl/Tk 的 **Python 3.11 或更高版本**，从源码目录运行 `py -3 -m pip install -r requirements.txt`。若需 PDF 或图片预览，再运行 `py -3 -m pip install -r requirements-preview.txt`。然后双击 `start.cmd`；不需打包成 EXE。若使用的是 `python` 而非 `py`，两处都使用同一个解释器。不要把旧版本的状态目录、授权配置或密钥复制到新版。
2. 打开「连接与开机自启」，填入自己的 HTTPS 入口（只填协议和域名，不加 `/mcp`），在「OAuth 回调白名单」中填写所选 MCP 客户端提供的准确 HTTPS 回调 URL（每行一个；默认留空），再点「保存连接配置」。选择「准备本机认证…」，核对地址并确认。此步骤生成本机认证配置，不会自行开放入口或启动服务。
3. 选择下面一种方式配置 HTTPS 代理，目标使用本机公开用的回环端口 `127.0.0.1:18773`。工作器私有回环端口 `127.0.0.1:18774` **不要转发**。如果端口已被旧版占用，先在隔离环境验证；不要覆盖或强制关闭现有实例。
4. 在「工作区与权限」选测试文件夹，再点「保存并统一授权」。可保存多份待用配置，但同时只有一份为当前工作区。然后到「总览」点「一键连接」。是否登录时自启可另行选择，默认关闭。
5. 点「复制地址」获得 `https://你的域名/mcp`。在云端客户端配置这个地址。仅在本机通过「查看本机连接口令…」查看口令，在 OAuth 页面按需输入，不要把口令贴进聊天。为客户端登记准确的 HTTPS OAuth 回调，不用通配符。公网可达的健康检查不是 OAuth 或文件验收。

## 2A. Tailscale Funnel：个人试用的简便路线

安装并登录 Tailscale，按 [官方 Funnel 指南](https://tailscale.com/kb/1223/funnel) 打开 Funnel 所需设置。将 Funnel 的唯一入口指向管理器显示的公开回环监听端口。控制台里检查生成的 HTTPS 地址，把该地址的 origin（不加 `/mcp`）登记到小助手；云端客户端则用完整 `https://…/mcp`。不要同时公开另一个用于本机工作器的端口。

可先用前台命令测试，按实际版本的 [Funnel CLI 文档](https://tailscale.com/docs/reference/tailscale-cli/funnel) 确认具体参数：

```powershell
tailscale funnel http://127.0.0.1:18773
```

如果代理更改了 HTTP `Host`，小助手会拒绝。不要降低小助手校验；换用保留原始公网 `Host` 的代理配置，或用 Funnel TLS 终止 TCP 模式接本机 HTTP 代理，再由后者准确设为 Funnel 的公网域名。没有配置对 Host 的代理不应视为验收通过。

Funnel 是公网反代，不等于 Tailnet 私网直连。它不承诺固定大文件吞吐；若只给本机或同一私网中的客户端访问，不要启用公网 Funnel。个人用量和功能以 Tailscale 当前条款为准。

## 2B. VPS + 域名：自管路线

1. 为你自己的域名添加 DNS 记录，指向 VPS。让 VPS 入口上的 HTTPS 代理（如 Caddy）为该域名获取和更新证书。
2. Windows 向 VPS 发起认证过的 SSH 反向转发，由 VPS 的**仅回环**目标接收，再转向 Windows 的公开回环监听。SSH 隧道使用独立低权限账户/密钥，仅给所需转发权限，开启重连。VPS 不把该转发端口直接开放到公网。
3. Caddy 按域名把请求交给 VPS 回环目标，保留请求方法、路径、查询和读取 Range 的能力。除了 MCP 路径，还要让小助手需要的 OAuth 发现、授权回调和原件传输路径能通过同一个 HTTPS origin。
4. 若 VPS 已有服务占用 443，优先让现有反代按不同域名分流。不能新增监听进程抢占 443。另选 HTTPS 端口前，先确认云端客户端会接受显式端口，证书验证和防火墙均正常。

下列只是配置模板，主机名、专用账户、密钥名都替换为自己的。先通过 VPS 控制台独立核验 SSH 主机指纹，别关闭主机校验。SSH 服务端对专用账号限制为仅可远程转发，并通过 `GatewayPorts no`、`PermitListen 127.0.0.1:28773` 让转发端口只可从 VPS 本机连接。

Windows PowerShell：

```powershell
ssh.exe -NT -o StrictHostKeyChecking=yes -o IdentitiesOnly=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=20 -o ServerAliveCountMax=3 -i "$env:USERPROFILE\.ssh\workspace-mcp_ed25519" -R 127.0.0.1:28773:127.0.0.1:18773 workspace-tunnel@vps.example.net
```

VPS Caddyfile：

```caddyfile
mcp.example.net {
    reverse_proxy 127.0.0.1:28773 {
        header_up Host mcp.example.net
    }
}
```

在 VPS 上确认隧道只监听 `127.0.0.1:28773`，并为这站点停用记录敏感路径、请求体或请求头的日志。设置 `Host` 为自己填写的**公网原始域名**，不是 `localhost`。HTTPS 如用非默认端口，`Host` 也要一致含端口。整个公网代理只转到公开回环端口，绝不转到工作器端口。

参考 [OpenSSH 远程转发](https://man.openbsd.org/ssh#R)、[Caddy reverse_proxy](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy)。域名、自管隧道和公网代理各自有维护责任；不把没有验收的自动化脚本充作一键安装。

## 3. 按顺序做一次无敏感文件验收

1. 先检查本机监听和工作器状态；然后从外网检查 HTTPS 证书、OAuth 与 MCP 客户端连接。未授权的调用不能读取文件。
2. 让客户端列出测试工作区。若本机设置为请求批准，确认客户端只得到请求编号；本机批准后，回查同一编号。切换授权目录后，旧范围不得继续可用。
3. 用独一无二的短文本试读和修改，复查内容与备份。再用小 ZIP 各传一个方向，分别核对实际字节数和 SHA-256；确认接收的文件不会被自动解压或执行。原件链接只交给预期的传输方。
4. 最后测试一个无副作用的预设任务。运行项目测试、npm 构建等会执行该项目代码，仅对可信仓库批准。
5. 测速时不要混进审批耗时。用同一测试文件、同一时间段和同一方向做至少三次，分别记首字节、传输总耗时和平均速率。若对比 Funnel 与 VPS，保留 Windows 到 VPS 的数据作为独立一段；只测云端通用测速站无法证明瓶颈在哪。

## 常见故障

- 本机无状态：先检查配置是否保存、进程是否运行及环回端口是否冲突。公网启动前确认本机没有继续运行旧版本的同端口服务。
- URL 能打开，客户端却连不上：查 HTTPS 证书、MCP discovery 和回调地址是否严格匹配，不要为了连通而关闭认证。
- 文件到了但哈希不对：停止使用该文件，检查是否收到的其实是代理错误页、是否到达设置上限、签名是否过期。不要绕过本机上限或审批。
- 中断：从客户端确认原操作结果后再决定续传，避免重复创建。下载和上传的续传能力不一定一样。
