# Windows Workspace MCP · 本机工作区小助手

把**支持远程 MCP 的云端 AI 客户端**连接到一台 Windows 电脑。你在 Windows 管理器里选择工作区和权限，客户端才能读写该目录、收发文件或申请运行预设任务；这不是接管整个桌面的远程控制工具。

**当前是 0.2.0-preview.1 源码预览版。** 与早期 v0.1 的只读工具不同，这一版包含图形管理器和本机工作器。没有 EXE/MSI 安装包，也没有预置账号、入口地址、令牌、OAuth 回调或目录授权；新版不会自动导入或替换旧部署的状态。实际工具列表取决于服务配置和客户端，具体平台兼容性需要实测。

## 能做什么

| 功能 | 范围 |
| --- | --- |
| 工作区文件 | 浏览目录，按文件名、后缀或正文查找；读取 UTF-8 文本或指定行；新建文件和目录，按原文 SHA-256 核对后替换或局部修改文本，修改前留备份。支持移动、改名，以及移入私有回收区、查看和恢复，不使用 Windows 系统回收站。 |
| 文档预览 | 预览 PDF 页文本、DOCX 文本、ZIP 成员列表或小段文本，以及图片尺寸等元数据。不是 Office 编辑器，也不会生成图片预览或执行 OCR。PDF、图片预览需要可选依赖；预览文件上限为 20 MB。 |
| 双向文件传输 | Windows 和 MCP 客户端可收发文件原件，也可将工作区子目录在本机打包成 ZIP 再发送；支持查看进度、取消、续签和用 SHA-256 核对收件。旧的同步原件准备接口上限为 20 MB，较大的文件走异步导出。单文件传输默认上限 100 MB，本机可调 20–1000 MB。下载链接有效期 7 分钟；代理和客户端支持 HTTP Range 时可续传下载，上传不承诺断点续传。 |
| 固定任务 | 可查 Git 状态/差异、检查 Python 语法、运行项目的 Python/npm 测试或 npm 构建。也能计算或核对 SHA-256、检查 ZIP/PE 文件头、盘点目录、复制文件、按固定流程解压 ZIP 或从纯文本生成 DOCX；可在本机把预设组合成任务配方。 |
| 本机管理 | 查看连接和工作器状态、待审批请求、操作记录、收发件箱、任务状态与结果；收发简短留言（客户端查询，不会自动投递到现有聊天）。还有受限的 Windows 网络接口、侦听端口和 Ping 诊断；关机倒计时仅限本机管理器。 |

## 权限与安全边界

- **同时只有一个工作区有效。** 可保存多套配置供切换。通过本机选择 `请求批准`、`按规则批准` 或 `工作区范围内完全访问`；普通文件审批默认 30 分钟，可设为 5–120 分钟。完全访问下，移动、回收、恢复仍默认逐次审批，可在本机分别放行。
- **完全访问也不是任意命令。** Git 状态/差异、测试和构建仍需本机确认；测试和构建会执行项目代码，只应批准可信项目。没有远程桌面、通用 CMD/PowerShell、远程关机或自动提权。请用标准 Windows 用户和专门工作区。
- **收件不自动解压、打开或运行。** 工作区切换或撤销授权可能使旧请求和链接失效，但已落盘的副本不会因此删除。先完成正在进行的传输，再切换工作区；不要把临时 HTTPS 链接交给无关人员。

## 从源码启动并连接云端

1. 在 Windows 安装带 Tcl/Tk 的 Python 3.11 或以上版本，按 [部署指南](docs/deployment.zh-CN.md) 安装依赖并运行 `start.cmd`。首次用不含敏感文件的测试目录和「请求批准」模式。
2. 在本机管理器保存自己的 HTTPS 入口和客户端提供的准确 HTTPS OAuth 回调，准备本机认证，然后启动服务。回调不使用通配符。云端客户端填写 `https://你的域名/mcp`，并按其 OAuth 流程完成连接。
3. 自行配置公共 HTTPS 入口，可以用 **Tailscale Funnel**，或用 **VPS + 自有域名 + Windows 主动发起的反向连接**。只代理面向 HTTPS 入口的本机回环服务；不公开私有工作器端口。Funnel 在公网可达，不等于私有 Tailnet，也不是鉴权；VPS 路线需自行维护证书、隧道和服务。两种路线都不保证传输速度。

先实测连接、审批和一个来回的无敏感样本传输，再使用真实工作区。具体配置及排查见 [部署指南](docs/deployment.zh-CN.md) 和 [安全说明](SECURITY.md)。

## English overview

Windows Workspace MCP connects a remote MCP client to one workspace explicitly authorized in the local Windows manager. The **0.2.0-preview.1 source preview** includes scoped file reads and edits, limited document previews, two-way original file transfer, local approvals, messages and predefined jobs. It is not a packaged installer, remote desktop or general-purpose shell. Start from source with Python 3.11+, bring your own HTTPS entry point, configure the client's exact OAuth callback, and verify the connection on a test folder. See the [deployment guide (Chinese)](docs/deployment.zh-CN.md).

## 贡献与许可证

项目代码采用 [MIT](LICENSE)，可免费使用、修改和分发。欢迎提交问题、实际兼容性测试结果和拉取请求；请勿上传令牌、真实目录清单或敏感日志。
