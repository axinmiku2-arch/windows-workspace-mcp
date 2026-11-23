# Windows Workspace MCP 小助手

一个免费开源的 Windows 本地文件桥接工具。它让支持 MCP 的客户端读取**你指定的一小块工作区**，例如把本机的设计说明或项目笔记提供给 AI。项目不是 OpenAI、Anthropic、Figma 或 Notion 的官方产品。

这是 **v0.1 只读预览版**：从自用小助手抽取了可移植的工作区读取能力，没有把原来账号专用的部署、写入、审批队列或命令执行一起公开。默认不联网，不预填任何授权地址、目录、回调或密钥。项目源码按 [MIT 许可证](LICENSE) 免费提供；AI 平台、域名、隧道或云主机可能有各自的套餐和费用。

## 先试最简单的方式

1. 在 Windows 安装 Python 3.11 或更高版本。建议使用单独的虚拟环境。
2. 建一个**专门的测试文件夹**，放一份自己写的 `hello.txt`，例如 `HELLO_FROM_WINDOWS`。不要选整个磁盘、用户目录或有凭据的项目。
3. 按 [Windows 快速开始](docs/quickstart.zh-CN.md) 安装依赖、填写工作区。优先用本机 **stdio**，由 MCP 客户端启动进程，不需要域名或端口。
4. 在客户端调用 `workspace_info`、`list_workspace` 和 `read_workspace_file`。以能读到自己刚写的标记为成功，不只看“已连接”。

| 工具 | 能做什么 |
|---|---|
| `workspace_info` | 查看协议版本和本服务的限制，不返回机器绝对路径。 |
| `list_workspace` | 查看指定相对目录的一层内容，在上限处截断。 |
| `read_workspace_file` | 读取允许的短 UTF-8 文本，路径相对工作区。 |

## AI 在云端时

云端平台看不到你电脑上的 `localhost`。本服务可选 Streamable HTTP，**仍只监听 Windows 本机回环**；需要使用者自行提供可信 HTTPS 反向代理，并由客户端在每次请求携带独立 Bearer 凭据。不提供公共服务，也不默认开启隧道或防火墙口子。远程方案请先阅读 [安全说明](SECURITY.md)。

| 配置 | 初始状态 | 谁来填 |
|---|---|---|
| 工作区 `WINDOWS_HELPER_WORKSPACE` | 空 | 电脑主人，在本机填专用文件夹的绝对路径。 |
| 对外授权/访问地址 | 无 | 只在需要远程时，由管理员在反代和客户端填自己实际的 HTTPS MCP URL。 |
| `WINDOWS_HELPER_BEARER_TOKEN` | 空 | 只在 HTTP 模式时生成并配置；不要写进仓库、聊天或 URL。 |
| OAuth 回调/发行者 | 无 | v0.1 未实现 OAuth。不能把回调 URL 填进去就自动支持 OAuth。 |

[Figma Agent / Make](https://help.figma.com/hc/en-us/articles/38147204302743-Create-and-use-custom-MCP-connectors-in-the-Figma-agent-and-Figma-Make) 和 [Notion Custom Agents](https://www.notion.com/help/mcp-connections-for-custom-agents) 的官方文档列出自定义远程 MCP 和请求头认证。它们是候选客户端，**本项目没有通过这两个平台的实际联调**，套餐/管理员权限另计。只支持 OAuth 且不能配置 Bearer 请求头的客户端，v0.1 不兼容。选择这些云端客户端后，读取的文档内容会传给相应平台；不要把密钥或私人文件放在测试工作区。

## 当前限制

- 只读：不写入、删除、执行命令、启动 EXE、控制桌面或调用 Codex。也不制作或加载公网可调用的命令入口。
- 支持的内容仅为有限格式、大小受限的 UTF-8 文本，不解析 PDF、Office、图片或二进制文件。跳过隐藏项和链接；只使用独立、可信的目录，不把其他进程能更换内容的共享目录作为服务根目录。
- 单实例只有一个工作区；HTTP Bearer 没有多人分权，不应跨用户或跨团队共享。生产环境不依赖这个初版来隔离互不信任的用户。
- 不提供公网托管、自动配置 TLS、OAuth、Windows 服务、自启动或速度保证。使用代理或隧道时，网络质量和限额取决于其提供方。
- 先在无敏感样本上试用。发布时只列出实际完成的测试，不把有协议支持写成平台兼容性认证。

## 欢迎参与

**所有人都可以免费使用、修改和分发。欢迎 Fork、提 Issue 和发 PR，一起把兼容性、中文文档和 Windows 验收做得更好。** 可优先贡献：不同客户端的只读联调记录、首次配置体验、Windows 文件系统边界的回归测试。详情见 [贡献指南](CONTRIBUTING.md)。请私下报告可影响安全边界的问题，不要在公开 Issue 贴密钥或真实用户数据。
