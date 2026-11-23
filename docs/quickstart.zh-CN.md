# Windows 快速上手

这个小助手只访问你**手动指定的一个工作区**。第一次没有已授权目录或令牌，不会扫描硬盘，不会安装开机自启，不会申请管理员权限。推荐通过 MCP 客户端以 **stdio** 启动：客户端用本机进程的输入和输出通信，不监听端口。

## 1. 安装依赖

准备 Windows 10 或 11 和 Python 3.11 或更新版本，确认 PowerShell 中的 `python --version` 能找到真正安装的 Python。把仓库解压或克隆到任一普通可写目录，再在该目录执行：

```powershell
.\setup.cmd
```

此步骤会把依赖安装到仓库内的 `.venv`，不安装系统服务。安装依赖可能联网，不会启动小助手。以后启动不用重复安装。

## 2. 指定一个测试工作区

先在固定本地磁盘的新目录 `McpWorkspace` 放一份 UTF-8 的 `hello.txt`，内容可填 `HELLO_FROM_WINDOWS`。工作区用真实的绝对路径，不选整个盘符、用户主目录或 Windows 系统目录。如果「文档」被重定向到链接或网络位置，换一个本地文件夹。不指定目录时，小助手拒绝启动。

## 3. 让本机 MCP 客户端启动

下例适用于支持 `mcpServers` 格式的客户端。把 Python、小助手和工作区三个路径换成你的实际路径。使用其他配置格式的客户端时，把同样的命令、参数、环境变量填进它的对应字段。

```json
{
  "mcpServers": {
    "windows-workspace-helper": {
      "command": "C:\\Tools\\windows-workspace-helper\\.venv\\Scripts\\python.exe",
      "args": ["-E", "-s", "-B", "-X", "utf8", "C:\\Tools\\windows-workspace-helper\\helper.py"],
      "env": {
        "WINDOWS_HELPER_WORKSPACE": "C:\\Users\\Example\\Documents\\McpWorkspace"
      }
    }
  }
}
```

先调用 `workspace_info` 查看只读状态，再用 `list_workspace`（`relative_dir` 为 `.`）和 `read_workspace_file`（`relative_path` 为 `hello.txt`）确认返回自己刚写的标记。结束时在客户端停用连接，或退出客户端。`start.cmd --help` 可查看启动参数；直接运行 `start.cmd` 并不会打开管理界面，stdio 模式通常应由 MCP 客户端启动。

## 可选：仅限本机的 HTTP

只有本机 MCP 客户端需要 HTTP 通信时才用此模式。用密码管理器生成一个 32–128 字符的随机令牌，只使用英文字母、数字、下划线和连字符。客户端地址填 `http://127.0.0.1:8765/mcp`（不用 `localhost`，结尾不加斜线），每个请求都携带 `Authorization: Bearer <本机令牌>`。尖括号不是令牌的一部分。不要把令牌保存进仓库或发往聊天。若客户端不支持自定义请求头，改用上面的 stdio 模式。

在仓库目录的 PowerShell 中执行，替换示例工作区路径，并在提示时粘贴同一个令牌。令牌不在终端回显，也不会由脚本写入文件：

```powershell
$env:WINDOWS_HELPER_WORKSPACE = 'C:\Users\Example\Documents\McpWorkspace'
$secret = Read-Host 'Paste the local bearer token' -AsSecureString
$env:WINDOWS_HELPER_BEARER_TOKEN = [System.Net.NetworkCredential]::new('', $secret).Password
$secret.Dispose()
try { .\start.cmd --transport streamable-http --port 8765 }
finally { Remove-Item Env:WINDOWS_HELPER_BEARER_TOKEN -ErrorAction SilentlyContinue }
```

HTTP 只绑定 `127.0.0.1`，不是公网连接方案；按 `Ctrl+C` 停止。

**云端接入是高级配置。** 本机示例地址不能直接填进 Figma 或 Notion；需要你自己管理的可信 HTTPS 反代及客户端请求头认证。先阅读[反代约束和共享风险](../SECURITY.md#高级由你管理的远程-https)。不要发布带个人令牌的连接器，也不要把本机工作区绑定到共享 Agent。

## 常见问题

- 找不到 `python.exe`：安装 Python 后重新打开 PowerShell，确认 `python --version`。找不到本仓库的 `.venv`：先运行 `setup.cmd`。
- 仓库移动后 `.venv` 不可用：把旧 `.venv` 移走，在新位置重建。无需删除工作区数据。
- 想收回访问：停止小助手进程并从客户端删除启动配置。此流程不在 Windows 中登记服务或自启任务。
