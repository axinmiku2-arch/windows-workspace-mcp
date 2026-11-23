# 更新记录

## v0.1.0 只读预览

- 以标准 MCP SDK 提供工作区信息、单层目录清单和短 UTF-8 文件读取。
- 未配置工作区则不启动。默认 stdio，不监听端口。可选 HTTP 只监听回环并要求独立 Bearer 凭据。
- 包含 Windows 安装与启动脚本、简体中文文档、MIT 许可证和回归测试。
- 发布验证：Linux 上实际用 MCP Python SDK 1.30.0 跑通 stdio 和回环 HTTP 的合成验证。Windows 专用文件访问分支和 Figma / Notion 真实账号联调尚未验收，不宣称生产可用。
