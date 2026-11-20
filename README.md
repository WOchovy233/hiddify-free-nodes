# 节点捕食者 Pro

## 一键上传到 GitHub（推荐）

1. 双击本目录下的 `publish-now.cmd`
2. 浏览器会打开 GitHub Classic Token 创建页面，确认勾选 `repo` 和 `workflow` 权限；不要使用 Fine-grained token
3. 创建 Token，复制后粘贴到黑色窗口
4. 直接回车使用默认仓库名 `hiddify-free-nodes`
5. 等待脚本自动创建仓库、上传文件、触发第一次抓取
6. 脚本最后会打印 Hiddify 订阅地址

Token 只在脚本运行期间使用，不会写入项目文件。仓库已存在时会更新项目文件，
不存在时会自动创建公开仓库。发布目标账号默认为 `WOchovy233`。

面向 Hiddify / Clash Meta / sing-box 的免费节点抓取、地区筛选、稳定性质检和订阅自动更新工具。

## 支持的协议

- VLESS（含 Reality、XTLS Vision、VLESS Encryption、XHTTP、HTTPUpgrade、WS、gRPC、H2）
- VMess
- Trojan
- Shadowsocks
- Hysteria / Hysteria2
- TUIC
- WireGuard
- SSH
- AnyTLS
- HTTP / SOCKS5
- 其他节点会先做字段校验，不能规范化成 Hiddify 可导入结构的节点会自动剔除

## 支持的订阅格式

每次运行会生成 4 份文件，并自动发布到 `output` 分支根目录：

- `clean_nodes_singbox.json`：sing-box 配置，支持全协议
- `clean_nodes.yaml`：Clash / Clash Meta / Mihomo 配置
- `clean_nodes.txt`：Base64 编码的 V2Ray 分享链接订阅
- `clean_nodes_plain.txt`：纯分享链接，便于调试和检查

使用独立 `output` 分支并每次强制更新，可以避免每 12 小时提交一次导致主仓库历史快速膨胀。

## GitHub Actions 自动更新

1. 在 GitHub 新建一个仓库，建议设为 Public。
2. 把本目录的文件上传到仓库根目录，确保包含：
   - `.github/workflows/update-nodes.yml`
   - `app.py`
   - `runner.py`
   - `config.json`
   - `requirements.txt`
3. 打开仓库的 Actions 页面，允许 Workflow 运行。
4. 进入 `Update free nodes`，点击 `Run workflow` 手动运行第一次。
5. 成功后仓库会出现一个名为 `output` 的分支，之后每 12 小时自动更新一次。

工作流使用 GitHub 自带的 `GITHUB_TOKEN` 提交更新，首次运行前请在
`Settings -> Actions -> General -> Workflow permissions` 选择
`Read and write permissions`。

## 手机上添加订阅

把下面的 `用户名` 和 `仓库名` 换成你的 GitHub 信息：

- Hiddify 全协议（推荐）：
  `https://raw.githubusercontent.com/用户名/仓库名/output/clean_nodes_singbox.json`
- Hiddify TXT / V2Ray：
  `https://raw.githubusercontent.com/用户名/仓库名/output/clean_nodes.txt`
- Clash Meta / Mihomo：
  `https://raw.githubusercontent.com/用户名/仓库名/output/clean_nodes.yaml`
- 纯链接：
  `https://raw.githubusercontent.com/用户名/仓库名/output/clean_nodes_plain.txt`

在 Hiddify 里添加订阅 URL 后，设置自动更新间隔为 12 小时；平时只需要点一下更新即可。
GitHub Raw 文件可能有几分钟缓存，刚更新完看不到变化时等几分钟再刷新。

## 本地运行

图形界面：

```bash
python app.py
```

无界面运行：

```bash
python runner.py --config config.json
```

Windows 打包：

```powershell
powershell -ExecutionPolicy Bypass -File build.ps1
```

## 质检说明

- TCP 协议：TCP 建连测速 + 多轮复测 + TLS 握手/证书校验 + 抖动过滤
- UDP/QUIC 协议：Hysteria / Hysteria2 / TUIC / WireGuard 不做 TCP 假测速，
  只做地址、端口、字段和 DNS 静态校验；这些节点会排在 TCP 质检节点之后
- 免费节点本身波动很大，严格模式建议最大抖动 120-180ms
- 本工具不验证机场账号是否过期，只验证节点结构和基础连通性

