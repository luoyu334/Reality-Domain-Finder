# Reality Domain Finder

一个面向 Xray REALITY 的目标域名自动发现与检测工具。脚本会根据 VPS 公网 IPv4 获取 BGP 前缀，**从公开证书数据中寻找邻近域名**，并通过 OpenSSL 检查 TLS 1.3、证书、X25519、H2、握手成功率和延迟，最终生成可直接用于筛选 REALITY `target` / `dest` 的候选列表。

当前版本：`V1.0.9`

## 功能特性

- 自动获取 VPS 公网 IPv4 和所属 BGP 前缀
- 从 `bgp.he.net` 的公开证书数据中发现邻近域名
- 再次检查域名当前 DNS，避免直接使用过期的历史解析记录
- 强制验证 TLS 1.3、证书信任链、证书域名和 X25519
- 检测 H2，并优先排列支持 H2 的候选
- 对基础条件通过的域名进行多次握手测试
- 记录握手成功率、中位延迟、平均延迟、最大延迟和延迟波动
- 支持三种数字域名过滤模式
- 默认只保留 `.com`、`.cn`、`.net`、`.org` 等主流顶级域名
- 按批次并发检测，达到最低合格数量后保存当前完整批次的全部结果
- 使用 JSON 历史文件标记已检测域名，避免重复验证
- 提供一键默认模式、自定义交互模式和非交互命令行模式
- 输出适合终端查看的中文定宽表格

## 工作流程

```text
获取 VPS 公网 IPv4
        ↓
查询 BGP 前缀
        ↓
获取该前缀的证书域名
        ↓
数字、后缀、服务类型及历史记录过滤
        ↓
确认当前 DNS 仍位于 VPS 前缀
        ↓
TLS 1.3 + 证书 + X25519 + Cipher 检测
        ↓
多次握手成功率与延迟统计
        ↓
排序并写入结果和历史文件
```

## 入选条件

域名必须满足以下基础条件才会入选：

- VPS 可以解析并连接目标域名的 `443` 端口
- 当前 DNS 位于 VPS 的 BGP 前缀内，除非使用 `--allow-off-prefix`
- 成功完成 TLS 1.3 握手
- 证书链受 VPS 系统 CA 信任库信任
- 证书未过期并覆盖当前域名
- 临时密钥使用 X25519
- 成功协商有效的 TLS Cipher

以下项目仅作为参考和推荐排序依据，不会淘汰已经通过基础条件的域名：

- H2 支持情况
- 握手成功率
- 中位、平均和最大延迟
- 延迟波动

即使后续握手测试成功率较低，只要第一次基础检测通过，域名仍会写入结果文件。

## 环境要求

- Linux VPS
- Python `3.10+`
- OpenSSL
- 可访问以下公开服务：
  - `api.ipify.org`、`ifconfig.co` 或 `icanhazip.com`
  - `stat.ripe.net`
  - `bgp.he.net`
- 默认写入 `/var/log/reality-domain-finder`，因此推荐使用 root 或具备该目录写权限的用户运行

Debian/Ubuntu 可安装依赖：

```bash
sudo apt update
sudo apt install -y python3 openssl
```

## 使用说明

### 1. 一键运行脚本

```bash
sudo bash -c 'python3 <(curl -fsSL https://raw.githubusercontent.com/luoyu334/Reality-Domain-Finder/main/reality-domain-finder/reality-domain-finder.py)'
```

启动后会先显示选项

- 输入 `1` 或直接回车：使用默认参数立即开始

- 输入 `2`：逐项设置 BGP 前缀、数量、过滤方式、日志路径等参数

### 2. 非交互运行

以下命令直接从 GitHub `main` 分支读取脚本并运行，不会在当前目录永久保存脚本文件。

使用全部默认参数：

```bash
sudo bash -c 'python3 <(curl -fsSL https://raw.githubusercontent.com/luoyu334/Reality-Domain-Finder/main/reality-domain-finder/reality-domain-finder.py) --non-interactive'
```

指定最低合格数量和批次大小：

```bash
sudo bash -c 'python3 <(curl -fsSL https://raw.githubusercontent.com/luoyu334/Reality-Domain-Finder/main/reality-domain-finder/reality-domain-finder.py) --non-interactive --count 10 --batch-size 20'
```

手动指定 VPS BGP 前缀：

```bash
sudo bash -c 'python3 <(curl -fsSL https://raw.githubusercontent.com/luoyu334/Reality-Domain-Finder/main/reality-domain-finder/reality-domain-finder.py) --non-interactive --prefix 198.200.32.0/19'
```

将日志写入当前目录，适合非 root 用户：

```bash
python3 <(curl -fsSL https://raw.githubusercontent.com/luoyu334/Reality-Domain-Finder/main/reality-domain-finder/reality-domain-finder.py) --non-interactive --history-file ./logs/reality-domain-history.json --output ./logs/reality-domains.txt
```

## 参数讲解

| 参数 | 默认值 | 说明 |
|---|---|---|
| `-h`, `--help` | - | 显示帮助信息并退出 |
| `--prefix PREFIX` | 自动检测 | 手动指定 VPS 的 IPv4 BGP 前缀，例如 `203.0.113.0/24` |
| `--count COUNT` | `5` | 至少需要找到的基础条件合格域名数量，不限制最终保存上限 |
| `--batch-size BATCH_SIZE` | `10` | 每批并发检测的候选数量；脚本会完整处理当前批次 |
| `--max-candidates MAX_CANDIDATES` | `200` | 单次运行最多检测的候选域名数量 |
| `--timeout TIMEOUT` | `10` | 每次网络请求、DNS 或 OpenSSL 检测的超时秒数 |
| `--handshake-attempts 次数` | `5` | 基础检测通过后的总握手检测次数，包含第一次基础握手；仅用于统计 |
| `--allow-off-prefix` | 关闭 | 允许当前 DNS 不在 VPS BGP 前缀内的域名继续检测 |
| `--numeric-filter MODE` | `any` | 数字域名过滤模式，可选 `none`、`pure`、`any` |
| `--allow-all-tlds` | 关闭 | 关闭主流顶级域名过滤，允许所有合法后缀 |
| `--mainstream-tlds LIST` | `com,cn,net,org` | 自定义允许的顶级域名，使用英文逗号分隔 |
| `--history-file PATH` | `/var/log/reality-domain-finder/reality-domain-history.json` | 历史标记 JSON 文件路径 |
| `--recheck` | 关闭 | 忽略历史跳过规则，重新验证已记录域名并更新结果 |
| `--output PATH` | `/var/log/reality-domain-finder/reality-domains.txt` | 对齐后的候选结果文件路径 |
| `--non-interactive` | 关闭 | 跳过交互菜单，直接使用命令行参数和默认值运行 |

### 数字过滤模式

| 模式 | 行为 | 示例 |
|---|---|---|
| `none` | 不过滤数字 | `123.com`、`abc12.com` 均保留 |
| `pure` | 过滤注册主域名标签为纯数字的域名 | 过滤 `123.com`，保留 `abc12.com` |
| `any` | 过滤完整域名中任何包含数字的候选 | `123.com`、`abc12.com`、`v2.example.com` 均过滤 |

示例：允许字母与数字混合，但排除纯数字主域名：

```bash
sudo python3 reality-domain-finder.py \
  --non-interactive \
  --numeric-filter pure
```

### 顶级域名过滤

默认仅允许：

```text
.com  .cn  .net  .org
```

`.com.cn`、`.net.cn` 等域名的最终顶级域名是 `.cn`，因此会被保留。

自定义列表：

```bash
sudo python3 reality-domain-finder.py \
  --non-interactive \
  --mainstream-tlds com,cn,net,org,io
```

允许全部后缀：

```bash
sudo python3 reality-domain-finder.py \
  --non-interactive \
  --allow-all-tlds
```

## 输出文件

默认结果文件：

```text
/var/log/reality-domain-finder/reality-domains.txt
```

示例：

```text
# VPS 公网 IPv4：198.200.42.221
# BGP 前缀：198.200.32.0/19
# 握手成功率与延迟仅供参考，不参与基础入选判断
域名:端口                H2  加密套件                握手成功率  中位延迟ms  平均延迟ms  最大延迟ms  延迟波动ms  当前解析IPv4
-----------------------  --  ----------------------  ----------  ----------  ----------  ----------  ----------  --------------
www.example.com:443      是  TLS_AES_256_GCM_SHA384        100%        72.4        75.1       110.3        12.8  198.200.35.189
```

各字段含义：

- `H2`：是否协商到 HTTP/2，属于推荐排序指标
- `加密套件`：TLS 1.3 实际协商的 Cipher
- `握手成功率`：多次握手成功次数的百分比，不参与基础入选
- `中位延迟ms`：成功握手耗时的中位数
- `平均延迟ms`：成功握手耗时的平均值
- `最大延迟ms`：成功握手中的最大耗时
- `延迟波动ms`：成功握手耗时的总体标准差
- `当前解析IPv4`：运行时解析到的 IPv4 地址

延迟测量范围是 VPS 上 OpenSSL 握手进程的耗时，不是客户端到 VPS 的延迟，也不代表隧道建立后的实际吞吐量。

## 历史记录

默认历史文件：

```text
/var/log/reality-domain-finder/reality-domain-history.json
```

脚本会将每个完成检测的域名立即写入历史文件，无论成功还是失败。后续运行默认按完整小写域名跳过已有记录，例如 `example.com` 与 `www.example.com` 会被视为两个不同域名。

历史记录包含：

- 检测时间和 BGP 前缀
- DNS 解析地址
- TLS 1.3、X25519、H2 和证书状态
- Cipher
- 握手次数、成功次数和成功率
- 各项延迟指标
- 最终原因

历史文件采用临时文件写入后原子替换的方式保存，降低程序中断导致 JSON 损坏的风险。

重新检测所有历史域名：

```bash
sudo python3 reality-domain-finder.py --recheck
```

使用另一份历史文件：

```bash
sudo python3 reality-domain-finder.py \
  --history-file /var/log/reality-domain-finder/another-history.json
```

## 应用于 REALITY

选择结果中的候选域名后，服务端与客户端的域名应保持一致。例如：

```text
服务端 target/dest：www.example.com:443
服务端 serverNames：www.example.com
客户端 serverName：www.example.com
客户端 fingerprint：chrome
```

脚本只负责筛选目标域名，不会修改 Xray 或 3X-UI 配置。`publicKey`、`shortId`、UUID、Flow 和端口仍需按照服务端配置填写。

## 注意事项

- BGP 证书数据包含历史记录，脚本会通过当前 DNS 重新确认，但域名解析仍可能在以后发生变化
- 与 VPS 网络位置接近是合理性和稳定性的加分条件，不是 REALITY 协议本身的绝对要求
- 域名应在客户端所在地区可以正常使用，避免选择可能被 SNI 阻断的域名
- CA 品牌不是硬性条件；只要证书链被 VPS 系统 CA 信任库信任即可
- 自签名证书、过期证书、域名不匹配证书和 Cloudflare Origin CA 默认无法通过验证
- 脚本的握手成功率和延迟只供比较，不决定隧道建立后的速度
- 技术检测通过不代表域名信誉、内容或长期稳定性合格，正式使用前应人工访问并确认
- 高频重复扫描可能增加目标站点负担，请合理设置批次、候选数量和握手次数
- 请遵守所在地法律法规以及目标服务的使用政策

## 故障排查

### 无法写入日志目录

默认目录位于 `/var/log`，请使用 `sudo` 运行，或通过参数改到当前用户可写目录：

```bash
python3 reality-domain-finder.py \
  --history-file ./logs/history.json \
  --output ./logs/domains.txt
```

### 自动检测 BGP 前缀失败

手动查询 VPS 前缀后运行：

```bash
sudo python3 reality-domain-finder.py \
  --prefix 198.200.32.0/19
```

### 所有候选都被历史记录跳过

使用 `--recheck` 重新检测，或指定新的历史文件：

```bash
sudo python3 reality-domain-finder.py --recheck
```

### 找不到足够域名

可按实际需要放宽部分条件：

```bash
sudo python3 reality-domain-finder.py \
  --count 5 \
  --max-candidates 500 \
  --numeric-filter pure \
  --allow-all-tlds
```

## 许可证

本项目采用 [GNU Affero General Public License v3.0](LICENSE) 许可证。
