# 信息面使用与扩展

这轮模块化覆盖信息面，不是重写整个项目。防护判定仍在 BPF/TC，relay 负责搬运，纯 Python 模块负责解释、有限窗口汇总和展示。审批、配置授权、既有管理命令保持原有职责。

## 从哪里看

运行 `sudo axdp tui`：

| 按键 | 内容 | 口径 |
|---|---|---|
| `o` | 总览、当前端口与流量 | 当前运行快照；不是历史规则证据 |
| `e` | 事件、具体 DROP 原因、ifindex、原始包长 | 保留事件样本，可滚动 |
| `v` | 来源/协议/端口排行、ALLOW/DROP、已记录字节、国家/ASN | 与 DROP 分布相同的本地窗口 |
| `c` | cookie 阶段、内核事件与 relay 健康 | 累计诊断次数；不同阶段可能重叠 |

`sudo axdp stats` 仍可查看计数。缺失指标显示 `unknown`，不会用零填补旧版本不支持的指标。`XDP_TOTAL`、`XDP_DROP_TOTAL` 使用专用包/字节计数；保留了原有跨重载累计机制，因此其生命周期与单次 map 的诊断计数不完全相同。

## DROP 理由与证据边界

统一目录在 `auto_xdp/telemetry.py`，与 `bpf/include/counters.h` 的数字 ID 对应。新指标追加到原有 0–45 之后，不复用旧编号。

- 策略：入口目的端口未授权、6in4 外层端点未授权、SCTP 目的端口未授权。
- 来源：AbuseIPDB 黑名单、handler 临时封锁、bogon 过滤。
- 限速：来源组 SYN/UDP、来源前缀聚合、全局 UDP、cookie 端口守卫、ACK 校验预算。
- 报文：截断、IPv4 头异常、IPv6 扩展头异常，以及原有 TCP/UDP flags、长度、分片检查。
- 协议：profile 拒绝、profile 不可用、GRE 版本不支持、ESP 保留 SPI。
- cookie：无效 ACK、helper 错误、回复缓冲调整失败、不可处理的报文/上下文。

端口 cookie 守卫拒绝既可能是额度耗尽/冷却，也可能是预算配置或状态不可用；ACK 预算拒绝也包含预算更新失败。不能把这两种计数都解释成已经确定的攻击超速。`SYN_COOKIE_STATE_STORE_ERROR` 是交接状态保存失败的诊断，不等同于该包被 DROP。

旧事件中的 `TCP_DROP`/`UDP_DROP` 无法追溯细分原因。profile DROP 目前也没有逐个 Minecraft 解析状态的细分原因。解析失败、无法可靠得到地址时使用 family=0、空地址，不伪造 `0.0.0.0` 作为攻击来源。事件没有携带历史策略版本或当时限速值，不能拿当前配置补造当时命中的规则。

## 数字可信到什么程度

1. **完整包计数**：主程序及本轮内置 cookie、Minecraft、GRE/ESP/SCTP 终结路径，一次入站报文计一次。cookie 构造回复前捕获原始长度；`XDP_TX` 计入入站总量，但不是 DROP，也不代表应用收到数据。
2. **诊断计数**：例如 `TCP_DROP` 与具体原因、cookie 总预算与细分预算会重叠；不能相加得到总 DROP。TC 的 handoff 计数不是新增入站报文。
3. **事件样本**：并非所有 ALLOW 都发事件，ringbuf、队列、保留窗口均可能丢失或裁剪。来源排行的 events/bytes 不是完整包数、PPS 或 BPS；`len` 表示其中有包长字段的覆盖条数。排行榜中的 cookie verified 仅代表该来源分组里曾保留有效 ACK 事件，不认证整组其他报文。

健康页分层显示：

| 指标 | 含义 |
|---|---|
| `EVENT_EMITTED` | 符合事件产生条件且成功写入 ringbuf |
| `EVENT_LOST` | 符合条件但 ringbuf reserve 失败 |
| `EVENT_SUPPRESSED` | 符合条件但观测开关关闭；包含符合条件的 ALLOW |
| relay `queue_dropped` | 用户态队列满，普通报文事件未入队 |
| relay `port_events_dropped` | 队列满导致端口状态事件丢失 |
| relay `invalid_records` | 不支持的报文记录长度或解析失败 |
| relay `client_disconnects` | relay 检测到的客户端断开/发送失败，不是业务连接断开 |
| `replay truncated` | 回放受条数/字节限制，不能声称断线期间完整恢复 |

每次 relay 启动有新 `session_id`；每个已解码事件有递增 `seq`，入队失败也会消耗序号。历史与实时消息使用相同身份，客户端重连不会重复计数。`seq` 同时涵盖端口事件，因此缺口不是精确的网络丢包数。

`[ringbuf]` 配置控制历史时间和条数；回放额外限制为 512 KiB 的最新事件，`max_history_send=0` 表示不发历史。客户端默认保留 500 条，单次读取与服务端广播都有处理上限，避免持续输入占满 UI 循环。健康消息独立于事件队列每秒发出。慢客户端仍可能断开；这不是无损审计系统。本轮没有增加概率抽样器或磁盘事件库。

## SYN cookie 是否有用，如何在本项目判断

本轮没有更改 cookie 阈值或启用它，默认 `[syncookie].enabled = false` 保持不变。项目已有 capability 检查、按服务/端口模式、端口守卫、ACK 预算以及 TC listener handoff；是否启用不能只看 TOML。

`c` 页分别显示配置意图与 `sync_run_cfg` 的运行配置，map 读不到就是 unknown。运行配置 enabled 也不是所有入口、所有端口和所有客户端都已成功工作的证明。

观察链条是：challenge → sent → valid → TC attempt → success/no-listener/error。这些是阶段计数，不是严格一一对应的漏斗（重传、时间窗口、绕行和重载都会影响它们）：

- `CHALLENGE`/`SENT`：开始处理 SYN、程序以 `XDP_TX` 返回 SYN-ACK；不是已确认 NIC 发出。
- `VALID`：ACK 通过 cookie 校验，不等于应用 `accept()` 成功。
- `HANDOFF_ATTEMPT`：TC 找到交接状态并再次验证 cookie 的候选 ACK；普通 ACK 不计成失败。
- `HANDOFF_SUCCESS`：request-socket helper 返回成功；仍不等于应用接入成功。
- `NO_LISTENER`/`ERROR`/`STATE_STORE_ERROR`：定位交接或状态问题，不应只看 VALID 上升就认为防护健康。

这些指标让有效性可以被检查，但本轮未证明实际防护收益。下一步应在隔离 Linux 环境比较 cookie 开/关时正常客户端建连成功率、P95/P99 延迟、CPU/softirq、内存与交接错误，再结合攻击负载判断是否值得启用。来源能回 ACK 也不代表它不会进行应用层滥用；主机信息面更不能说明上游链路是否有清洗能力。

## 可选 IP 国家与 ASN

仅使用本地 MaxMind 格式 MMDB，不上传来源 IP、不访问在线查询服务、不自动下载数据库。默认关闭，不影响没有数据库的部署。

在运行 TUI 的 Python 环境中安装可选依赖。源码/虚拟环境安装可使用：

```bash
python3 -m pip install '.[geoip]'
```

该命令适用于项目源码目录与选定虚拟环境，不要为了此功能覆盖发行版管理的系统 Python。已有源码安装器不自动安装此额外依赖；确保 `axdp tui` 使用的解释器能够导入 `maxminddb`。自行取得并维护合法可用的数据库，然后配置：

```toml
[geoip]
enabled = true
country_db = "/usr/share/GeoIP/GeoLite2-Country.mmdb"
asn_db = "/usr/share/GeoIP/GeoLite2-ASN.mmdb"
cache_size = 4096
```

两个路径可只配置其中一个，必须为本地绝对路径；缓存上限为 65536。修改数据库或配置后重开 TUI。界面显示库构建日期、可用/降级状态；私网、保留地址与未知结果不会猜测国家。城市/经纬度和在线 IP 声誉查询暂不加入：当前国家/ASN 已能说明来源网络，不能把低可信度地理信息当成人员定位。

## 升级与扩展合同

- v1=48B，v2=64B；新版 relay 同时读取两种事件。v2 保留原前缀，在 48/52/56 偏移追加 ifindex、包长、版本，保留字节清零。旧版 relay 不识别 v2，须协调升级 relay 与 BPF 程序。
- `pkt_counters` 扩容到 66 条，ABI 清单已更新。应通过项目正常候选加载/升级流程使用匹配的程序和 maps，不手工删除线上 pinned maps，也不要只替换一个旧 handler 对象。
- 内置独立对象必须共享 `pkt_counters`、`byte_counters`、`pkt_ringbuf`、`xdp_runtime_cfg`；TC 共享主计数 map。第三方 handler 原有加载合同不被强制扩展，但若不主动共享并记账，总量会缺少其 tail-call 终结流量。
- 新原因要同时追加 C 枚举与 Python 目录，并更新 ABI manifest 及测试。新展示只依赖 `traffic`/`telemetry`/`geoip`，不要反向依赖主 TUI 或把查库放进 relay 读取线程。
- 剩余模块化、规则版本证据、全量每端口速率与压力实验见[分阶段计划](./2026-09-05-information-plane.md)。
