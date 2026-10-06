# 信息面模块化实施计划

日期：2026-09-05。范围：现有 XDP/TC → relay → TUI 的观测闭环。

## 目标与边界

让使用者能够回答：为什么 DROP、影响哪个入口与端口、观测是否完整、SYN cookie 是否实际工作、源地址属于什么网络。信息面的故障不得改变防火墙判定。

本轮交付统一原因目录、兼容的扩展事件、观测丢失统计、可靠的 relay 重连、独立展示/统计模块、cookie 指标及可选本地国家/ASN。延续 Python >=3.10；默认运行仅依赖 stdlib 与已有 tomli。IP 查询仅使用本地数据库，maxminddb 是可选依赖。

保留工作区原有的审批、配置权限及安装权限改动。不会启用线上防护、修改服务授权、自动下载属地库或运行攻击流量。仅为本轮真实职责拆模块，不建立通用插件框架、不整体重写审批和后端。

## Phase 0：源码与可用 API 调查

- [x] 核对工作区修改、测试入口、安装与更新路径。
- [x] 两个只读子代理调查 BPF 事件 ABI、TUI/relay 和复用点；主代理综合计划。
- [x] 建立修改前基线：65 个相关测试通过、1 个 Linux SO_PEERCRED 测试在 macOS 跳过。
- [x] 确认现有 Docker 中有 Linux 构建工具镜像，可在隔离容器编译，不依赖 macOS 内核加载 BPF。

可用接口与证据：

| 位置 | 复用接口/约束 |
|---|---|
| `bpf/include/counters.h` | append-only `CNT_*`，现有 0..45 不改编号 |
| `bpf/include/common.h` | 48 字节 `pkt_event`；事件提交与开关的统一位置 |
| `bpf/xdp_firewall.c` | `check_tcp_policy()` 的 shared drop 标签丢失细分原因 |
| `bpf/xdp_syncookie.c` | 独立 tail-call 程序；部分路径没有完整记账 |
| `bpf/tc_syncookie_handoff.c` | `bpf_sk_assign_tcp_reqsk()` 返回结果尚无观测计数 |
| `pkt_relay.py` | `decode_event(raw)`、`RingBufReader.drain()`、`RelayServer` |
| `auto_xdp/tui.py` | `RelayClient`、`_collect_snapshot()`、既有 curses 绘制与导航 |
| `auto_xdp/admin_cli.py` | `_collect_stats_rows()`、`_read_xdp_rows()`；仅局部替换重复名称目录 |
| `auto_xdp/bpf/maps.py` | `BpfSyncookieRuntimeMap(path).get()/close()` |
| `tests/python/test_tui.py` | `FakeWindow` 与 fake socket：无需真实终端测试展示/重连 |
| `lib/setup/install.sh` | 已递归安装 `.py`；新增 flat 模块由现有更新 glob 覆盖 |

## 模块边界与数据流

```text
BPF / TC：判定 + 数字 reason + 有限元数据 + 计数
   │
   ▼
pkt_relay.py：ring 消费、队列、保留历史、Unix socket、健康状态
   │          使用 telemetry.py 统一解码，不查 IP 网络信息
   ▼
relay_client.py：协议、重连、去重、有界事件窗口
   │
   ├── telemetry.py：稳定原因目录、兼容事件解码
   ├── traffic.py：事件样本汇总、诊断/cookie 展示模型
   └── geoip.py：本地库、有限缓存、查询状态
                │
                ▼
tui_traffic.py：观测界面；tui.py 保留主循环、导航和既有管理页面
```

根据实际拆分需要复用小型 `tui_widgets.py`，禁止新增只有一个实现的抽象 provider/factory。新模块不得反向导入 `tui.py` 或 `pkt_relay.py`。

## Phase 1：明确原因与事件合同

文件：新建 `auto_xdp/telemetry.py`；修改 `pkt_relay.py`、`auto_xdp/admin_cli.py` 的名称目录；新增 `tests/python/test_telemetry.py`。

- [x] 将原因 ID、canonical name、CLI 兼容名称、分类、说明集中到一个 Python 目录，覆盖旧枚举及本轮追加项。
- [x] 提供 `decode_event(raw: bytes) -> dict | None`；relay 重导出旧入口，保留已有调用。
- [x] 继续读取旧 48B 事件。新事件保留旧字段前缀，增加 ingress ifindex、原始包长及显式版本；精确检查支持的长度和版本。
- [x] 未知 reason 保留数字 ID，显示未知，不伪造解释；未知 family/verdict/版本拒绝解析并计入观测损失。
- [x] 字段保留 `src/dst/sport/dport/proto/family/verdict/reason/reason_id/ts_ns`；新增 `event_version/ifindex/pkt_len`，旧事件新增字段用缺失值表达。
- [x] 测试 IPv4/IPv6、大小端端口、48B/扩展事件、未知版本、截断及原因覆盖，验证生产 decoder 而非复制算法。

防误用：不能从旧 `TCP_DROP` 推断当时是端口未授权还是黑名单命中；没有当时策略版本时不显示虚构的规则历史。

## Phase 2：补齐内核观测

文件：`bpf/include/counters.h`、`common.h`、按需新建 `telemetry.h`、`rate_limit.h`、`xdp_firewall.c`、`xdp_syncookie.c`、`tc_syncookie_handoff.c`、内置 handlers、运行时加载器和相关 ABI/内核测试。

- [x] 分开 TCP/UDP 目的端口未授权、来源限速、端口 cookie 预算和 ACK 校验预算；保留黑名单/handler 的实际原因。
- [x] 统一事件提交；记录已提交、ringbuf 满导致丢失、配置关闭导致抑制的事件次数。
- [x] 扩展事件带 ifindex 与包长；明确原始入站包与 cookie 回复包的区别。
- [x] 为匹配 cookie 交接的请求记录 attempt/success/no-listener/error；普通 ACK 不记成 cookie 失败。
- [x] 所有共享计数 map 在独立 BPF/TC 对象加载时绑定同一 pinned map；更新 ABI/测试，不能只改 C 声明。
- [x] 核对内置 tail-call 程序的一次报文记账；覆盖原始入口总量，避免扩大/缩短 SYN-ACK 后扭曲入站字节。
- [x] 新增计数保持旧 ID 不变；旧 map/旧生产者缺项显示未知，而非假定零。
- [x] 用 Linux clang 编译实际程序及内置 handlers；能加载时验证报文判定与计数，不能加载则记录具体环境限制。

防误用：不改 SYN cookie 阈值、可信来源、ACL、协议放行判定；诊断计数可能重叠，不相加得出总 DROP。第三方 handler 的记账合同需文档说明。

## Phase 3：可靠的 relay 与客户端

文件：修改 `pkt_relay.py`；抽出 `auto_xdp/relay_client.py`；扩展 `test_sock_state.py` 或独立 `test_relay_telemetry.py`。

- [x] ring reader 同时接收 48B 与本轮扩展事件，保留 socket-state 固定长度读取。
- [x] 每次 relay 启动生成 `session_id`，按成功解码顺序给事件递增 `seq`；身份不可使用五元组或时间戳代替。
- [x] `history` 和 live 事件使用相同身份；客户端重连合并不重复。relay 重启换 session 时重置序列基线。
- [x] 处理 live `port_change`；连接关闭清理残缺 JSON 缓冲；限制消息缓存和保留事件数量。
- [x] 原因分布与来源排行榜使用相同的保留窗口；裁剪后不保留旧事件的累计次数。
- [x] `telemetry_status` 消息每秒从独立路径发送，包含 session、已解码、队列丢失、端口事件丢失、无效记录、保留条数和断线等健康信息。
- [x] 每轮广播处理有上限的 batch，持续洪流不能阻止接受连接和发送状态。
- [x] 测试同 session 历史重播、不同 session 重启、相同五元组的不同报文、残缺消息、队列满、live 端口事件及窗口裁剪。

合同：`RelayClient(path, max_events=500)` 保留原有 `events/events_offset/events_end/status/ports_dirty/poll/close`；增加 `telemetry_status`。`pkt_relay` 安全 socket/权限代码不被重构覆盖。

## Phase 4：可选本地 IP 信息

文件：`auto_xdp/geoip.py`、`tests/python/test_geoip.py`、`pyproject.toml` 和两个 TOML 模板。

- [x] 对照 MaxMind 官方 reader 文档核对 `open_database/get/metadata/close`。
- [x] 提供 `GeoIPResolver.from_config(config: dict)`、`lookup(ip: str) -> dict`、`status` 和 `close()`。
- [x] lookup 返回 `country_code/country_name/asn/as_org/network/status/scope/db_updated_at`，缺失值明确为空。
- [x] `[geoip]` 默认关闭；支持 `country_db/asn_db/cache_size`，验证类型与缓存上限。
- [x] 仅为展示中的有限来源行查询本地数据库并缓存；不在 XDP 或 ring 消费线程查库，不调用第三方在线 API。
- [x] 缺依赖、缺文件、损坏记录、私网/保留地址、未知 IP 均有可读结果；不阻断 TUI。
- [x] 文档说明库更新时间、源 IP 可伪造、ASN/地理估计不是攻击者身份。
- [x] fake reader 测试不依赖真实地址库；可选依赖安装在 TUI 使用的解释器环境，源码安装器不偷偷联网安装。

## Phase 5：独立的观测视图

文件：`auto_xdp/traffic.py`、`auto_xdp/tui_traffic.py`、按需 `tui_widgets.py`、`tui.py`、相关 TUI/客户端测试。

- [x] 保留既有导航/审批功能，将来源汇总、原因分布、cookie 指标等从主 TUI 拆出。
- [x] 来源排行明确叫保留事件样本：显示事件数、已记录字节、ALLOW/DROP 数、最近出现、国家/ASN；不将样本当全量 PPS。
- [x] 原因展示包含描述；区分内核诊断次数与保留事件次数。原有总流量仍从修正后的报文总计数读取。
- [x] 展示 BPF emitted/lost/suppressed 与 relay queue loss、连接状态、库状态；观测关闭或数据未知不画成零流量。
- [x] cookie 面板复用 snapshot 已有计数，展示 challenge/sent/valid/invalid/预算丢弃及 TC attempt/success/error；明确 VALID 不等于应用 accept。
- [x] 实际启用状态来自可读 runtime map；只有配置存在时显示 configured/unknown，不宣称运行成功。避免每次重绘调用完整 BPF feature probe。
- [x] 显示当前服务归属时注明为当前快照；不作为历史策略证据。
- [x] 80×20 小终端不崩溃、长 IPv6/ASN 文字不破坏布局；FakeWindow 验证标签、缺数据与统计口径。

## Phase 6：验证与交付

- [x] 运行相关 Python 测试，再运行完整 Python 回归和 Python 3.10/TOML/shell 语法检查。
- [x] 运行 mypy，修复本次新增类型问题；既有问题单独记录。
- [x] 在现有 Linux Docker 工具镜像中编译所有改动 BPF 对象。容器用只读源码挂载和临时输出，不安装/挂载到宿主网卡。
- [x] 验证新 Python 模块可打包/被更新候选枚举；保留所有原有用户修改。
- [x] 更新 `architecture.md` 模块表、README 使用方式及 `plans/information-plane.md` 操作说明。
- [x] 在此计划勾选完成项，记录实际运行的检查结果和未验证的内核/线上行为；不报告没有进行的压力测试。

## 后续里程碑（本轮不假装已完成）

1. 精确的规则证据：新增事件采集时 policy generation、限速计数范围和当时额度，在内核决策点采集；不能用事后配置补造。
2. 真实每端口/来源速率与短期趋势：独立有容量上限的内核聚合，明确 CPU/内存成本；事件抽样仅用于解释。
3. 防护收益实验：隔离 Linux 环境比较现有限速+内核 cookie 与追加 XDP cookie；测正常客户端成功率、P95/P99、CPU/softirq、交接状态淘汰和内存；包括模式切换、重传及 IPv6。
4. 按证据推进剩余项目模块化：将 admin CLI 的独立命令组逐步迁出，保留命令合同；本轮不混入审批/安装权限重构。

## 执行记录

- 基线：相关 Python 测试 65 passed / 1 skipped（macOS 无 Linux SO_PEERCRED）。
- 当前阶段：Phase 0–6 本轮范围已完成。按 make-plan 的调查先行/阶段验收方式推进，最多三个有界子代理；主代理维护公共合同、复核和集成。
- Linux 完整 Python 回归：`docker run --rm --network=none --mount type=bind,source=/Users/lulingna/basic_xdp,target=/src,readonly --workdir /src --env PYTHONDONTWRITEBYTECODE=1 axdp-test:latest python3 -m pytest tests/python -q --tb=short -o addopts='' -o log_cli=false -p no:cacheprovider` → **332 passed**，包含实际 C emitter harness、SO_PEERCRED 和 C/Python counter 目录一致性。
- macOS 回归快照：329 passed / 2 skipped / 24 subtests；随后追加的目录一致性检查已包含在上述 Linux 完整回归中。
- `mypy` → 37 个生产源文件无错误。`bash tests/run.sh static` → Python 3.10 语法、TOML、workflow YAML 和测试元数据通过；另对五个修改的 shell 文件逐一执行 `bash -n` 通过。
- `bash tests/bash/test_setup_xdp.sh` → **106 passed / 0 failed**，包含 SDK 安装及原有权限合同。
- 只读源码挂载、非特权 Linux Docker：main/cookie/TC(vmlinux)/Minecraft/GRE/ESP/SCTP **7 个 BPF 对象编译通过**；安装到容器临时目录后再编译 **4 个 handler 对象通过**。已有 cookie unroll、Minecraft label declaration、vmlinux header 编译警告未作为本轮重构范围。
- Wheel：使用现有 setuptools 75.6.0 / wheel 0.45.1 在临时源码副本构建；七个信息面模块和 ABI 资源均打包，Linux 无 GeoIP 依赖时全部可导入；现有更新候选枚举覆盖新增文件。
- 历史回放集成复现：Linux socketpair、5000 条 IPv6 事件、客户端每 200ms poll；512 KiB 上限生成 524044B / 1103 条，0.415s 内发送成功，客户端保留最新 500 条，last seq=5000，正确标记 truncated。
- 集成中补齐：历史按字节预算截断与零条回放；未知包总数不污染累计基线；安装 SDK 交付共享 BPF 头；保护用户已有 dirty 修改。`git diff --check` 通过。
- 未执行：真实内核 verifier/attach、真实应用建连/accept、洪流性能及收益实验、真实 MMDB 地理准确性验证、真实 curses 终端交互（已有 FakeWindow 小终端合同）。没有改线上防护开关，没有下载数据库，没有 Git 提交或部署。
- 后续里程碑仍未完成：参见上一节，不把本轮信息面模块化描述为整个项目的全部模块化。
