# 完整安装与实测记录

目标：在本机 Docker 与用户指定的 `root@103.114.163.74` 安装当前工作区并实际测试；允许覆盖远程现有 Auto XDP。SSH 使用指定的 `termius-key`，密钥未上传。

最新状态（2026-09-05 22:20 CST）：按用户“重新部署远程”要求，TC 清理修补版已重新安装到 `103.114.163.74`，release `local-20260905-141706-3677340`。两个服务 active/enabled，eth0 native XDP healthy，原配置和审批记录恢复，SSH、HTTP/443 及真实报文事件通过。部署回退计时器已撤销；没有升级内核或重启整机。详情见末节，前面的卸载状态为历史记录。

## 验证边界

先备份和隔离内核测试，再替换公网接口上的程序。保留远程已有 SSH/HTTP/HTTPS 授权，不调整其他业务；不对公网发送洪流，不升级远程内核。

验证采用 `verify-and-stop` 的通过/失败/未执行区分；出现真实加载失败后按 `investigate-first` 追踪原因。用户随后明确回复“修复”，并在确认方案后回复“ok，开始修复版”；以下保留首轮失败记录，最终结果见末节。修复按 `surgical-patch` 限定在已复现问题及相应加载、回归契约。

## 远程基线与备份

- Ubuntu 24.04.4 LTS，Linux `6.8.0-124-generic`，clang 18.1.3，bpftool 7.4.0 / libbpf 1.4。
- 旧版本 `local-20260904-133108-3373485`，`eth0` native XDP，program ID 4527。
- `xdp-port-sync`、`auto-xdp-relay`、SSH 与 Caddy 均 active。原策略为 enforce；授权 TCP 22/80/443、UDP 443。
- 备份目录：`/root/axdp-validation-20260905.RNQN4v/before`。安装目录、配置和服务文件备份为 `installation.tar.gz`，SHA-256 `98a9390c1a4e74dc82e528ef12426a7bbf8311130d1f3bcf81d84c1742e447bd`。
- 待测源码包 SHA-256：`f213792701edbd5fa2d79e204d9dc74a3db9356b37dbbda8facd491789513aba`，包含当前未提交及新增文件。
- `setup_xdp.sh --dry-run` 通过，识别 eth0/systemd，无缺失命令。

## 第一轮真实内核结果

| 环境 | 编译 | 主程序 verifier | 公网安装 |
|---|---|---|---|
| 本机 Docker LinuxKit 7.0.12 + clang 18 | 7 个 BPF 对象通过 | 失败 | 不适用 |
| 远程 Linux 6.8 + clang 18 | 主程序通过 | 失败 | 验证门禁暂停，未替换旧版本 |

Docker 分对象加载进一步确认：主程序、GRE、ESP、SCTP 四个对象在相同包长路径失败；SYN-cookie、Minecraft、TC cookie handoff 三个对象成功通过 verifier（尚不能因此声称完成握手或应用接入）。测试容器使用独立 bridge/net/pid 空间和精确 capability，未使用 host network/pid、未挂载宿主 `/sys`，无需 `--privileged`。

两处错误一致：

```text
bpf/include/telemetry.h: packet_length()
1135: r1 = *(u32 *)(r1 +0)          ; R1=pkt
1136: *(u32 *)(r10 -112) = r1
invalid size of register spill
```

原因：新增包长 helper 返回 u32，编译器延迟指针差值计算，并把仍带 packet-pointer 类型的寄存器以 32 位暂存，verifier 拒绝。仓库已有 `barrier_var` 用法可参考；[libbpf 1.4 定义](https://github.com/libbpf/libbpf/blob/v1.4.0/src/bpf_helpers.h)说明了它如何约束会导致不可验证代码的整数宽度优化。修复必须重新进行真实加载验证。

远程使用外层 `axdp-validation-20260905` 网络命名空间运行现有 kernel 套件，内部 nftables 测试不会操作公网所在网络空间。失败发生在第一项 attach 前；不能报告后续报文用例通过。临时命名空间及空运行目录已经清理，公网 program ID 4527 和原服务保持不变。

清理后使用新的非复用 SSH 连接验证成功，两个 Auto XDP 服务均 active，`axdp backend` 仍报告旧版本 native/healthy。

远程内核 BTF 中未发现 `bpf_sk_assign_tcp_reqsk`，完整 cookie listener handoff 不可用；不能把此能力缺失报成 cookie 建连测试成功。

证据：远程 `/root/axdp-validation-20260905.RNQN4v/kernel.log`；本机 `/private/tmp/axdp-deploy-validation.6AXzsv/remote-kernel-before.log`。备份留在远程 root 私有目录，未下载敏感配置。

## 首轮结束状态（历史记录）

Docker 已完成一次真实 fresh/audit 安装，产物位于容器 `/usr/local/lib/auto_xdp/current`。不能把 audit 模式的包安装成功描述成 XDP 防护验收成功。

- 容器无 init；`axdp enable --force` 返回 1 并回到 audit。单独运行已安装 launcher 后，也实际重现主程序 verifier 拒绝，明确区分环境限制与产品错误。
- 真实 PTY 中 TUI 的 `e` 事件、`v` 来源样本、`c` cookie/健康页均成功切换；无 maps 时运行状态与计数显示 unknown，随后正常退出。
- 旧安装产物检查另有失败：硬编码 `/etc/auto_xdp/handlers/minecraft_handler.o`，而实际内置对象位于版本化 release 的 `handlers/`。尚未修改该测试，也不把它算通过。
- 容器名 `axdp-information-plane-20260905`，镜像 `xdpbuild:tools`。容器已停止（exited），安装状态与同名独立 bridge 保留，供修复后复测，避免重复下载依赖。测试进程及临时网络资源已清理；专用 bridge 留存不是公网部署。
- Docker 完整日志：`/private/tmp/axdp-information-plane-e2e.8H4l38/final-logs/`，包括 `install-audit.log`、`verifier-preinstall-*.log`、`installed-loader-enforce.log`、`tui-pty.ansi` 和清理状态。未将本轮代码提交到 Git。

该轮请求追加修复授权后暂停公网升级；当时目标尚未完成。以下为获得授权后的修复和最终验收。

## 修复版最终结果

远程已成功覆盖安装，当前为 `local-20260905-115608-3652822`，eth0 native XDP program ID **5810**。`xdp-port-sync`、`auto-xdp-relay` 均 active/enabled；SSH、Caddy active。原配置完整保留，SHA-256 仍为 `642aff71de2867608bad06a7b1365d146eff495a99ced37cdeb05a0efaf4c033`。

最终源码包（含当前工作区修改和新增文件、没有 Git 提交）的 SHA-256 为 `a5839914468a835197ce3d3dddb2a188405e49c06792047f42ada63d29e91d8a`，本机和远程一致。

### 已修复的真实故障

- 包长 helper：64 位差值加 `barrier_var`，避免 clang 18 生成非法 32 位 packet-pointer spill。此前失败的主程序、GRE、ESP、SCTP 均通过真实 verifier。
- Minecraft TC：真实 `sendmsg` 的两字节响应可能位于非线性 skb fragments；按受限长度拉取控制帧后重新检查指针，不再仅按线性区长度判断无负载。
- conntrack lookup：固定 12 字节 options ABI，显式清零最后两字节；此前实测尾部为非零垃圾数据，kfunc 返回 `-EINVAL`。可变内核 snapshot 仍使用 CO-RE。
- Minecraft 撤销：有界 `mc_verified` LRU 保存完整的 64 位 policy/profile generations；connmark 仅作提示。记录丢失、代次不符或标记不匹配时，已验证连接直接 DROP，不重开 probation；新连接与关闭路径清理相关状态。加载器、热更新、必需 maps 和 ABI manifest 同步绑定新表。缓存容量 65,536，淘汰会撤销相应连接的验证状态。
- SYN-cookie RST：跟踪确认 NAT LOCAL_IN 在 TCP 收包前清除了 TC 分配的 request socket；同样代码移到无 NAT 命名空间后实际应用接入成功。因此加入只读兼容性门禁：有 NAT 或无法可靠检查 NAT 时拒绝 Level 2；清理旧可选挑战入口与 TC filter，strict 模式失败，不修改宿主 NAT。
- 测试契约：修正版本化内置 handler 路径、共享 telemetry/maps 绑定、handler 编译 include 路径、实际进程归属识别，以及隔离网络的 conntrack 启用方式。没有通过删掉失败断言来获得通过。

### 验收证据

| 检查 | 结果 |
|---|---|
| `python3 -m pytest -q tests/python` | 346 passed，3 个 macOS 平台 skip，24 subtests passed |
| `bash tests/bash/test_setup_xdp.sh` | 106 passed |
| `bash tests/bash/test_axdp.sh` | 27 passed |
| Linux native `minecraft_session_contract.c` | 实际调用生产 helper；完整代次、低位 epoch 碰撞、缺失记录、写失败不改 connmark、12 字节 opts 均通过 |
| Docker 独立 net/mount namespace，`REQUIRE_KERNEL_TESTS=1` | 20/20 实际通过；私有 sysfs/bpffs，未改 Docker NAT |
| 远程 6.8 隔离 kernel suite | 19 项实际通过，cookie handoff 因缺少 helper 跳过；脚本汇总 20 passed、0 failed，不能把跳过项算真实通过 |
| Minecraft 双环境真实 TCP 对话 | legacy/modern 登录、PLAY、status/ping；profile generation +256、policy generation 单独变化、删除验证缓存均撤销旧连接；错误初始负载被挡 |
| Cookie 无 NAT 环境 | 应用 accept、收到 `cookie` 并回显 `ok`；TC attempt/success=1、error=0；另用受控报文证明 VALID/INVALID v2 事件和 54 B 入包变 58 B 回复仍按入包 54 B 计量 |
| Cookie NAT 门禁 | 实际 Docker NAT：level=1、degraded、明确 NAT 原因；无 NAT：level=2、ready；21 项专属 Python 测试通过 |
| Docker 最终重装 | `install_status=replace`、`install_result=complete`，产物检查通过；release `local-20260905-115359-4676` |
| Docker 已安装 runtime | 指定测试 veth peer 后，真实 TCP 32877 监听出现→授权放行→关闭撤销，sock_state/relay 事件通过；容器无 systemd，直接运行已安装 launcher/relay |
| Docker 最终真实 PTY | `axdp tui --interface axdpci0`；e 页显示 UDP DROP/ifindex=27/len=60，v 页显示 60 B 和 len 1/1，c 页显示 cookie/丢失/relay 状态，q 正常退出 |
| 远程实际安装 | systemd 安装单元 exit 0；产物、已安装 XDP/sock_state/relay 检查通过；公网接口不是 veth，该脚本的自动监听发包子测试明确跳过 |
| 远程公网低频探测 | 新的非复用 SSH 成功；HTTP 返回 308，TCP 443 建连成功；单个 UDP 49189 报文经实际 relay 返回 v2、ifindex=2、pkt_len=60、DROP、PORT_NOT_AUTHORIZED |

远程覆盖前保留旧 BPF program 救援 pin 并启用五分钟独立 systemd 回滚计时器。新 SSH、服务、native backend、配置哈希和公网事件验证通过后，写入 `validated` 标记并撤销计时器。**回滚未触发**；临时救援 pin 和隔离网络命名空间已清理。旧安装备份仍完整保存在 `/root/axdp-validation-20260905.RNQN4v/before/installation.tar.gz`，可恢复。

### 明确限制与留存

- 远程 Linux 6.8 不含 `bpf_sk_assign_tcp_reqsk`，未升级内核，保留原有 cookie 关闭配置。基础 XDP、信息平面、Minecraft 实测通过不等于该可选能力可用。
- NAT 下的完整 cookie handoff 当前明确禁用；未声称修复了 Linux NAT 内核行为，也未删除 NAT 规则。需要该拓扑能力时应另行验证内核修复。
- 有界 Minecraft probation 不是完整 TCP 重组，也不是协议服务器认证；缓存淘汰按拒绝处理。没有进行公网洪流、容量压测或真实 Minecraft 游戏服务器兼容性遍历。
- Docker 容器 `axdp-information-plane-20260905` 测试后停止；已安装文件、镜像和独立 bridge 留存，bridge 无活动端点。临时 reader、relay、PTY 和 kernel 测试进程已结束。
- 本机最终日志：`/private/tmp/axdp-deploy-validation.6AXzsv/` 下的 `python-final.log`、`setup-final.log`、`axdp-final.log`、`kernel-full-proof.log`、`install-final.log`、`docker-final-logs/`。更详细的诊断仍在容器 `/logs/repaired/`、`/logs/cookie-repair/`。
- 远程安装与内核日志：`/root/axdp-validation-20260905.RNQN4v/install-final.log`、`kernel-full-proof.log`；源码包与安装前备份保留在同一私有目录。SSH 私钥没有上传，敏感配置没有下载。

## systemd 修复版部署与真实卸载（20:54 CST）

用户先要求“完善 systemd 卸载逻辑”，随后要求部署实测，并明确选择“实际卸载 AutoXDP”。本轮按 `verify-and-stop` 验证，不升级内核、不重启整机、不重新安装已卸载的应用。

- 本地 systemd 修复此前通过 CLI 28 项、setup 106 项检查；CLI 检查包含 13 种卸载生命周期情形。真实服务器补充验证不能由这些 mock 结果替代。
- 本轮备份为 `/root/axdp-uninstall-validation-20260905.NufHwO/installation.tar.gz`，SHA-256 `f662ca56b89d4a8a1ba346215829a6578fbca8a2b49afc5e3f66d7d1128c0cf3`。安装、配置和 unit 文件保留，可用于恢复；没有下载敏感配置。
- 部署源码包 SHA-256 `6ca9102cfa1547781e10345a420ed26952ae9b1c07b49a7e2e4a69ed45d14709`；新 release 为 `local-20260905-124856-3665447`，安装退出 0，产物检查通过。
- 安装后的 CLI SHA-256 `933120ee490822c57abbbc28290dcce3a180bd93823c2c189cacb1feb4893d38` 与本地修复版一致。配置哈希未变，native XDP ID 5914，Minecraft TC ID 5984；两个服务 active，backend healthy，新 SSH 连接、HTTP 308、TCP 443 均成功。
- 部署回滚计时器在验证后撤销，救援 pin 删除；确认回滚未触发后，从保留的测试源码运行 `tests/bash/test_uninstall.sh`，实际调用已安装的 `axdp uninstall eth0`。卸载单元退出 0。

### 真实卸载发现的额外缺陷

systemd 清理实际通过：两个服务均为 `LoadState=not-found`、`ActiveState=inactive`，开机链接和运行文件消失。但独立检查发现 Minecraft TC ID 5984 仍挂在 eth0 egress，现有卸载 E2E 未检查 TC，因此不能把其退出 0 视为完整无残留通过。

原命令 `tc filter del dev eth0 egress pref 49153 handle 2` 在真实 iproute2 上返回 255：`Must specify filter type when using "handle"`。`axdp` 吞掉该错误；runtime 的同类删除调用也缺少类型。这轮没有改生产代码，该缺陷仍待单独修复。

核对 pref 49153、handle 0x2、program ID 5984 确属本轮 AutoXDP 后，执行 `tc filter del dev eth0 egress protocol all pref 49153 handle 2 bpf`，删除成功。原有 pref 49152、handle 0x1、TC program ID 898 保留，未删除共享 clsact qdisc。

### 最终卸载终态

独立 `postcheck.py` 实测通过：两个 unit 不存在且 inactive；18 个安装/配置/pin/运行/开机链接路径不存在（含悬空链接检查）；无 XDP、无 AutoXDP ingress/egress TC、无安装目录下的运行进程、无 `inet auto_xdp` nft table；原 TC ID 898 保留。备份哈希再次验证，回滚 timer/service 均 inactive。

新的非复用 SSH 连接成功，SSH/Caddy active，公网 HTTP 返回 308，TCP 443 可连接。内核仍为 `6.8.0-124-generic`。AutoXDP 已卸载，因此不再提供该应用的防护；备份和测试源码仅作为恢复/验收材料保留。

远程证据在 `/root/axdp-uninstall-validation-20260905.NufHwO/`：`install.log`、`uninstall.log`、`postcheck.py`、`postcheck.json`。最终通过包含对 TC 残留的人工定点清理，并非现有卸载命令能自动完成全部清理。

## TC 删除缺陷代码修补（用户 21:54 CST 追加授权）

- `axdp` 和 runtime 的 Minecraft 清理/回滚、cookie 清理调用均指定 `protocol all` 和 `bpf` 类型；集成测试中的同类删除命令同步修正。
- 卸载同时处理 cookie ingress pref 49151 与 Minecraft egress pref 49153 的 handle 2，随后读取 TC JSON 验证。删除仍有残留、查询失败、无效 JSON 或缺少 `tc` 时，返回失败并保留安装文件、配置和 pins 供重试；不会删除共享 clsact 或其他 handle。
- 真实卸载 E2E 增加 TC 残留检查，补上此前“脚本退出 0，但过滤器仍在”的验收缺口。
- 新回归测试在旧代码上实际失败：CLI 2 项失败（残留和假成功），setup 1 项失败（runtime 清理残留）。修复后 CLI **29/29**、setup **107/107** 通过，覆盖清理、已不存在、删除失败、查询失败、无效 JSON、假成功、缺少工具及双接口 Minecraft 回滚。Bash 语法和 `git diff --check` 通过。
- 隔离 Docker 使用已有 `axdp-test:latest`、`--network none`、仅额外 `NET_ADMIN` 和只读源码挂载。在两个真实 veth 上挂载 classic-BPF TC filters，实际调用共享清理函数两次，再通过当前 CLI 的安装夹具运行卸载 E2E。所属 handle 2 全部清除，其他 pref 以及同 pref 的 handle 3 均保留。此项是实际 TC 与无 systemd 安装夹具验证，不声称再次运行公网安装或真实 systemd 卸载。

本轮没有 SSH 操作、没有重装远程、没有升级内核。临时 Docker 容器运行后自动删除，原测试容器保持停止。实测脚本及日志在本机 `/private/tmp/axdp-tc-validation.je9Lfo/`，组件前后对照日志为 `/private/tmp/axdp-tc-{before,after}-{cli,setup}.log`。最初选择的基础镜像缺少 `ip`，未运行用例；换用已有完整工具镜像后全部通过。

## TC 修补版远程重新部署（22:20 CST）

用户 22:10 CST 要求“重新部署远程”。部署前确认主机仍为卸载终态，两个 unit not-found/inactive，无 XDP，只有原有 TC ID 898；SSH/Caddy active。

- 按 `deployment-patterns` 的回退与健康检查流程保留独立五分钟保护，以 `verify-and-stop` 完成验收。复用上一节通过的组件及真实 Docker TC 回归结果，本轮没有改生产代码。
- 从原备份 `/root/axdp-uninstall-validation-20260905.NufHwO/installation.tar.gz` 恢复 `config.toml`、`approval_requests.json` 和自定义 handlers；不恢复旧 machine/runtime/transaction 状态、旧 unit 或旧 release。备份 SHA-256 `f662ca56b89d4a8a1ba346215829a6578fbca8a2b49afc5e3f66d7d1128c0cf3` 再次验证。
- 新源码包 SHA-256 `598553479b105c2f83b0ba1e350248d917cab119268c7ae3272822f293146b33`，标准 `setup_xdp.sh --force eth0` 安装退出 0，release `local-20260905-141706-3677340`。预先恢复配置使安装器报告 `install_status=replace`；运行文件实际上从卸载状态重新生成。
- 已安装 CLI SHA-256 `cb24ef06c60dac6f1da53e25d3430796dbf2c15464f8f67bc7906bfebde94025`、runtime common SHA-256 `ba27de90dc3152d2a18fd17461cb44fc599f5af60780d4056fe8591e5829b3d5` 均与本地 TC 修补版一致。
- 配置 SHA-256 仍为 `642aff71de2867608bad06a7b1365d146eff495a99ced37cdeb05a0efaf4c033`，审批记录与备份逐字节一致。两个服务 active/enabled，backend healthy/native、无 fallback、无 install transition；主 XDP ID 6114，Minecraft egress TC ID 6183，原有 TC ID 898 保留。
- 安装产物检查和已安装 XDP/sock_state/relay 检查通过。公网 eth0 非 veth，自动监听发包循环明确跳过；这不影响上一节隔离 Docker 的真实 TC 证明，也不将跳过项算作公网通过。
- 新的非复用 SSH 成功，HTTP 返回 308、TCP 443 可连接。单个 18 B UDP 探测报文被实际 relay 记录为 v2、ifindex 2、pkt_len 60、DROP、PORT_NOT_AUTHORIZED；观察器退出 0。

全部门禁通过后创建 `validated` 标记并撤销回退 timer，确认 timer/service 均 inactive、没有 `rollback.log`，回退未触发。本轮没有再次卸载应用、没有改 NAT、没有升级 Linux `6.8.0-124-generic`，也没有重启整机；既有 cookie 能力限制不变。

远程源码、选择性配置副本、回退脚本和日志留在 root 私有目录 `/root/axdp-redeploy-20260905.KfMpsu/`。本机 `/private/tmp/axdp-redeploy-validation.pcZtiq/` 留存源码包及 `install.log`、`runtime-check.log`、`backend.json`、`event.log`；敏感配置未下载，SSH 密钥未上传。
