# aidbg

Linux C/C++ 进程调试工具，测试版。项目面向 x86_64 和 AArch64。Rust 服务端在目标主机运行，客户端提供命令行和 MCP stdio。两端通过 Unix socket 上的 gRPC / Protobuf 通信。

后续功能、验收边界和实现顺序见 [需求与路线图](REQUIREMENTS.md)。

## 平台支持

| 功能 | Linux x86_64 | Linux AArch64 |
|---|---|---|
| 进程快照、寄存器和调用栈 | 已通过本地集成测试 | 已通过树莓派 4B 集成测试 |
| ELF 符号、地址查询和本地外置 DWARF | 已通过本地集成测试 | 已通过树莓派 4B 集成测试 |
| Capstone 反汇编 | 已通过实时进程测试 | 已通过树莓派 4B 实时进程测试 |
| 硬件执行断点、硬件数据观察点、软件执行断点 | 已通过本地集成测试 | 已通过树莓派 4B 集成测试 |
| 软件值变化观察、标量目标函数调用 | 已通过本地集成测试 | 已通过树莓派 4B 集成测试 |

`breakpoint capabilities` 可查询当前服务端开放的断点类型、观察点宽度和对齐。AArch64 可用 `breakpoint capabilities --pid "$TARGET_PID"` 读取内核报告的两类槽位数。树莓派 4B 实测 6 个执行槽位和 4 个观察槽位。

## 构建和运行

构建需要 Rust、C/C++ 编译器、CMake、Ninja、tar 和 Python 3。服务端静态链接 Capstone、Keystone 和 Unicorn。Keystone 和 Unicorn 的固定版本源码随仓库提供，构建过程无需另行下载引擎。GNU 构建也静态链接 C++ 标准库，运行时仅依赖系统核心库。[引擎源码版本](vendor/README.md)

```sh
cargo build --locked --release --bins

runtime="$(mktemp -d)"
mkdir -m 700 "$runtime/snapshots"
export AIDBG_SOCKET="$runtime/aidbg.sock"
printf '%s\n' "$AIDBG_SOCKET"
./target/release/aidbg-server --socket "$AIDBG_SOCKET" --state-dir "$runtime/snapshots"
```

另开终端，将 `AIDBG_SOCKET` 设置为上面打印或复制的绝对路径。传入当前用户有权调试的目标进程 PID（线程组 leader）。

```sh
./target/release/aidbg --socket "$AIDBG_SOCKET" snapshot --pid "$TARGET_PID"
./target/release/aidbg --socket "$AIDBG_SOCKET" snapshot --pid "$TARGET_PID" \
  --freeze required --fields process.pid,threads.stack.frames.function --frames 4 \
  --save snapshot.json

./target/release/aidbg --socket "$AIDBG_SOCKET" snapshot --from "$SNAPSHOT_ID" \
  --tid "$THREAD_ID" --fields threads.registers
```

服务端在指定状态目录为每次采集保存一份完整 JSON，并返回 `snapshot_id`。筛选只改变响应。CLI 的 `--save` 也导出完整 JSON，`--from` 通过 ID 查询服务端文件。只要状态目录保留，目标退出或 server 重启后都能查询。支持点分字段路径、按 TID 筛选及限制每线程返回的帧数。输出保留采集状态和快照 ID。

## Linux core 转储

```bash
aidbg --socket "$AIDBG_SOCKET" coredump --pid "$TARGET_PID" --output case.core.zst
aidbg --socket "$AIDBG_SOCKET" coredump --pid "$TARGET_PID" --mode extended --output ipc.core.zst
zstd -d case.core.zst
gdb /path/to/executable case.core
```

| 模式 | 采集范围 |
|---|---|
| `lite` | 全部线程、寄存器和地址映射，记录可取得的模块 build ID |
| `stack-4k` | `lite` 加 `[vdso]`、模块 ELF 头和动态链接器的回溯记录。每线程从 SP 到高地址采集最多 4 KiB，在映射末尾截断 |
| `stack`（默认） | 将 4 KiB 扩大为每线程 SP 所在的整段映射，并包含可识别的主线程栈 |
| `standard` | `stack` 加主程序和共享库的 ELF 可写加载段、私有文件映射的 COW 和换出页，以及需要保留的普通文件映射范围 |
| `extended` | `standard` 加堆、匿名私有可写区及可读的 IPC 共享内存，包括匿名共享区、POSIX/SysV 共享内存和 `memfd` |
| `full` | 尝试采集全部映射 |

普通共享文件映射有脏页或无法确定状态时，`standard` 及以上会保守采集整段。转储只冻结目标进程，其他进程仍可能改写共享内存。解压后可检查 ELF 的 `AIDBG` note，拿到原始地址映射、模块身份和缺失范围。

CLI 和 MCP 的 `coredump` 把 Zstd level 1 压缩的 core 保存到显式指定的新文件，并返回采集、暂存和压缩大小、暂停时间及覆盖状态。`--timeout-ms` 默认 60000。目标有活动断点会话时先结束该会话。线程冻结、通用寄存器采集或清理失败时，命令失败。部分内存无法采集时，产物仍会发布，摘要标记为 `partial`。可用至少两核时，服务端并行采集与压缩。压缩队列满时，服务端把剩余内存写入临时文件，恢复目标后继续压缩。目标设备无需安装 Zstd 命令或 GDB。离线调试按需提供匹配的可执行文件和共享库。

服务端恢复目标后，保存压缩数据并为产物计算 SHA-256。连接在采集期间中断时，已接受的采集任务会在原预算内继续。传输中断时，客户端保留 `.part` 和 `.part.json`，重连后用相同的输出路径继续下载同一个 `dump_id`。目标退出或服务端重启后，已保存的产物仍可续传。客户端校验长度和 SHA-256 后原子发布最终文件。

```bash
aidbg --socket "$AIDBG_SOCKET" coredump --resume --output case.core.zst
```

服务端默认保存已压缩产物一小时，总额度为 4096 MiB。可用 `--coredump-retention-secs` 和 `--coredump-max-mib` 调整，两项均为服务端选项。采集和压缩的暂存文件还需要额外磁盘空间。客户端默认等待每次 RPC 或下载消息最多 30 秒，可用 `--download-idle-ms` 调整。已过期的产物需要重新采集。

`tests/run.sh` 用随机数据压力夹具和业务型合成夹具各验证六种模式。业务型夹具混合堆对象、日志、稀疏内存和少量随机数据。构建夹具后，可运行 `python3 tests/coredump.py --benchmark`，用同一份解压后的 ELF 比较 Zstd level 1、3 和 5。输出耗时包含启动本地压缩工具和管道传输。

采集使用冻结前预分配的缓冲池。CLI 可用 `--buffer-mib` 和 `--block-kib` 调节，MCP 参数为 `buffer_mib` 和 `block_kib`。默认块大小是 1024 KiB，`stack-4k` 默认缓冲 2 MiB，其余含内存档默认 16 MiB。缓冲预算为 0 时，内存写入临时文件，目标恢复后压缩。单核或预算不足两个读块时使用同一路径。

模块 ELF 在冻结前解析，以冻结后读取的映射和文件身份校验缓存。需要模块内容来确定采集范围的档位会重新解析变动的模块。

摘要的 `pause_us` 从首次附加算到分离结束，`timing_us` 细分冻结、映射、寄存器、ELF、`smaps`、选区、读取、缓冲和分离，其中 `staging` 计入 `buffering`，`preflight` 在暂停窗口之外。可在构建后用 `python3 tests/coredump.py --pause-sweep` 比较缓冲预算、读块大小、暂停耗时、文件就绪耗时和服务端进程 RSS 峰值。可用 `--baseline-bin-dir` 指定旧版二进制目录做对照。

## 冻结模式

| 参数 | 采集方式 |
|---|---|
| `--freeze never` | 只读 `/proc`。线程、信号、内存和模块照常返回，寄存器与用户栈为空 |
| `--freeze try`（默认） | 尝试全线程暂停。未完全停止时返回可用的 `/proc` 信息和已停线程的寄存器 |
| `--freeze required` | 确认全线程暂停后才开始主体采集。冻结失败时返回错误与分离结果 |

JSON 的 `freeze_achieved` 与 `status` 独立。全组已停但某线程缺少展开信息时，仍可能返回部分栈。地址和寄存器用十六进制字符串。回溯使用 gimli CFI 并尝试帧指针后备路径。符号化和快照保存发生在分离之后。

`status` 可为 `complete`、`partial` 或 `failed`。CLI 对应退出码为 0、0、1，命令行参数错误为 2。服务端将附加、等待和分离留在同一 OS 线程完成。客户端请求中途断开时，已开始的采集仍由服务端清理。

## 硬件执行断点

Linux x86_64 的执行断点和观察点共享四个槽位。AArch64 有独立的执行和数据槽位，执行地址须四字节对齐。断点命中时，服务端执行内部快照回调并恢复目标。默认采集命中线程，`--all-threads` 请求采集全进程。AArch64 为单步恢复会短暂停住其他线程。回调预算由 `--timeout-ms` 设置，默认 100 毫秒。采集在各步骤之间检查预算，超时后进入恢复流程。阻塞的系统调用返回后才能继续清理，事件记录实际观测到的暂停时长。

```sh
aidbg --socket "$AIDBG_SOCKET" breakpoint set --pid "$TARGET_PID" --address 0x555555555180
aidbg --socket "$AIDBG_SOCKET" breakpoint events --breakpoint-id "$BREAKPOINT_ID"
aidbg --socket "$AIDBG_SOCKET" snapshot --event "$EVENT_ID"
aidbg --socket "$AIDBG_SOCKET" breakpoint remove --pid "$TARGET_PID" --breakpoint-id "$BREAKPOINT_ID"
```

断点由服务端持有，CLI 退出或 MCP 断开后仍生效。查询可传 `--after-event-id` 增量读取。内存中保留最近 512 个事件。事件包含采集范围、采集状态、恢复结果和快照保存状态。`snapshot_status` 为 `saved` 时可用事件 ID 或 `snapshot_id` 查询持久化结果。正常关闭 server 会撤销活动断点。被断点会话跟踪的进程仍支持 `snapshot --freeze never`，全进程断点快照可用 `--all-threads`。

## 硬件观察点和软件断点

```sh
aidbg --socket "$AIDBG_SOCKET" breakpoint capabilities
aidbg --socket "$AIDBG_SOCKET" breakpoint set --pid "$TARGET_PID" --kind write \
  --address "$DATA_ADDRESS" --length 8
aidbg --socket "$AIDBG_SOCKET" breakpoint set --pid "$TARGET_PID" --kind software \
  --module "$MODULE" --symbol "$SYMBOL"
```

硬件观察点支持 `write` 和 `read-write`，宽度为 1、2、4 或 8 字节，地址须按宽度对齐。命中事件包含前后采样值和 `value_changed`。x86_64 同时观察到多次访问时，无法归属的比较结果为 `null`。AArch64 记录内核报告地址及精确或近似归属，并对触发指令单步比较前后值。在读写模式下，`write_observed` 为 `null`。

软件断点接受私有可执行映射中的指令地址。命中时暂停同进程的其他线程，单步执行原指令，再恢复断点。创建独立子进程时，含软件断点的会话会清理父子地址空间中的补丁并结束。请通过移除断点或正常关闭 server 触发清理。

## 模块地址和符号

```sh
aidbg --socket "$AIDBG_SOCKET" symbols --pid "$TARGET_PID" --pattern 'library_*' --mode glob
aidbg --socket "$AIDBG_SOCKET" resolve --pid "$TARGET_PID" --address "$RUNTIME_ADDRESS"
aidbg --socket "$AIDBG_SOCKET" breakpoint set --pid "$TARGET_PID" \
  --module libfixture.so --symbol library_wait
```

符号搜索按原始 ELF 名称匹配，支持 `exact`、`glob` 和 `regex`。可用 `--module` 按路径、文件名或 build ID 筛选。结果包含运行时地址、ELF 地址、模块偏移、加载实例和符号表来源。同一模块多次加载时，可将结果中的 `instance` 传给断点命令的 `--instance` 来消除歧义。符号断点安装时绑定解析出的运行时地址。

服务端按 build ID 或 `.gnu_debuglink` 发现本地调试文件并校验归属。地址查询可返回外置 DWARF 源文件和行号。缺少匹配符号时，查询返回模块和偏移。

## 反汇编和 C++ 名称

```sh
aidbg --socket "$AIDBG_SOCKET" disassemble --pid "$TARGET_PID" \
  --address "$RUNTIME_ADDRESS" --before 4 --after 8
```

反汇编读取目标进程中的实时字节，支持 x86_64 和 AArch64。x86_64 从可用的函数入口或调用方通过 `--start` 提供的指令地址向前解码。缺少可信起点时返回 `boundary: uncertain`。窗口中的指令包含运行时地址、字节、助记符和操作数。

C++ 符号保留原始名称、完整解修饰名和简写显示名。libstdc++、libc++ 的标准参数可显示为 `std::string` 等常用别名。搜索使用原始 ELF 名称。

## MCP client

在 MCP 客户端注册可执行文件 `aidbg`，启动参数使用 `["--socket", "/absolute/path/aidbg.sock", "mcp"]`。stdio 工具包括以下操作。

- `snapshot`，接受 `pid`、`freeze` 和可选的 `fields`、`tid`、`frames`。
- `snapshot_query`，接受 `snapshot_id` 或断点 `event_id` 及相同的筛选项。
- `coredump`，接受 `pid`、`output` 和可选采集参数，返回输出路径、`dump_id` 和采集摘要。设置 `resume: true` 后用原 `output` 续传，可用 `download_idle_ms` 调整下载等待时间。
- `breakpoint_set`、`breakpoint_remove`、`breakpoint_events`，接受对应命令的参数。
- `breakpoint_capabilities`，查询观察类型、宽度、对齐和槽位。
- `symbols`、`resolve_address`、`disassemble`，查询 ELF 符号、运行时地址和反汇编窗口。
- `perf`、`symbol_override_set`、`symbol_override_list`、`symbol_override_remove`、`inspect`，采样和查询进程状态。
- `assemble`、`plan_patch`、`emulate`，汇编、生成离线补丁和运行仿真。
- `watch_step`、`target_call`，限域单步观察与标量目标函数调用。

本机直接连接 socket。远程主机已有 SSH 时，也可通过 SSH 转发该 socket 后接到同一 client。测试版建议 client 和 server 使用同一个构建版本。

## 采样和变量读取

```sh
aidbg --socket "$AIDBG_SOCKET" perf --pid "$TARGET_PID" --hotspot --duration-ms 1000
aidbg --socket "$AIDBG_SOCKET" perf --pid "$TARGET_PID" --stack --frequency-hz 99
aidbg --socket "$AIDBG_SOCKET" inspect --pid "$TARGET_PID" --tid "$THREAD_ID" \
  --expression 'state.items[2].value'
```

`perf` 默认对采样开始时发现的线程建立用户态 perf 事件。`--tid` 可选定一个线程。热点输出包含相邻地址的范围、样本数和占比，调用树还包含占父节点比例。回溯使用样本中的寄存器和栈字节，报告丢样、部分栈的截断原因以及实际采用的展开方式。内核或权限阻止采样时返回 `unavailable` 和线程级原因。

`inspect` 冻结目标，在指定线程的当前物理帧中解析变量及内联作用域，省略 `--tid` 时使用线程组 leader。支持命名空间、成员、固定大小数组、指针解引用和常量偏移的基类。标量表达式支持算术、比较、短路逻辑和基础类型显式转换。返回类型大小和可解析的成员布局。可按 `--module` 和 `--instance` 消除多个全局定义的歧义。返回状态区分 `optimized_out`、`unavailable_at_pc`、`read_failed`、`unsupported` 和 `invalid_expression`。

## 软件观察点与目标函数调用

```sh
aidbg --socket "$AIDBG_SOCKET" watch-step --pid "$TARGET_PID" \
  --address "$DATA_ADDRESS" --length 8 --pc-start "$PC_START" --pc-end "$PC_END" \
  --max-steps 128 --timeout-ms 250

aidbg --socket "$AIDBG_SOCKET" target-call --pid "$TARGET_PID" \
  --module libtarget.so --symbol 'demo::add' --arg i32:2 --arg f64:0.25 \
  --return-type f64 --scratch-address "$SCRATCH_ADDRESS" --scratch-length 8192 \
  --allow-side-effects
```

`watch-step` 从目标当前 PC 开始，只在半开指令区间内单步，每步比较指定内存的字节。其他线程保持暂停。报告覆盖值变化，观测能力限于变化后的值。步数、墙钟时间、信号和离开窗口都会结束采集并进入分离流程。

`target-call` 使用调用方明确提供的专用可写暂存区作为栈。它按 x86_64 SysV 或 AArch64 AAPCS64 传递标量寄存器参数。C++ 调用可按实参的精确类型匹配重载。支持 `i32`、`u32`、`i64`、`u64`、`bool`、`ptr`、`f32`、`f64`，返回类型另支持 `void`。每步检查符号窗口、栈指针和执行预算。正常结束或可恢复的中止会还原寄存器与暂存区，转发异步信号并报告调用内的同步故障。目标函数对其他内存的写入属于调用副作用。

## 调试器符号覆盖

```sh
aidbg --socket "$AIDBG_SOCKET" symbol-override set --pid "$TARGET_PID" \
  --address "$RUNTIME_ADDRESS" --length 16 --name debugger_name
aidbg --socket "$AIDBG_SOCKET" symbol-override list
aidbg --socket "$AIDBG_SOCKET" symbol-override remove --id "$OVERRIDE_ID"
```

同一模块身份下的覆盖范围须互不重叠。`symbols` 可搜索覆盖名称，`resolve` 返回覆盖结果及原始 ELF 符号。带 build ID 的规则按模块内偏移存入服务端状态目录，适用于该构建的其他加载实例。缺少 build ID 的规则绑定当前服务会话中的进程和实例。

## 离线汇编、补丁和仿真

服务端内置静态链接的 Keystone 0.9.2 和 Unicorn 2.1.4。两个引擎只构建服务端架构，设备直接运行 `aidbg-server` 即可使用这些命令。

```sh
aidbg --socket "$AIDBG_SOCKET" asm --address 0x10000 --source 'nop'
aidbg --socket "$AIDBG_SOCKET" patch --base 0x10000 --address 0x10000 \
  --original "$ORIGINAL_HEX" --source 'nop' --existing 0x10010:4
aidbg --socket "$AIDBG_SOCKET" emulate --state simulation.json
```

`patch` 检查允许的原始字节窗口、原指令边界和现有补丁范围，并返回供预检的 `patched_image`。在仿真 JSON 中把它作为 `code`，同时提供 `address`、可选的 `registers`（名称到数值字符串的映射）和 `memory`（包含 `address`、十六进制 `bytes`、`writable` 的列表）。代码与内存副本应放在互不重叠的仿真页。`watch` 接受包含 `address` 和 `length` 的区间列表。`objects` 另需 `name`，可用 `guard_bytes` 观察邻近的越界访问。仿真结果标记事件来源，报告未提供的寄存器、缺失内存、提前停止和指令或时间预算。所有输入和输出均为副本。

## 测试与版本构建

```sh
tests/run.sh
```

x86_64 实时集成测试用 GCC、G++、binutils 和 Python 3 创建并附加自有子进程。覆盖快照、MCP stdio、断点命中与撤销、线程创建、槽位耗尽、加载实例和外置 DWARF。运行环境需允许 ptrace。

```sh
rustup target add aarch64-unknown-linux-musl
tests/run.sh --pi
```

树莓派集成测试默认连接 SSH 主机 `pi`，也可用 `tests/run.sh --pi <ssh-host>` 指定主机。构建机还需在 `PATH` 中提供 Zig（已验证 0.15.2）、`aarch64-linux-gnu-gcc`、`aarch64-linux-gnu-g++` 和 AArch64 GNU binutils。脚本在本机交叉构建全静态 musl 客户端和服务端，以及使用 glibc 的 C/C++ 夹具，再通过 SSH 上传并运行。树莓派需运行 64 位 Linux，提供 Python 3、与交叉工具链兼容的 glibc 和 C++ 运行库，并允许 ptrace。

真机测试覆盖全线程暂停与恢复、通用寄存器、信号处理栈、优化构建的跨共享库回溯、PIE 和非 PIE 地址、外置 DWARF、实时反汇编、MCP 与三类断点。设备信息及测试日志保存在本机 `artifacts/pi.*/integration.log`，远端临时目录在运行结束时清理。

两端集成测试也覆盖 perf、符号覆盖、DWARF 变量、汇编补丁和仿真，并检查产物的 ELF 动态依赖。有 Clang 时同时运行 GCC 与 Clang 的 DWARF 4/5 夹具。在 x86_64 上运行全静态版回归可使用 `CARGO_BUILD_TARGET=x86_64-unknown-linux-musl tests/run.sh`，需提前安装相应 Rust 目标和 Zig。

推送 `v0.1.0` 这类以 v 加数字开头的版本标签触发 **Build version** workflow。Actions 为 Linux x86_64 和 AArch64 各生成一个包含 `aidbg` 和 `aidbg-server` 的静态 musl 压缩包，并上传到该次运行的 Artifacts。普通分支推送没有版本构建。
