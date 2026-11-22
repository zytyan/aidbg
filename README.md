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
| TypeScript 命中回调、寄存器读取和可选快照 | 已通过本地集成测试 | 已通过树莓派 4B 集成测试 |
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

## Windows 客户端

Windows x64 客户端可以直连 Linux 服务端，也可以通过 SSH 转发连接，支持 CLI、MCP 和 core 下载。把示例中的账号、主机和 socket 路径换成服务端实际值。

```powershell
ssh.exe -N -o ExitOnForwardFailure=yes -L 127.0.0.1:55051:/home/user/aidbg/aidbg.sock user@server
.\aidbg.exe mcp
```

MCP 启动后在会话中调用 `connect({})`。它会连接上面的转发端口。自定义端口时，调用 `connect({endpoint: "http://127.0.0.1:端口"})`。

`--endpoint` 也可用于 Linux 客户端。可信内网可以启动 `aidbg-server --listen 0.0.0.0:55051 --state-dir "$STATE_DIR"`，再用 `--endpoint http://PI_IP:55051` 直连，或通过 MCP 调用 `connect({endpoint: "http://PI_IP:55051"})`。TCP 使用明文 gRPC，服务端同时支持 `--socket`。Windows 上的 TypeScript 检查和 core 分析在连接的 Linux 服务端执行。用 `core_open({dump_id})` 打开已保留的 core，也可用 `core_open({path, executable?, debug_symbols?})` 上传 Windows 本地文件后分析。下载 core 时将 `--output` 设到 Windows 本地磁盘，续传需要文件锁。

在 Linux 或 WSL 上，用 MinGW-w64 工具链交叉构建 Windows 客户端。

```sh
rustup target add x86_64-pc-windows-gnu
build/windows-client.sh
```

## 启动程序和处理信号

`run` 让服务端直接启动并跟踪一个进程及其线程，从第一次 `exec` 开始观察信号。CLI 和 MCP 都会等待进程结束并返回 PID、退出码或终止信号、stdout/stderr 和回调结果。命令成功返回时，从 JSON 的 `exit_code` 或 `exit_signal` 读取目标结局。可执行文件与可选的 `--cwd` 使用服务端绝对路径。参数直接传给程序。可重复传 `--env NAME=VALUE` 覆盖目标继承的环境。用 `--stdin TEXT` 提供文本，读完后 EOF。省略时 stdin 指向 `/dev/null`。默认运行超时为 30 秒，可以用 `--timeout-ms` 调整。通过 fork 创建的独立进程不在这一跟踪会话内。

传 `--pause-at-entry` 时，首次 `exec` 后立即停止，动态链接程序此时仍在加载器入口。首包包含 `run_id`、PID 和 `paused` 状态，可以安装断点、采集快照或检查变量。传 `--detach` 则从启动后继续运行，首包也包含 `run_id` 和 PID。暂停期间继续计入运行超时。

```sh
aidbg --socket "$AIDBG_SOCKET" run --pause-at-entry /absolute/path/to/program
aidbg --socket "$AIDBG_SOCKET" breakpoint set --run-id "$RUN_ID" --module program --symbol main
aidbg --socket "$AIDBG_SOCKET" run-continue --run-id "$RUN_ID"
aidbg --socket "$AIDBG_SOCKET" run-pause --run-id "$RUN_ID"
```

```ts
// signal.ts
dbg.onSignal(builtins.SIGSEGV, (seg) => {
    dbg.coredump("full");
});
```

```sh
aidbg script-api --mode signal
aidbg script-check --mode signal --source signal.ts
aidbg --socket "$AIDBG_SOCKET" run --on-signal signal.ts /absolute/path/to/program -- arg1 arg2
```

脚本在启动前完成 TypeScript 检查并注册回调。回调同步执行，可读取信号、线程、`si_code` 和故障地址。请求 `dbg.coredump("full")` 后，调试器会在交付信号前冻结目标线程并保存全量 ELF core。原始信号随后继续交付，回调或转储出错时也会交付，失败原因出现在事件的 `issue`。每个常量可注册一个回调，每次运行最多处理 32 条匹配事件。回调可用的信号列在 `script-api --mode signal` 的声明里。

成功的转储在 `signals[].coredump.dump_id` 返回 ID，可在保留期内用 MCP 的 `core_open({dump_id, executable})` 打开，或下载到客户端。

```sh
aidbg --socket "$AIDBG_SOCKET" coredump --dump-id "$DUMP_ID" --output crash.core.zst
```

MCP 的对应工具为 `run({executable, arguments?, cwd?, signal_source?, timeout_ms?})`，其中 `signal_source` 是 TypeScript 源码。

## Linux core 转储

```bash
aidbg --socket "$AIDBG_SOCKET" coredump --pid "$TARGET_PID" --output case.core.zst
aidbg --socket "$AIDBG_SOCKET" coredump --pid "$TARGET_PID" --mode extended --output ipc.core.zst
```

`aidbg script-run --core` 与 MCP `core_open` 在 Linux 客户端上通过内嵌的 Zstandard 1.5.7 解码器直接打开 `.core.zst`。使用 GDB 时，可以先导出未压缩的 ELF 文件。

```bash
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

CLI 和 MCP 的 `coredump` 把 Zstd level 1 压缩的 core 保存到显式指定的新文件，并返回采集、暂存和压缩大小、暂停时间及覆盖状态。`--timeout-ms` 默认 60000。目标有活动断点会话时先结束该会话。线程冻结、通用寄存器采集或清理失败时，命令失败。采集没有缺口或其他问题时，摘要标记为 `complete`。仅缺内核 vvar 页时，摘要标记为 `complete_without_vvar`，`comment` 说明跨进程采集时 vvar 不可读是常见现象。其他缺口或采集问题标记为 `partial`，产物仍会发布。可用至少两核时，服务端并行采集与压缩。压缩队列满时，服务端把剩余内存写入临时文件，恢复目标后继续压缩。目标设备无需安装 Zstd 命令或 GDB。离线调试按需提供匹配的可执行文件和共享库。

服务端恢复目标后，保存压缩数据并为产物计算 SHA-256。连接在采集期间中断时，已接受的采集任务会在原预算内继续。传输中断时，客户端保留 `.part` 和 `.part.json`，重连后用相同的输出路径继续下载同一个 `dump_id`。目标退出或服务端重启后，已保存的产物仍可续传。客户端校验长度和 SHA-256 后原子发布最终文件。

```bash
aidbg --socket "$AIDBG_SOCKET" coredump --resume --output case.core.zst
```

服务端默认保存已压缩产物一小时，总额度为 4096 MiB。可用 `--coredump-retention-secs` 和 `--coredump-max-mib` 调整，两项均为服务端选项。采集和压缩的暂存文件还需要额外磁盘空间。客户端默认等待每次 RPC 或下载消息最多 30 秒，可用 `--download-idle-ms` 调整。已过期的产物需要重新采集。

`tests/run.sh` 用随机数据压力夹具和业务型合成夹具各验证六种模式。业务型夹具混合堆对象、日志、稀疏内存和少量随机数据。构建夹具后，可运行 `python3 tests/coredump.py --benchmark`，用同一份解压后的 ELF 比较 Zstd level 1、3 和 5。输出耗时包含启动本地压缩工具和管道传输。

采集使用冻结前预分配的缓冲池。CLI 可用 `--buffer-mib` 和 `--block-kib` 调节，MCP 参数为 `buffer_mib` 和 `block_kib`。默认块大小是 1024 KiB，`stack-4k` 默认缓冲 2 MiB，其余含内存档默认 16 MiB。缓冲预算为 0 时，内存写入临时文件，目标恢复后压缩。单核或预算不足两个读块时使用同一路径。

模块 ELF 在冻结前解析，以冻结后读取的映射和文件身份校验缓存。需要模块内容来确定采集范围的档位会重新解析变动的模块。

摘要的 `pause_us` 从首次附加算到分离结束，`timing_us` 细分冻结、映射、寄存器、ELF、`smaps`、选区、读取、缓冲和分离，其中 `staging` 计入 `buffering`，`preflight` 在暂停窗口之外。可在构建后用 `python3 tests/coredump.py --pause-sweep` 比较缓冲预算、读块大小、暂停耗时、文件就绪耗时和服务端进程 RSS 峰值。可用 `--baseline-bin-dir` 指定旧版二进制目录做对照。


## 离线 core 脚本

客户端和服务端均内嵌 tsrs `7.1.0-beta.tsrs4` 和 QuickJS-ng `0.15.1`，构建使用 `rust-toolchain.toml` 固定的 Rust 1.100.0。TypeScript 编译使用内存文件和可复用的工程会话。每次执行创建独立的 QuickJS 运行时，开放 ECMAScript 内建对象和 `dbg`，脚本执行时限为一秒。

```bash
aidbg script-api --mode offline
aidbg script-check --source inspect.ts
aidbg script-run --core case.core.zst --executable ./app --source inspect.ts
```

```ts
const thread = dbg.threads().find(t => t.tid === 1234);
if (thread) {
    const frame = dbg.frames(thread.tid)[0];
    if (frame) dbg.printVal("g_Data->foo[10].bar->baz", { frame: frame.handle });
}
```

- `aidbg mcp` 可通过 `core_open({path, executable?, debug_symbols?})` 打开本地 ELF core，返回 `target_id`、架构、内存覆盖和符号匹配状态。用该 ID 调用 `script_check({source, mode?, target_id?})`、`script_run({source, target_id})` 和 `core_close({target_id})`。Linux 本地目标 ID 在打开它的 MCP 会话内有效。Windows 客户端自动上传。Linux 可传 `upload: true` 选择服务端分析。结果的 `analysis_host` 是 `client` 或 `server`，上传成功时同时返回 `dump_id`。
- MCP 会话调用 `connect` 后，向 `core_open` 传 `dump_id`，并给出服务端可以读取的可执行文件和可选调试符号路径。CLI 的对应入口是 `core-open --dump-id … --executable …`、`script-run --target-id … --source …` 和 `core-close --target-id …`，均带 `--socket` 或 `--endpoint`。远端目标由服务端持有，关闭目标或服务端退出后 ID 失效。
- 当前读取支持与 debugger 同架构的小端 Linux ELF64。为主可执行文件关联符号时，core 需要保存原可执行文件的 GNU Build ID note。外置调试文件的 GNU Build ID 必须匹配。DWARF 变量解析和 CFI 回溯使用已验证的主可执行文件，其他模块的变量和回溯信息尚未接入。
- 预检在 TypeScript 通过后检查已绑定的宿主调用及其中可解析的访问路径。诊断偏移使用 UTF-16，行列从 1 开始，范围尾端为开区间。动态表达式、需要运行时帧上下文的局部变量和缺少 DWARF 的表达式可在执行时尝试读取。`printVal` 把 `inspect` 的报告和标签写入结构化输出。`inspect` 返回的地址和 64 位整数在脚本里是 `bigint`，在返回的 JSON 中为字符串。
- `script_check` 和 `script_run` 返回 `check_us`。`script_run` 另返回 `emit_us`、`execute_us`、`stop_reason` 和输出。C/C++ 值的读取状态含 `null_pointer`、`missing_page` 和 `invalid_frame`。

集成测试在原生 Linux 主机生成真实 core，并覆盖本地 CLI、本地 MCP 和服务端保留的产物。客户端解压测试在服务端退出后运行，子进程的 PATH 指向空目录。运行环境需要 C++ 编译器、GDB、objcopy 和 Python 3。

```bash
c++ -O0 -g -pthread -fno-omit-frame-pointer -Wl,--build-id tests/script_fixture.cc -o /tmp/aidbg-script-fixture
c++ -O0 -g -pthread -fno-omit-frame-pointer -Wl,--build-id -DFIXTURE_VALUE=41 tests/script_fixture.cc -o /tmp/aidbg-script-wrong
python3 tests/scripts.py ./target/release/aidbg ./target/release/aidbg-server \
  /tmp/aidbg-script-fixture /tmp/aidbg-script-wrong --bench 50
```

2026-11-21 在 Intel Core i3-12300T 上用 x86_64 静态 musl release 验证。计时从已打开的双线程 core 开始。首次 `script_run` 的 MCP 往返为 **26.01 ms**，其中检查 20.18 ms、emit 0.73 ms、执行 1.10 ms。随后各循环 50 次，每次更换访问的数组下标。

| 阶段 | p50（ms） | p95（ms） |
| --- | ---: | ---: |
| 重复检查，MCP 往返 | 3.70 | 10.40 |
| 重复运行，MCP 往返 | 5.46 | 9.36 |
| 重复运行中的检查和 DWARF 预检 | 2.77 | 4.60 |
| 重复运行中的 emit | 0.73 | 1.14 |
| 重复运行中的 QuickJS 执行和读值 | 0.88 | 1.22 |

原型有效路径的热态 p50/p95 为 11.34/13.51 ms，测量至 emit 完成。本次热态运行还包含真实 core 读取和 MCP 往返，两个统计的边界不同。

小模型试跑使用 GPT‑6 Luna，三次独立提交只提供 `script_api` 声明、一个短示例和读值任务。首次 TS 检查 3/3 通过，DWARF 预检验证 2/3，执行结果 3/3 符合预期。调用者局部变量的帧来自运行时选择，预检报告 `NO_FRAME_CONTEXT`，执行读取值 91。

用同一 Rust 1.100.0、Zig 0.15.2 和 release 配置重建基线 `ef2e906`。以下是离线脚本交付时剥离符号后的静态 ELF 大小。

| 架构 | 二进制 | 基线（MiB） | 离线脚本（MiB） | 增量（MiB） |
| --- | --- | ---: | ---: | ---: |
| x86_64 | `aidbg` | 4.35 | 25.97 | +21.62 |
| x86_64 | `aidbg-server` | 12.24 | 32.00 | +19.77 |
| aarch64 | `aidbg` | 3.81 | 23.02 | +19.22 |
| aarch64 | `aidbg-server` | 11.33 | 28.94 | +17.61 |

AArch64 包装器沿用旧版 Zig 的链接行为，因为 Zig 0.15.2 拒绝新版 Rust 传入的 Cortex‑A53 843419 勘误选项。

AArch64 启用 tsrs 的 `plain-ptrs`，以适配 Raspberry Pi 4 等用户态虚拟地址范围较小的环境。

AArch64 的客户端和服务端在原生 Raspberry Pi 4 Model B 上通过静态 ELF 检查和完整集成测试。静态客户端在服务端退出、PATH 指向空目录时通过 CLI 和 MCP 从 `.core.zst` 读值。Pi 上首次运行的 MCP 往返为 28.12 ms，50 次重复运行的 p50/p95 为 8.80/9.00 ms，其中检查为 4.78/4.93 ms、emit 为 1.18/1.25 ms、执行为 1.73/1.82 ms。

## 冻结模式

| 参数 | 采集方式 |
|---|---|
| `--freeze never` | 只读 `/proc`。线程、信号、内存和模块照常返回，寄存器与用户栈为空 |
| `--freeze try`（默认） | 尝试全线程暂停。未完全停止时返回可用的 `/proc` 信息和已停线程的寄存器 |
| `--freeze required` | 确认全线程暂停后才开始主体采集。冻结失败时返回错误与分离结果 |

JSON 的 `freeze_achieved` 与 `status` 独立。全组已停但某线程缺少展开信息时，仍可能返回部分栈。地址和寄存器用十六进制字符串。回溯使用 gimli CFI 并尝试帧指针后备路径。符号化和快照保存发生在分离之后。

`status` 可为 `complete`、`partial` 或 `failed`。CLI 对应退出码为 0、0、1，命令行参数错误为 2。服务端将附加、等待和分离留在同一 OS 线程完成。客户端请求中途断开时，已开始的采集仍由服务端清理。

## 硬件执行断点

Linux x86_64 的执行断点和观察点共享四个槽位。AArch64 有独立的执行和数据槽位，执行地址须四字节对齐。断点命中时，服务端默认采集快照并恢复目标。可用 TypeScript 回调决定命中时采集什么。默认采集命中线程，`--all-threads` 请求采集全进程。AArch64 为单步恢复会短暂停住其他线程。回调预算由 `--timeout-ms` 设置，默认 100 毫秒。采集在各步骤之间检查预算，超时后进入恢复流程。阻塞的系统调用返回后才能继续清理，事件记录实际观测到的暂停时长。

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
aidbg --socket "$AIDBG_SOCKET" breakpoint set --run-id "$RUN_ID" --kind software \
  --file D06.c --line 12
```

能力查询返回每线程的执行断点和观察点容量。x86_64 共用一组槽位。AArch64 分别报告两组槽位，可使用 `--pid` 或 `--run-id` 查询指定目标。文件行号断点优先选择 DWARF 语句地址，也可定位到有明确入口的函数声明行。找不到地址或地址有歧义时返回 `LINE_UNAVAILABLE`，可用 `--module` 和 `--instance` 缩小范围。

硬件观察点支持 `write` 和 `read-write`，宽度为 1、2、4 或 8 字节，地址须按宽度对齐。命中事件包含前后采样值和 `value_changed`。x86_64 同时观察到多次访问时，无法归属的比较结果为 `null`。AArch64 记录内核报告地址及精确或近似归属，并对触发指令单步比较前后值。在读写模式下，`write_observed` 为 `null`。

软件断点接受私有可执行映射中的指令地址。命中时暂停同进程的其他线程，单步执行原指令，再恢复断点。创建独立子进程时，含软件断点的会话会清理父子地址空间中的补丁并结束。请通过移除断点或正常关闭 server 触发清理。

## 断点与观察点回调

硬件和软件执行断点及硬件观察点共用 `onHit` 接口。服务端安装前检查 TypeScript 并初始化模块。使用默认导出函数时，通过断点的 `timeout_ms` 设置每次回调的暂停预算。模块变量在同一断点的多次命中间保留，脚本可用它们记录计数或保存读取结果。

```ts
let matches = 0;

export default function onHit(hit: BreakpointHit) {
    if (hit.watch?.changed === false) return false;
    hit.emit("address", hit.address);
    if (++matches === 3) hit.disable();
}
```

将脚本保存为 `hit.ts`。CLI 使用 `--rule` 传文件，MCP 的 `breakpoint_set` 使用 `rule_source` 传源码。

```bash
aidbg script-api --mode breakpoint
aidbg script-check --mode breakpoint --source hit.ts
aidbg --socket "$AIDBG_SOCKET" breakpoint set --pid "$TARGET_PID" --address "$PC" --rule hit.ts
aidbg --socket "$AIDBG_SOCKET" breakpoint set --pid "$TARGET_PID" --kind write --address "$WATCH" --length 8 --rule hit.ts
aidbg --socket "$AIDBG_SOCKET" breakpoint events
```

- `hit` 提供 PID、命中线程的 TID、断点或观察点地址、类型及命中时的通用寄存器。寄存器和地址是 `bigint`。AArch64 观察点的寄存器来自触发指令单步执行前。
- `hit.watch` 只在观察点回调中提供。可用时，`valueBefore`、`valueAfter` 为 `bigint`，`changed` 为布尔值，与事件中的 `watch` 来自同一次采集。无法观测的值为 `undefined`。
- `hit.inspect(expression)` 从命中线程当前帧读取 DWARF 值，优先查找该帧所在模块中的全局变量，返回 `DebugValue`。`hit.memory(address, length)` 每次读取 1–4096 字节，返回原生 `DataView`（`view`）、十六进制 `bytes` 和 `complete`。短读时 `view.byteLength` 和 `bytes` 只覆盖已读取的前缀。`view.getUint32(offset)` 按标准读取大端，传 `true` 读取小端。脚本可以跨命中保留 `view`，写入方法只修改它持有的副本。AArch64 观察点的这两种读取以及回调请求的快照发生在触发指令单步执行后。共享内存的一致性取决于其他写入线程是否已冻结。
- `hit.emit(label, value)` 将标量或字节视图写入事件的 `callback.output`。JSON 中的 `bigint` 是整数。使用 `{ kind: "pointer" }` 输出十六进制地址，使用 `{ kind: "json" }` 输出结构体和数组。离线的 `dbg.emit` 使用同一套选项。`hit.snapshot()` 请求沿用现有采集及保存流程，可以继续用事件 ID 查询。未请求时 `snapshot_status` 为 `not_requested`。
- 回调同步执行，读取和快照共用回调的剩余暂停预算。返回布尔值 `false` 时省略本次成功命中的事件和快照。调用 `hit.disable()` 会在本次命中处理后撤销当前断点，也可与 `return false` 一起使用。异常和超时会记录 `callback.status`、`callback.issue` 和 `callback.disarming`，撤销当前断点，并保留已提交的输出和目标恢复结果。
- 默认导出函数自行控制断点生命周期，只使用外部的 `timeout_ms` 预算，默认 100 毫秒。已有的 `defineRule({onHit, maxHits?, pauseBudgetMs?})` 写法仍可使用。该写法默认执行 100 次，`maxHits` 可设置为 1–1000，返回 `false` 的回调也计入。`pauseBudgetMs` 可设置为小于等于断点预算的值。

MCP 的 `rule_define({name, source})` 在服务端登记命名规则。将返回的 `rule_id` 传入多个 `breakpoint_set` 调用即可复用。`rule_list()` 返回命名规则、当前版本和累计回调命中数。`rule_remove({rule_id})` 只删除未被断点引用的规则。规则保存在服务端内存中。重复调用 `rule_remove` 返回 `already_removed`。

`rule_update({rule_id, source})` 验证全部引用断点的配置后发布新版本。验证失败时所有引用继续使用原版本。更新保留断点 ID 和历史事件。每个断点独立保存模块状态和命中序号，发布新版本时重新初始化。已开始处理的一批命中仍使用原版本。事件中的 `rule_id` 和 `rule_revision` 标识实际执行的规则版本。继续使用 `rule_source` 会为该断点创建匿名规则，命中事件也会记录其 ID 和版本。

`breakpoint_update({breakpoint_id, address?, rule_id?})` 修改单个断点的位置或命名规则，保留断点 ID 和历史事件。CLI 对应 `breakpoint update --breakpoint-id ID --address ADDRESS --rule-id RULE`。

### 活进程脚本与线程限定

- CLI 的 `read-memory --run-id ID --address ADDRESS --length N` 和 MCP 的 `read_memory` 都接受 `run_id`、`pid` 或 core 的 `target_id`。两种目标返回同样的十六进制 `bytes`、`bytes_read` 和 `complete`。遇到缺页时保留连续可读前缀并给出 `first_unread_address`。读运行中的目标时，数据可能被目标并发修改。
- `hit.locals(page?)`、`hit.globals(glob?, page?)` 和 `hit.types(glob?, page?)` 使用离线脚本的分页结果。回调中的枚举使用命中帧所属模块的 DWARF。两种脚本也共用 `modules()`、`memory()`、`inspect()`、`printVal()` 的结果格式。离线读取变量时传入 `{frame}`，回调使用当前命中帧。
- 对暂停的 run 使用 `step` 执行一条机器指令，`next` 跨过当前调用，`step_out` 执行到当前帧的返回位置。三个工具都接受 `run_id`、可选 `tid`、`timeout_ms` 和 `max_steps`。调试器停点、信号、系统调用边界或预算会提前结束步进，结果包含 `stop_reason` 和当前 PC。
- `run({exit_coredump: true, …})` 在进程领头线程的退出停点保存 core。通过 `exit_coredump.dump_id` 打开，采集失败可查看 `exit_coredump_issue`。CLI 对应 `run --exit-coredump`。
- `run_list` 列出仍在保留期内的 run。受管理进程的断点按 `run_id` 管理，在进程退出后自动撤销。对已撤销断点的重复移除返回 `already_removed`，历史事件在事件缓冲区内仍可查询。用 `breakpoint_list({run_id})` 检查当前安装状态，用 `breakpoint_capabilities({run_id})` 的 `used_slots` 查看每线程实际配置的执行、观察及共享槽位占用。
- 观察点可用 `module + offset` 或 `module + symbol + offset` 定位。CLI 示例为 `breakpoint set --run-id ID --kind write --length 4 --module D08 --symbol rows --offset 0`。偏移相对于 ELF 模块基址或选中符号。

- `inspect` 的 `timeout_ms` 可设为 1–5000 毫秒。MCP、`hit.inspect` 和离线 `dbg.inspect` 都接受 `expand: {offset?, limit?}`，返回结构体字段、数组或 `std::array` 元素的分页结果。`printVal` 可用同样的展开选项。页大小为 1–64，`next_offset` 为下一页边界。
- `observe_threads({run_id|pid|target_id, samples?, interval_ms?, locks?, waits?})` 返回线程状态变化和最新一帧锁依赖图。`locks` 中每个条目使用 `{address, owner_offset?}`，默认偏移 8 字节，适用于 glibc mutex。活进程通过可读的 futex 系统调用识别等待线程，锁图按观察到的等待者和锁所有者连边。core 提供单次采集状态和寄存器，可提供 `waits: [{tid, address}]` 作为等待证据。采样间发生的变化可能遗漏。
- `breakpoint_events` 的 `accesses` 按地址、线程、停点 PC 和访问类型统计本次返回的观察点事件。没有充分证据区分读写时返回 `unknown`。x86 的记录 PC 位于触发指令执行后。
- 观察点事件的 `stop_context` 包含停点函数、可用的源码行、被观察地址的符号和命中时采集的形参。预算或 DWARF 不足时，参数页会带状态。先读 `pc_relation` 判断停点 PC 是否位于触发指令之后。
- `core_retain({dump_id, retention_secs})` 可将仍在保留期内的 core 延长到距当前时间最多 30 天。下载文件的 `path` 属于客户端，`dump_id` 属于连接的服务端。

MCP 的 `script_run({run_id, source})` 在目标的 tracer 会话中执行脚本，返回 `breakpoint_ids` 和 `return_value`。脚本失败时回滚本次安装并丢弃本次断点的事件。用 `script_api({mode: "live"})` 查看声明，或用 CLI 运行脚本。offline、live 和命中回调共用 `src/script/debugger.d.ts`。live 安装阶段的 `dbg` 可直接调用 `threads`、`frames`、`locals`、`globals`、`types`、`modules`、`memory`、`inspect`、`printVal` 和 `emit`。这些入口使用 tracer 暂停的上下文，在放行前读取。命中后用 `hit` 访问命中线程，`hit.frames(hit.tid)` 可选取调用栈中的帧。

```sh
aidbg --socket "$AIDBG_SOCKET" script-run --run-id "$RUN_ID" --source live.ts
aidbg --socket "$AIDBG_SOCKET" breakpoint set --run-id "$RUN_ID" --tid "$TID" --address "$PC"
```

```ts
let hits = 0;
dbg.hardwareBreakpoint(0x401020n, hit => {
    hit.emit("address", hit.address, { kind: "pointer" });
    hit.emit("hits", ++hits);
    if (hits === 3) hit.disable();
}, { tid: 1234, timeoutMs: 50 });
```

同一个函数传入多个断点时，它们共享该函数的闭包。每次运行顶层脚本都有独立的模块作用域。省略回调时命中会保存快照。安装后仍可通过 `run_continue` 继续入口暂停的目标。`dbg.softwareBreakpoint` 使用相同参数。

`dbg.watchpoint(address, length, "read" | "write" | "read_write", callback, options?)` 与 MCP 观察点共用同一个安装和回调路径。AArch64 支持只读观察点。通过 `breakpoint_capabilities.watch_access` 查看目标支持的模式。`tid` 可通过 MCP 的 `breakpoint_set`、CLI 的 `--tid` 或脚本选项传入。硬件断点和观察点使用选定线程的槽位。软件执行断点会让其他线程经过同址时单步执行原指令，跳过逻辑命中。定向断点在线程退出后自动撤销。快照范围仍由 `all_threads` 控制。

要在一次调用中收集事件，在安装完成后调用 `dbg.continue()`，再 `await dbg.events()`。事件集合包含本次脚本安装的断点，默认等待目标退出的上限为一秒。在线和离线的 `script_run` 都可通过 `timeout_ms` 调整执行预算，范围为 1–10000 毫秒。两者都支持顶层 `return` 和默认导出函数。MCP 的 `breakpoint_workflow({run_id?, run?, points, timeout_ms?})` 封装了安装、继续和收集流程。每个点可用 `address` 或 `symbol` 配合可选的 `module` 和 `offset`，并指定命中时读取的 `expressions`。`return_value` 按事件采集顺序排列，`points` 给出每个站点的观测命中次数和回调完成状态。

```ts
export default async function main() {
    const point = dbg.hardwareBreakpoint(0x401020n, hit => {
        hit.emit("attempts", hit.inspect("job.attempts").result?.value ?? null);
    });
    dbg.continue();
    return (await dbg.events()).filter(event => event.breakpoint_id === point.id);
}
```

`rule_define({name, source, mode: "exports"})` 登记 TypeScript 模块的命名同步函数。通过 `breakpoint_set({run_id, address, handler: "$.someHit"})` 绑定导出。每个目标会话独立初始化模块，同一会话内使用相同版本的断点共享模块状态。`rule_update` 保留这些断点的 ID 和命中序号，在命中批次之间切换版本。

所有回调通过 `callback.output` 提供结构化字段。MCP 同时提供文本字段行。整数同时显示十进制和十六进制，指针仅显示十六进制，浮点数包含 `f64` 位模式，`DataView` 和 `Uint8Array` 的字节以 `0a 0c 33 36` 的格式显示。CLI 的断点事件在 `callback.output_text` 中提供这些行。

通过 `coredump` 保留带活动断点的 core 后，`export_bundle` 会附带 `rules/*.ts` 和 `breakpoints.json`。后者记录原始地址、模块标识和模块内偏移。启动新的入口暂停 run 后调用 `restore_breakpoints({bundle, run_id})`，或执行 `aidbg restore-breakpoints --bundle DIR --run-id ID`。工具按新进程的模块加载地址恢复断点，返回新旧 ID 的对应关系。恢复支持有模块偏移的地址及主线程限定。使用 `restore_breakpoints({bundle, launch: true})` 可直接上传客户端 bundle 中的可执行文件，在连接的服务端启动入口暂停的 run 并恢复断点。

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

在 MCP 客户端注册可执行文件 `aidbg`，启动参数为 `["mcp"]`。需要访问服务端时，先在同一 MCP 会话里调用 `connect`。

- `capabilities`，按任务查看工具、目标选择器和示例。对已有 Linux 进程，可直接向支持该选择器的工具传入 `pid`。
- `connect`，Linux 本地连接传 `{socket: "/absolute/path/aidbg.sock"}`。SSH 转发连接传 `{endpoint: "http://127.0.0.1:55051"}`。空对象默认连接该转发地址。连接验证成功后，同一会话的远程工具使用新连接。连接失败时可以继续使用上一次成功连接。返回值包含客户端版本、远端版本、构建修订和远端能力，以及服务端探测到的用户态 VA 位数与 ASan 高位地址可映射性。两端 CLI 均支持 `--version`。
- `snapshot`，接受 `pid` 或 detached run 的 `run_id`，以及 `freeze` 和可选的 `fields`、`tid`、`frames`。
- `snapshot_query`，接受 `snapshot_id` 或断点 `event_id` 及相同的筛选项。
- `coredump`，接受 `pid`、`output` 和可选采集参数，返回输出路径、`dump_id` 和采集摘要。设置 `resume: true` 后用原 `output` 续传，可用 `download_idle_ms` 调整下载等待时间。
- `core_open`、`core_close`，管理离线 core 目标。`script_api` 和 `script_check` 提供离线脚本、断点回调和信号回调的声明和检查，`script_run` 执行离线脚本。
- `run`，启动一个服务端进程，从程序入口跟踪信号，可用 TypeScript 回调保留崩溃现场。支持 `env`、`stdin`、`detach` 和 `pause_at_entry`。用 `run_pause`、`run_continue` 控制运行，用 `run_status` 和 `run_cancel` 查询或取消。断点安装、移除、快照和变量检查可用 `run_id` 复用该进程的 tracer。
- `breakpoint_set`、`breakpoint_remove`、`breakpoint_events`，安装、撤销和查询断点或观察点。使用 `rule_source` 传入 TypeScript 回调，或用 `rule_id` 复用已登记的回调。
- `rule_define`、`rule_list`、`rule_update`、`rule_remove`，管理服务端命名断点规则。
- `breakpoint_capabilities`，查询观察类型、宽度、对齐和槽位。
- `symbols`、`resolve_address`、`disassemble`，接受 live `pid` 或离线 `target_id`，查询 ELF 符号、运行时地址和指令。
- `search_memory`、`xref`、`pointer_chain`，搜索字节、查找引用或跟踪 core 中的指针链。前两项还接受活进程的 `pid` 或 `run_id` 和明确的 `start/end`。
- `export_bundle`，将保留的 core、匹配镜像和分析材料导出到客户端目录。
- `perf`、`symbol_override_set`、`symbol_override_list`、`symbol_override_remove`、`inspect`，采样和查询进程状态。
- `assemble`、`plan_patch`、`emulate`，汇编、生成离线补丁和运行仿真。
- `watch_step`、`target_call`，限域单步观察与标量目标函数调用。

本机直接连接 socket。远程主机已有 SSH 时，也可通过 SSH 转发该 socket 后接到同一 client。测试版建议 client 和 server 使用同一个构建版本。

### 从崩溃 core 恢复证据

`core_open({dump_id})` 默认使用采集元数据定位并验证主程序。可显式传入服务端的 `executable` 和 `debug_symbols` 路径。原路径上的文件已替换或不可访问时，返回可查询的 core 和带代码的警告。旧 core 可以根据主程序入口和映射记录定位镜像。在 Linux 客户端打开的外部文件支持显式提供 ELF。采集摘要保留 `missing_ranges` 计数，`missing_range_details` 的每项给出半开地址区间和原因。`PARTIAL_CORE` 说明采集覆盖有缺口，成功读取的证据仍可使用。

需要从同一帧取多个值时，直接调用 `inspect({target_id, expressions: ["account->id", "account->profile"]})`。可传 `tid` 和从零开始的 `frame_index`。省略 `tid` 时选择唯一线程或唯一带停止信号的线程。批量结果按输入顺序返回，每项有独立的读取状态。回包带所选帧的函数、源码行和可恢复的形参。变量的存储地址在 `result.address`，指针指向的代码或数据符号在 `result.symbol`。可识别的 `char*` 和 libstdc++ 窄字符 `std::string`、`std::string_view` 在 `result.preview` 给出文本、原始字节和读取状态，最多读取 256 字节。

`inspect` 的 `result.type.fields` 和 `dbg.types(glob)` 返回可用的聚合布局，包括字段偏移、字节数和数组维度。查内存变化时，把同地址同长度的两份 `read_memory` 回包传给 `memory_diff({before, after})`。也可把两个停点已采集的字节整理成 `{address, length, bytes}`。回包仅比较两份都有数据的前缀，并给出首个不可比较地址。

`dbg.frames(tid)` 给出运行时 PC、符号及可用的文件、行、列。活进程的快照优先使用与模块 ELF 匹配的独立符号文件，glibc 的内部帧依赖目标机或服务端有匹配的调试符号。`dbg.locals(frame.handle)`、`dbg.globals(glob)` 和 `dbg.types(glob)` 返回带分页的发现结果。`dbg.modules()` 从映射记录恢复模块。`script_run` 将 `console.log` 写入 `output`，并调用可选的 `export default function main()` 生成 `return_value`。依赖运行时 frame handle 的表达式在预检中标为 `runtime_only`。`script_api` 的 `discovery_example` 给出可直接检查的多行 TypeScript 示例。日志和返回值中的大整数采用形如 `{"$bigint":"18446744073709551615"}` 的表示。

`disassemble` 的 `byte_source` 为 `core` 或 `executable`。当该指令区间未被采集时，工具可以使用已验证 ELF 的文件字节，并在回包中加上警告。指令 `xref` 需要传 `instruction_references: true` 及从已知指令边界开始的 `start/end` 区间。其结果区分直接跳转目标、PC 相对引用和默认模式的内存指针值。AArch64 还能识别同一基本块内可确定的页基址、取地址和访存，并提示跳过的不可解码指令词。分页时保持 `start/end`，将 `next_address` 传给 `resume_from`。

`plan_patch` 可用 `target_id` 和 `original_length` 读取原指令。基于 core 的 `emulate` 使用 `target_id` 和 `frame`，可通过 `code_length`、`core_memory` 复制原始现场，再叠加指定的寄存器和内存变更。读取缺页或缺少仿真所需寄存器时返回明确的错误。

```bash
aidbg --socket "$AIDBG_SOCKET" run --detach --on-signal signal.ts "$PROGRAM"
aidbg --socket "$AIDBG_SOCKET" snapshot --run-id "$RUN_ID" --freeze required
aidbg --socket "$AIDBG_SOCKET" run-status --run-id "$RUN_ID"
aidbg --socket "$AIDBG_SOCKET" export-bundle --dump-id "$DUMP_ID" \
  --output ./replay --script-file analysis.ts
aidbg script-run --core ./replay/target.core.zst --executable ./replay/executable \
  --source ./replay/analysis.ts
```

若 bundle 含独立符号文件，回放时再传 `--debug-symbols ./replay/executable.debug`。`manifest.json` 记录校验值、采集覆盖、构建版本和回放路径。MCP 调用还可传入 `script_output`、`environment` 和 `conclusion`。

活进程搜索读取当时的内存。需要一致的字节视图时，先暂停目标。观察点事件的 `value_before` 和 `value_after` 为十六进制字符串，`value_before_decimal` 和 `value_after_decimal` 为保留全部精度的十进制字符串。

目标函数调用在进程内实际执行，可能改变内存、写文件、发起 I/O 或影响其他进程。函数出错时，这些副作用也可能已经发生。

服务端可通过 `--target-call-policy` 加载 JSON 白名单，匹配解析出的 ELF build ID 和原始函数符号。配置示意为 `{"allow":[{"build_id":"abcdef01","symbol":"get_quota"}]}`。空 `allow` 禁用所有目标调用。服务端将请求、授权结果和完成状态写入私有状态目录中的 `target-call-audit.jsonl`。

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

用于评估 AI 故障定位的 13 个独立样例覆盖 D01–D10 和 D13–D15，附复现步骤、验证脚本和参考答案。[AI 故障定位样例](tests/debug-cases/README.md)

```sh
tests/run.sh
```

x86_64 实时集成测试用 GCC、G++、binutils 和 Python 3 创建并附加自有子进程。覆盖快照、MCP stdio、断点命中与撤销、线程创建、槽位耗尽、加载实例和外置 DWARF。运行环境需允许 ptrace。

```sh
rustup target add aarch64-unknown-linux-musl
tests/run.sh --pi
```

树莓派集成测试默认连接 SSH 主机 `pi`，也可用 `tests/run.sh --pi <ssh-host>` 指定主机。构建机用 Zig（已验证 0.15.2）交叉构建静态 musl 客户端和服务端，通过 SSH 上传二进制和夹具源码。树莓派直接编译 C/C++ 夹具并运行测试，需要 64 位 Linux、`cc`、`c++`、GNU binutils、Python 3 和 ptrace 权限。

真机测试覆盖全线程暂停与恢复、通用寄存器、信号处理栈、优化构建的跨共享库回溯、PIE 和非 PIE 地址、外置 DWARF、实时反汇编、MCP 与三类断点。设备信息及测试日志保存在本机 `artifacts/pi.*/integration.log`，远端临时目录在运行结束时清理。

两端集成测试也覆盖 perf、符号覆盖、DWARF 变量、汇编补丁和仿真，并检查产物的 ELF 动态依赖。有 Clang 时同时运行 GCC 与 Clang 的 DWARF 4/5 夹具。在 x86_64 上运行全静态版回归可使用 `CARGO_BUILD_TARGET=x86_64-unknown-linux-musl tests/run.sh`，需提前安装相应 Rust 目标和 Zig。

推送 `v0.1.0` 这类以 v 加数字开头的版本标签触发 **Build version** workflow。Actions 为 Linux x86_64 和 AArch64 各生成一个包含 `aidbg` 和 `aidbg-server` 的静态 musl 压缩包，并上传到该次运行的 Artifacts。普通分支推送没有版本构建。
