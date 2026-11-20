# aidbg

Linux C/C++ 进程调试工具，测试版。项目面向 x86_64 和 AArch64。Rust 服务端在目标主机运行，客户端提供命令行和 MCP stdio。两端通过 Unix socket 上的 gRPC / Protobuf 通信。

后续功能、验收边界和实现顺序见 [需求与路线图](REQUIREMENTS.md)。

## 平台支持

| 功能 | Linux x86_64 | Linux AArch64 |
|---|---|---|
| 进程快照、寄存器和调用栈 | 已通过本地集成测试 | 已交叉构建，待真机验收 |
| ELF 符号、地址查询和本地外置 DWARF | 已通过本地集成测试 | 已交叉构建，待真机验收 |
| Capstone 反汇编 | 已通过实时进程测试 | 已通过指令样本测试和 musl 交叉构建，待实时进程验收 |
| 硬件执行断点、硬件数据观察点、软件执行断点 | 已通过本地集成测试 | 尚未实现 |

`breakpoint capabilities` 可查询当前服务端开放的断点类型、观察点宽度、对齐和槽位。树莓派上的后续工作见 [AArch64 真机验收](REQUIREMENTS.md#aarch64-真机验收)。

## 构建和运行

构建需要 Rust 工具链和 C 编译器。服务端静态链接 Capstone。

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

## 冻结模式

| 参数 | 采集方式 |
|---|---|
| `--freeze never` | 只读 `/proc`。线程、信号、内存和模块照常返回，寄存器与用户栈为空 |
| `--freeze try`（默认） | 尝试全线程暂停。未完全停止时返回可用的 `/proc` 信息和已停线程的寄存器 |
| `--freeze required` | 确认全线程暂停后才开始主体采集。冻结失败时返回错误与分离结果 |

JSON 的 `freeze_achieved` 与 `status` 独立。全组已停但某线程缺少展开信息时，仍可能返回部分栈。地址和寄存器用十六进制字符串。回溯使用 gimli CFI 并尝试帧指针后备路径。符号化和快照保存发生在分离之后。

`status` 可为 `complete`、`partial` 或 `failed`。CLI 对应退出码为 0、0、1，命令行参数错误为 2。服务端将附加、等待和分离留在同一 OS 线程完成。客户端请求中途断开时，已开始的采集仍由服务端清理。

## 硬件执行断点

Linux x86_64 支持每个目标最多四个硬件执行断点。断点命中时，服务端执行内部快照回调并恢复目标。默认采集命中线程，`--all-threads` 请求冻结整个进程。回调预算由 `--timeout-ms` 设置，默认 100 毫秒。采集在各步骤之间检查预算，超时后进入恢复流程。阻塞的系统调用返回后才能继续清理，事件记录实际观测到的暂停时长。

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

x86_64 观察点支持 `write` 和 `read-write`，宽度为 1、2、4 或 8 字节，地址须按宽度对齐。观察点与硬件执行断点共用四个槽位。命中事件包含前后采样值和 `value_changed`。同时观察到多次访问时，无法归属的比较结果为 `null`。在读写模式下，硬件事件未提供触发访问的读写方向，`write_observed` 为 `null`。

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
- `breakpoint_set`、`breakpoint_remove`、`breakpoint_events`，接受对应命令的参数。
- `breakpoint_capabilities`，查询观察类型、宽度、对齐和槽位。
- `symbols`、`resolve_address`、`disassemble`，查询 ELF 符号、运行时地址和反汇编窗口。

本机直接连接 socket。远程主机已有 SSH 时，也可通过 SSH 转发该 socket 后接到同一 client。测试版建议 client 和 server 使用同一个构建版本。

## 测试与版本构建

```sh
tests/run.sh
```

x86_64 实时集成测试用 GCC、G++、binutils 和 Python 3 创建并附加自有子进程。覆盖快照、MCP stdio、断点命中与撤销、线程创建、槽位耗尽、加载实例和外置 DWARF。运行环境需允许 ptrace。

推送 `v0.1.0` 这类以 v 加数字开头的版本标签触发 **Build version** workflow。Actions 为 Linux x86_64 和 AArch64 各生成一个包含 `aidbg` 和 `aidbg-server` 的静态 musl 压缩包，并上传到该次运行的 Artifacts。普通分支推送没有版本构建。
