# aidbg

aidbg 是面向 Agent 的 Linux 调试器。客户端通过 MCP stdio 接收请求，通过明文 gRPC 访问服务端。服务端支持 Linux x86-64 和 AArch64，调试与服务端架构一致的 64 位目标。客户端也支持 Windows x64。

## 下载

GitHub Release 分别提供客户端 `aidbg-client-*` 和服务端 `aidbg-server-*`。Windows x64 提供客户端 ZIP，Linux x86-64 和 AArch64 提供客户端和服务端的 tar.gz。AArch64 的两种包分别标记为 `plain-ptrs`（非压缩指针）和 `compressed-ptrs`（压缩指针）。用户态虚拟地址范围较小的 AArch64 系统应选用 `plain-ptrs`。

## 启动

在 Linux 调试主机上构建并启动服务端。

```sh
cargo build --release --locked --bins
state_dir="$(mktemp -d)"
target/release/aidbg-server --state-dir "$state_dir" --socket "$state_dir/aidbg.sock"
```

在需要非压缩指针的 AArch64 系统上，从源码构建时加上 `--features plain-ptrs`。

在 MCP 客户端配置中，将 `command` 设为 `aidbg` 可执行文件的绝对路径，`args` 设为 `["mcp"]`。启动后调用 MCP 工具 `connect`，传入 `{"socket": "/absolute/path/to/aidbg.sock"}`。跨主机或从 Windows 连接时，在服务端使用 `--listen HOST:PORT`，再向 `connect` 传入 `{"endpoint": "http://HOST:PORT"}`。明文服务应仅绑定可信网络或通过 SSH 转发访问。`aidbg help mcp` 提供两种服务端启动方式。

每个调试会话拥有一个调试目标。`connect` 返回 `session` 令牌，客户端重启后可将该令牌传给 `connect` 以恢复同一个会话。也可以指定自己的令牌，须包含 24 至 128 个 ASCII 字母、数字、连字符或下划线。服务端在 30 秒内未收到客户端请求或心跳后释放调试目标。

## MCP 工具

工具默认在 MCP `content` 中返回可读文本。需要兼容原有的结构化 MCP 客户端时，可传入 `output_format: "structured"`。脚本内继续使用结构化的 `dbg` 和 `Value` API 处理数据。

| 工具 | 参数和用法 |
| --- | --- |
| `connect` | 连接服务端。填写 `socket` 或 `endpoint`，可传入 `session` 复用会话。 |
| `docs` | 返回 `script_run` 的完整 TypeScript 声明、可导入模块和脚本执行规则。可在连接前调用。 |
| `run` | `path` 是服务端程序的绝对路径，`arg` 是可选字符串数组。目标默认继续运行，`pause: true` 在 exec 后暂停。结果包含当前目标状态。 |
| `attach` | `pid` 是进程 ID。线程默认继续运行，`pause: true` 保持暂停。结果包含当前目标状态。 |
| `core_open` | `path` 是服务端上的 ELF core 或 zstd 压缩的 core，可指定 `executable` 和 `debug_symbols`。 |
| `script_run` | `src` 是 TypeScript 模块源码。可通过 `run: {path, arg, pause}` 先启动目标，通过 `wait_ms` 等待完成并收集输出。文本模式默认等 100 毫秒。传入 `wait_ms: 0` 可立即收集当前进度。 |
| `script_wait` | 按 `script_id` 等待已提交的脚本，默认等 5 秒。超时后脚本继续执行。 |
| `status` | 查看会话、目标、线程、暂停原因、断点、观察点、信号策略、运行中的脚本、输入请求和待处理事件。查询保留目标状态和待收集的输出。 |
| `gdb` | 执行支持的 GDB 指令。传入 `command`，例如 `bt`、`info locals` 或 `disassemble main`。 |
| `snapshot` | 可传入 `tid` 获取指定线程的快照。默认暂停预算为 1 秒，超时可返回部分结果。采集时先保存已暂停线程的寄存器，再分配栈展开预算。`stop_timeout_ms: 0` 仅采集已暂停线程。`context: true` 会附上 live 目标的状态、syscall、文件描述符和等待点。 |
| `send_input` | 向正在通过 `ask()` 等待回复的 `handler` 传入字符串 `data`。 |
| `interrupt_input` | 向指定 `handler` 抛出异常，可传入消息 `msg`。 |
| `perf` | 传入 `pid`，选择 `hotspot` 或 `stack`。可选 `tid`、`duration_ms`、`frequency_hz`。 |
| `ps` | 列出进程，默认省略命令行参数并隐藏内核线程。支持 `threads`、`pattern`、`fields`、`limit`、`offset`。 |
| `syscall_table` | 列出服务端原生架构的 Linux syscall ID、名称和六个顺序固定的参数槽。可按 `id` 或 `name` 筛选。 |
| `set_fork_policy` | 传入 `mode: "parent"` 或 `mode: "child"`，设置普通 fork 后跟踪哪一侧。 |

脚本可用 `fmt.status()`、`fmt.snapshot()`、`fmt.frame()`、`fmt.registers()`、`fmt.address(addr)` 和 `fmt.disassemble(addr)` 直接输出调试信息。需要继续处理数据时，使用 `dbg.snapshot()`、`dbg.symbolAt(addr)`、`dbg.disassemble(addr, count)` 和 `value.$toJS()`。`fmt.printf`、`fmt.sprintf`、`fmt.hexdump`、`fmt.bytesFromHex` 接管原调试输出辅助方法。

`value.$format()` 和模板插值使用有界输出。`Type.withFormatter()` 返回带自定义格式化函数的新类型。`$asType(type)` 创建同地址视图。`$toJS()` 保留已知视图的循环关系，把空指针转换为 `null`，将无效 UTF-8 字节替换为 U+FFFD。读取失败、缺少终止符或超出转换预算会抛出错误。`fmt.diff(before, after)` 可比较包含循环引用的普通数据。

栈回溯复用已验证调试镜像的 DWARF 数据。源码行号和内联帧按镜像内地址缓存，可在后续回溯中复用。

GDB 兼容指令与脚本共享目标和断点。支持 `bt`、`thread apply all bt`、`thread TID`、`frame`、`up`、`down`、常用 `info` 查询、`b`、`delete`、`disable`、`enable`、`c`、`si`、`ni`、`finish` 和 `disassemble`。`p` 和 `ptype` 接受当前帧的变量名。`x` 支持默认的十六进制字和显式 `x/16xb`。源代码重映射可通过 `set substitute-path FROM TO` 或 `dbg.substitutePath(from, to)` 注册。`list` 读取重映射后的路径。

调试器用 `*` 标记事件和警告。异步脚本报告脚本 ID 和运行或等待状态，完成时会通知。异步断点回调可以通过 `ask()` 等待输入。使用 `status` 可重新查看待处理事件，该查询保留事件和未收集的输出。

`run` 捕获 stdout 和 stderr，工具收集到新输出时会按捕获顺序标注所属流。缓冲区溢出和分批返回会有各自的提示。脚本可用 `await dbg.waitOutput(pid, timeoutMs)` 从独立游标读取输出及退出或超时信息。目标切换后，仍可按旧 PID 查询保留的输出。live 和 core 共用 TypeScript 声明，core 中的执行控制和写入操作会抛出 `NotSupport`。

`run` 和 `attach` 用于调试。一般 shell 命令请使用 shell 工具。普通 fork 默认跟踪父进程，未注册 `SIGCHLD` 处理器时自动将该信号交付目标。

## TypeScript

脚本成功完成后，可通过同一会话的 `$` 使用其具名导出。切换调试目标会重置导出。

- `console.log({address: 0x1234n})` 可直接输出含 BigInt 的对象。需要 JSON 文本时用 `dbg.stringify(value)`，其中 BigInt 保留为十进制字符串。控制台会标出循环引用和数组、对象或字符串的显示裁剪。脚本直接输出的字符串会按原文呈现。大批脚本输出会分次返回，缓冲区丢失另行报告。
- `dbg.continueForStop("all", {pausedOnly: true})` 等待仍暂停的现场或退出。已经继续的命中可用 `dbg.waitStops()` 读取。`dbg.traceHits("push")` 可记录断点命中并自动继续。
- `dbg.backtraceAll()` 从一次全线程快照读取调用栈。快照可在 live 目标运行时采集，`incomplete` 报告未完成的阶段。
- `dbg.list(frame, 5, [{from: "/build/project", to: "/srv/src/project"}])` 按第一条匹配规则替换 DWARF 路径前缀。路径在调试服务端解析。`frame.inlineFrames` 显示 DWARF 为当前指令记录的逻辑内联调用。
- `m.typeOfVar(name)` 支持运行时字符串。`m.findTypes("Node", {exact: true, module: "app"})` 可限定类型名及模块。断点选项的 `condition` 可筛选命中，`m.setPrettyPrinter(type, fn)` 可格式化同一类型描述符的调试值。

AI 可直接调用 MCP 的 `docs` 工具获取 `script_run` 的完整 TypeScript 声明，包括 `aidbg` 模块、会话全局对象和内置文件及路径模块。调用 `docs` 无需先连接调试服务。编译时，目标的 DWARF 信息和本会话已导出的值可提供额外的类型信息。

MCP 资源 `aidbg://debugger.d.ts` 提供调试器接口，`aidbg://node.d.ts` 提供文件和路径模块接口。脚本以 TypeScript 模块的顶层作用域执行，宿主能力限于声明中的全局对象和模块。文件模块支持同步及 Promise 读操作，二进制读取返回 `Uint8Array`，单次读取上限为 16 MiB。相对路径基于 aidbg 服务端工作目录。源码见 [debugger.d.ts](docs/debugger.d.ts)，设计见 [需求文档](docs/下一代演进调试器需求文档.md)。

调用 `run` 或 `attach` 后，可以用 `script_run` 安装断点并恢复目标。

```ts
export const breakpoint = dbg.softwareBreakpoint("main", async hit => {
    const [frame] = hit.thread.backtrace(1);
    console.log(frame?.symbol, frame?.pc);
    const answer = await hit.thread.ask({ prompt: "pause or continue?" }, 30_000);
    if (answer === "pause") hit.pause();
});
dbg.resumeAll();
```

`dbg.resumeThread(tid)` 和 `dbg.resumeAll()` 同步恢复线程，调用完成后立即返回。`dbg.continueForStop()` 会取出一个排队的停点或恢复并等待，`dbg.waitStops()` 可以批量取出停点。脚本可用 `dbg.ask({ stop })` 将现场放进工具回包，等待 `send_input` 写回字符串。消费停点和回复输入都不自动恢复线程。

顶层脚本至少要有一项执行操作，例如调用函数或读取可能触发 getter 的属性。仅声明或导出的脚本可在开头使用 `"I know this is a no-op script"`。顶层 Promise 调用应使用 `await` 或 `.then()` 处理，可用 `"I intentionally allow unawaited Promises"` 显式豁免。

`m.typeOfVar("variable")` 从当前顶层栈帧查询 DWARF 类型描述符。Live 目标中，`dbg.catchSyscall(tid, "entry" | "exit" | "both", callback?)` 捕获系统调用，使用 `"all"` 选择整个进程，使用 `null` 作为阶段取消该范围的捕获。省略回调时命中会暂停，回调中可调用 `hit.pause()` 或 `hit.continue()`。系统调用捕获要求 Linux 支持 `PTRACE_GET_SYSCALL_INFO`（Linux 5.3 起）。成功 exec 后会产生 `exec` 停点。

合成类型按目标 GCC 的布局规则计算，支持位域、枚举、匿名成员、字节序、对齐及 packing。`Type.offsetOf()` 查询静态偏移，`Type.layout()` 展示布局，`Type.$readBytes(addr)` 和 `Type.$writeBytes(addr, bytes)` 同步访问静态存储。终止指针用 `$deref()` 读取序列，用 `$writeContents()` 写入序列和终止元素。写入超过原序列范围时，结果包含 `warning`。

`m.findTypes()` 查询 DWARF 类型及模块。同步 `dbg.attachDwarf(file, position?)` 可加载额外的 ELF 调试文件。`position` 支持 ELF 加载偏移或节起始地址映射，省略时要求唯一匹配模块。加载后可在下一次 `script_run` 中用 `m.fromDwarf()` 获取静态类型检查。调用栈提供 `missingDebugSections` 以标识缺少的符号和 DWARF 节。

`dbg.coredump` 将压缩 core 写到服务端路径。使用 `core_open` 可以重新打开它。TypeScript 中地址与寄存器为 `bigint`，MCP 文本通常以十六进制显示地址与寄存器。

软件观察点通过单步检测常见指令的内存访问，并通过前后对照检测其它写入引起的值变化。原生函数调用支持整数、指针和浮点 ABI。动态链接的 ELF 目标文件需使用受支持的重定位，并放入调用者提供的可写映射。

## 测试

```sh
cargo test --locked
bash tests/run.sh --lease
npm --prefix tests/types ci
npm --prefix tests/types test
```

集成测试使用本机 Unix 套接字及 ptrace。GCC 编译 DWARF 4 fixture，有 Clang 时同时编译 DWARF 5 版本。加上 `--lease` 会额外等待会话租约过期并检查目标已被释放。
