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

在 MCP 客户端配置中，将 `command` 设为 `aidbg` 可执行文件的绝对路径，并传入 `["--socket", "/absolute/path/to/aidbg.sock"]`。跨主机使用服务端的 `--listen HOST:PORT` 和客户端的 `--endpoint http://HOST:PORT`。Windows 客户端使用 TCP。明文服务应仅绑定可信网络或通过 SSH 转发访问。

每个 MCP 客户端会话拥有一个调试目标。指定 `--session` 可以在客户端重启时复用同一个会话令牌，令牌须包含 24 至 128 个字母、数字、连字符或下划线。服务端在 30 秒内未收到客户端请求或心跳后释放调试目标。

## MCP 工具

| 工具 | 参数和用法 |
| --- | --- |
| `run` | `path` 是服务端程序的绝对路径，`arg` 是可选字符串数组。目标在 exec 后暂停。 |
| `attach` | `pid` 是进程 ID。附加后线程暂停。 |
| `core_open` | `path` 是服务端上的 ELF core 或 zstd 压缩的 core，可指定 `executable` 和 `debug_symbols`。 |
| `script_run` | `src` 是 TypeScript 模块源码。脚本通过检查后由 QuickJS 执行，具名导出可在后续脚本中用 `$` 访问。 |
| `snapshot` | 可传入 `tid` 获取指定线程的快照。默认读取所有线程。 |
| `send_input` | 向正在通过 `ask()` 等待回复的 `handler` 传入字符串 `data`。 |
| `interrupt_input` | 向指定 `handler` 抛出异常，可传入消息 `msg`。 |
| `perf` | 传入 `pid`，选择 `hotspot` 或 `stack`。可选 `tid`、`duration_ms`、`frequency_hz`。 |
| `ps` | 默认每个进程一行并显示线程数，隐藏内核线程。传入 `threads: true` 时显示各线程的 TID。 |
| `set_fork_policy` | 传入 `mode: "parent"` 或 `mode: "child"`，设置普通 fork 后跟踪哪一侧。 |

工具响应里的 `paused_threads`、`waiting_inputs` 和 `running_scripts` 是当前会话状态。异步断点回调可以等待输入。脚本输出缓存在服务端，随工具响应返回。`run` 启动的进程也会在回包的 `process_output` 中返回新增 stdout 和 stderr。live 和 core 使用同一套 TypeScript 声明，core 中的执行控制和写入操作会抛出 `NotSupport`。

## TypeScript

MCP 资源 `aidbg://debugger.d.ts` 提供调试器接口，`aidbg://node.d.ts` 提供文件和路径模块接口。脚本以 TypeScript 模块的顶层作用域执行，宿主能力限于声明中的全局对象和模块。文件模块支持同步及 Promise 读操作，二进制读取返回 `Uint8Array`，单次读取上限为 16 MiB。相对路径基于 aidbg 服务端工作目录。源码见 [debugger.d.ts](docs/debugger.d.ts)，设计见 [需求文档](docs/下一代演进调试器需求文档.md)。

调用 `run` 或 `attach` 后，可以用 `script_run` 安装断点并恢复目标。

```ts
export const breakpoint = dbg.softwareBreakpoint("main", async hit => {
    const [frame] = hit.thread.backtrace(1);
    console.log(frame?.symbol, frame?.pc);
    const answer = await hit.thread.ask({ prompt: "pause or continue?" }, 30_000);
    if (answer === "pause") hit.pause();
});
await dbg.resumeAll();
```

`dbg.resumeThread(tid)` 和 `dbg.resumeAll()` 恢复后立即返回。`dbg.continueForStop()` 会取出一个排队的停点或恢复并等待，`dbg.waitStops()` 可以批量取出停点。脚本可用 `dbg.ask({ stop })` 将现场放进工具回包，等待 `send_input` 写回字符串。消费停点和回复输入都不自动恢复线程。

顶层脚本至少要有一项执行操作，例如调用函数或读取可能触发 getter 的属性。仅声明或导出的脚本可在开头使用 `"I know this is a no-op script"`。顶层 Promise 调用应使用 `await` 或 `.then()` 处理，可用 `"I intentionally allow unawaited Promises"` 显式豁免。

`m.typeOfVar("variable")` 从当前顶层栈帧查询 DWARF 类型描述符。Live 目标中，`dbg.catchSyscall(tid, "entry" | "exit" | "both", callback?)` 捕获系统调用，使用 `"all"` 选择整个进程，使用 `null` 作为阶段取消该范围的捕获。省略回调时命中会暂停，回调中可调用 `hit.pause()` 或 `hit.continue()`。系统调用捕获要求 Linux 支持 `PTRACE_GET_SYSCALL_INFO`（Linux 5.3 起）。成功 exec 后会产生 `exec` 停点。

`dbg.coredump` 将压缩 core 写到服务端路径。使用 `core_open` 可以重新打开它。TypeScript 中地址与寄存器为 `bigint`，MCP JSON 中的地址与寄存器使用十六进制字符串。

软件观察点通过单步检测常见指令的内存访问，并通过前后对照检测其它写入引起的值变化。原生函数调用支持整数、指针和浮点 ABI。动态链接的 ELF 目标文件需使用受支持的重定位，并放入调用者提供的可写映射。

## 测试

```sh
cargo test --locked
bash tests/run.sh --lease
npm --prefix tests/types ci
npm --prefix tests/types test
```

集成测试使用本机 Unix 套接字及 ptrace。GCC 编译 DWARF 4 fixture，有 Clang 时同时编译 DWARF 5 版本。加上 `--lease` 会额外等待会话租约过期并检查目标已被释放。
