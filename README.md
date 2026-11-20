# aidbg

Linux C/C++ 进程快照工具，测试版。项目面向 x86_64 和 AArch64。Rust 服务端在目标主机运行，客户端提供命令行和 MCP stdio。两端通过 Unix socket 上的 gRPC / Protobuf 通信。

后续功能、验收边界和实现顺序见 [需求与路线图](REQUIREMENTS.md)。

## 构建和运行

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

## MCP client

在 MCP 客户端注册可执行文件 `aidbg`，启动参数使用 `["--socket", "/absolute/path/aidbg.sock", "mcp"]`。stdio 工具为：

- `snapshot`，接受 `pid`、`freeze` 和可选的 `fields`、`tid`、`frames`。
- `snapshot_query`，接受已保存的 `snapshot_id` 及相同的筛选项。

本机直接连接 socket。远程主机已有 SSH 时，也可通过 SSH 转发该 socket 后接到同一 client。测试版建议 client 和 server 使用同一个构建版本。

## 测试与版本构建

```sh
tests/run.sh
```

x86_64 实时集成测试用 GCC 和 Python 3 创建并附加自有子进程。覆盖三种冻结方式、寄存器、跨共享库回溯、分离清理、全量文件保存、筛选、跨重启查询及 MCP stdio。环境需允许 ptrace。

推送 `v0.1.0` 这类以 v 加数字开头的版本标签触发 **Build version** workflow。Actions 为 Linux x86_64 和 AArch64 各生成一个包含 `aidbg` 和 `aidbg-server` 的静态 musl 压缩包，并上传到该次运行的 Artifacts。普通分支推送没有版本构建。
