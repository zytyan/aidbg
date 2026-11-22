# AI 故障定位样例

每题有一个可复现故障。把单题的复现命令、[预期结果](EXPECTED.md) 和对应源码交给 AI。要求报告故障所在的文件和函数或构建目标、触发条件、实际证据和最小修复。需要评估调试器使用能力时，同时保留 aidbg 命令与输出。评测者可在作答后查阅 [参考答案](ANSWERS.md)。

当前仓库有 13 个运行时夹具，覆盖 D01–D10、D13–D15。Pi 旧部署保留了 D11、D12 两道构建题，结果和答案也已收录。当前夹具修复后的标准输出、退出状态和可用变体记录在 [cases.json](cases.json)。D04 的两条启动消息可按任意顺序出现，随后应打印 `completed` 并退出。

## 运行时题目

从仓库根目录构建，Linux 上需要 GNU Make、支持 POSIX 线程的 C11 编译器和 C++17 编译器。

```sh
make -C tests/debug-cases -j4
target/debug-cases/D02
timeout 3s target/debug-cases/D04
```

| 编号 | 源码 | 实际表现 | 期望行为 |
| --- | --- | --- | --- |
| D01 | [D01.c](cases/D01.c) | 第一个账户显示配额，处理第二个账户时收到 SIGSEGV | 第二个账户在资料缺失时使用默认配额 64 |
| D02 | [D02.c](cases/D02.c) | 输出 `10 20 30 10` | 按入队顺序输出 `10 20 30 40` |
| D03 | [D03.c](cases/D03.c) | 两个线程各记入 10，汇总为 10 | 汇总为 20 |
| D04 | [D04.c](cases/D04.c) | 两个线程都显示已启动，进程一直未退出 | 两个操作都完成，程序打印 `completed` 后退出 |
| D05 | [D05.c](cases/D05.c) | 70,000 字节被计为 2 块 | 按每块 4,096 字节向上取整，结果为 18 块 |
| D06 | [D06.c](cases/D06.c) | 启用写权限后标志从 5 变为 2 | 保留已有标志，结果为 7 |
| D07 | [D07.c](cases/D07.c) | 从 `10 → 20 → 30` 删除 20 后只剩 10 | 剩余 `10 → 30` |
| D08 | [D08.c](cases/D08.c) | 清零第一行的采样值后，两个行标记变成 0 和 202 | 采样值清零，行标记保持 101 和 202 |
| D09 | [D09.cc](cases/D09.cc) | 安排重试后，两个任务的尝试次数仍为 0 | 三个任务的尝试次数均为 1 |
| D10 | [D10.cc](cases/D10.cc) | 连续读取两个名称得到 `south south` | 保留两次返回值，随后打印 `north south` |

### 使用 aidbg 观察现场

按仓库文档启动 [aidbg-server](../../README.md#构建和运行)。运行 D03 时，让调试器在初次 `exec` 处暂停，返回 `run_id` 和 PID。安装断点或观察点后再继续。

```sh
aidbg --socket "$AIDBG_SOCKET" run --pause-at-entry "$PWD/target/debug-cases/D03"
aidbg --socket "$AIDBG_SOCKET" breakpoint set --run-id "$RUN_ID" --module D03 --symbol record
aidbg --socket "$AIDBG_SOCKET" run-continue --run-id "$RUN_ID"
aidbg --socket "$AIDBG_SOCKET" breakpoint events
aidbg --socket "$AIDBG_SOCKET" run-status --run-id "$RUN_ID"
```

MCP 使用 `run({executable, pause_at_entry: true})`、`breakpoint_set({run_id, ...})`、`run_continue({run_id})` 和 `breakpoint_events`。D04 可用 `detach: true` 启动，在两个线程进入死锁后用 `run_pause` 和 `snapshot` 查看现场。检查全局互斥锁时传 `inspect({run_id, module: "D04", expression: "::catalog.__data.__lock"})`，最后用 `run_cancel` 结束。

D01 可用 [信号回调](../../README.md#启动程序和处理信号) 在 SIGSEGV 时保留 ELF core。

夹具也可通过环境变量停在 `case_start`。设置 `AIDBG_WAIT_RELEASE=signal:SIGUSR1` 时，等夹具打印 PID 再发送 `SIGUSR1`。设置 `AIDBG_WAIT_RELEASE=file:/absolute/path` 时，用尚不存在的路径等待，采集完现场后创建该文件。原有的 `AIDBG_WAIT=1` 仍可用回车放行。

## 内存错误题目

这三题是 C 程序。用支持 AddressSanitizer 的 GCC 或 Clang 构建，便于稳定复现并保留分配、释放和访问位置。

```sh
make -C tests/debug-cases asan
target/debug-cases/D13
target/debug-cases/D14
target/debug-cases/D15
```

| 编号 | 源码 | 实际表现 | 期望行为 |
| --- | --- | --- | --- |
| D13 | [D13.c](cases/D13.c) | 替换当前分数后，读取分数时 ASan 报 `heap-use-after-free` | 打印当前分数 `score=23` |
| D14 | [D14.c](cases/D14.c) | 复制 `queued` 时 ASan 报 `heap-buffer-overflow`，访问类型为写 | 复制并打印完整的 C 字符串 `queued` |
| D15 | [D15.c](cases/D15.c) | 打印 `report rejected` 后，清理路径触发 ASan 的 `attempting double-free` | 拒绝空报表并退出，释放一次已分配的缓冲区 |

## 验证题目可复现

```sh
python3 tests/debug-cases/verify.py
```

验证脚本在临时目录构建和运行，检查上述故障表现。D13–D15 可用兼容的 ASan 运行库或 Valgrind Memcheck 验证。脚本无需启动 aidbg-server，也不会生成 core 文件。

## 树莓派上的 ASan

在本项目的树莓派上实测，AArch64 内核 `6.18.34+rpt-rpi-v8` 使用 4 KiB 页，内核配置为 `CONFIG_ARM64_VA_BITS=39`。39 位用户虚拟地址空间是 512 GiB，最高地址为 `0x0000007fffffffff`。这里的 39 位是内核为进程配置的虚拟地址宽度。[Linux 内核的 AArch64 内存布局](https://docs.kernel.org/arch/arm64/memory.html)

这台 Pi 上用 GCC 14.2.0 编译的探针链接 `libasan.so.8`。该运行库的主分配器初始化时要求从固定地址 `0x500000000000`（80 TiB）起预留虚拟地址区间，超出了 39 位用户地址空间。预留失败后，ASan 断言输出 `(0x500000000000, 0xfffffffffffffff4)`，后一个值是以无符号十六进制显示的负错误码 `-ENOMEM`。这里失败的是虚拟地址预留。[GCC 14.2 的分配器布局](https://github.com/gcc-mirror/gcc/blob/releases/gcc-14.2.0/libsanitizer/asan/asan_allocator.h#L203-L211) · [主分配器的地址检查](https://github.com/gcc-mirror/gcc/blob/releases/gcc-14.2.0/libsanitizer/sanitizer_common/sanitizer_allocator_primary64.h#L117-L122)

直接运行 [asan-probe.c](cases/asan-probe.c) 的编译产物也会在进入 `main` 前报相同断言并以退出码 1 结束。该探针只分配、写入并释放一个字节，所以这个断言可以独立用于确认运行库兼容性。aidbg 的 `server_info.environment` 在这台 Pi 上报告 `va_bits: 39` 与 `asan_high_address_mappable: false`。D13–D15 的内存错误要等可用的检测后端启动后才能判定。

### 在 Pi 上验证

将本目录复制到 Pi 后，在本目录运行 `python3 verify.py`。验证已有构建可用 `python3 verify.py --bin-dir /absolute/path/to/bin`。脚本先探测 ASan。在高地址不可用时优先探测 `asan39/`。ASan 无法初始化时，脚本查找 `VALGRIND`、部署目录下的 `tools/bin/valgrind` 或 PATH 中的 Valgrind，运行 `memcheck/` 下的普通调试版。两种后端都不可用时，脚本将 D13–D15 标记为跳过。

在这台 Pi 上用当前源码重新构建后，普通 ASan 未通过预检，自动回退到已部署的 Valgrind，D01–D10 和 D13–D15 的预期表现全部通过。旧部署目录里的普通夹具与当前源码的放行提示存在差异，完整回归使用本次临时重建产物。当前部署的 `asan/D13` 和 `memcheck/D13` 具有不同 inode。判断 Memcheck 变体是否正确时，应检查它是否由 `make memcheck` 生成并且未链接 ASan。Memcheck 变体与普通调试版之间可以使用硬链接。

若需要 ASan 报告，使用带 39 位 VA 支持的 AArch64 Linux compiler-rt 重新链接。从仓库根目录构建时，`ASAN39_CC` 中的 Clang 资源目录需要包含用 `-DSANITIZER_AARCH64_39BIT_VA=ON` 构建的运行库。该选项改变主分配器的地址布局，配置作用于 compiler-rt 的构建。此变体尚未在这台 Pi 上验证。[LLVM 的 39 位 ASan 配置](https://github.com/llvm/llvm-project/commit/b71eb53cd4399cea26c4aebdefb238e80c22ba95)

```sh
make -C tests/debug-cases asan39 \
  ASAN39_CC='clang -resource-dir /path/to/clang-with-asan39'
```

也可以直接用 Memcheck 验证，以下命令从仓库根目录运行。

```sh
python3 tests/debug-cases/verify.py --memcheck valgrind
```

使用 `--bin-dir` 时，先确保普通调试版位于该目录的 `memcheck/` 下。可用 `make -C tests/debug-cases memcheck` 单独构建。
