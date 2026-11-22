# D01–D15 预期结果

“带故障版本”用于复现原题。“修复后”用于验收，程序应以退出码 0 结束。多行输出以 `\n` 标记换行。当前仓库的 13 道运行时题目可对照 `cases.json`。D11、D12 是 Pi 上仍保留的旧版构建题，源文件位于 Pi 的 `debug-cases/build-cases/`。

| 编号 | 带故障版本 | 修复后 |
| --- | --- | --- |
| D01 | 输出 `account=7 quota=64`，随后收到 SIGSEGV | `account=7 quota=64\naccount=9 quota=64` |
| D02 | `10 20 30 10` | `10 20 30 40` |
| D03 | `total=10` | `total=20` |
| D04 | 输出 `refresh started` 与 `reconcile started`，随后一直等待 | 两条启动消息顺序不限，随后输出 `completed` |
| D05 | `bytes=70000 blocks=2` | `bytes=70000 blocks=18` |
| D06 | `before=5\nafter=2` | `before=5\nafter=7` |
| D07 | `10` | `10 30` |
| D08 | `samples=0,0,0,0 markers=0,202` | `samples=0,0,0,0 markers=101,202` |
| D09 | `fetch=0\nparse=1\nsave=0` | `fetch=1\nparse=1\nsave=1` |
| D10 | `south south` | `north south` |
| D11 | 初次构建输出 `port=4100`。把端口改为 4200 后，增量构建仍输出 `port=4100`。 | 从未修改的项目初次构建输出 `port=4100`。端口变更后的增量构建输出 `port=4200`。 |
| D12 | CMake 配置成功，构建在链接阶段失败，报告未定义的 `metrics_total`。 | 配置、构建和运行均成功，输出 `total=42`。 |
| D13 | ASan 报 `heap-use-after-free`，Memcheck 报 `Invalid read of size 4` | `score=23`，无内存错误报告 |
| D14 | ASan 报 `heap-buffer-overflow`，Memcheck 报 `Invalid write of size 1` | `queued`，无内存错误报告 |
| D15 | 输出 `report rejected`，ASan 报 `attempting double-free`，Memcheck 报 `Invalid free()` | `report rejected`，缓冲区只释放一次 |

D13–D15 的诊断以 ASan 或 Memcheck 已成功初始化为前提。树莓派上若先看到 `sanitizer_allocator_primary64.h` 断言，可用 Memcheck 运行普通调试版。
