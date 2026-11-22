# 调试用例与 MCP 改进清单

- [x] 仅保留 D01–D10、D13–D15，并以 `cases.json` 记录修复后的期望行为。
- [x] 用 `pause_at_entry` 在初次 exec 时暂停，首包返回 PID 和 `run_id`。支持环境变量、stdin、`run_pause` 和 `run_continue`。
- [x] 按 `run_id` 安装和移除断点、采集快照并检查变量。已有断点会话也可按 PID 检查变量。
- [x] 增加 `asan39` 构建入口及运行库预检。无法初始化时明确跳过 D13–D15。
- [x] 从服务端能力读取 VA 位数与 ASan 高位地址可映射性。
- [x] 保留仅缺 vvar 时的 `complete_without_vvar` 状态，验证 core 的覆盖摘要。
- [x] 活进程快照查找并校验独立符号文件，运行时 frame 表达式标为 `runtime_only`。
- [x] 支持活进程 `search_memory` 和 `xref`，观察点事件提供两种进制的值，说明 `target_call` 的副作用。
- [ ] 用支持 39 位 VA 的 compiler-rt 在 Pi 上验证 D13–D15 的 ASan 报告。
- [x] 部署 Pi 服务端和 Windows 客户端，从 Windows MCP 验证 D03 的两次写观察点命中与 D04 的三线程快照、libc 符号和互斥锁状态。
