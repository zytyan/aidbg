# D01–D15 参考答案

输出、退出状态和验收条件见 [预期结果](EXPECTED.md)。

| 编号 | 根因与判定证据 | 最小修复 |
| --- | --- | --- |
| D01 | `quota_for` 的崩溃帧中 `account->id == 9`，`account->profile == NULL`，解引用报 `NULL_POINTER`。 | 资料缺失时使用 `default_profile`。 |
| D02 | 观察 `queue.head` 得到 `0 → 1 → 2 → 0 → 1`，其中下标 3 存着 40。`pop` 错用 `CAPACITY - 1` 作模数。 | 用 `CAPACITY` 取模。 |
| D03 | 两个线程在 `record` 中各读到 `before=0`。屏障后两次写观察点分别看到 `0 → 10` 和 `10 → 10`。退出 core 中 `total=10`。 | 屏障后执行 `atomic_fetch_add(&total, amount)`，删除分开的读取。 |
| D04 | `refresh` 持有 `catalog`、等待 `ledger`，`reconcile` 持有 `ledger`、等待 `catalog`。两个工作线程的栈或 `observe_threads` 的锁图给出这两条边。 | 两条路径先过屏障，再统一按 `catalog`、`ledger` 的顺序加锁，逆序解锁。 |
| D05 | 调用方的 `bytes` 是 70,000，`blocks_for` 的 `uint16_t bytes` 是 4,464。以 4,096 字节为一块向上取整得到 2。 | 扩大形参类型，用商加余数是否非零计算块数。 |
| D06 | `enable` 的 `requested=2`，写观察点看到 `flags` 从 5 变为 2，`changed=true`。 | 用 `flags |= requested` 保留已有标志。 |
| D07 | 在 `remove_next` 中，待摘除的节点 20 原本指向节点 30。先清空 `removed->next`，再将空指针写给节点 10 的 `next`。 | 先把后继链接到前驱，再清空被摘除节点的 `next`。 |
| D08 | `clear_samples` 前两行为 `[0,46,0,12,101]`、`[0,0,0,0,202]`。对比 40 字节的 `rows` 可看到首行标记变为 0。对 `rows[0][4]` 的写观察点在 `i=4` 时命中。该写入仍在实际数组内，跨过的是采样区的业务边界。 | 循环条件改为 `i < count`。 |
| D09 | `schedule_retry` 中局部副本 `job.attempts` 从 0 增到 1，原数组的 `jobs[0].attempts` 和 `jobs[2].attempts` 仍是 0。 | 用 `auto &job` 遍历。 |
| D10 | 两个 `std::string_view` 的 `data()` 相同。第二次 `Reader::read` 把同一缓冲区的内容从 `north` 改成 `south`。 | 返回拥有字符数据的 `std::string`。 |
| D11 | Pi 旧版 Make 题。`report.c` 包含 `settings.h`，但 `report` 的构建规则只依赖 `report.c`。修改头文件后，`make -W settings.h` 仍判定 `report` 已是最新。 | 把 `settings.h` 加入 `report` 的依赖列表。 |
| D12 | Pi 旧版 CMake 题。`report_data.c` 调用 `metrics_total`，定义在 `metrics` 库中。两个库都被编译，但 `report` 的链接只带上 `report_data`。 | 用 `target_link_libraries(report_data PRIVATE metrics)` 声明库之间的依赖。 |
| D13 | `replace_score` 释放旧分数，`main` 随后读取仍指向旧对象的 `cached_score`。对照报告中的释放栈和读取栈。 | 输出时访问当前的 `active_score`，移除跨替换保留的地址。 |
| D14 | `copy_label` 为 6 个字符分配 6 字节，在紧邻分配区末尾的位置写入字符串结束符。 | 分配 `length + 1` 字节。 |
| D15 | 同一地址先在 `prepare` 的拒绝路径释放，接着在 `close_report` 再次释放。对照报告中的两次释放栈。 | 由 `close_report` 统一释放缓冲区。 |
