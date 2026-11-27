# Linux 目标进程资源查询

## 目标

在调试会话中，从目标线程、系统调用参数、文件描述符或内存地址定位对应的 Linux 内核资源。优先回答「这个线程在等什么」「这个连接对应哪个 fd」「为什么打开文件失败」和「进程为什么突然变慢或退出」。本节扩展 [spec-03 的进程上下文需求](spec-03.md#默认文档增强)。

由目标所在主机的 `aidbg-server` 通过 Linux 提供的只读接口采集。查询可在目标运行时进行，无需向目标注入代码或让目标执行系统调用。

## 第一阶段：文件描述符和等待关系

- 提供结构化查询，候选脚本入口为 `dbg.resources.fds()` 和 `dbg.resources.fd(fd)`。通过 `/proc/<pid>/fd` 和 `fdinfo` 识别普通文件、设备、管道、FIFO、socket 和匿名 fd。返回可获取的路径、inode、挂载 ID、读写及状态标志、当前位置，以及文件已删除但仍打开的状态。管道展示端点类型，权限允许时可补充其他持有者。
- 解码 epoll 监听项及事件掩码、eventfd 计数、timerfd 剩余时间和周期、signalfd 信号掩码、inotify 和 fanotify 监听项。关联 epoll 监听项和当前 fd 时核对可用的对象标识，fd 已关闭或复用时保留监听记录并标明关联状态。
- 在目标的网络命名空间视图中，用 socket inode 关联 TCP、UDP 和 Unix socket。展示适用的本地端点、对端、状态和收发队列。
- 结合线程状态、当前系统调用及内核等待点，把系统调用的 fd 参数关联到资源。例如从 `epoll_wait(3, …)` 查到 epoll 实例、监听项及其 socket 端点。在脚本中可显式把 `conn->fd` 等表达式结果用于资源查询。系统调用参数按已知语义解码，普通整数由调用方明确指定为 fd。

数据来源见 [Linux procfs 文档](https://docs.kernel.org/filesystems/proc.html)。

## 第二阶段：地址空间和进程上下文

- 扩展现有映射查询，按地址展示映射范围、权限、文件偏移和后备对象。按需提供 RSS、脏页及可识别的共享内存信息。建立映射时使用的 fd 关闭后，仍可从地址定位当前映射。
- 展示目标所属命名空间、挂载和 cgroup。区分目标持有的对象和目标所在命名空间可见的对象。System V 共享内存、消息队列和信号量等没有明确持有关系时，按命名空间展示。
- 对 `futex(addr, …)` 等等待，把地址关联到映射，并在 DWARF 和运行时信息足够时关联到用户态锁变量。持有者仅在能依据具体锁实现可靠解码时展示。
- 关联文件锁、等待者、设备号、inode 和字节范围。展示线程及进程待处理的信号、线程掩码和信号处置方式，以及 UID、capabilities、seccomp 模式和资源软硬限制。排查 `EMFILE` 时可并列展示当前 fd 数量与 fd 上限。

数据来源见 [Linux procfs 文档](https://docs.kernel.org/filesystems/proc.html)及 [cgroup v2 文档](https://docs.kernel.org/admin-guide/cgroup-v2.html)。

## 第三阶段：资源压力和事件

- 内核提供任务延迟统计时，比较两次采样之间的 CPU 等待、同步块 I/O、换入和内存回收等累计时间变化。结合调用栈和等待点理解延迟来源。见 [Linux delay accounting](https://docs.kernel.org/accounting/delay-accounting.html)。
- 按需展示目标 cgroup 的 CPU 节流、内存限制与 OOM 事件、I/O 用量，以及 CPU、内存和 I/O 压力。cgroup 计数提供组级上下文，单个进程的退出原因需要结合目标事件判断。见 [cgroup v2 文档](https://docs.kernel.org/admin-guide/cgroup-v2.html)和 [Linux PSI 文档](https://docs.kernel.org/accounting/psi.html)。

## 采集语义

结构化查询供脚本使用，摘要按需纳入现有进程上下文。运行中读取多个接口得到的是各自采样时的观测。目标退出、fd 复用、权限不足或内核未提供某项数据时，保留已取得的结果并标明缺失原因。
