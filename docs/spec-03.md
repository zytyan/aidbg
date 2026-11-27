## TypeSystem 功能完善与问题修复

### 1. 通用约束

- 类型布局遵循目标进程的 C ABI，而非调试器自身的 ABI。
- 类型修饰器统一采用链式 API，返回新的类型描述符，不得修改原类型。
- 聚合类型成员按照声明顺序布局，不允许使用数组索引形式的字符串作为成员名称。
- 对不支持的类型及布局组合明确报错，不得静默猜测。
- 所有新增接口均需提供对应的 TypeScript 类型定义。

### 2. Bitfield、Enum、Endian、Pack、Align、Anonymous

增加以下接口：

- `IntegerType.bitfield(n)`：声明占用 n 位的整数位域，支持有符号、无符号、匿名及零宽度匿名位域。布局遵循目标 ABI，写入不得破坏相邻成员。
- `IntegerType.enum(values)`：声明枚举，继承基础整数类型的大小、对齐及字节序。读取返回数值，允许未知枚举值；写入支持数值和枚举名称。
- `Type.be()` / `Type.le()`：为 16 位及以上整数和浮点类型指定字节序，默认使用目标进程本机序。字节序与位域分配方向相互独立。
- `Type.align(n)`：指定显式对齐要求，不改变基础类型的有效数据大小。
- `AggregateType.pack(n)`：限制 struct/union 直接成员的对齐，不递归修改嵌套类型的内部布局，不引入全局 packing 状态。
- `m.anonymous(type)`：通过对象展开语法声明匿名 struct、union 或位域。保留声明顺序及独立内存布局，匿名聚合类型的成员提升至父级，名称冲突时报错，不得暴露内部生成的名称。

非本机字节序位域、pack 与 align 的组合必须具有明确的布局语义，无法正确支持时应报错。

```ts
const EnumType = m.u32().enum({
    UNKNOWN: 0,
    OK: 1,
    ERR: 2,
})

const Packet = m.struct({
    ack: m.u32().bitfield(1),
    req: m.u32().bitfield(4),

    ...m.anonymous(m.u32().bitfield(3)),

    unused: m.opaque(3),

    ...m.anonymous(m.union({
        ipv4: m.u32(),
        ipv6: m.array(m.u8(), 16),
    })),

    type: EnumType,
    ptr: m.pointer(m.void()).align(16),
})

const PackedHeader = m.struct({
    type: m.u8(),
    length: m.u32().be(),
}).pack(1)
```

### 3. 类型发现

增加 `m.findTypes(query)`，支持按名称搜索 DWARF 类型，返回类型名称、所属模块、大小及必要的消歧信息。

完善 `m.fromDwarf()`：

- 查找失败时提供少量相近类型。
- 存在歧义时提供候选类型，不得任意选择。
- 优先使用 DWARF 中明确记录的布局信息，不得以推导结果覆盖。

```ts
m.findTypes("Packet")
m.fromDwarf("struct Packet")
```

### 4. OffsetOf

增加 `Type.offsetOf(path)`，语义类似 C 的 `offsetof`，返回相对于当前类型起始地址的字节偏移。

支持嵌套成员、数组下标及匿名成员。不允许穿过指针，不支持位域及无法静态确定偏移的成员。

```ts
Packet.offsetOf("type")
Packet.offsetOf("ipv4")
Packet.offsetOf("header.length")
Packet.offsetOf("entries[3].value")
```

### 5. Opaque、Char、NullTerminate、CStr

增加以下接口：

```ts
m.opaque(n)
// 等价于 m.array(m.u8(), n)

m.cStr(maxLength?)
// 等价于 m.pointer(m.char()).nullTerminate(maxLength?)
```

`m.char()` 表示具有字符语义的单字节 C char 类型，其符号属性遵循目标 ABI。

`PointerType.nullTerminate(maxLength?)` 表示解引用指针时连续读取元素，直至遇到零值终止元素。

指针支持以下长度确定方式：

```ts
m.pointer(m.u8(), 16)
m.pointer(m.u8(), ctx => ctx.length)
m.pointer(m.u8()).nullTerminate()
```

约束：

- `nullTerminate()` 仅适用于指针类型，与显式长度及上下文长度回调互斥。
- 被指向的元素必须具有确定的静态大小及明确的零值语义。
- `maxLength` 以元素数量为单位，必须具有有限的默认值。
- 终止元素不包含在读取结果中。
- 达到读取上限仍未发现终止元素时应报错。
- 对指针元素，必须在解引用前判断其是否为 NULL。
- 字符序列读取为字符串，默认使用 UTF-8 编码；其他序列遵循现有指针数组的读写语义。
- 写入序列内容时应包含终止元素，不得隐式分配目标进程内存。
- `nullTerminate()` 仅改变指针的解引用策略，不改变指针自身的大小、对齐及内存布局。

```ts
// char *
m.cStr()
m.cStr(256)
m.pointer(m.char()).nullTerminate()

// uint32_t *，以 0 结尾
m.pointer(m.u32()).nullTerminate(128)

// void **，以 NULL 结尾
m.pointer(m.pointer(m.void())).nullTerminate()

// char **argv，以 NULL 结尾
m.pointer(m.cStr()).nullTerminate()

// 固定大小的原始字节数组
m.opaque(32)
```

上述指针类型均具有确定的静态大小，可以直接作为聚合类型成员。

```ts
const ProcessArgs = m.struct({
    name: m.cStr(),
    argc: m.u32(),
    argv: m.pointer(m.cStr()).nullTerminate(),
})
```

### 6. ReadBytes / WriteBytes

所有具有确定静态大小且可独立寻址的类型均增加同步 `$readBytes(addr)` / `$writeBytes(addr, bytes)` 接口，使用 `Uint8Array` 表示原始数据。

约束：

- 读写范围为类型的完整静态大小，包含 padding。
- 不进行类型解析、字节序转换或指针解引用。
- 不执行动态长度计算、终止元素扫描及成员上下文回调。
- 写入长度必须与类型大小完全一致。
- 不支持静态大小不确定的类型及不可独立寻址的位域。

```ts
const bytes = Packet.$readBytes(addr)
Packet.$writeBytes(otherAddr, bytes)

// 仅复制结构体本身，不复制字符串及 argv 内容
const args = ProcessArgs.$readBytes(addr)

// 仅读取指针本身，不读取字符串
const ptr = m.cStr().$readBytes(addr)
```

### 7. Layout

增加 `Type.layout(): string`，以接近 C 声明的形式展示类型及其内存布局。

应包含适用的以下信息：

- 类型大小及对齐。
- 成员字节偏移。
- 位域偏移及宽度。
- 枚举名称及数值。
- 非本机字节序。
- Pack、align 及 padding。
- 指针解引用长度及终止条件。

输出必须具有确定性，不得暴露内部匿名成员名称。不要求输出能够直接作为 C 源码编译。

```ts
Packet.layout()
PackedHeader.layout()
ProcessArgs.layout()
m.cStr().layout()
```

`Packet.layout()` 的输出类似：

```c
enum EnumType {
    UNKNOWN = 0,
    OK = 1,
    ERR = 2,
};

struct {
    uint32_t ack : 1;   // byteoffset: 0, bitoffset: 0
    uint32_t req : 4;   // byteoffset: 0, bitoffset: 1
    uint32_t : 3;       // byteoffset: 0, bitoffset: 5

    uint8_t unused[3];  // byteoffset: 1

    union {            // byteoffset: 4
        uint32_t ipv4;
        uint8_t ipv6[16];
    };

    enum EnumType type; // byteoffset: 20

    // padding: 8 bytes

    _Alignas(16) void *ptr; // byteoffset: 32

    // tail padding: 8 bytes
};

// sizeof: 48
// alignof: 16
```

`PackedHeader.layout()` 的输出类似：

```c
#pragma pack(push, 1)
struct {
    uint8_t type;      // byteoffset: 0
    uint32_t length;   // byteoffset: 1, big-endian
};
#pragma pack(pop)

// sizeof: 5
// alignof: 1
```

`ProcessArgs.layout()` 的输出类似：

```c
struct {
    char *name;       // byteoffset: 0, NUL-terminated string
    uint32_t argc;    // byteoffset: 8

    // padding: 4 bytes

    char **argv;      // byteoffset: 16
                      // NULL-terminated pointer array
                      // elements: NUL-terminated strings
};

// sizeof: 24
// alignof: 8
```

`m.cStr().layout()` 的输出类似：

```c
char *; // NUL-terminated string

// sizeof: 8
// alignof: 8
```

上述布局以默认 x86_64 SysV ABI 为例，实际输出以目标 ABI 为准。

## 默认文档增强

### 应该明确提示run能力不应作为普通的shell能力使用

MCP工具`run` `attach` 是用于调试程序使用，不应该认为其是正常的run能力，文档中应说明采用其它方案执行shell。

默认情况下文档应注明默认仅跟踪父进程，不在`SIGCHILD`，除非手动调用配置，否则应该一直是父进程。

MCP工具介绍里应该给AI一份 .d.ts 文件，让AI直接看到都有什么接口，但是类型体操部分可以省略，
只需要告诉AI有这些trait，最后合成大结构即可，让AI不要调用，检查依然使用复杂的类型体操部分。
这种操作应该足够避免幻觉了，不需要告诉所有严格约束。大概可以减少token量？

`ps` 返回的值，默认不要返回参数，不然一下子太长了，另外还是返回结构化json吧。太长的多个属性，保证整体在4k以内。

缺少符号表、缺少dwarf时，应明确报告stripped symtab/dwarf ，不要静默symbol=null，告诉AI缺少哪些调试节。

对于stripped的二进制，要能正确使用 .eh_frame 进行CFI回溯，目前有问题。

dbg增加一个 `dbg.attachDwarf(file: string, [position:bigint | positionMap: {".text":0x9888n}])`这种用于额外增加被玻璃的dwarf信息。同步操作，不要返回Promise

syscall要有符号解码，每个系统调用号代表什么和参数代表什么。

 6. snapshot 带进程上下文
这次为了拿 syscall/fd/state，我 spawn 了 cat、ls 四次。工具内部读这些是零成本的，建议 snapshot({context:true}) 直接带：
- /proc/<pid>/status：State、TracerPid、Threads
- /proc/<pid>/syscall
- /proc/<pid>/fd + readlink（fd 3 → eventpoll，11/12 → socket）
- /proc/<pid>/wchan
 7. "为什么停"的 reason 字段
attach 静默暂停是历史遗留问题。每次 stop 都应带 reason: attach|signal|breakpoint|syscall|step|exit，signal 时带名字。这次 ttyd 被暂停，我只能从 paused_threads 自己推断。
 8. 输出生命周期（正确性问题，优先级高）
现在 resumeThread 返回时 process_output 为空，要下一次调用才拿到；目标退出还可能丢。建议：
- resumeThread 同步返回本次 flush 的 output；
- 或提供 waitOutput(tid, timeout)；
- 输出按 target 分桶、保留 ring buffer，target 退出后仍可读，并带 exitCode。
否则 run + resume 做任何自动化都不可靠。
 9. SIGCHLD 默认策略
sh -c "cmd1; cmd2" 只跑第一条就被 SIGCHLD 停住，静默截断。建议默认 SIGCHLD: pass，或提供 signalPolicy: {SIGCHLD:"pass"} / run(..., autoPassSignals:["SIGCHLD"])。
10. target 切换显式化
attach/run 新目标时旧目标被悄悄 detach（TracerPid 归 0）。响应里加 released: [oldPid]，或者强制先 detach。
11. ps 过滤/分页
threads=true 48KB 直接落盘。加 pattern、limit、fields，默认精简。
12. help/docs 工具
aidbg://debugger.d.ts 对 tools-only 客户端不可读，入口语义（"只执行顶层代码，导出函数不自动调用"）也不在 server instructions 里。加一个 docs 工具返回 d.ts 摘要 + 语义说明，能省掉我这次 Object.getOwnPropertyNames(dbg) 的反射。

## 后续改进

### 已定事项

- `m.fromDwarf(name)` 接受运行时字符串。解析失败在调用处报告。静态可确定且能解析的名称继续参与精确类型推导。
- `$format()` 默认把 C `char[N]` 展示为字符串，最多读取 `N` 字节，在首个 NUL 处停止，并遵守字符串展示上限。没有 NUL 时按有界字符序列展示。`$toJS()` 是否同步返回字符串待定。
- MCP 已提供 `gdb`，其中 `c` 继续执行并等待停点。补充分离、暂停和立即恢复的工具入口。沿用 `gdb` 命令还是增加 `debug({action})` 待定。
- `fmt` 直接打印已落地。结构化数据继续由 `dbg` 等 API 提供，`fmt.sprintf()` 和字节数组版 `fmt.hexdump()` 返回字符串。

### 待排期建议

1. 调用栈与 `symbolAt` 共享底层符号查找和缓存，为结构化结果提供 `demangledName`，展示优先采用可读名称。调用者帧使用 `lookupPc`，区分符号区间命中和最近符号候选。
2. 从 DWARF 导入枚举成员名及其数值。`$format()` 默认显示已知名称，例如 `UV_SIGNAL`，未知值显示数值。`{enums: "raw"}` 始终显示数值。
3. 为 `$toJS()` 和 `$toJson()` 补空指针与 BigInt 示例。普通空指针在 `$toJS()` 中为 `null`，在 `$toJson()` 摘要中显示为十六进制地址字符串。`$toJS({pointer: "string"})` 只转换地址值，64 位整数仍为 BigInt。序列化报错时提示使用 `$toJson()`。
4. 补齐基本控制动词的 MCP 入口，并在速查中区分继续并等待停点与立即恢复。
5. `layout()` 按 C 声明展示指针成员及偏移，例如 `uv_loop_t *loop; // byteoffset: 8`，避免在成员行展开 pointee。
6. 文档说明 `m.cStr().at(addr)` 读取指针槽位，字符串首地址用 `dbg.memory.readCString(addr, maxLen)` 读取。
7. 明确 `withFormatter()` 返回新的类型描述符。审视声明签名时保留接收者的具体类型和方法链，并补充 `m.self()` 示例。
8. 错误信息给出可执行的下一步。`p`/`ptype` 说明支持当前帧中的裸局部变量和形参，并区分不支持的表达式、变量不存在和值不可读。DWARF 类型找不到时提示 `m.findTypes("*Name*")`。考虑让 `deref: true` 表示默认深度。
9. 在 Quick Start 集中说明 `attach`/`run` 默认 running、`$format()` 默认 `deref: 2`，以及 `maxElements` 控制序列、`maxFields` 控制字段。
10. 保持 `fmt.*` 作为主命名空间，以 `fmt.backtrace` 为主名。现有 `pVar`、`pType` 的去留及 `pBacktrace` 兼容别名待定。工具描述提供一屏速查。
11. 从 DWARF 声明独立取得栈帧变量和形参类型。即使值被优化掉或内存不可读，只要声明类型已知，`ptype` 仍应显示它。
12. 用同一运行时地址和原始回包核对 `addrToLine` 的差异，检查调用者帧 PC、模块地址换算及行表覆盖。按确认的缺口决定是否增加符号级源码回退。
13. 评估 `fmt.symbols({pattern})` 的字符串模式、`fmt.disassemble(addr, count)` 简写和 `fmt.hexdump(addr, len)` 重载。`fmt.memory(addr, len)` 已覆盖按地址读取并直接打印的场景。

### C++ 标准库

#### DWARF 类型名称匹配

- 优先按真实限定名查找。根据 DWARF 父作用域拼接限定名，命中 typedef 后沿 `DW_AT_type` 获取实际类型。
- 真实限定名未命中时，复用现有 C++ 名称规则生成标准库简写的候选。优先比较 DWARF 模板参数和类型引用，缺少结构化元数据时解析模板名称。识别已知的标准库 ABI 命名空间，仅在默认模板参数一致时允许省略。例如 `std::vector<app::MyType>` 匹配采用 `std::allocator<app::MyType>` 的实例，自定义 allocator 可用完整名称查询。
- 返回目标的原始 DWARF 类型，保留模块、ABI 和实际限定名。指向同一类型记录的 typedef 和类定义可去重，存在多个有效候选时报告歧义。
- 第一批覆盖 `std::string`、`std::string_view` 及对应的宽字符和 UTF 字符别名，以及 `std::vector<T>` 和 `std::array<T, N>`。用固定工具链生成 GCC/libstdc++ 和 Clang/libc++ 的 ELF 与 DWARF 样本，验证标准别名、非类型模板参数、用户类型、自定义 allocator 和 ABI 歧义。标准库头文件作为样本生成依赖。
- 第二批考虑 `map`、`set`、`unordered_map`、`unordered_set`、`deque`、`list` 和 `forward_list`。后续考虑 `pair`、`tuple`、`optional`、`variant` 和智能指针。`std::pmr` 别名保留其 allocator 语义。

#### 值展示

- 基于目标 DWARF 验证字段和偏移，内置适配器直接生成有界预览。第一批覆盖 `string`、`string_view`、普通 `vector<T>` 和 `array<T, N>`。`vector<bool>` 的压缩布局单独处理。未知布局回退普通字段展示。
- 后续优先展示 `map` 和 `unordered_map` 的键值对，再扩展其他容器和智能指针。沿节点读取时遵循元素和读取预算。

### 长期项

- 完善 C++ 继承、引用、vtable 和 RTTI。
- 多目标及会话生命周期沿用 [spec-02 的多实例规划](spec-02.md#暂停恢复和进程生命周期)。客户端通过 TCP 连接远端 `aidbg-server` 已有，`gdbserver` 等远程目标协议待定。
