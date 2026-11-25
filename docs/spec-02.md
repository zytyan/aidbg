## 新增功能

### 变量类型

`TypeSystem` 新增 `typeOfVar`，脚本通过 `m.typeOfVar(name)` 查询变量的 DWARF 类型。找不到类型时返回 `undefined`。

### 文件和路径

首批支持以下 Node.js API 子集。脚本使用 `node:fs`、`node:fs/promises` 和 `node:path` 的 ESM 导入。

| 用途 | 同步 API（`node:fs`） | 异步 API（`node:fs/promises`） |
| --- | --- | --- |
| 读取文件 | `readFileSync` | `readFile` |
| 列出目录 | `readdirSync` | `readdir` |
| 查询文件或目录属性 | `statSync` | `stat` |
| 检查路径可访问性 | `accessSync`、`existsSync` | `access` |
| 解析实际路径 | `realpathSync` | `realpath` |

首批文件操作覆盖读取和查询。路径参数支持字符串，文件读取支持 UTF-8 文本和二进制。同步调用直接返回结果，异步调用返回 Promise。文件路径指向 aidbg 服务端，相关操作以服务端工作目录为相对路径基准。

`node:path` 提供 `join`、`resolve`、`normalize`、`relative`、`isAbsolute`、`dirname`、`basename`、`extname`、`parse`、`format` 和 `sep`，采用 Linux/POSIX 路径语义。这些操作只处理字符串，直接返回结果。

参考 [Node.js 文件系统 API](https://nodejs.org/api/fs.html) 和 [Node.js 路径 API](https://nodejs.org/api/path.html)。

### 系统调用捕获

`dbg.catchSyscall` 支持捕获指定线程或整个被调试进程的系统调用。脚本可选择入口、出口或两者。命中时生成 `SyscallCaught`，沿用断点的命中回调和暂停控制语义。事件包含线程、阶段、系统调用号和原始参数，尽可能提供系统调用名、参数名和解码后的内容。出口事件还返回系统调用结果。

## 目标修改

### 进程列表

`ps` 默认每个进程输出一行，显示 `pid`、`ppid`、`args` 和线程数，默认隐藏内核线程。仅在显式请求线程列表时按线程逐行输出，并显示各线程的 `tid`。

### 脚本顶层静态检查

通过 AST 检查脚本的顶层作用域，识别只有声明或导出、缺少实际执行操作的脚本，以发现脚本生成时的遗漏。出现函数调用（例如 `console.log(...)`）或可能触发 getter 的访问就算有操作，无需证明其有外部副作用。递归检查顶层变量初始化表达式，函数声明和回调内部的调用在该函数实际被调用时才执行。

只有声明或导出、缺少执行操作的脚本应在编译时报告错误。脚本可以在顶层显式声明豁免。

```ts
"I know this is a no-op script";

export function onHit(hit: BreakpointHit) {
    // ...
}
```

顶层调用返回 Promise 的工具时，通过 `await` 或 `.then()` 处理返回值。静态检查应识别先保存到变量、再在顶层处理的写法。未处理的调用应在编译时报告错误。可使用以下顶层指令显式豁免。

```ts
"I intentionally allow unawaited Promises";
dbg.continueForStop();
```

### 暂停、恢复和进程生命周期

- 顶层 `dbg` 的暂停接口统一为 `pauseThread` 和 `pauseAll`，恢复接口统一为 `resumeThread` 和 `resumeAll`。删除原有的 `dbg.pause`、`dbg.resume`、`dbg.continue`。
- MCP 工具和脚本均可通过 `setForkPolicy("child" | "parent" | "both")` 配置 fork 跟踪策略。成功执行 `execve` 时应触发暂停。
- 多实例目标为每个被调试进程一个 QuickJS 实例。只有一个实例时可省略 `session`，有多个实例时必须显式指定 `session`。跟踪 fork 子进程时，子进程的 QuickJS 实例直接从父进程克隆。进程成功执行 `execve` 时清理旧 QuickJS 实例所持有的资源。多实例及其 QuickJS 生命周期管理可视实现复杂度延期。

## 文档修改

说明脚本的顶层作用域、可用全局对象及可导入模块。宿主能力限于文档列出的全局对象和模块。
