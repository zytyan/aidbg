## 新增功能

1. 新增`dbg.typeOfVar`，可以从变量中获取类型。
2. 新增node接口兼容的 `fs` `path` 子集，可以让程序处理路径和读取文件
3. 新增 `dbg.catchSyscall` 接口，捕获特定线程或整个进程的系统调用。尽可能给出系统调用名和参数名及内容。

## 目标修改

ps功能的默认输出要稍微少一些，推荐参数和Linux的ps一致，正常情况下可以不输出json格式而是行格式，以避免json过大。

对于仅导出函数，静态检查没有副作用的脚本，如果发现脚本没有任何副作用，

静态报错，除非显式声明一个字符串（类似'use strict'）

```ts
"I know this is a no-op script";

export function onHit(hit: BreakpointHit) {
    // ...
}
```

顶层若使用返回Promise的工具，却没有await或.then()，同样报错，除非显式声明一个字符串
```ts
"I intentionally allow unawaited Promises";
dbg.continueForStop();
```

以上通过AST过静态检查，对于变量声明也是递归静态检查，若没有调用函数或可能的get，那就报错。

没必要动态检查，再怎么有幻觉也不至于这样，这种级别的小模型也不指望它能定位。

`continue()`接口应该删除，仅留下resume接口。

删除`pause`的重载，仅留下语义明确的`pauseThread`和`pauseAll`

删除resume的重载，类似的，改为语义明确的`resumeThread` `resumeAll`

fork策略需要在MCP工具和脚本中可配置 setForkPolicy("child" | "parent" | "both")，同时execve应触发暂停。

应该支持多实例，使用 `session01-handler01`这种格式？

## 文档修改

文档需要写明这是顶层作用域

同文档问题：必须说明除了导出的特定变量，是没有其它node/deno能力的。小模型喜欢生造内容。