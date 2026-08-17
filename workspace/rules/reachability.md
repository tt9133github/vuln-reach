# 漏洞可达性研判方法论（供 Agent 消费）

## 输入

- `/workspace/runtime/current.json` — 本次不可变快照指针
- `/workspace/runtime/snapshots/<snapshot_id>/alerts/*.json` — 仓库内固定的真实告警输入副本
- `/workspace/runtime/snapshots/<snapshot_id>/repo/dependencies.json` — 程序从真实 `pom.xml` 解析的依赖清单
- `/workspace/runtime/snapshots/<snapshot_id>/repo/usage.json` — 程序从固定 commit 扫描出的代码证据
- `/workspace/rules/*.yaml` — 研判规则（版本区间、sink、前置条件）与判定策略

## 步骤

1. 通过 OctoBus `BuildRepositoryEvidence` 校验固定告警输入、下载固定 commit 并生成快照
2. 读取同一个 `snapshot_id`，确定待研判 CVE、安装版本、sink 调用点与入口来源
3. 通过 OctoBus `CheckReachability` 对同一快照中的告警逐条执行确定性判定
4. 将能力返回的结构化证据写入报告，Agent 只负责解释和整理

## 判定口径

- `reachable`：版本命中 + sink 存在 + 全部前置条件满足
- `not_reachable`：至少一个必要条件有完整、可追溯的反证；例如权威依赖清单确认版本未命中，或完整 sink 扫描确认不存在调用
- `unknown`：证据缺失、版本或约束不能严格解析，或扫描完整性未知

三态值为 `true / false / null`。禁止把“没有找到”自动解释成 `false`，也禁止忽略无法解析的规则片段继续给出肯定结论。

## 研判边界

当前 fastjson 结论覆盖目标 commit 的“组件 public API 参数到危险 sink”的代码边界。它不自动证明该 API 已由公网请求调用，也不证明运行环境存在可利用 gadget、JNDI 出网或成功 RCE。报告必须明确保留这些限制。

正式运行以 OctoBus 能力返回为唯一确定性判定来源。Agent 不得修改判定，只能结合证据、限制和修复建议生成可读报告。

## 证据要求

每条结论必须引用 `rule_id`、目标源码 commit、检查状态以及可用的文件路径与行号；无证据不下结论。
