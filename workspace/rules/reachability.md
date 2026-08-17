# 漏洞可达性研判方法论（供 Agent 消费）

## 输入

- `/workspace/runtime/current.json` — 本次不可变快照指针
- `/workspace/runtime/snapshots/<snapshot_id>/alerts/*.json` — 仓库内固定的真实告警输入副本
- `/workspace/runtime/snapshots/<snapshot_id>/repo/dependencies.json` — 程序从真实 `pom.xml` 解析的依赖清单
- `/workspace/runtime/snapshots/<snapshot_id>/repo/usage.json` — 程序从固定 commit 扫描出的代码证据
- `/workspace/rules/*.yaml` — 研判规则（版本区间、sink、前置条件、Level 证据信号）与判定策略

## 步骤

1. 通过 OctoBus `BuildRepositoryEvidence` 校验固定告警输入、下载固定 commit 并生成快照
2. 读取同一个 `snapshot_id`，确定待研判 CVE、安装版本、sink 调用点与入口来源
3. 通过 OctoBus `CheckReachability` 对同一快照中的告警逐条执行确定性判定
4. 将能力返回的结构化证据写入报告，Agent 只负责解释和整理

## 企业可达性等级

Level 不是 CVSS 的替代品。CVSS 描述漏洞固有严重性；Level 0-4 描述在当前资产、当前 commit 和当前配置证据下，攻击链走到了哪一步。程序采用“最高已证实阶段”，不会把证据缺失自动当成安全：

- `L0`：漏洞版本存在，但完整扫描没有发现组件使用
- `L1`：组件使用已确认，尚未证明到达规则定义的危险函数
- `L2`：危险函数调用已确认，尚未证明其危险参数来自外部输入
- `L3`：分析边界外的调用者可控输入到达危险函数，但配置、gadget、网络、权限等完整利用前提尚未全部成立。应用项目的边界输入可以是 HTTP、消息或文件；库项目的边界输入可以是 public API 参数
- `L4`：版本、外部入口、危险函数和漏洞特定前提全部形成可追溯的完整攻击路径
- `unknown`：连对应阶段所需的证据或扫描完整性都不足；它不是 `L0`
- `NA`：权威版本证据证明安装版本不在漏洞区间；等级不适用

每条 CVE 规则的 `level_evidence` 声明组件使用、危险函数、外部输入和完整攻击路径分别需要哪些结构化证据，OctoBus 能力实际读取这些字段完成分级。企业治理动作由 `verdict.yaml` 统一配置，便于按组织实践调整而不改程序。

### Log4Shell 口径示例

以 `log4j-core 2.14.1 / CVE-2021-44228 / CVSS 10.0` 为例，CVSS 仍是 10.0，但企业内等级取决于本资产及分析边界的证据：

- 完整扫描未发现 Log4j 使用：`L0`
- 只确认普通组件使用、未证明危险日志/消息处理路径：`L1`
- 危险日志处理点存在，但没有外部输入到达其消息参数：最高 `L2`
- 边界外调用者可控输入进入危险日志处理点，但 JNDI/消息 lookup 已被可信配置阻断，或 gadget、网络条件不成立：`L3`，实际处置优先级可因补偿控制下调
- 外部输入、lookup/JNDI、运行时依赖及网络条件均成立：`L4`

因此，“没有分析边界外的可控输入”不能写成 `L3`，应停在 `L2`；“边界输入已到 sink，但 JNDI 被关闭”才是典型 `L3`。对于库项目，public API 参数可控且到达 sink 已经满足边界输入条件，但仍不能据此声称互联网暴露。这里也不以业务代码是否显式调用 `lookup()` 为唯一条件，因为漏洞组件可能在内部完成消息解析。

## 判定口径

- `reachable`：版本命中 + sink 存在 + 全部前置条件满足
- `not_reachable`：至少一个必要条件有完整、可追溯的反证；例如权威依赖清单确认版本未命中，或完整 sink 扫描确认不存在调用
- `unknown`：证据缺失、版本或约束不能严格解析，或扫描完整性未知

三态值为 `true / false / null`。禁止把“没有找到”自动解释成 `false`，也禁止忽略无法解析的规则片段继续给出肯定结论。

## 研判边界

当前 fastjson 的 `verdict` 覆盖目标 commit 的“组件 public API 参数到危险 sink”代码边界；该路径对应 `L3`。它证明库项目边界外的调用者可以控制 sink 参数，但不自动证明该 API 已由公网请求调用，也不证明运行环境存在可利用 gadget、网络条件或成功 RCE。报告必须明确保留这些限制。

正式运行以 OctoBus 能力返回为唯一确定性判定来源。Agent 不得修改判定，只能结合证据、限制和修复建议生成可读报告。

## 证据要求

每条结论必须引用 `rule_id`、目标源码 commit、检查状态以及可用的文件路径与行号；无证据不下结论。
