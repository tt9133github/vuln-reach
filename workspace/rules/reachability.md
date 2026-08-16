# 漏洞可达性研判方法论（供 Agent 消费）

## 输入

- `/workspace/alerts/*.json` — 归一化告警契约（`normalize.py` 产出）
- `/workspace/repo/dependencies.json` — 仓库依赖清单
- `/workspace/repo/usage.json` — 代码用法证据（文件、行号、sink、入口）
- `/workspace/rules/*.yaml` — 研判规则（版本区间、sink、前置条件）与判定策略

## 步骤

1. 读取告警契约，确定待研判的 CVE 与受影响包
2. 从依赖清单与代码证据中提取安装版本、sink 调用点、入口来源
3. 运行 `python3 /workspace/scripts/reachability.py` 得到结构化判定
4. 对每个判定核验证据链，输出带证据的最终报告

## 判定口径

- `reachable`：版本命中 + sink 存在 + 全部前置条件满足
- `not_reachable`：至少一个必要条件有完整、可追溯的反证；例如权威依赖清单确认版本未命中，或完整 sink 扫描确认不存在调用
- `unknown`：证据缺失、版本或约束不能严格解析、扫描完整性未知，或 Python/OctoBus 双引擎结果不一致

三态值为 `true / false / null`。禁止把“没有找到”自动解释成 `false`，也禁止忽略无法解析的规则片段继续给出肯定结论。

## 研判边界

当前 fastjson 结论覆盖目标 commit 的“组件 public API 参数到危险 sink”的代码边界。它不自动证明该 API 已由公网请求调用，也不证明运行环境存在可利用 gadget、JNDI 出网或成功 RCE。报告必须明确保留这些限制。

Python 脚本与 OctoBus JS 能力是异构交叉验证。二者消费同一规则和证据，但分别实现判定；关键字段不一致时，Agent 必须降级为 `unknown` 并并列展示差异。

## 证据要求

每条结论必须引用 `rule_id`、目标源码 commit、检查状态以及可用的文件路径与行号；无证据不下结论。
