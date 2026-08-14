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
- `not_reachable`：版本未命中 / sink 不存在 / 任一前置条件明确不满足
- `unknown`：证据缺失，无法判定

## 证据要求

每条结论必须引用 `rule_id`、文件路径与行号；无证据不下结论。
