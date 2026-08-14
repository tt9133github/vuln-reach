# vuln-reach：组件漏洞可达性研判 Agent

`vuln-reach` 是运行在 Agent-Compose + OctoBus 基础平台上的安全 Agent 应用，不包含两套平台本身。

它订阅并归一化 GitHub Dependabot 告警，通过确定性规则和代码证据判断漏洞是否真实可达；Agent 负责组织证据、处理不确定性和生成修复报告，并经 OctoBus 调用 `CheckReachability` 做交叉验证和审计留痕。

## 架构与职责

```text
GitHub Dependabot API
        │ fetch_alerts.py / normalize.py（确定性取数与格式转换）
        ▼
workspace/alerts + rules + repo evidence
        ├──────────────► reachability.py（确定性规则判定）
        │
        └──────────────► Agent-Compose / reach-analyzer（证据组织、差异处理、报告）
                                  │
                                  ▼
                         OctoBus capset=vulnreach
                                  │ CheckReachability
                                  ▼
                         审计日志 access.log
```

- `agent-compose.yml`：Agent、模型、工作区、定时触发器和 OctoBus capset 声明。
- `workspace/`：归一化告警、依赖清单、代码使用证据、规则和确定性研判脚本。
- `octobus/`：`vuln-reach` 能力服务源码；导入时与同一份 `workspace/` 组装，避免维护两份规则。
- `scripts/`：Dependabot 在线取数和归一化脚本。
- `run.sh`：应用项目、运行 Agent、打印运行日志和 OctoBus 审计记录。

## 仓库结构

```text
vuln-reach/
├── agent-compose.yml
├── run.sh
├── sources.yaml
├── scripts/
│   ├── fetch_alerts.py
│   └── normalize.py
├── workspace/
│   ├── alerts/
│   ├── repo/
│   ├── rules/
│   └── scripts/reachability.py
└── octobus/
    ├── bin/vuln-reach.js
    ├── proto/vuln_reach.proto
    ├── service.json
    ├── package.json
    ├── config.schema.json
    └── secret.schema.json
```

## 前置条件

服务器应已安装并运行：

- Docker 与 Docker Compose v2。
- Agent-Compose daemon，容器名为 `agent-compose`。
- OctoBus daemon，容器名为 `octobus`，端口仅绑定 `127.0.0.1:9000`。


## 从干净目录部署

以下步骤假设仓库被放到固定路径 `/opt/agent-compose/data/projects/vuln-reach`。固定路径可以确保 Agent-Compose 使用稳定的项目标识，避免因配置文件路径变化生成重复项目记录。

### 0. 删除旧目录前先下线旧项目

```bash
docker exec agent-compose agent-compose -f \
  /data/projects/vuln-reach/agent-compose/agent-compose.yml down 2>/dev/null || true

docker exec agent-compose agent-compose -f \
  /data/projects/vuln-reach/agent-compose.yml down 2>/dev/null || true
```

`down` 不删除运行历史；它只停止旧沙箱和调度器。完成后再移除或备份服务器上的旧 `vuln-reach` 目录。

### 1. 获取代码并启动基础平台

```bash
cd /opt/agent-compose
docker compose up -d octobus agent-compose

mkdir -p /opt/agent-compose/data/projects
cd /opt/agent-compose/data/projects
git clone <仓库地址> vuln-reach
cd vuln-reach
```

### 2. 准备共享 Token


```bash
cd /opt/agent-compose

if ! grep -q '^OCTOBUS_TOKEN=.' .env; then
  umask 077
  printf '\nOCTOBUS_TOKEN=%s\n' "$(openssl rand -hex 32)" >> .env
fi

OCTOBUS_TOKEN="$(sed -n 's/^OCTOBUS_TOKEN=//p' .env | tail -1)"
test -n "$OCTOBUS_TOKEN"
docker compose up -d --force-recreate agent-compose
```

不要打印或提交该变量。

### 3. 导入 OctoBus 能力服务

下面的命令只清理并重建本项目使用的 `vulnreach`、`reach-01` 和 `vuln-reach`，不会影响其他能力服务：

```bash
cd /opt/agent-compose/data/projects/vuln-reach

docker exec octobus octobus --addr 127.0.0.1:9000 capset delete vulnreach 2>/dev/null || true
docker exec octobus octobus --addr 127.0.0.1:9000 instance delete reach-01 2>/dev/null || true
docker exec octobus octobus --addr 127.0.0.1:9000 service delete vuln-reach 2>/dev/null || true

docker exec -u 0 octobus sh -c \
  'rm -rf /var/lib/octobus/imports/vuln-reach && mkdir -p /var/lib/octobus/imports/vuln-reach/workspace'

docker cp octobus/. octobus:/var/lib/octobus/imports/vuln-reach/
docker cp workspace/. octobus:/var/lib/octobus/imports/vuln-reach/workspace/
docker exec -u 0 octobus chmod 755 /var/lib/octobus/imports/vuln-reach/bin/vuln-reach.js

docker exec octobus octobus --addr 127.0.0.1:9000 service import \
  vuln-reach /var/lib/octobus/imports/vuln-reach --build auto --reinstall
```

### 4. 创建 instance → capset → method → token 链路

```bash
docker exec octobus octobus --addr 127.0.0.1:9000 instance create \
  reach-01 --service vuln-reach --config-json '{}'

docker exec octobus octobus --addr 127.0.0.1:9000 capset create \
  vulnreach --name VulnerabilityReach \
  --description 'Vulnerability reachability capability set'

docker exec octobus octobus --addr 127.0.0.1:9000 capset add-instance \
  vulnreach reach-01 --no-all-methods

docker exec octobus octobus --addr 127.0.0.1:9000 capset select-method \
  vulnreach reach-01 vulnreach.v1.VulnReachService/CheckReachability \
  --mcp-tool vuln-reach__reach-01__check_reachability

printf '%s' "$OCTOBUS_TOKEN" | docker exec -i octobus \
  octobus --addr 127.0.0.1:9000 capset add-token \
  vulnreach vulnreach-token-01 --token-stdin
```

验证注册结果：

```bash
docker exec octobus octobus --addr 127.0.0.1:9000 status
docker exec octobus octobus --addr 127.0.0.1:9000 service list
docker exec octobus octobus --addr 127.0.0.1:9000 instance list
docker exec octobus octobus --addr 127.0.0.1:9000 capset list-methods vulnreach
```

结果中应看到：

- service：`vuln-reach`
- instance：`reach-01`，状态为 `running`
- capset：`vulnreach`
- method：`vulnreach.v1.VulnReachService/CheckReachability`

### 5. 应用并运行 Agent

```bash
cd /opt/agent-compose/data/projects/vuln-reach
bash run.sh
```

`run.sh` 会依次完成：

1. 检查 Agent-Compose 和 OctoBus 状态。
2. 校验并应用 `agent-compose.yml`。
3. 运行 `reach-analyzer`。
4. 输出 Agent 日志和最新的 OctoBus `CheckReachability` 审计记录。

输出文件位于：

```text
workspace/report/verdicts.json
workspace/report/reachability-report.md
workspace/report/agent-report.md
```

定时触发器 `daily-reachability` 每天 03:00 执行，也可检查：

```bash
docker exec agent-compose agent-compose -f \
  /data/projects/vuln-reach/agent-compose.yml scheduler ls
```

## 可选：重新拉取 Dependabot 告警

仓库已包含可离线复现的归一化样例。重新在线取数时，在当前 shell 临时设置只读 GitHub Token：

```bash
cd /opt/agent-compose/data/projects/vuln-reach
export GITHUB_TOKEN='<只读 GitHub Token>'
python3 scripts/fetch_alerts.py
python3 scripts/normalize.py
unset GITHUB_TOKEN
```

更新 `workspace/` 后，重新执行“导入 OctoBus 能力服务”，确保 Agent 与能力服务消费同一份数据和规则。

## 判定知识与脚本分工

确定性代码负责：

- 版本区间解析与命中判断。
- 危险 API sink 与代码行证据匹配。
- 前置条件逐项求值。
- `reachable / not_reachable / unknown` 状态计算。
- 输入归一化、字段校验和结构化报告。

LLM Agent 负责：

- 组织多来源证据并解释判定。
- 对本地脚本与 OctoBus 结果做一致性检查。
- 证据不足时维持 `unknown`，而不是补造结论。
- 生成面向修复人员的建议和最终报告。

核心经验规则位于 `workspace/rules/`，实际被 Python 研判脚本和 OctoBus JS 服务共同消费。每条结论必须引用 `rule_id` 和具体文件行号。
