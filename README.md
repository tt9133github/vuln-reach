# vuln-reach：组件漏洞可达性研判 Agent

本仓库包含一套可复现的 Agent-Compose + OctoBus 部署，以及考核应用 `vuln-reach`。它分析 GitHub Dependabot 告警，用确定性规则和代码行证据判断漏洞是否可达，再由 Agent 调用 OctoBus 能力做异构交叉验证并生成报告。

仓库只保存自研 Agent、能力服务、规则、测试和可复现的部署配置，不复制 Agent-Compose 与 OctoBus 的上游源码。两套平台通过官方容器镜像部署；密钥、Token、运行数据库、Docker volume 和现场日志均不进入 Git。

## 架构与考核点

```text
Dependabot 告警 → normalize.py → 统一告警契约
                                  │
                  依赖清单 + 源码证据 + YAML 规则
                                  │
                   ┌──────────────┴──────────────┐
                   │ Python 确定性引擎           │ OctoBus JS 能力
                   └──────────────┬──────────────┘
                                  │ 关键字段必须一致
                         Agent 解释并输出报告
```

- `deploy/docker-compose.yml`：统一管理 Agent-Compose 与 OctoBus，均为 `restart: always`。
- `agent-compose.yml`：Agent、固定 Guest 镜像、模型、工作区、capset 和 UTC cron。
- `octobus/`：可导入的 `vuln-reach` 服务；仅授权一个显式 gRPC method。
- `workspace/`：离线告警样例、目标 commit、依赖清单、源码证据、规则和 Python 判定引擎。
- `scripts/`：平台配置、OctoBus 注册、在线取数、归一化与验收。
- `run.sh`：构建 Guest、应用项目、执行 demo、检查三个报告和审计记录。

当前兼容矩阵固定为：

| 组件 | 版本策略 |
| --- | --- |
| Agent-Compose daemon/guest | `v2607.10.0`，保持 `workspace.provider: local` 配置兼容 |
| 自定义 Guest | 基于官方 `v2607.10.0`，额外安装 `PyYAML==6.0.2` |
| OctoBus | `.env` 中可替换；首次拉取后建议将 `latest` 改成已验证 digest |
| Node.js 能力依赖 | `package-lock.json` 锁定 |

## 交付与验收环境

- SSH 地址：`8.130.33.113`
- 用户名：`root`
- SSH 端口：`22`
- 认证方式：SSH 公钥；收到考官公钥后写入 `/root/.ssh/authorized_keys`

服务端口 `7410` 与 `9000` 仅绑定本机回环地址，云安全组不放行这两个端口。仓库与文档不提供 SSH 密码、模型密钥或 OctoBus Token。

## 全新安装

以下命令会替换同名 `agent-compose`、`octobus` 容器以及同名 Compose 项目。重要数据先备份；不要直接复制示例中的空 Token。

### 1. 准备平台目录和配置

```bash
sudo mkdir -p /opt/agent-compose/data/projects
cd /opt/agent-compose

# 将仓库 deploy/docker-compose.yml 和 deploy/.env.example 放到此目录
cp /path/to/vuln-reach/deploy/docker-compose.yml ./docker-compose.yml
cp /path/to/vuln-reach/deploy/.env.example ./.env
chmod 600 .env

# 编辑模型接入参数：LLM_API_ENDPOINT / LLM_API_KEY / LLM_MODEL
vi .env

# 生成 OctoBus capset Token；命令不会向终端打印值
umask 077
token="$(openssl rand -hex 32)"
sed -i "s/^OCTOBUS_TOKEN=.*/OCTOBUS_TOKEN=${token}/" .env
unset token
```

`docker-compose.yml` 已声明所有持久化映射，不需要每次手工映射：

- `/opt/agent-compose/data:/data`：Agent-Compose 数据、项目与运行记录。
- Docker named volume `octobus-data:/var/lib/octobus`：OctoBus 服务、实例、capset 与审计日志。
- `/var/run/docker.sock`：Agent-Compose 创建 Guest 沙箱所需。

两个 HTTP 端口只绑定 `127.0.0.1`，不会直接暴露控制面到公网。云安全组也不应放行 7410/9000。

### 2. 启动基础平台

```bash
cd /opt/agent-compose
docker compose pull
docker compose up -d
docker compose ps
```

### 3. 克隆答题仓库

```bash
cd /opt/agent-compose/data/projects
git clone --branch main --single-branch \
  https://github.com/tt9133github/vuln-reach.git vuln-reach
cd vuln-reach
```

### 4. 配置网关并注册 OctoBus 能力

```bash
cd /opt/agent-compose/data/projects/vuln-reach
bash scripts/configure_gateway.sh
bash scripts/deploy_octobus.sh
```

两个脚本分别完成：

1. 将 OctoBus 内网地址和 Token 写入 Agent-Compose settings；全新数据库不能跳过此步。
2. 导入 `octobus/` 与同一份 `workspace/`，创建 `service → instance → capset → method → token` 链路。

脚本只重建本项目的 `vuln-reach` service、`reach-01` instance 和 `vulnreach` capset，不会打印 Token。

### 5. 跑通 demo 和验收

```bash
cd /opt/agent-compose/data/projects/vuln-reach
bash run.sh
```

首次运行会构建 `vuln-reach-guest:v1.0.0`。成功后应得到：

```text
workspace/report/verdicts.json
workspace/report/reachability-report.md
workspace/report/agent-report.md
```

也可单独复验：

```bash
bash scripts/verify.sh
docker exec agent-compose agent-compose -f \
  /data/projects/vuln-reach/agent-compose.yml scheduler ls
docker exec octobus sh -c \
  "grep 'CheckReachability' /var/lib/octobus/access.log | tail"
```

声明式 cron 使用 UTC：`0 19 * * *` 对应北京时间次日 03:00。重启服务器后用 `docker compose ps` 确认两个服务自动恢复。

## 实施问题与处理

### 1. 项目路径变化会生成重复记录

早期试跑时曾在不同层级放置 `agent-compose.yml`，导致 Agent-Compose 将同一应用识别为多个项目，并留下重复调度器记录。最终将仓库固定到 `/opt/agent-compose/data/projects/vuln-reach`，配置固定在仓库根目录；替换代码前先对旧配置执行 `down`。

### 2. 全新数据库中 Agent 无法自动找到 OctoBus

仅启动两个 daemon 并不会自动建立能力网关配置。表现为 OctoBus `status` 正常，capset 也存在，但 Guest 内没有可用能力。`scripts/configure_gateway.sh` 在部署后显式写入 OctoBus 内网地址和 Token；`scripts/deploy_octobus.sh` 再建立 `service → instance → capset → method → token` 链路，且不在终端打印 Token。

### 3. Python 与 JS 双引擎可能给出不一致结论

确定性研判脚本和 OctoBus 能力分别使用 Python 与 JavaScript 实现，若只同步文档而没有同步测试，规则边界容易漂移。处理方式是让两个引擎消费同一份 `workspace/` 证据，在 CI 中使用相同的 CVE 场景验证关键字段；运行时若结果不一致，最终结论必须降级为 `unknown`，不允许 Agent 任选一边。

### 4. 默认暴露控制面不符合交付要求

试跑阶段使用过对外发布的 UI，但控制面不应在无额外鉴权时暴露到公网。最终 Compose 不启动 UI，并将 Agent-Compose 和 OctoBus HTTP 端口均绑定到 `127.0.0.1`；对外只保留受安全组限制的 SSH。

## 判定边界与证据

三态口径：

- `reachable`：版本、sink 和全部利用前置条件都有肯定证据。
- `not_reachable`：至少一个必要条件有完整、可追溯的反证。
- `unknown`：必要证据缺失、版本/规则解析失败、扫描完整性未知，或 Python/JS 结果不一致。

“没有找到”不自动等于“不存在”。依赖缺失只有在清单标记为 authoritative 时才能成为反证；sink 缺失只有在 `sink_scan_complete: true` 时才能成为反证。

目标源码证据固定到 `tt9133github/mvntree-util@d253e2585d9cc702037b43edb7cff5752a1281bc`。fastjson 结论只证明目标组件的 public API 参数到达 `JSONObject.parseObject`，不声称该 API 已暴露公网，也不声称实际 RCE 成功。报告会保留 gadget、运行时配置、网络入口等限制。

修复建议区分“CVE 首个修复版本”和“当前部署选择”：fastjson 优先迁移 fastjson2；保留 1.x 时至少使用 1.2.84。SafeMode 从较新 1.x 才提供，不能作为 1.2.31 原地开启的措施。Velocity 2.x 迁移需要把 Maven artifact 改为 `org.apache.velocity:velocity-engine-core`。

规则依据包括 [fastjson 1.2.84 官方发布说明](https://github.com/alibaba/fastjson/releases)、[fastjson SafeMode 官方安全更新](https://github.com/alibaba/fastjson/wiki/security_update_20200601)、[Apache Velocity CVE-2020-13936 公告](https://velocity.apache.org/news.html) 和 [Velocity 2.x 升级说明](https://velocity.apache.org/engine/2.3/upgrading.html)。

## 更新告警与本地测试

仓库自带离线样例。重新获取 Dependabot 告警时使用只读 GitHub Token：

```bash
export GITHUB_TOKEN='<read-only token>'
python3 scripts/fetch_alerts.py
python3 scripts/normalize.py
unset GITHUB_TOKEN
bash scripts/deploy_octobus.sh
```

`normalize.py` 会拒绝输出文件名冲突，并删除本次输入中已不存在的旧告警，避免陈旧文件继续参与分析。

```bash
pip install -r guest/requirements.txt
python -m unittest discover -s tests -v
cd octobus && npm ci && npm test
```

CI 同时执行 Python 与 JS 共享场景、静态语法检查。任何新增规则都应为两个引擎补充相同预期结果。
