# vuln-reach：组件漏洞可达性研判 Agent

本仓库包含一套可复现的 Agent-Compose + OctoBus 部署，以及代码组件漏洞可达性应用 `vuln-reach`。它分析 GitHub Dependabot 告警。Agent 通过 OctoBus 网关调用自研 vuln-reach 能力服务；该服务依据确定性规则和源码行级证据生成漏洞可达性结论，Agent 再整理证据并输出报告。

仓库只保存自研 Agent、能力服务、规则、测试和可复现的部署配置，不复制 Agent-Compose 与 OctoBus 的上游源码。两套平台通过官方容器镜像部署；密钥、Token、运行数据库、Docker volume 和现场日志均不进入 Git。

## 架构

```text
仓库内GitHub Dependabot告警（固定）─────┐
                                        │
                                        ├── OctoBus.BuildRepositoryEvidence → 不可变 runtime snapshot
                                        │
仓库代码（固定）────────────────────────┘          │
                                                 │  告警 + pom.xml + Java/资源源码 + provenance
                                                 │
                                    OctoBus.CheckReachability × 每条告警
                                                 │
                                                 │  唯一确定性判定来源
                                                 │
                     verdicts.json（verdict + Level）+ reachability-report.md
                                                 │
                                        Agent 只解释证据并输出报告
```

- `deploy/docker-compose.yml`：统一管理 Agent-Compose 与 OctoBus，均为 `restart: always`。
- `agent-compose.yml`：Agent、固定 Guest 镜像、模型、工作区、capset 和 UTC cron。
- `octobus/`：可导入的 `vuln-reach` 服务；显式授权刷新证据和校验判定两个 gRPC method。
- `inputs/`：固定的真实 Dependabot 告警输入、抓取时间和 SHA-256 完整性清单；不包含派生分析结果。
- `workspace/`：确定性判定代码、Level 0-4 企业治理规则与报告脚本；`runtime/` 和 `report/` 均由每次真实运行生成并被 Git 忽略。
- `tests/fixtures/`：只供单元测试使用的固定样例，正式运行路径不会读取。
- `scripts/`：平台配置、OctoBus 注册、兼容性取数工具与验收。
- `run.sh`：部署最新能力、构建 Guest、运行完整真实数据闭环并检查报告和审计记录。


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
- 同一 `/opt/agent-compose/data:/data` 也挂载给 OctoBus，使能力服务可以在项目目录生成 runtime snapshot。
- Docker named volume `octobus-data:/var/lib/octobus`：OctoBus 服务、实例、capset 与审计日志。
- `/var/run/docker.sock`：Agent-Compose 创建 Guest 沙箱所需。
- `agent-compose.yml` 将 `./workspace/runtime` 只读挂载到 Guest，使运行中可以读取 OctoBus 新生成的快照；同时将 `./workspace/report` 可写挂载到 Guest，保证手工任务和定时任务的报告回写项目目录。


### 2. 启动基础平台

```bash
cd /opt/agent-compose
docker compose pull
docker compose up -d
docker compose ps
```

### 3. 克隆仓库

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
2. 导入 `octobus/`、固定告警输入、规则和数据源配置，再创建 `service → instance → capset → method → token` 链路。

capset 只开放 `BuildRepositoryEvidence` 与 `CheckReachability`；脚本只重建本项目的 `vuln-reach` service、`reach-01` instance 和 `vulnreach` capset，不会打印 capset Token。`run.sh` 会幂等重做这两步，因此替换新代码后可直接再次运行。

### 5. 跑通 demo 和验收

```bash
cd /opt/agent-compose/data/projects/vuln-reach
bash run.sh
```

首次运行会构建 `vuln-reach-guest:v1.0.0`。成功后应得到：

```text
workspace/report/verdicts.json
workspace/report/reachability-report.md
workspace/report/snapshot.json
workspace/report/agent-report.md
workspace/runtime/current.json
workspace/runtime/snapshots/<snapshot_id>/provenance.json
```

也可单独复验：

```bash
bash scripts/verify.sh
docker exec agent-compose agent-compose -f \
  /data/projects/vuln-reach/agent-compose.yml scheduler ls
docker exec octobus sh -c \
  "grep -E 'BuildRepositoryEvidence|CheckReachability' /var/lib/octobus/access.log | tail"
```

### 已有部署直接更新代码

不需要删除平台数据库或 Docker volume。本次版本给 OctoBus 新增了共享 `/data` 挂载，所以只需更新仓库、覆盖 Compose 文件并让 Compose 按新配置重建容器；`octobus-data` 会保留：

```bash
cd /opt/agent-compose/data/projects/vuln-reach
git pull --ff-only origin main
cp deploy/docker-compose.yml /opt/agent-compose/docker-compose.yml

cd /opt/agent-compose
docker compose up -d

cd /opt/agent-compose/data/projects/vuln-reach
bash run.sh
```

`run.sh` 会重新导入本项目能力并重建 `vuln-reach/reach-01/vulnreach` 三个本项目资源，但不会删除其他 OctoBus service、instance、capset，也不会删除 named volume。

## 实施问题与处理

### 1. 官方一键安装器无法拉取运行镜像

**现象：** 在阿里云服务器执行官方 `installer-latest` 一键安装命令时，安装脚本能够下载，但启动阶段持续拉取镜像失败。安装器解析出的镜像包括 `docker.io/chaitin/agent-compose:v2608.3.0` 和 `docker.io/chaitin/agent-compose-ui:v2608.2.0`；改为源码构建后，构建所需的 `docker.io/library/golang:1.26.4-alpine` 也无法拉取。

**定位：** 将管道命令拆开，单独保存并执行 `install.sh`，再结合独立 `docker pull` 和 Docker daemon 日志排查。日志显示，国内 Docker Hub 代理分别出现镜像或标签未同步的 `404`、allowlist 拒绝的 `403`、`502`、DNS/TLS 异常和连接超时，最终回退 `registry-1.docker.io` 后仍超时。因此根因不是安装脚本无法下载或官方镜像内容损坏，而是安装器选用的 Docker Hub 拉取链路与当前网络、镜像代理不兼容。

**处理：** 不再依赖安装器自动选择镜像，在 `deploy/docker-compose.yml` 中显式使用考核文档指定的官方 GHCR 镜像，并将 Agent-Compose daemon/guest 固定为已验证兼容的 `v2607.10.0`。GHCR 直连不稳定时曾通过国内 GHCR 代理完成拉取，并用 digest 与 OCI source 标签核对上游来源；随后由 `docker compose pull`、`docker compose up -d` 统一管理 Agent-Compose 与 OctoBus。Compose 提供的是可控、可复现的编排，真正绕开故障的是显式控制镜像仓库和版本。

**改进：** 部署前分别探测 GitHub Release、GHCR 和基础镜像的可达性；生产部署固定版本及 digest，不依赖 `latest` 或镜像站是否及时同步；条件允许时将验证过的镜像同步到企业私有仓库，形成受控的镜像供应链。

### 2. 仅填写环境变量不会自动配置能力网关

Agent-Compose 原始设计由 Settings 页面调用 `UpdateCapabilityGatewayConfig`，将 OctoBus 地址和 Token 持久化到 `data.db`；仅在 `.env` 中填写 Token 或仅启动 Compose 不会自动完成这一步。本项目不公开 UI/控制面，因此 `scripts/configure_gateway.sh` 从 `/opt/agent-compose/.env` 读取 Token，通过本机接口完成同等配置；`scripts/deploy_octobus.sh` 则在 OctoBus 中建立 `service → instance → capset → method → token` 链路，且两个脚本均不打印 Token。

单纯重建容器不会丢失配置；删除 Agent-Compose 的 `data.db`、删除 `octobus-data` volume 或更换 Token 后，才需要重新执行相应脚本，把仍保留在 `.env` 与仓库中的配置来源重新应用到平台。

## 判定边界与证据

三态口径：

- `reachable`：在规则声明的分析边界内，版本、sink 和前置条件都有肯定证据。
- `not_reachable`：至少一个必要条件有完整、可追溯的反证。
- `unknown`：必要证据缺失、版本/规则解析失败或扫描完整性未知。

三态 `verdict` 回答“规则边界内是否可达”；企业 Level 回答“最高已经证实到攻击链哪一阶段”。`L0` 为漏洞版本存在但完整扫描未发现组件使用，`L1` 为组件使用但未证实到危险函数，`L2` 为危险函数调用已确认，`L3` 为分析边界外的调用者可控输入到达危险函数，`L4` 为完整利用条件全部成立。证据不足保持 `unknown`，不能冒充 `L0`；Level 也不替代 CVSS。

“没有找到”不自动等于“不存在”。依赖缺失只有在清单标记为 authoritative 时才能成为反证；sink 缺失只有在 `sink_scan_complete: true` 时才能成为反证。

目标源码固定到 `tt9133github/mvntree-util@d253e2585d9cc702037b43edb7cff5752a1281bc`。每次运行都从公开 GitHub codeload 地址下载该 commit 的源码归档，不需要凭证；程序从归档中读取 `pom.xml`、全部 Java 文件和相关资源文件，解析直接依赖、扫描规则 sink，并对同一 Java 文件内的 public String 参数到本地方法再到 sink 的简单数据流做确定性追踪。Velocity 模板只有在全部 `getTemplatePath()` 返回值都能对应到该 commit 的 classpath 资源时才记为 `internal`，否则为 `unknown`。

这是面向固定 Java/Maven 仓库的最小分析器，不宣称具备通用 AST、跨模块调用图或完整污点分析能力。

修复建议区分“CVE 首个修复版本”和“当前部署选择”：fastjson 优先迁移 fastjson2；保留 1.x 时至少使用 1.2.84。SafeMode 从较新 1.x 才提供，不能作为 1.2.31 原地开启的措施。Velocity 2.x 迁移需要把 Maven artifact 改为 `org.apache.velocity:velocity-engine-core`。

规则依据包括 [fastjson 1.2.84 官方发布说明](https://github.com/alibaba/fastjson/releases)、[fastjson SafeMode 官方安全更新](https://github.com/alibaba/fastjson/wiki/security_update_20200601)、[Apache Velocity CVE-2020-13936 公告](https://velocity.apache.org/news.html) 和 [Velocity 2.x 升级说明](https://velocity.apache.org/engine/2.3/upgrading.html)。

## 固定输入、派生快照与本地测试

正式运行把 `inputs/alerts/` 中三条真实 Dependabot 告警快照作为固定考题输入；`inputs/manifest.json` 记录来源、抓取时间和每个文件的 SHA-256。它不声称反映 GitHub 当前告警状态，因此不需要 GitHub Token。依赖清单、源码使用证据、可达性判定和报告均不作为输入提交。

每次 Agent 运行首先通过能力网关调用 `BuildRepositoryEvidence`：校验固定告警文件哈希，从无需认证的公开 GitHub codeload 地址获取指定 commit 源码归档，然后重新解析 `pom.xml`、扫描 Java 使用证据并生成快照。commit 配置不合法、归档下载/解压失败、输入哈希错误、依赖版本无法解析或源码扫描不完整时会中止，不会静默读取旧的派生数据。

对当前固定输入和 commit，确定性预期为：`CVE-2025-70974 = reachable + L3`、`CVE-2022-25845 = reachable + L3`、`CVE-2020-13936 = unknown + L2`。最后一条不是预设结论：代码能确认 Velocity 危险调用，因此最高已证实阶段为 `L2`；但源码归档里缺少对应模板资源，无法可靠判断模板是否由攻击者控制，故三态判定按失败闭锁原则保持 `unknown`。

每个成功快照位于 `workspace/runtime/snapshots/<snapshot_id>/`，包含输入清单副本、固定告警、实际读取的源码、依赖清单、使用证据与 `provenance.json`。`workspace/runtime/current.json` 只在新快照完整落盘后原子切换。`scripts/fetch_alerts.py` 和 `scripts/normalize.py` 仅保留为将来人工更新固定输入时使用的诊断/兼容工具，不属于生产执行链。
