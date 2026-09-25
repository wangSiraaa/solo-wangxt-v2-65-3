# 路由策略离线推演工作台 (Routing Policy Rehearsal Workbench)

在**发布前**离线看清前缀策略会放行/拒绝哪些前缀。完全本地，**不连接任何生产设备**。

* **React**：前缀树 + 命中链可视化、规则编辑、遮蔽检查、语义差异（最小见证前缀集）、有序回放、FRR 交叉验证、配置导入（行级诊断/差异/采纳）
* **FastAPI**：REST API，判定核心用 Python 标准库 **`ipaddress`**
* **PostgreSQL**：邻居、有序规则、不可变配置快照、场景、验证运行（也可用 SQLite 免依赖运行）
* **FRRouting 容器**（router-a / router-b，隔离 bridge）：用 FRR 自己的 prefix-list 匹配器做交叉验证

---

## 1. 语义模型（模拟器）

每条规则 `(seq, prefix, action, ge, le)`，规则按 **seq 升序，首条匹配即终止**：

1. **包含关系**：候选前缀必须是规则基址的子网（`candidate subnet-of base`）；
2. **掩码长度窗口**：`effective_min = ge ?? base_len`，`effective_max = le ?? (ge ?? base_len) : base_len`，即
   * 无 ge/le：精确匹配基址长度；
   * 仅 `le`：窗口 `[base_len, le]`；
   * 仅 `ge`：窗口 `[ge, 32|128]`（Cisco 语义）；
3. 第一个同时满足包含与窗口的规则决定 permit/deny；
4. 都不命中 → 策略的**隐式默认动作**（可配，通常 deny）；
5. **IPv4 与 IPv6 严格隔离**：混合规则在构造/分类时直接报错。

`IPv4Network/IPv6Network` 完成全部地址与掩码计算；引擎与 FRR 的 ge/le 边界一致（见下“FRR 一致性”）。

## 2. 不是文本 diff：最小行为见证集

用户改完规则后，系统计算两个**不可变快照**之间的语义差异，输出**行为发生变化的最小前缀集合**，而不是规则文本差异：

* 前缀空间被精确切分为单元（规则基址边界 + ge/le 长度边界），**全枚举、非采样**；
* 同状态单元用并查集合并成“最大等价区域”（同深度地址相邻 + 跨深度包含且获胜规则/窗口一致），区域被更粗的获胜规则切断时不会跨越；
* 每个发生动作变化的区域给出**一个最浅代表前缀**作为探针，并标注旧/新命中 seq；
* `deny→deny` 只是命中规则换了、转发结果没变，**不会**出现；纯文本改写（如改备注）得到空集。

同时提供**遮蔽分析**：完全遮蔽（永不可达，给出被截获的代表前缀）与部分重叠。

### 三个内置示例（`backend/app/seed.py`，含 before/after 快照与有序探针，可回放）

| 场景 | 说明 | 关键见证 |
|---|---|---|
| **over-permit** 更具体路由误放行 | `192.168.0.0/16 le 24` 过宽，把本应拒绝的 DC /24（如 `192.168.100.0/24`）放了进来；收紧到 `le 23` 并加显式 guard | `192.168.0.0/24`、`192.168.100.0/24` 等 `permit→deny` |
| **reorder** 规则换序 | 宽 `172.16/12 le32 permit` 从 seq 20 换到 seq 5，压过窄 `172.31/16 deny`（后者变完全遮蔽） | `172.31.0.0/16 deny→permit` |
| **default-flip** 默认动作变化 | 删掉 `0/0 permit` 风格兜底、默认从 permit 翻成 deny | `0.0.0.0/0 permit→deny`（最宽代表） |

另含 IPv6 示例 **over-permit-v6**（`2001:db8::/32 le 48` 过宽）。

## 3. 回放：输入与生效次序

* 每次“发布候选”都生成**不可变快照**（含有序规则、默认动作、族、渲染好的 FRR 配置）；
* 场景保存**有序探针列表**，`/api/scenarios/{id}/replay` 以相同顺序对 before/after 两个快照确定性回放，返回每条命中链与差异；
* 快照 payload 自包含，后续再编辑规则不影响历史回放——满足“可回放输入及生效次序”。

## 4. FRR 配置导入闭环（来源保真 + 原子采纳）

网络团队已有的 FRR prefix-list 文本可以**离线整体导入**，不必逐条重录。闭环为
**上传 → 隔离草稿 → 诊断处理 → 原子采纳为快照**，主线规则在采纳前绝不被触碰：

1. **解析与保真**（`backend/app/importer.py`）：逐行解析 `ip/ipv6 prefix-list NAME [seq N] permit|deny PREFIX [ge X] [le Y]`；
   每一行的**原始行号、原文、类别**（规则/注释/空行/description/未识别指令）全部入库，
   未识别指令原样保留并给警告，绝不静默丢弃。省略 `seq` 时按 FRR 惯例自动步进 5 并标注。
   一个文件可含多个列表、双栈并存——草稿按 `(列表名, 地址族)` 分组，一份双栈文件产生多个草稿。
2. **分别解释的诊断**：`duplicate-seq`（序号重复，附行号）、`family-mismatch`（`ip` 关键字下出现
   IPv6 前缀等地址族混用）、`bad-ge-le`（非法 ge/le 窗口，附引擎判定原因）、`bad-prefix`、
   `missing-default`（文件未携带默认行为，采纳前必须显式确认）等，行级与列表级分开。
3. **幂等**：会话按文件内容 sha256 寻址，**同一文件重复提交只生成一个会话**（返回 `deduplicated`）。
4. **语义差异预览**：规范化后的草稿与当前主线做**最小见证集**比较（不是文本 diff）——
   重排但语义等价的文件显示「无行为变化」；有变化时逐区域给出最浅见证前缀。
5. **原子采纳**：采纳 = 替换主线规则 + 生成不可变快照 + 写入映射历史，全部在**一个事务**内；
   任一校验失败整体回滚——含一条非法 ge/le 的文件**不会产生半个快照**。
6. **乐观并发**：草稿记录预览时的主线 `revision`；采纳时主线已被改动则返回 **409 版本冲突**，
   草稿、诊断与原始文本完整保留，刷新重看差异后可再次采纳。
7. **有限交叉验证**：草稿可直接推送本地 FRR 容器比对（`POST .../cross-validate`），
   验证运行记入 `runs`（`snapshot_id` 为空表示草稿验证）。

数据表：`import_sessions`（原文+哈希）、`import_lines`（逐行保真+诊断）、
`import_drafts`（规范化规则+确认状态+基线 revision）、`import_adoptions`（映射历史）。

## 5. FRR 容器交叉验证

两个 FRR 8.4 节点在隔离的 internal bridge（`172.30.10.0/24`，无外部连通）上。验证流程（`backend/app/validate.py`）：

1. 把快照渲染成 `ip/ipv6 prefix-list NAME seq N permit/deny PREFIX [ge X] [le Y]` 下发到容器；
2. 对每个探针执行 FRR 原生命令
   `vtysh -c "debug ip prefix-list NAME match PREFIX"`
   —— 输出由 **FRR 自己的匹配代码**给出 `PERMIT/DENY` 与 `matching entry #seq`；
3. 与 `ipaddress` 模拟器逐条比对动作与 seq，结果写入 `runs` 表；
4. 结束后删除该 prefix-list。

FRR 语义已对照其源码 `lib/plist.c` 核对（包含关系、无 ge/le 精确匹配、窗口、首条最小 seq、未命中 DENY）。注意 FRR 对**空** prefix-list 返回 PERMIT，因此空策略会被报为 lab setup error 而非静默一致。

传输默认 `docker exec`（`RLAB_FRR_TRANSPORT=docker`），也可切到 SSH（`RLAB_FRR_TRANSPORT=ssh`，见 `backend/app/config.py`）。容器不在线时相关测试自动 skip，UI 显示离线徽标。

## 6. 快速开始

### 免容器 / 免 Postgres（SQLite，最快体验）

```bash
cd backend
python -m pip install -r requirements.txt
python -m app.seed                       # 建表 + 写入示例（数据在 backend/data/）
python -m uvicorn app.main:app --port 8765
# API 文档 http://127.0.0.1:8765/docs

cd ../frontend
npm install && npm run dev               # http://localhost:5173 （已配 /api 代理）
```

### 完整本地栈（PostgreSQL + FRR）

```bash
docker compose up -d postgres router-a router-b
cd backend
DATABASE_URL=postgresql+psycopg://rlab:rlab@127.0.0.1:5432/rlab \
  python -m app.seed
RLAB_FRR_TRANSPORT=docker python -m uvicorn app.main:app --port 8765
```

在 UI “④ 回放 / FRR 交叉验证”页选快照与节点（router-a / router-b），点“推送 FRR 并比对”，或：

```bash
curl -s localhost:8765/api/frr/status
curl -s -XPOST localhost:8765/api/snapshots/<id>/cross-validate \
  -H 'content-type: application/json' \
  -d '{"probes":["192.168.100.0/24","10.1.2.3/32"],"node":"a"}'
```

## 7. 测试

```bash
pip install pytest httpx
python -m pytest tests/ -q
```

* `test_engine.py`：精确匹配、ge/le 窗口、首条匹配、默认拒绝、v4/v6 隔离、三个示例决策；
* `test_properties.py`：在完整枚举的 /0../6（v4）与 /32../34（v6）格子上，对数百个随机策略用暴力预言机验证**遮蔽判定**与**最小见证集**逐区域一致（非采样）；
* `test_api.py`：编辑→快照→差异→回放的端到端 REST；
* `test_import.py`：导入闭环验收——双栈导入回放、非法 ge/le 无半快照、重排等价无行为变化、重复提交幂等、主线更新后采纳 409 且草稿/诊断/原文保留；
* `test_frr_consistency.py`：FRR 输出解析、随机 400 例与 FRR `prefix_list_apply` 移植模型逐条一致；`test_live_frr_consistency` 在检测到容器时自动对真实 FRR 运行。

## 8. 主要 API

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/policies` | 策略列表（含规则与渲染的 FRR 配置） |
| PUT | `/api/policies/{id}/rules` | 整表有序替换规则（经 ipaddress 校验、族隔离、ge/le 校验） |
| GET | `/api/policies/{id}/analyze` | 完全/部分遮蔽分析 |
| POST | `/api/policies/{id}/classify` | 单条命中链（含 trie_path、每条规则包含/窗口判定与原因） |
| POST | `/api/policies/{id}/classify/batch` | 批量有序推演（坏输入逐条隔离报错） |
| GET | `/api/policies/{id}/trie` | 前缀树视图 |
| POST | `/api/policies/{id}/snapshots` | 创建不可变快照 |
| POST | `/api/snapshots/diff` | 两个快照的最小见证集差异 |
| POST | `/api/snapshots/{id}/replay` | 有序探针确定性回放 |
| POST | `/api/snapshots/{id}/cross-validate` | 推送 FRR 容器并逐条比对 |
| GET/POST | `/api/scenarios`、`/api/scenarios/{id}/replay` | 场景（输入+两个快照+结果） |
| GET/POST | `/api/neighbors` | 本地实验室邻居 |
| GET | `/api/frr/status`、`/api/runs` | 容器在线状态、历史验证运行 |
| POST | `/api/imports` | 上传 FRR 配置文本（内容寻址，重复提交幂等） |
| GET | `/api/imports`、`/api/imports/{id}` | 会话列表 / 完整预览（原文+逐行诊断+草稿+语义差异） |
| PUT | `/api/imports/{id}/drafts/{did}` | 处理可接受项：确认默认动作、映射目标策略、修订规则 |
| POST | `/api/imports/{id}/drafts/{did}/adopt` | 原子采纳（规则替换+快照+映射历史一个事务；409=版本冲突） |
| POST | `/api/imports/{id}/drafts/{did}/cross-validate` | 草稿推送本地 FRR 容器有限交叉验证 |
| GET | `/api/adoptions` | 映射历史（草稿 → 策略快照） |

## 目录

```
backend/app/   engine.py(匹配/遮蔽) trie.py(精确单元+最小见证) service.py db.py
               importer.py(保真解析) import_service.py(草稿/原子采纳) validate.py
               frr_bridge.py treeview.py routers/api.py seed.py
frontend/src/  App.jsx + components/(PolicyEditor/TrieView/DiffView/ReplayLab/Neighbors/ImportView)
frr/           两个节点的 daemons/vtysh/frr.conf 与独立 docker-compose
tests/         引擎/属性/API/导入闭环/FRR 一致性
docker-compose.yml   postgres + backend + router-a/b
```
