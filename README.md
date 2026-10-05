# 项目授权依赖包

机构申请新增治疗项目时，场地、设备、药械、人员四类条件必须**同时**满足。本服务把授权条件建模为
**带版本的依赖包（Authorization Package）**：提交时固定证据摘要并运行完整性规则；批准后持续跟踪
关键依赖；替代设备、部分授权、条件暂停/恢复都形成**不可变新决定**；依赖失效只影响**未来服务**；
API 可沿授权依赖图列出受影响授权，并在每一层强制**机构数据隔离**。

对应领域契约（`domain/contract.json`）的四个不变量：

| 不变量 | 实现位置 |
| --- | --- |
| 授权依赖图 | 治疗项目槽位 → 授权包版本钉选（pin）→ 依赖版本 的图边（`service.impact_graph`） |
| 证据摘要冻结 | 提交时把证据拷贝进清单并计算规范 JSON 的 SHA-256（`digest.py`、`service._freeze_manifest`） |
| 依赖失效传播 | 依赖暂停/恢复/撤销发布事件并沿图登记影响面，只阻断未来服务（`service._publish_status_event`） |
| 机构数据隔离 | 所有读写按 `org_id` 过滤，跨机构访问统一 404（`api.dep_in_org / package_in_org`） |

## 核心模型

- **依赖 Dependency**：`facility | device | drug | personnel`，有显式整数版本、状态历史
  （`active → suspended → active`，`revoked` 为终态），每个版本携带证据（`evidence_id + sha256`）。
- **授权包 Package**：机构就某治疗项目提交的版本化清单，每个槽位钉选 `(dep_id, version)`；
  同一包重提交产生新版本，旧版本与旧决定全部保留。
- **决定 Decision**：`grant / partial_grant / suspend / resume / replace / revoke`，
  全部是只追加（append-only）的新决定，当前授权状态由决定链回放得到。
- **服务 Service**：执业人员登记实际服务时冻结当时准入快照；之后依赖失效不重写历史。

## 关键业务规则

1. **完整性规则（提交时）**：必填槽位齐备、槽位属于项目目录、依赖类别匹配槽位、
   依赖属于本机构、钉选版本存在且 `active`、证据摘要齐备；所有问题一次性返回。
2. **证据冻结**：清单摘要 = `sha256(canonical_json(项目 + 机构 + 各槽位证据快照))`。
   依赖侧证据更新只产生依赖新版本，已提交清单不变；钉选新版本需重提交且必须重新审批。
3. **决定链回放**：只回放**当前清单版本**上作出的决定（旧版本批准不自动沿用）。
   整体授权 active 当且仅当所有必填关键槽位有效。
4. **替代设备**：`replace` 决定把槽位改指向同类别、有效、证据齐备的替代依赖；
   原钉选与原决定不被改写。
5. **失效只影响未来**：失效前已登记的服务保留当时快照；失效后准入检查阻断新服务，
   并可经 `GET /deps/{id}/impact` 沿图谱列出全部受影响授权（可按版本查询）。
6. **机构隔离**：跨机构读、写、审批、暂停、探测图谱一律 404；事件流也按机构过滤；
   图谱出口再做一次机构裁剪作为双保险。

## 目录

- `domain/contract.json`、`src/domain_contract/`：领域契约与校验（既有）。
- `src/authorization_package/`：服务端
  - `models.py`：领域对象与工厂；`digest.py`：确定性摘要；`errors.py`：错误码。
  - `store.py`：线程安全内存存储（可替换为数据库实现）；`seed.py`：双机构演示数据。
  - `service.py`：提交/完整性/决定状态机/图谱传播/服务准入（纯领域逻辑）。
  - `api.py`：FastAPI 接口、认证头与机构隔离。
- `tests/`：契约回归（unittest）+ 39 个服务端场景测试（pytest）。
- `tools/check_contract.py`：契约命令行摘要。

## 运行

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[test]'
.venv/bin/python -m uvicorn authorization_package.api:app --port 8000
# 交互文档：http://localhost:8000/docs
```

认证采用演示模型：请求头 `X-Principal-Id` 标识已认证主体（角色 + 所属机构）。
种子账号：`U-COMP-A/U-REG-A/U-REV/U-DOC-A`（机构 A），`U-COMP-B/U-REG-B/U-DOC-B`（机构 B）。

## 主要 API

| 方法与路径 | 角色 | 说明 |
| --- | --- | --- |
| `POST /deps` `GET /deps` `GET /deps/{id}` | 合规/监管/复核 | 登记依赖、按机构列出 |
| `POST /deps/{id}/evidence` | 合规/监管/复核 | 证据更新 → 依赖新版本 |
| `POST /deps/{id}/suspend|resume|revoke` | 监管/复核 | 依赖状态变更并发布传播事件 |
| `POST /packages` | 合规/监管 | 提交授权包（冻结摘要 + 完整性规则） |
| `POST /packages/{id}/resubmit` | 合规/监管 | 清单新版本（须重新审批） |
| `POST /packages/{id}/decisions/grant` | 监管/复核 | 整体批准（新决定） |
| `POST .../decisions/partial-grant` | 监管/复核 | 部分授权（未批必填槽位不得服务） |
| `POST .../decisions/suspend|resume` | 监管/复核 | 条件暂停 / 恢复（新决定） |
| `POST .../decisions/replace` | 监管/复核 | 替代设备/药械（新决定） |
| `POST .../decisions/revoke` | 监管/复核 | 撤销授权（新决定） |
| `GET /packages/{id}/eligibility` | 已认证 | 实时未来服务准入（逐槽位结论） |
| `POST /packages/{id}/services` | 执业人员 | 登记服务并冻结当时快照 |
| `GET /packages/{id}/services` `GET /services` | 已认证 | 历史服务（机构隔离） |
| `GET /deps/{id}/impact?version=n` | 已认证 | 沿图谱列出受影响授权 |
| `GET /events` | 已认证 | 本机构依赖状态传播事件 |

## 验证

```bash
.venv/bin/python -m pytest tests/ -q          # 39 个服务端场景测试
python3 -m unittest discover -s tests -v      # 契约回归（无需第三方依赖）
python3 -m compileall -q src tools tests      # 编译检查
python3 tools/check_contract.py domain/contract.json
```
