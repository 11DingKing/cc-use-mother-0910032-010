# 项目授权依赖包

机构开展新增治疗项目时，必须**同时**满足场地、设备、药械、人员四类条件。本服务把这些
条件建模为**带版本的依赖**，把一次授权申请建模为**固定证据摘要的依赖包**：

- 提交申请时固定每个依赖的版本与证据 SHA-256，并运行完整性规则；
- 批准后持续跟踪关键依赖：单个依赖撤销/暂停，整体授权立即对**未来服务**失效，
  无需逐项审批开关；
- 替代设备、部分授权、条件暂停与恢复都形成**只追加的新决定**（替代设备还产生新包修订）；
- 历史服务结论按服务发生时点冻结，依赖失效**不改写历史**；
- 沿依赖图（包固定边 + 依赖 `requires` 边）列出受影响授权，全部查询严格机构隔离。

## 核心语义

授权在时刻 *t* 对某服务范围有效，当且仅当：

1. *t* 之前存在生效的批准类决定（批准 / 部分批准 / 替代设备），确定基线修订与批准范围；
2. 该范围在 *t* 未被条件暂停（暂停后恢复由新的决定声明）；
3. 基线修订固定的**全部**依赖在 *t* 均为 `active`，且固定版本已生效、证据摘要未被篡改。

决定与依赖事件都带 `effective_at`，时间线只许追加、不许回填改写；任意历史时点的授权
状态都可重算（bitemporal）。

## 目录

- `domain/contract.json`：领域角色、状态、约束和样例。
- `src/domain_contract/`：契约读取与确定性校验。
- `src/authz_service/`：授权服务端
  - `models.py`：依赖/版本/事件、包/修订/决定、服务记录等领域模型；
  - `hashing.py`：规范化 JSON + SHA-256 证据摘要；
  - `rules.py`：提交/替代时的完整性规则（四类齐备、版本可解析、摘要一致、同机构、
    requires 闭包、无环）；
  - `engine.py`：领域引擎（登记、冻结、决定、时间点有效性、图谱传播）；
  - `repository.py`：线程安全内存仓储（所有读取带机构过滤，可替换为数据库实现）；
  - `api.py`：基于标准库的零依赖 HTTP API。
- `tools/`：契约检查、服务启动脚本。
- `tests/`：契约、领域引擎（13 例）与 HTTP 端到端（8 例）回归测试。

## 验证

```bash
python3 -m unittest discover -s tests -v     # 23 个测试
python3 -m compileall -q src tools tests     # 编译检查
python3 tools/check_contract.py domain/contract.json
python3 tools/serve.py 8080                  # 启动 HTTP 服务
```

## HTTP API

所有业务接口都必须携带 `X-Org-Id` 头标识机构；缺失返回 401。跨机构访问资源与资源
不存在**同样返回 404**（`NOT_FOUND`），不暴露资源归属差异。角色经请求体 `actor`
字段传递（如 `机构合规员`/`监管人员`/`复核专家`）。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/dependencies` | 登记带版本依赖（`category` ∈ 场地/设备/药械/人员，`evidence` 在创建时冻结摘要，`requires` 声明前置依赖） |
| GET | `/dependencies` | 列出本机构依赖 |
| POST | `/dependencies/{id}/versions` | 证据换新版本（旧修订固定值不变） |
| POST | `/dependencies/{id}/status` | 追加 `active`/`suspended`/`revoked`/`expired` 事件 |
| GET | `/dependencies/{id}/impact` | 沿图谱列出受影响授权（含传播路径、当前有效性） |
| POST | `/packages` | 创建授权包（草案） |
| POST | `/packages/{id}/submit` | 固定证据摘要并运行完整性规则，失败返回 422 |
| POST | `/packages/{id}/decisions` | 追加决定：`批准`/`不予批准`/`部分批准`/`替代设备`/`条件暂停`/`恢复` |
| POST | `/packages/{id}/archive` | 归档 |
| GET | `/packages/{id}` | 包详情（修订与决定时间线） |
| GET | `/packages/{id}/effective?at=ISO8601` | 重算某时刻各范围有效性 |
| POST | `/packages/{id}/services` | 登记服务，按 `service_at` 时点冻结授权结论 |
| GET | `/services` | 本机构服务记录 |

### 典型流程

```bash
B=http://127.0.0.1:8080
O='-H X-Org-Id:hospital-01'
J='-H Content-Type:application/json'

# 1) 登记四类条件
curl -s $J $O -d '{"category":"设备","name":"加速器","evidence":{"sn":"SN-1"},
  "valid_from":"2026-01-01T00:00:00+00:00"}' $B/dependencies
# ... 场地 / 药械 / 人员同理

# 2) 建包 -> 提交（冻结摘要 + 完整性规则）-> 批准
curl -s $J $O -d '{"project_code":"TX-放疗","scopes":["门诊","住院"],
  "pins":[{"dep_id":"dep_..."}, ...]}' $B/packages
curl -s $J $O -d '{"actor":"机构合规员"}' $B/packages/pkg_xxx/submit
curl -s $J $O -d '{"decision":"批准",
  "effective_at":"2026-02-01T00:00:00+00:00","actor":"复核专家"}' \
  $B/packages/pkg_xxx/decisions

# 3) 设备撤销：未来立即失效；历史服务结论不变
curl -s $J $O -d '{"status":"revoked","reason":"年检不合格",
  "effective_at":"2026-03-01T00:00:00+00:00","actor":"监管人员"}' \
  $B/dependencies/dep_equipment/status
curl -s $O "$B/packages/pkg_xxx/effective?at=2026-03-02T00:00:00%2B00:00"

# 4) 替代设备 -> 新修订 v2 + 新决定；只影响替代生效之后
curl -s $J $O -d '{"decision":"替代设备",
  "replacements":[{"remove":"dep_old","add":"dep_new"}],
  "effective_at":"2026-03-10T00:00:00+00:00"}' $B/packages/pkg_xxx/decisions

# 5) 沿图谱查看受影响授权
curl -s $O $B/dependencies/dep_equipment/impact
```

完整性校验失败（422）返回结构化 `violations`，错误码包括 `CATEGORY_MISSING`、
`VERSION_NOT_FOUND`、`EVIDENCE_DIGEST_MISMATCH`、`CROSS_ORG_DEPENDENCY`、
`REQUIRES_MISSING`、`REQUIRES_CYCLE` 等。
