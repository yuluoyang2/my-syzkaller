# 定向 fuzzing 核心方案（保存 / 最小化 / 调度）

> 状态：核心方案  
> 范围：单目标、单 corpus，聚焦 seed 的保存、最小化和调度。  
> 示例目标：`nr_add_node`（`net/netrom/nr_route.c`）。

---

## 0. 核心结论

本方案的核心贡献是：

```text
保存：C ∨ K_level ∨ K_depth
最小化：保留实际触发保存的 witness
调度：K + G + 探索
```

核心机制：

> corpus 的保存条件从“新 signal”扩展为“新 signal 或目标进展”；最小化保留对应的 witness；调度使用 K/G/ε 选择 seed。

K 依赖 raw PC，因此所有 fuzz 执行默认开启 raw cover，不按 target 过滤、不做采样；正常完成且覆盖数据有效的执行用于检测 K 候选。  
K 使用固定 3 个有效执行求交得到的 `StableCover`；同一 attempt 的 C/K 验证及 G 结算共享这一份确认结果。`K_level` witness 表示最低可达层级，`K_depth` witness 固定保存时的覆盖层级；异常或确认未完成不能解释为 K=0。

---

## 1. 范围与职责

### 1.1 输入

单目标、单 corpus。输入由三部分组成：

```text
target:        func / path / close_funcs / subsystem
target call:   进入目标函数的 syzlang 调用
related calls: target call 的显式依赖调用
```

- **target**：目标函数和覆盖层级定义。
- **target call**：进入目标函数的 syzlang 调用，例如 `ioctl$sock_netrom_SIOCADDRT`。
- **related calls**：target call 的显式依赖调用，例如 `syz_init_net_socket$netrom`；这些依赖由 syzlang 调用关系给出，用户可以显式提供。
- **隐藏前置状态**（例如 `bpq0` up）属于运行时状态，超出静态 related 依赖的范围；这类 setup 由 State Builder 扩展发现和验证。
- fuzzer 从 target call + related calls 生成初始程序（例如 `GenerateCallPair` / `GenerateSequence`），再对参数和结构做变异。
- corpus 中的程序由生成和变异产生。

### 1.2 核心职责

核心方案负责四件事：

1. **保存**：C、K_level、K_depth 三种 reason。
2. **最小化**：`MinimizeProgram` 保留 witness；`MinimizeCorpus` 按 reason key 覆盖。
3. **调度**：K + G + ε 的加权随机选择。
4. **容量与去抖**：last carrier、覆盖集合、deflake。

---

## 2. 目标配置与调用关系

### 2.1 目标配置

```json
{
  "directed": {
    "target": {
      "func": "nr_add_node",
      "close_funcs": ["nr_rt_ioctl"],
      "path": "net/netrom/nr_route.c",
      "subsystem": "net/netrom/"
    }
  }
}
```

| 字段          | 含义                                                  |
| ------------- | ----------------------------------------------------- |
| `func`        | 目标函数名；必填；用于 vmlinux 符号解析和最高覆盖层级 |
| `close_funcs` | 核心路径函数；可空；用于第二覆盖层级                  |
| `path`        | 目标函数所在源码文件；可空；用于第三覆盖层级          |
| `subsystem`   | 目标子系统前缀；可空；用于第四覆盖层级                |

`func` 是唯一必填字段；`close_funcs`、`path`、`subsystem` 都可以为空。  
空字段对应的层级 PC 集为空，该层级不参与 `K_level` 计算。

### 2.2 Target call 与 related calls

```text
target call:   ioctl$sock_netrom_SIOCADDRT
related calls:
    - syz_init_net_socket$netrom
```

- `target call`：进入目标函数的 syzlang 调用。
- `related calls`：target call 的显式依赖调用，在 target 之前生成；这些依赖由 syzlang 调用关系给出。
- fuzzer 从 target call + related calls 生成初始程序，再对参数/结构做变异。
- 隐藏前置状态（如 `bpq0` up）由 State Builder 扩展发现和验证。

---

## 3. 覆盖层级与 K

### 3.1 覆盖层级

`func`、`close_funcs`、`path`、`subsystem` 构成从高到低的覆盖层级：

| 最高命中层级 | 含义         | `K_level` |
| ------------ | ------------ | --------: |
| func         | 目标函数     |       1.0 |
| close_funcs  | 核心路径函数 |       0.5 |
| path         | 目标文件     |      0.25 |
| subsystem    | 目标子系统   |     0.125 |
| other        | 其他         |         0 |

`K_level` 取命中的最高层级对应的权重；多个层级同时命中时取最高，不累加。

### 3.2 可观测 PC 集

`P_level` 使用当前内核构建中实际可观测的 KCOV raw PC：

```text
P_level = {
    pc | pc 出现在 vmlinux 回调点表中
         且当前构建/配置下有 KCOV 插桩
         且属于对应层级
}
```

- 使用 raw cover；所有 fuzz 执行默认开启 `ExecFlagCollectCover`。
- K 只使用 `StableCover(s)`（定义见 5.3），不使用可能是多次执行并集的 `Item.Cover`。
- 不因采样跳过 K 候选检测；无有效 raw PC 或确认未完成时，K 尚未确认，不能将其记为 0。
- 空层级对应 `K_depth=0`；`depth(s, ℓ)` 只对 func / close_funcs / path / subsystem 定义，空 PC 集按 0 处理。other 只用于 G 的外围覆盖分类，不产生 K_depth reason。
- PC 归属规则：每个 PC 算入它所在的最高层级。

```text
P_func      = target_func PCs
P_close     = close_funcs PCs \ P_func
P_path      = target file PCs \ (P_func ∪ P_close)
P_subsystem = subsystem PCs \ (P_func ∪ P_close ∪ P_path)
P_other     = rest
```

### 3.3 K 计算

```text
K_level(s) =
  1.0    if StableCover(s) ∩ P_func ≠ ∅
  0.5    else if StableCover(s) ∩ P_close ≠ ∅
  0.25   else if StableCover(s) ∩ P_path ≠ ∅
  0.125  else if StableCover(s) ∩ P_subsystem ≠ ∅
  0      otherwise

ℓ ∈ {func, close_funcs, path, subsystem}
depth(s, ℓ) = 0                                  if |P_ℓ| = 0
            = |StableCover(s) ∩ P_ℓ| / |P_ℓ|     otherwise
K_depth(s)  = 0                         if K_level(s) = 0
            = depth(s, K_level(s).level) otherwise
K_score(s)  = K_level(s) * (1 + 0.5 * K_depth(s))
```

`K_level` 是乘性底数，`K_depth` 只在该层级内部提供最多 50% 的加成。这样：

```text
target 最低 1.0 > close 最高 0.75
close 最低 0.5 > file 最高 0.375
file 最低 0.25 > subsystem 最高 0.1875
```

层级顺序不会被同一层内的覆盖深度反转。

- `K_level(s).level` 是 `s` 当前最高命中层级；`K_depth(s)` 的分子和分母都固定使用这一层级。
- `K_level` witness 记录最低可达层级；最小化和接管统一要求候选的 `K_level >= witness.level`。
- `K_depth` witness 固定保存时的 `level`；验证深度时不能根据 `s'` 的当前最高层级切换分子和分母（见 6.3）。
- `StableCover` 只由有效执行产生；结果缺失、覆盖溢出都不算有效执行（见 5.3）。

命名：代码保留 `K_depth`；文档/论文称“层级内覆盖程度”。

---

## 4. Reason 与保存

### 4.1 Reason

```text
R(s) ⊆ {C, K_level, K_depth}
Save(s) = C ∨ K_level_new ∨ K_depth_new
```

C 使用 stable signal，K_level / K_depth 使用 `StableCover`（由固定 3 个有效执行的 raw cover 求交得到）。所有 fuzz 执行请求 raw cover，但只有确认完成后才能发布 K；异常或确认失败不是 K=0。C 的 signal 稳定化继续沿用原规则，不与 K 的严格交集规则混用。

| Reason  | 保存条件                 | witness                         | 最小化约束                                      |
| ------- | ------------------------ | ------------------------------- | ----------------------------------------------- |
| C       | 新 stable signal         | `NewSignal`（元素及 priority）  | 保留每个元素，且 priority 不低于 witness 要求    |
| K_level | `K_level(s) > max_level` | 最低可达层级 level              | `K_level(s') >= witness.level`                  |
| K_depth | 见 4.3                   | depth 阈值 / new PC 集合 / both | 固定 `witness.level`，见 6.3                    |

K_level 和 K_depth 的 witness 都记录保存时的 `level`。K_level 将其作为最低可达层级，允许更高层级满足；K_depth 始终使用该层级的 PC 集计算深度或检查指定 PC，不随候选当前最高层级切换。

### 4.2 C

- 沿用 syzkaller 的新信号保存，包括 signal priority 提升产生的新 signal。
- deflake 后保存。
- 保存 `NewSignal`，作为 C 的 witness；witness 同时包含 signal 元素和最低 priority。
- 最小化与接管均沿用现有 signal 比较语义：每个 witness 元素必须存在，且对应 priority 不低于 witness 要求，不能退化为只检查 bit 是否存在。

### 4.3 K_depth 与 witness

保存条件：

```text
if K_level(s) == 0:
    K_depth_new(s) = false
else:
    level = K_level(s).level
    K_depth_new(s) =
        depth(s, level) > max_depth[level]
        OR
        |StableCover(s) ∩ (P_level \ CoveredPCs[level])| > 0
```

- `K_depth_new` 只对 func / close_funcs / path / subsystem 检查；other 不建立 depth 统计，也不产生 K_depth witness。
- `K_level=0` 不影响程序按 C 资格保存；如果已完成覆盖确认，其外围新增覆盖仍可参与 G。

其中：

```text
CoveredPCs = corpus 在该 level 已经覆盖的 stable PC 并集
max_depth  = corpus 在该 level 的最大 depth(s, level)
```

witness 记录实际触发条件：

```text
KDepthWitness =
    { type: depth,   level, threshold: depth(s, level) }
  | { type: new_pcs, level, pcs: StableCover(s) ∩ (P_level \ CoveredPCs) }
  | { type: both,    level, threshold, pcs }
```

`KDepth` 保存覆盖比例，`KDepthWitness` 保存实际触发保存的条件。  
`witness.level` 是保存时的层级；最小化、容量淘汰和 `MinimizeCorpus` 接管都使用这个值，不随 `s'` 重新计算。

---

## 5. 候选检测与 K verify

### 5.1 设计

syzkaller 的 Triage 由新 signal 启动。核心增加一条 K 候选路径，让 K 进展进入 verify 和保存：

```text
execute
  -> candidate detect
       C: new signal
       K: raw cover 的 level/depth 候选
  -> K candidate -> K verify job
  -> verify 通过 -> Save(reason=K)
```

- Candidate detect 可以使用单次执行的 raw cover，只负责触发候选。
- K 保存资格必须在 K verify 中用 `StableCover` 重新确认（见 5.3）。
- 同一 mutation 的 C triage 和 K verify 共享 `attempt_id` 及一份原始后代的覆盖确认结果，不各自产生用于 K/G 的 StableCover。
- C-only 后代也通过相同的覆盖确认口径结算 G，不因没有 K 保存资格就一律记零；确认失败时按 5.3 和 8.1 处理。

### 5.2 Raw cover 默认开启

K 依赖 raw PC：没有 raw PC 就无法判断程序是否到达目标函数或核心路径。因此所有 fuzz 执行默认收集 raw cover：

```text
每次 fuzz 执行：
    ExecFlags |= ExecFlagCollectCover
    ExecFlags |= ExecFlagCollectSignal
```

- 执行请求必须显式设置 `ExecFlagCollectCover`；`raw_cover: true` 只控制是否保留 raw PC 以及是否关闭 cover 去重，不等于请求会收集 cover。
- 不按 target/related 过滤，也不做采样：每个正常完成、覆盖数据有效的执行都参与 K 候选检测。
- C 候选检测继续使用 signal；C 与 K 使用同一份执行结果。
- `ExecutorFilter` / focus area 只过滤 signal，不过滤 raw cover；K 使用有效执行报告的程序级 raw PC 集。
- 不存在因未采样而缺失 K 的分支；结果缺失、覆盖溢出或验证终止时，K 未确认，不能当成空覆盖或 K=0。

### 5.3 StableCover 与 K verify

第一版固定收集同一程序的 3 个有效确认执行，取 raw PC 严格交集：

```text
C_i = dedup( (∪_{call} Cover_i(call)) ∪ Cover_i(Extra) )
StableCover(s) = C_1 ∩ C_2 ∩ C_3
```

- 可以复用 C triage 中满足条件的执行结果，但不复用其 `needRuns`，也不采用 signal deflake 的累计出现次数规则计算 raw PC 稳定性。
- 三个样本必须来自同一个程序版本，不能混入最小化后程序或其他后代的执行结果。

有效执行必须同时满足：

```text
result.Status == Success
result.Info != nil
每个 call 都有 Executed 和 Finished
Calls / Extra 均没有 CoverageOverflow
执行未 timeout
```

终止与重试：

| 结果 | 覆盖确认处理 |
| ---- | ------------ |
| Success，且覆盖数据有效 | 计入三个有效执行 |
| Crashed / Hanged，或确认执行发生 timeout | 立即结束本次 K verify，不为凑足三次继续重试；异常交给 syzkaller 现有处理流程 |
| ExecFailure / Restarted、结果缺失、覆盖溢出或其他非终止性无效结果 | 不计入有效样本，在有限尝试和时间预算内重试；仍不足三个有效样本则 expire |

- 必须按具体 `Status` 区分处理，不能把所有 `Result.Stop()` 都当成可重试的数据缺失，也不能把它们记为 K=0。
- 终止或 expire 的覆盖确认不能发布 K、更新 K 全局统计或产生 K 保存资格；不以未完成的样本交集代替 `StableCover`。
- 不引入新的 crash/race corpus；本模块只停止自己的覆盖验证，不改变现有异常处理职责。

同一 attempt 的共享结果：

- 同一 mutation 的 C/K 验证共享一份确认上下文，绑定原始后代程序；按收集顺序取前三个有效确认执行，生成唯一的 `StableCoverAttempt`。
- 确认完成后该结果固定，K 判定和 G 结算都引用它；不能由 C/K 各取一批执行、各算一个 StableCover，再按提交先后选择。
- C 的 signal deflake 继续沿用原规则；后续 signal 回放不能改变已确认的 `StableCoverAttempt`。`info.cover.Merge(...)` 的并集不得作为 K/G 输入。
- C-only mutation 同样使用这一共享覆盖确认过程；覆盖确认失败时，不能用 C 的 cover 并集替代，G 按失败规则结算。
- 最小化候选 `s'` 需要独立验证自己的覆盖和 signal，不得继承或替换原始后代的 `StableCoverAttempt`。

K 保存规则：

- 只有 `StableCover` 才能更新 `max_level`、`max_depth`、`CoveredPCs`。
- `new_pcs` witness 从 `StableCover` 计算；不稳定的 PC 不进入 witness，也不进入 `CoveredPCs`。
- K verify 用共享确认结果对当前 corpus 状态重新确认 level/depth 和保存资格。
- 候选 key：`(program sig, level, witness)`；同一 key 只验证一次。
- 并发上限和去重是执行资源调度细节，不影响候选是否参与 K 判断。
- K 候选不因开销被丢弃；没有采样率，也没有“队列满则放弃”的降级路径。
- K 是程序级覆盖：必须合并 `result.Info.Calls` 中所有 call 的 `Cover`（以及 `Info.Extra`，如果有）。`Item.Cover` 是“被保存 call”的 cover，还会跨 update 合并，不能直接当作 `StableCover`。
- 记录 exec/s、raw cover 字节数、verify 次数，用于观察，不作为正确性条件。

---

## 6. 最小化

### 6.1 两个独立操作

#### `MinimizeProgram(s)`

```text
目标：缩短单个程序
约束：保留 R(s) 中所有 reason 的 witness
      C 使用候选自身的 StableSignal(s') 保留元素及其最低 priority
      K_level 将 witness.level 作为最低可达层级
      K_depth 固定使用 witness.level 对应的 PC 集
策略：贪心删除 call / 简化 arg
      每个候选 s' 重新执行，按待保留的 reason 确认 StableSignal(s') / StableCover(s')
      每一步用候选自身的确认结果重新验证所有 witness
      保留满足全部 witness 的简化版本
```

- C 复验按 `s'` 更新后的调用映射，结合实际 errno 和 ANY 情况重新计算 signal priority；沿用原 signal deflake 得到 `StableSignal(s')`，再检查 C witness。
- 原 seed 的 `Item.Signal` / `NewSignal` 只能提供需要保护的依据，不能充当 `s'` 已满足该依据的证据。
- K 复验固定使用 `s'` 三个有效执行的严格交集；可以与 C 复验复用执行结果，但 signal deflake 与 raw PC 求交的判定规则保持独立。
- `s'` 的覆盖和 signal 都不能继承原程序的确认结果：删除 call 或简化参数会改变控制流、调用索引、errno 和 priority。
- 中间剪枝可以用单次执行拒绝候选；任何保留的最终候选，都必须完成其 C witness 的 signal 稳定化复验和 K witness 的三次有效覆盖复验。不能得到有效确认结果时，不接受该候选。
- 最终入库的 signal / `StableCover` 记录必须对应最终程序；原始 mutation 的 `StableCoverAttempt` 只用于该次原始后代的 G 归因，不被最小化结果替换。

#### `MinimizeCorpus`

```text
目标：减少 corpus 冗余
策略：按 reason key 做集合覆盖
      seed 失去被其他 seed 完全覆盖的 reason
      R(s) 为空时删除该 seed
```

### 6.2 Reason key

| Reason  | key                                         |
| ------- | ------------------------------------------- |
| C       | signal 元素 + 最低 priority                  |
| K_level | 最低可达层级 level                          |
| K_depth | `witness.level` + witness（depth 阈值 / new PC 集合） |

- C 的 key 保留 signal 元素及最低 priority；删除前，必须确认每个元素都由其他保留 seed 以不低于要求的 priority 覆盖。
- 本节接管检查仅用于 `MinimizeCorpus`：程序内容不变，C 可以使用各保留 seed 已确认的 stable signal（`Item.Signal`）；沿用现有 signal 的 priority 比较与代表选择语义，不能只比较元素集合。`MinimizeProgram` 必须使用候选重新执行所得的 `StableSignal(s')`，不能读取原 seed 的 `Item.Signal` 代替复验。
- K_level 的 key 是最低可达 `level`；只要保留 seed 的 `K_level >= witness.level`，即可接管，最小化和接管使用同一判定。
- K_depth 的 key 使用 `witness.level`，不是接管者的当前最高层级；即使接管者达到更高层级，也必须单独满足原层级的 depth / new_pcs 约束。

### 6.3 K witness 约束

`witness.level` 始终取保存时记录的值：K_level 将其作为最低可达层级，K_depth 将其作为固定的覆盖层级。`depth(s, ℓ)` 定义见 3.3。

```text
K_level:
    K_level(s') >= witness.level

depth:
    depth(s', witness.level) >= witness.threshold

new_pcs:
    witness.pcs ⊆ StableCover(s')

both:
    depth 和 new_pcs 两者都满足
```

- 约束按实际触发的子条件启用。
- `MinimizeCorpus` 阶段，witness 可以由另一个 seed 接管；接管检查同样使用原 `witness.level` 和该 seed 的 `StableCover`。
- K_level 的最小化和接管统一要求 `K_level(candidate) >= witness.level`，不要求两者层级相同。
- `P_level` 互不包含不影响 K_level 的等级门槛语义；但达到更高层级不能自动满足 K_depth，后者仍需固定原层级检查。
- 删除调用或简化参数都可能让程序进入更高层级，不能假设最小化后的 level 不会升高。
- witness 无法保留时，保留原程序。

---

## 7. 容量

每个 level 的保留规则：

```text
1. 保护 last carrier：target PC / witness PC / C signal（含所需 priority）只有它满足时，优先保留
2. 保留最高 depth 代表
3. 保留贡献独特 PC 的 seed
4. 只有当 seed 的所有 C/K reason key 都已被其他保留 seed 满足时，才允许淘汰；
   PC 集合被其他 seed 包含只是辅助条件，不能单独作为删除依据
5. 最后按 Score + 长度做容量优化
```

- top-8 是 depth 代表名额。
- last carrier 享有优先保留权；唯一分支种子优先于 depth 名额。
- 同一 `StableCover` 口径下，PC 包含可以满足 K 的 depth / new_pcs 义务，但不能推出 signal 义务；C 必须单独检查元素及 priority。
- 如果某个 C witness 元素只有该 seed 能以所需 priority 产生，它就是 C 的 last carrier；即使其他 seed 包含同一元素但 priority 更低，也不能替代它，更不能仅因 PC 被包含而删除。

---

## 8. 调度

```text
K_score(s) = K_level(s) * (1 + 0.5 * K_depth(s))
Score(s)   = K_score(s) * (1 + 0.1 * G(s))

T = min(N, max(8, min(64, floor(1% * N))))
c = 第 T 高的 Score（Top 边界分数）
A = {s | Score(s) > c}       # 严格高于边界的种子
B = {s | Score(s) = c}       # 边界同分种子
b = T - |A|                 # 边界可用名额
Z = Σ_{j∈A} Score(j) + b*c

P(s) = ε/N + (1-ε) * Score(s)/Z       if s ∈ A
     = ε/N + (1-ε) * (b/|B|)*c/Z     if s ∈ B
     = ε/N                           otherwise

如果 Z = 0：P(s) = 1/N
```

默认：

- `ε = 0.12`。
- `G` 只做层级内部的 tie-breaker：`target` 最低分仍高于 `close` 最高分，`close` 最低分仍高于 `file` 最高分，以此类推。
- 88% 的利用预算只按最高 T 个名额的分数质量分配，12% 在整个 corpus 均匀探索；Top 不固定对应某个覆盖档。
- 边界同分不按 seed 签名固定截断。每次选种公平分享边界名额，等价于从 B 中随机选 b 个名额后按分数抽样；实现不需要每次显式构造随机 Top。
- 边界组的利用总权重是 `b*c`，不是 `|B|*c`，所以大量边界同分种子不会重新稀释严格高分种子。
- 全零时在整个 corpus 均匀抽样；没有分数证据时不制造固定精英。
- 低分种子仍保留 `ε/N` 的探索概率。12% 是全局探索比例，不是非目标种子的固定预算；探索也可能选中目标种子。
- `K_level` / `K_depth` 使用保存时的 `StableCover` 结果，不使用单次执行的临时覆盖，避免调度抖动。
- 采样结构在 corpus 写锁下使用索引双堆维护 Top，权重和排名更新 O(log N)，相同权重不重复更新；选种只读，最多扫描 T 个名额，不在读锁下重建缓存或全量排序。Fenwick 总权重单独维护。
- 同一分数的边界组使用索引表 O(1) 维护和均匀取样；corpus 最小化后从保留种子重建采样结构。

### 8.1 G

```text
h(n) = n / (n + 1)

r_e = (8h(ΔT) + 4h(ΔP) + 2h(ΔF) + h(ΔS) + 0.2h(ΔO)) / 15.2

G(s) ← (1-η)G(s) + η r_e
η = 0.3
```

新增覆盖口径：

- `GainSeenPCs` 是当前内核构建、本轮收益统计周期内，全局已确认发现的 PC 集合；mutation 的输入只能是 5.3 定义的、针对原始后代唯一确认的 `StableCoverAttempt`。
- `GainSeenPCs` 是发现历史，不是当前 corpus 的覆盖并集；不能因 corpus 最小化或 seed 删除而缩小，避免同一 PC 反复获得首次发现奖励。
- ΔT/ΔP/ΔF/ΔS/ΔO 来自 `Delta = StableCoverAttempt \ GainSeenPCs_before_commit`，再按 target/core/file/subsystem/other 的互斥 PC 归属拆分；不是相对于父 seed 的覆盖增量。
- C 的 cover 并集、C/K 独立验证批次的合并，以及最小化后程序的覆盖都不能替代这份 `StableCoverAttempt`；同一 attempt 的奖励不由 C/K 谁先提交决定。
- 初始 seed 和没有 mutation 父 seed 的生成程序，使用各自三个有效执行确认的 `StableCover` 更新全局发现基线，但不产生父 seed 的 G 奖励。

确认与结算顺序：

1. 等待该 attempt 唯一的 `StableCoverAttempt` 确认完成；C/K 引用同一份固定结果，不独立计算或合并两份确认覆盖。未经确认的单次 raw cover 或 C 的 cover 并集不计正收益。
2. 提交这份共享结果时，在同一临界区内检查 `attempt_id`、确定首次发现增量 `Delta`、为该 attempt 记录增量，并将 `StableCoverAttempt` 合并到 `GainSeenPCs`；确定增量必须发生在合并之前。已有增量记录或已结算的 attempt 不重复领取，也不覆盖原记录。
3. 使用该 `attempt_id` 已记录的增量计算 `r_e`、结算直接父 seed 的 G；不能在全局集合更新后重新做差集。
4. 不同 attempt 同时发现同一 PC 时，只有首次提交确认的一次获得该 PC 奖励；同一 mutation 的 C/K 验证共享 `attempt_id` 和 `StableCoverAttempt`，只能领取一次增量并结算一次。

- 每次 mutation 结算一次，包括无新覆盖时以 `r_e=0` 结算；收益只归直接父 seed。
- C-only mutation 也等待共享覆盖确认，确认后的外围或目标新增覆盖照常计奖，不因没有 K reason 一律记零。
- verify/deflake/最小化回放不作为新的 mutation 独立领取奖励，也不能提前消耗所属 mutation 的待结算发现增量。
- 新种子 G 先验：空 corpus 用 0.1；之后用 corpus 均值 clamp `[0.05,0.2]`。
- 异步结算状态：`pending -> positive | zero | expired`；crash/hang/timeout 或确认失败、过期、丢失时以 0 收益关闭 attempt，已完成结算的 `attempt_id` 不再重复结算；这只表示没有可结算的确认收益，不表示 K=0。
- G 是可选调度项；消融实验使用 `Score = K_score` 的 K+ε 版本。

### 8.2 评分构成

核心评分由 K、G、ε 三部分组成。`C_novelty` 作为扩展章节的消融项，用于观察 general coverage seed 的冷启动效果。

---

## 9. Deflake 与重启

- C：使用原 signal deflake；程序最小化必须重新确认候选自身的 `StableSignal(s')`，Corpus 集合最小化才使用已保存的 `Item.Signal`。
- K：固定 3 个有效执行取严格交集得到 `StableCover`，不复用 C 的 `needRuns` 或 signal 稳定化算法。
- 同一 attempt 的 C/K 和 G 共享唯一的 `StableCoverAttempt`；最小化后程序的确认结果单独记录，不能覆盖原始后代的收益依据。
- crash/hang/timeout 终止本次 K verify，不为凑足三次继续重试；其他可重试无效结果仅在有限预算内重试，不足三个有效样本则 expire。异常交给现有流程处理，不引入 crash/race corpus，也不将确认失败记为 K=0。
- 只有 `StableCover` 才能更新 `max_level`、`max_depth`、`CoveredPCs`；`K_level=0` 不产生 K_depth reason。
- 所有 fuzz 执行默认收集 raw cover，因此重启后 K 不需要采样补偿或覆盖率回退。
- 重启恢复：
  - K 使用持久化的 `StableCover`、`max_level`、`max_depth`、`CoveredPCs`，或重新执行；
  - G 重置为先验/均值；`GainSeenPCs` 从同一内核构建的持久化发现历史恢复，不因 G 重置而清空；
  - 如果没有可用的 `GainSeenPCs` 历史，先用恢复 seed 的 `StableCover` 建立新的收益统计周期基线，再开始正常 mutation 结算；恢复回放不领取 G 奖励，不能声称恢复了已删除 seed 的全部历史发现；
  - C 的 `NewSignal` 通过持久化恢复，或重新执行获得；
  - 动态覆盖信息通过持久化或回放恢复。

---

## 10. 调度改进方案与 SyzDirect 对照

本节记录当前评分的改进动机、已经采用的方案，以及从 SyzDirect 中可以借鉴和不应照搬的部分。

### 10.1 旧评分的问题

旧评分：

```text
K_score = K_level + 0.1 * K_depth
Score   = 0.65 * K_score + 0.35 * G
```

问题：

- `target` 最低约 0.650，`close` 最高约 0.740，低层级可以反超 target；
- `K_depth` 对最终 Score 的最大贡献只有 `0.1 * 0.65 = 0.065`，层内深度几乎没有区分度；
- `G` 权重 0.35，和层级差距同一量级，会跨层补偿。

### 10.2 已经采用的改进

评分改为层级乘性分离：

```text
K_score = K_level * (1 + 0.5 * K_depth)
Score   = K_score * (1 + 0.1 * G)
```

对应范围：

| 层级 | K_score | Score（G=0..1） |
|---|---:|---:|
| target | 1.0 ~ 1.5 | 1.0 ~ 1.65 |
| close | 0.5 ~ 0.75 | 0.5 ~ 0.825 |
| file | 0.25 ~ 0.375 | 0.25 ~ 0.4125 |
| subsystem | 0.125 ~ 0.1875 | 0.125 ~ 0.20625 |

即使 `G=1`，也不能跨层反超：

```text
target 最低 1.0 > close 最高 0.825
close 最低 0.5 > file 最高 0.4125
file 最低 0.25 > subsystem 最高 0.20625
```

选种改为 Top band + 探索：

```text
Top = Score 最高的 T 个 seed
T   = max(8, min(64, 1% * N))

P(s) = ε/N + (1-ε) * Score(s) / Σ_{Top} Score(j)   if s ∈ Top
     = ε/N                                          otherwise

ε = 0.12
```

这样可以避免大量低分种子稀释高分种子，同时保留低分种子的探索机会。

### 10.3 可借鉴 SyzDirect 的点

#### 10.3.1 分位阈值 + 线性 closeness

SyzDirect 的 seed 调度不是全量加权，而是：

```text
threshold = 距离分位阈值
只考虑 dist < threshold 的 seed
weight = threshold - dist
```

对应到我们的 Score，可以把固定 Top T 改成动态阈值：

```text
threshold = Score 的 q 分位（例如 Top 10%）
Top = { s | Score(s) >= threshold }

weight(s) = max(0, Score(s) - threshold) + floor
```

好处：

- 阈值随 corpus 的 Score 分布自适应；
- Top band 边缘的种子权重接近 0，不会和最高分种子同权；
- 比单纯 `Score^γ` 更可解释。

注意：仍然保留 `ε`，不做 SyzDirect 那种硬 cutoff。

#### 10.3.2 work queue 按 K 进展排序

SyzDirect 的 triage/smash 队列按 `Dist` 升序处理。  
我们可以对 directed 候选的 triage/smash 增加优先级：

```text
优先：K_level 更高
其次：K_depth 更高
再次：新增 target PC 更多
```

这属于实现层优化，不改变保存/评分语义。

#### 10.3.3 smash 能量

SyzDirect 对越接近目标的程序给越多 smash 变异：

```text
normalized = (maxDist - dist) / (maxDist - minDist)
mutateNum = 50 + 150 * normalized
```

可以借鉴为：

```text
energy = base + scale * normalized(K_score)
```

但只建议用于 **smash**，不要用于普通 mutation：

- 普通 mutation 是一次选择一次 attempt，便于 G 结算；
- 一次选择做大量 mutation 会让 G 归因和 attempt 语义变复杂。

#### 10.3.4 call pair 选择

SyzDirect 会按 target/related call 组合的历史距离给 pair 加权。  
如果以后 related calls 较多，可以借鉴：

```text
每个 related call 维护历史 K 进展
按 K 进展/Score 加权选择，而不是均匀随机
```

当前单目标、related 较少的场景优先级不高。

#### 10.3.5 连续距离作为后续方向

SyzDirect 的核心是内核插桩得到的连续距离，比我们的 `K_level + K_depth` 更细。  
如果后续发现层级 + depth 仍然太粗，可以考虑引入：

- 调用图/基本块距离；
- 目标 PC 到当前 PC 的最短路径；
- 距离改善作为额外信号。

这是较大的静态分析改动，不属于当前核心。

### 10.4 不建议照搬的点

- **硬 cutoff 远距离种子**：`bpq0 up` 这类低 K 但必要的前置 seed 会被饿死，必须保留 `ε`。
- **distanceGroup 只增不减**：SyzDirect 的 distance 统计在 corpus 缩小时容易变旧；我们的 sampler 在最小化后会重建。
- **同距离组内完全等同**：会丢掉 K_depth 和 G 的层内区分。
- **把 smash 能量套到普通 mutation**：会打乱 per-mutation 的 G 结算和一次 attempt 的语义。

### 10.5 落地顺序

```text
P0 已完成：
  - K_level 乘性分离
  - G 作为有界 tie-breaker
  - Top band + ε

P1 建议：
  - Top band 内改为「分位阈值 + 线性 closeness」
  - directed triage/smash 按 K 进展排序

P2 可选：
  - smash energy
  - related call 的加权选择

P3 扩展：
  - 连续距离/调用图距离
```

---
