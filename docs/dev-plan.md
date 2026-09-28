# 开发方案

更新：2026-09-28。设计依据见 `docs/design.md`。

## 0. 环境

| 项目 | 位置 | 说明 |
|---|---|---|
| 脚本执行器 | monorepo 内的 `scriptexec/` | 来自 Bitcoin-Wildlife-Sanctuary/rust-bitcoin-scriptexec 的 `fac1401`（master，比 tag 1.0.0 多 2 个 commit），CC0。原仓库没有测试。 |
| 账本模拟器 | monorepo 内的 `simulator/` | 来自 Bitcoin-Wildlife-Sanctuary/bitcoin-simulator 的 `16b73cf`（tag 1.1.0），MIT。上游原有 6 个测试，全部通过。 |
| GSR 参考实现 | `jmoik/bitcoin`，固定在 `8384b7a`（`gsr-inquisition`，即 inquisition PR #119 的 head，2026-06-24） | 相关源码和测试向量复制在 `docs/ref/gsr-ref-8384b7a/` |
| 规范原文 | `docs/ref/bip-0440/0441/0342/0347.mediawiki` | 取自 bitcoin/bips `4f979da` |
| 公开 GSR signet | gsr-net（`jmoik/bitcoin` 分支 `gsr-net`，2026-09-11） | 2026-09-28 从本机连不上：explorer 和 P2P 都超时。它运行的是 gsr-full，除 BIP 441 外还多了 CSFS/TWEAKADD/BYTEREV/MULTI。 |

一致性测试向量：`tapscript_v2_restored_ops.json`（114 条）和 `tapscript_v2_varops.json`（124 条），每条都给出初始栈、opcode、预期结果栈和 varops 成本。

## 阶段

### P1 scriptexec：tapleaf 0xc2 模式 —— 完成（2026-09-28）

- **leaf version**：新增 0xc2 执行上下文，按 control block 里的 leaf version 选择。
- **限制**：单个元素 ≤ 4,000,000 字节（push 和初始栈都适用）；栈加 altstack 总字节数 ≤ 8,000,000；元素个数 ≤ 32,768。
- **数字**：一律是任意长度的无符号小端数。
  - 算术运算（1ADD、1SUB、2MUL、2DIV、ADD、SUB、MUL、DIV、MOD、MIN、MAX）的结果要规范化，去掉末尾的 0 字节。
  - 以下 opcode 按新规则读取数字：CLTV、CSV（值必须 < 2^32）、VERIFY、PICK、ROLL、IFDUP、CHECKSIGADD。
  - 以下 opcode 按最小长度写出数字：CHECKSIGADD、DEPTH、SIZE。
  - 比较、布尔运算按无符号语义实现，细节以参考实现为准。
- **opcode**：恢复的 15 个——CAT、SUBSTR、LEFT、RIGHT、INVERT、AND、OR、XOR、2MUL、2DIV、MUL、DIV、MOD、UPSHIFT、DOWNSHIFT。
  - 1NEGATE、NEGATE、ABS 改为 OP_SUCCESS。
  - RIPEMD160、SHA1 的操作数超过 520 字节时失败。
- **结束条件**：执行结束时栈上恰好一个元素，并且它含有非零字节。
- **varops**：按 BIP 440/441 的公式计费；预算 = 整笔交易 weight × 10,000，由所有输入共享；超出预算时是否判失败可以配置。
- **测试**：写一个 Rust runner 跑上面 238 条向量，目标全部通过；如有偏差，逐条记录。
- **结果**：
  - 新增 `src/v2.rs`（数值运算和 varops 成本）、`src/exec_v2.rs`（执行路径）。
  - `tests/v2_conformance.rs`：238/238 条参考向量全部通过，结果栈和 varops 成本都完全一致。
  - `tests/v2_semantics.rs`：5 组失败路径测试，覆盖下溢、除零、各项上限、预算、控制流、OP_SUCCESS、最终检查。
  - 顺带修复：`check_sig_schnorr` 在遇到非法 x-only 公钥时会 panic，现在改为返回错误。

### P2 simulator：接入 0xc2 —— 完成（2026-09-28）

- P2TR 检查按 control block 里的 leaf version 计算 tapleaf hash，并分派到 0xc0 或 0xc2 执行。
- varops 预算在一笔交易的所有输入之间共享。
- 0xc2 允许大 witness 元素；标准交易 weight 上限 400k WU。
- 付费输入先用 P2WPKH（已经支持）；key path 花费以后按需要再加。
- 端到端测试：一个最简单的 0xc2 花费；一个用到 CAT、SUBSTR、MUL 的花费。
- **结果**：
  - `check_with_varops` 按 leaf version 分派执行；`verify_transaction` 让所有输入共享同一个 varops 预算，并新增检查：输入如果已被花费则报错。原仓库这一版不检查双花。
  - 用 `[patch]` 把依赖指向本地的 scriptexec。
  - 测试：原有 6 个全部通过；新增 `tests/tapscript_v2.rs` 中的 2 个也通过。
    - 0xc2 leaf 使用真实 Schnorr 签名，sighash 使用 0xc2 的 leaf hash；用 0xc0 hash 签的名会被拒绝。
    - 40 字节 × 40 字节的大数乘法。
    - 双花会被拒绝。
    - 单个输入、两个输入各自超出 varops 预算时失败；交易 weight 足够大时同样的计算可以通过。

### P3 基础 gadget —— 完成（2026-09-28），crate 为 `gadgets/`（`gsr-gadgets`）

- SIGHASH_ALL（0x01）内省，覆盖全部输入向量（prevouts、amounts、scriptpubkeys、sequences）和 outputs，并检查 input_index。
- G/G Schnorr trick，不做 grinding：s = e+1，末字节不是 0xff 时直接 1ADD。
- txid 反射：整笔父交易作为一个 witness 元素传入，脚本用 SUBSTR 解析。
- **结果**：写法沿用 covenants-gadgets，每个 gadget 都是"脚本 + Rust 端 hint 生成"两部分，hint 用 `OP_HINT` 从栈底取。
  - `sighash`：`SighashAllGadget::build(n, m, input_index, version)`，从 hint 重建 SIGHASH_ALL 的签名消息。每个字段都做长度校验，保证 hint 对承诺向量的切分是唯一的。
  - `schnorr`：`SchnorrTrickGadget::verify()`，用 G/G trick，对末字节做 1ADD。只有末字节为 0xff 时才需要调整交易（概率 1/256）。
  - `tx`：`TxBuildGadget::build(n, m)`，从 hint 拼出父交易的非见证序列化并算出 txid。做法是由脚本插入计数和空 scriptSig，而不是去解析一个大元素，这样不会出现切分歧义。
  - `leaf`：`V2Tree` 构造 NUMS 内部键下的 0xc2 树，并调用 `assert_no_op_success`，因为 `script!` 会把 0x81 编成 OP_1NEGATE，而它在 v2 里是 OP_SUCCESS。
  - `pseudo`：`push_data`、`push_u64`，都是 v2 安全的常量 push。
  - 测试 `tests/covenant.rs`，4 项全部通过：
    - sighash 与 rust-bitcoin 的计算结果一致；
    - OP_SUCCESS 守卫生效；
    - 自复制 covenant：违规时在 covenant 检查处失败；伪造签名消息并重新算 challenge 时，在 CHECKSIGVERIFY 处以 SchnorrSig 失败；
    - F→X1→X2→X3 的父交易反射：父交易不对时在 txid 比较处失败。
  - 大小：
    - `SighashAllGadget::build(2,2)` 190B，`build(8,8)` 630B；
    - `TxBuildGadget::build(2,2)` 110B；
    - `SchnorrTrickGadget::verify()` 204B。
  - 开销：一次 2 进 2 出的自复制花费约 53 万 varops，主要是一次 CHECKSIG 的 50 万，大约相当于 50 WU 的预算。

### P4a vault 身份核心 —— 完成（2026-09-28），crate 为 `vault/`（`bitcoinl2-vault`）

- **gadgets 新增两个模块**：
  - `stack.rs`：带名字的栈模型，自动算 PICK/ROLL 深度，IF 分支结束后自动还原栈的顺序。
  - `parse.rs`：`parse_tx` 把一个交易 blob 做规范解析，循环有上限。它校验单字节计数、空 scriptSig、单字节脚本长度、结尾恰好剩 4 字节 locktime，可选校验 sequence 和"禁止出现某个 spk"，取出 txid、in0、out0、第 k 个输出和最后一个输出。
  - 测试：60 笔随机交易与 rust-bitcoin 逐字段一致；畸形输入全部被拒。上限 8/8 时脚本 891B。
- **`vault/`**：
  - `state.rs`：spec §6 的 envelope、应用状态 `acc ‖ mode`、裸 OP_RETURN caboose。
  - `leaf.rs`：`transition_leaf` 按 spec §10 逐条实现：
    - AUTH-1：SIGHASH_ALL 加 Schnorr trick；
    - 格式与角色：LIN-1/2、CAB-1、原生 segwit；
    - AUTH-2：规范解析 T，T.out0 == Spent(X,0)，T 的格式和唯一 P；
    - 旧状态和新状态的 envelope 检查，以及 acc 规则；
    - AUTH-3：规范解析 Q，k < n_out；
    - AUTH-4：按 Q.output[k] 的 spk 选分支。延续分支要求 k == 0、ACTIVE、id 不变；创世分支要求 T 只有 1 个输入、旧状态是 GENESIS、id == txid(T)。
  - `tx.rs`：构造创世交易和迁移交易。Schnorr trick 需要调整时改的是 caboose 的随机数 r，这正是 spec CAB-3 设计 r 的用途。
- **测试 `vault/tests/identity.rs`**：10 项全部通过，覆盖 G01–G10、L02/L04/L06、A01/A04/A06、E04、acc、mode、金额守恒、唯一后继（双花被拒）。每个反例都是只改诚实 plan 的一个字段。
- **大小**：leaf 2,306B；一次迁移交易 4,307 WU（1,077 vB），执行约 64 万 varops。
- **暴露出的约束**（相当于 spec RES-2 在 GSR 下的版本）：被反射的 T 和 Q 最多 8 个输入、8 个输出，scriptSig 为空，输出脚本短于 253 字节。这也包括创世的出资交易，也就是创世分支里的 Q。
- **P4a 的简化，留给 P4b**：只有一种交易模板（in `[vault, fee]`、out `[vault, change, caboose]`）；金额不变；Init、First 和出资来源谓词都接受任意值。

### P4b vault 应用迁移（下一步）

- 按 spec v0.1.0 加上已定的偏离：
  - envelope 格式不变；`app_root = H(acc ‖ mode ‖ 模式相关数据)`。
  - caboose 用裸 OP_RETURN。
  - 两代回溯，分创世和延续两个分支。
  - 每次迁移 `acc' = H(acc ‖ txid(父交易))`。
- 迁移类型：并入；锁定（VERIFYING，保证金，nLockTime = h）；验证步骤；完成提款（退还保证金，提款用 operator CHECKSIG 占位）；超时（单独的 leaf，CLTV ≥ h + N）。
- 测试：覆盖 `verification-cases.md` 中的 G/L/A/E/V 各组用例。

### P5 program a / program b

- program a：地址 a_L 里写死 L 和 P；合并规则；并入规则。
- program b：Merkle-sum 拆分树。

### P6 在真实实现上对照验证（已取消，2026-09-28）

- 用户决定：不安装 inquisition 版的 bitcoind，全部用本地模拟器。模拟器调试起来更方便。
- 与真实实现的一致性，靠参考实现的 JSON 向量保证（P1 已全部通过）。以后参考实现更新时，只需重新拉取向量再跑一遍。

## 约定

- 整个 `~/bitcoinl2` 是一个 monorepo（Cargo workspace），对应 GitHub 上的 weikengchen/bitcoinl2-gsr（private），于 2026-09-28 按用户要求建立。
  - scriptexec 和 simulator 放的是修改后的版本，来源写在 README 里。第一个 commit 原样导入上游，之后的 commit 是我们的改动。
  - 不在上游仓库上开分支。
- 不使用 git worktree。
- `docs/ref/` 下的参考资料只保存在本地（已 gitignore），出处和固定的 commit 都记在本文件里。
