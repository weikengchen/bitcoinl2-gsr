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

### P4b/P5a 存款线（vault 并入 + program a）—— 完成（2026-09-28）

- **gadgets**：`SighashAllGadget::build_ext` 可以把输入下标作为 hint 传入，由签名检查认证，并留在栈上。用于需要在任意输入位置执行的 leaf。
- **vault**：`vault_leaf(Template)` 按模板生成 leaf。
  - 模板：输入 `[vault, 存款×j, fee]`，输出 `[vault, change, (聚合者 OP_RETURN), caboose]`；vault 金额恰好增加这些存款之和。
  - vault 的树有 5 个 leaf：原来的迁移，加上并入 j = 1～4。
  - `Vault::with_deposits`、`build_with` 负责构造并入交易。
- **program a**（`vault/src/program_a.rs`）：
  - 规则见 design §6"实现"。7 个 leaf：合并 j = 2～4，并入 j = 1～4。
  - 构造器：`deposit_outputs`；`merge_tx`，靠 OP_RETURN 的 nonce 做调整；`fold_tx`，经 `Vault::build_with` 调整 caboose 的 r。
- **测试 `vault/tests/deposit.rs`**：7 项全部通过。
  - 正例：
    - 存款 → 两层合并 → 并入：vault 余额和 acc 都正确；之后的迁移能把并入交易当作父交易反射。
    - 7 种形状各走一遍。
  - 反例：只单独执行那个 a 输入，断言具体失败的 opcode，因此不会因为签名错误而"碰巧"失败；每个反例都有诚实对照。
    - 合并：out0 少 1 或多 1；out0 不是 a_L；change 是 a_L；fee 输入是 a_L；两个 L2 的 a 混在一起。
    - 并入：
      - 并进克隆 vault（克隆 vault 自己的 leaf 能通过，a 拒绝）；
      - 别的 L2 的 a 并进本 vault；
      - change 是 a_L（vault 的 leaf 允许，a 拒绝）；
      - vault 少增加 1；
      - S′ 与 caboose 不一致；
      - in0 不是 P，而是普通输出，caboose 伪称 id 为 L。
  - identity 和 deposit 两组测试共用 `tests/common/` 里的钱包和模拟器环境。
- **大小**：见 design §6。并入 j = 1 时整笔交易 1,588 vB，j = 4 时 3,404 vB；合并 j = 2 时 834 vB。

### P4b 锁定、完成、超时 —— 完成（2026-09-28）

- **设计**：见 design §8.4"实现"和 §4.3 第 3、4 条。
  - vault 的树有 8 个 leaf：普通迁移，并入 j = 1～4，锁定，完成，超时。
  - 应用状态加入 B_min、N，VERIFYING 时再加锁定信息。
  - 新状态改为由脚本构造，不再作为 hint。
  - 证明用 operator 签名占位，b 的地址先用占位地址。
- **simulator**：`Database::set_height`，按共识检查 nLockTime 是否生效。时间型 nLockTime 不模拟，按"未生效"处理。
- **测试 `vault/tests/verify.rs`**：6 项全部通过。反例的做法同 deposit：单独执行 vault 输入，断言失败的 opcode。
  - 锁定 → 完成：提款付给 b，保证金退回，参数更新。之后 vault 能继续并入；新的 B_min 生效，低于它的锁定会被拒绝。
  - 锁定的规则：
    - 保证金低于 B_min；
    - vault 增加的金额与记录的保证金不一致；
    - nLockTime 是时间型；
    - 状态里的 h 与 nLockTime 不一致；
    - 高度 H 时锁定交易还没有生效。
  - 锁定期间：普通迁移、并入、再次锁定都被拒绝；未锁定的 vault 不能执行"完成"。
  - 完成的规则：
    - 签名的不是 operator；
    - 提款没有付给 b；
    - witness 里的清单与 OP_RETURN 的哈希不一致；
    - vault 多付出 1 sat；
    - 退款少 1 sat；
    - 退款地址不是记录的那个。
  - 退款地址设成 P 时，完成交易被拒绝，只能等超时（防止 vault 被冻结）。
  - 超时：
    - nLockTime = h + N − 1 时 CLTV 失败；
    - nLockTime = h + N 时，高度 h + N 还没有生效，高度 h + N + 1 才可以；
    - 不能拿走保证金，不能改参数；
    - 超时之后可以再次锁定并完成。
- identity 测试随新状态的构造方式做了调整：E04 在构造上已经不可能发生，因此删掉；新增一项"普通迁移不能改参数"。
- **全部测试**：workspace 共 48 项，全部通过。
- **大小**：锁定 1,085 vB，完成 1,369 vB，超时 1,090 vB，普通迁移 1,068 vB；leaf 2.3～2.7 KB。

### P4c 以后（未排期）

- 真正的验证器确定之后：
  - 加入多步验证的迁移，以及它的进度字段；
  - 把语句定下来：acc、R、W、H(清单)、新参数、L1 链尖；
  - L1 链尖的记录（design §6，方案 A 第 4 条）还没有实现。
- 覆盖 `verification-cases.md` 中剩下的 V 组用例。

### P5b program b —— 完成（2026-09-28）

- **设计**：见 design §7 第 2 条"实现"。
  - 节点的承诺 R 就是拆分交易的 sha_outputs；
  - 两个 leaf：root、internal；
  - 内部节点采用 43 字节的规范布局。
- **代码**（`vault/src/program_b.rs`）：
  - `ProgramB`：`split_tx` 负责调整 nLockTime nonce；`witness_from` 给测试构造"最强攻击者"的 hint。
  - `SplitTree`：按扇出分层构造树；可以从公开的清单重建；`withdrawal()` 生成完成交易所需的 (W, R, 清单)。
- vault 的 `b_spk` 换成真实的 program b 地址。测试环境里的 World 同步修改。
- **测试 `vault/tests/withdraw.rs`**：5 项全部通过。
  - 端到端：存款、锁定、完成，再逐层拆分到 20 个收款人（扇出 4，三层）；另测一层的树（根节点直接付款）。每笔拆分交易的手续费都恰好是设定值。
  - DA：从完成交易的 witness 中按哈希找回清单，重建出的根与完成交易承诺的 R 一致。
  - 拆分的规则。反例的 hint 都和脚本的视角一致，也就是最强的攻击者，因此只能在签名检查处以 SchnorrSig 失败：
    - 输出少付 1 sat；
    - 输出改付给别人；
    - 多加一个输入；
    - 用另一个节点的输出去花这个 b。
  - 其他反例：
    - 根 b 用 internal leaf 花（父交易有两个输入）；
    - 子节点的 pieces 错位（前段长度不对）。
  - 大小：256 笔提款、扇出 16，平均每笔 74 vB。
- **全部测试**：workspace 共 53 项，全部通过。
- **暂未做**：
  - 手续费目前是每笔拆分交易一个固定值，应改为按参考费率乘以交易大小；
  - P2A anchor 输出。

### P5c DA 数据与 L2 状态根 —— 完成（2026-09-28）

- **设计**：见 design §7 第 5 条（DA 格式、H 的定义与安全论证）和 §8.4（应用状态）。
- **`vault/src/da.rs`**：
  - `DaData`：提款清单、新账户、变动账户，编码和解码都只接受规范格式；
  - `chain_hash`：可分块的 H。
  - 3 个单元测试：
    - 编解码往返，并核对每个变动账户实际占用的字节数；
    - 拒绝多余字节、截断、重复编号、非最短 CompactSize；
    - 哈希链的定义（单块和两块）。
- **vault**：
  - 应用状态加入 l2_root（77 / 153 字节），字段偏移统一放在 `state::app_offset`。
  - 完成交易：
    - 新的 l2_root 和参数作为一个 44 字节的 hint 传入；
    - DA 数据作为一个 witness 元素传入，脚本检查 SHA256(数据 ‖ 32 个零字节) 等于 OP_RETURN 里的 H；
    - `Withdrawal` 改为 `Batch`，即一次证明确定的全部内容：W、R、DA 数据、l2_root、参数。
- **program b**：`SplitTree::from_da` 从 DA 数据里的提款清单重建拆分树。
- **测试**：
  - 从完成交易的 witness 中按 H 找回 DA 数据，解码结果与提交的数据完全一致，重建出的拆分树根与承诺一致；
  - 普通迁移和超时都不能改 l2_root；
  - 完成交易正确设置 l2_root。
- **全部测试**：workspace 共 56 项，全部通过。
- **暂未做**：
  - 分块公布（哈希链的格式已经预留）；
  - L2 状态树本身，也就是 Merkle 树的具体定义和 l2_root 的计算。vault 只把 l2_root 当作证明给出的值。
    - 用户决定（2026-09-28）：L2 抽象化，不做。

### P5d 验证器接口与 franking 占位 —— 完成（2026-09-28）

- **设计**：见 design §7 第 6 条。
  - 语句 212 字节；
  - franker 先在链下检查（DA 规范且与 H 一致，R、W 是提款清单的拆分树），通过后用 SIGHASH_DEFAULT 对整笔完成交易签名。
- **代码**：
  - `vault/src/verifier.rs`：
    - `Statement`：定义、编码，以及 `of_completion` 从完成交易读出语句；
    - `Franker`：`check` 做链下检查，`frank` = 检查 + 签名；`sign` 不做检查，只给链上规则的测试用。
  - `VaultConfig.operator` 改名为 `franker`；`build_complete` 改为调用 franker，franker 拒绝时返回错误；另有 `build_complete_with`，可以自定义签名方式。
- **测试**：
  - 语句的各个字段与完成交易一致，长度 212 字节；
  - franker 拒绝三种批次：R 不对、W 不对、DA 数据格式错误；
  - 原有的链上反例改为：franker 会接受的就正常签名；franker 会拒绝的（DA 不一致、未锁定就完成）绕过它签名，以便单独测链上规则。
- **全部测试**：workspace 共 57 项，全部通过。

### P5e 存款格式与分类 —— 完成（2026-09-29）

- **设计**：见 design §6"存款格式与分类"，以及 §7 第 6 条"证明要读的历史"。
- **program a**：
  - 合并 leaf 新增两条检查：out1 必须是原生 segwit，付费输入必须是原生 segwit。每个合并 leaf 因此多 61 字节，合并 j = 2 的交易从 834 vB 变成 865 vB。
  - 存款格式：`DEPOSIT_TAG`，`deposit_outputs` 和 `deposit_tx` 负责构造，`deposit_of` 负责检查。
  - `classify`：电路往下追溯时用的分类规则的参考实现，结果是存款、合并（接着追它的 j 个 a 输入）或无归属。
- **测试**：
  - 合并交易的 out1 写成存款标记、付费输入是 P2SH，这两种都被 a 输入拒绝；
  - 存款格式：合法的存款被识别；以下六种改动都被判为无归属：多一个输出、找零不是原生 segwit、out0 不是 a_L、没有标记、有 scriptSig、输入超过 8 个。
  - 真正的合并被分类为 Merge(j)。
  - 测试里的存款改为每笔交易一笔，按存款格式构造。
- **全部测试**：workspace 共 59 项，全部通过。

### P7 OP_TX instead of the Schnorr trick — done (2026-09-30)

- **Why**: objections to reflecting transactions with the CAT/Schnorr trick; the
  user asked to use the community-proposed OP_TX instead.
- **Reference**: OP_TX as implemented in jmoik/bitcoin `gsr-full` at `d279905`
  (`src/script/op_tx.cpp`, 76 vectors in `src/test/data/op_tx.json`). Its
  6-byte selector differs from Rusty Russell's v0.1.0 draft text. That branch
  also moved to a newer varops model (a fixed charge per opcode); we take over
  only OP_TX's own charge and keep BIP 440/441 at `8384b7a` for everything else.
- **scriptexec**: `optx.rs` implements OP_TX; 0xbd is no longer OP_SUCCESS in
  tapscript v2; a future selector version makes validation succeed at once, as
  in the reference. `TxTemplate` carries the control block (OP_TX can read it).
  All 76 reference vectors pass: outputs, varops charges and error kinds.
- **simulator**: passes the control block; an end-to-end OP_TX covenant test.
- **gadgets**: `optx.rs` with `TxFieldsGadget`, which reads the same fields the
  SIGHASH_ALL gadget produced (36-byte outpoints, 8-byte amounts,
  compact-size-prefixed scriptPubKeys, sequences, serialized outputs, lock
  time) and first checks nVersion and the exact input and output counts, which
  the signature message used to pin. The leaves' own logic is unchanged.
- **vault, program a, program b**: all read the spending transaction with
  OP_TX. Program b hashes all outputs read with OP_TX and compares with R. No
  grinding is left: caboose r = 0, no merge nonce, split nLockTime 0. Witnesses
  no longer carry signature-message hints.
- **Tests**: 62 in the workspace, all pass. New: exact shape (an extra input, an
  extra output or nVersion 3 is rejected) for the vault and for merges.
- **Sizes** (before → after):

  | | Schnorr trick | OP_TX |
  |---|---|---|
  | plain transition | 1,076 vB | 918 vB |
  | lock / completion / timeout | 1,093 / 1,396 / 1,098 vB | 935 / 1,191 / 940 vB |
  | fold of 1 / 2 / 3 / 4 | 1,560 / 2,106 / 2,726 / 3,383 vB | 1,168 / 1,438 / 1,732 / 2,011 vB |
  | merge of 2 / 3 / 4 | 865 / 1,315 / 1,841 vB | 493 / 683 / 896 vB |
  | withdrawals, per payout (256, fan-out 16) | 74 vB | 67 vB |
  | vault leaf (plain) / a leaf (merge 2) / b leaf (internal) | 2,269 / 615 / 421 B | 1,996 / 319 / 163 B |

  Every covenant input also saves a 500,000-varops CHECKSIG; an OP_TX call
  costs 1,250 plus 3 per byte read.

### P6 在真实实现上对照验证（已取消，2026-09-28）

- 用户决定：不安装 inquisition 版的 bitcoind，全部用本地模拟器。模拟器调试起来更方便。
- 与真实实现的一致性，靠参考实现的 JSON 向量保证（P1 已全部通过）。以后参考实现更新时，只需重新拉取向量再跑一遍。

## 约定

- 整个 `~/bitcoinl2` 是一个 monorepo（Cargo workspace），对应 GitHub 上的 weikengchen/bitcoinl2-gsr（private），于 2026-09-28 按用户要求建立。
  - scriptexec 和 simulator 放的是修改后的版本，来源写在 README 里。第一个 commit 原样导入上游，之后的 commit 是我们的改动。
  - 不在上游仓库上开分支。
- 不使用 git worktree。
- `docs/ref/` 下的参考资料只保存在本地（已 gitignore），出处和固定的 commit 都记在本文件里。
