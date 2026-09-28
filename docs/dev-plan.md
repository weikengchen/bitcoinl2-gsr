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

### P3 基础 gadget（我们自己的 crate，放在 monorepo 下）

- SIGHASH_ALL（0x01）内省，覆盖全部输入向量（prevouts、amounts、scriptpubkeys、sequences）和 outputs，并检查 input_index。
- G/G Schnorr trick，不做 grinding：s = e+1，末字节不是 0xff 时直接 1ADD。
- txid 反射：整笔父交易作为一个 witness 元素传入，脚本用 SUBSTR 解析。

### P4 vault

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
