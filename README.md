# Smart Contract Security Practice

> 智能合约安全审计练习集 —— 从漏洞原理到攻击复现，再到修复验证。

这个仓库记录我系统学习 **Solidity 智能合约安全** 的过程：审计存在缺陷的合约、编写攻击合约验证漏洞可利用性、给出修复方案，并复盘每一个漏洞背后的通用模式。

**不是教程笔记，是审计报告。**

---

## 目录

| 路径 | 内容 |
|---|---|
| [`targets/`](targets/) | 审计目标合约（教学靶场，含已知缺陷） |
| [`audit-reports/`](audit-reports/) | 4 份审计报告，逐条漏洞分析 |
| [`contracts/`](contracts/) | 自己编写并部署的合约 + 攻击合约 |
| [`docs/audit-methodology.md`](docs/audit-methodology.md) | 我使用的审计方法论（扫描清单 / 六问法 / 不变量） |

---

## 审计成果

| # | 目标合约 | 漏洞 | 高危 | 类型 | 报告 |
|---|---|---|---|---|---|
| 1 | `TipJar` | 3 | 2 | 重入 / 钓鱼 / 中心化风险 | [报告](audit-reports/TipJar.md) |
| 2 | `Savings` | 3 | 3 | 重入 / 访问控制缺失 / 钓鱼 | [报告](audit-reports/Savings.md) |
| 3 | `Escrow` | 3 | 3 | 缺失状态更新 / 访问控制缺失 / 钓鱼 | [报告](audit-reports/Escrow.md) |
| 4 | `Exchange` | 2 | 2 | 重入 / 钓鱼 | [报告](audit-reports/Exchange.md) |
| | **合计** | **11** | **10** | | |

---

## 漏洞类型覆盖

| 类型 | 说明 | 出现次数 |
|---|---|---|
| **重入（Reentrancy）** | 先转账、后扣账 → 外部合约在收到钱时回调，重复取款 | 3 |
| **访问控制缺失** | `require` 检查的是`金额`而不是`人` → 任何人都能调用 | 2 |
| **`tx.origin` 钓鱼** | 用 `tx.origin` 判断身份 → 诱导 owner 调用攻击合约即可绕过 | 4 |
| **缺失状态更新** | 转账前没有扣减余额 → 可无限重复领取 | 1 |
| **中心化风险** | owner 可提取合约全部余额（设计问题，非代码缺陷） | 1 |

---

## 自建合约

### [`contracts/Bank.sol`](contracts/Bank.sol)

一个存取款合约，实现三个要求：

1. 任何人都能存款
2. 只能提取自己的余额，且**先扣账、再转账**（CEI 模式）
3. 只有 owner 能提取手续费，手续费**独立记账**，与用户余额完全分离

**关键设计：手续费池 `fees` 与用户账本 `balances` 分离。**

如果手续费直接从「合约余额」里按比例提取（`address(this).balance / 100`），就会出现**坏账**：合约的真实余额被抽走，但用户账本上的数字没变，最后一个取款的人取不出钱。

**不变量：`合约余额 == Σ balances + fees`**，任何时刻不成立就说明有漏洞。

### [`contracts/Attackers.sol`](contracts/Attackers.sol)

复现三类攻击：

- `ReentrancyAttacker` —— 通过 `receive()` 回调重复调用 `withdraw()`
- `CoinFlipAttacker` —— 在同一笔交易内算出与目标合约相同的「随机数」
- `DoSKingAttacker` —— 故意不实现 `receive()`，让资金永久锁死

---

## 工具与环境

- **语言**：Solidity `^0.8.0`
- **IDE**：Remix IDE（Remix VM 本地测试网）
- **方法**：手动代码审计 + 攻击合约验证（PoC）

---

## 方法论

完整的扫描清单、六问法、不变量检查表见 [`docs/audit-methodology.md`](docs/audit-methodology.md)。

核心是三条：

1. **用搜索，不用阅读** —— 严重漏洞集中在少数几个模式里，`Ctrl+F` 关键词比逐行读代码快得多。
2. **函数三分类** —— 碰钱的逐行读，改状态的细读，纯读的扫一眼跳过。
3. **找不变量** —— 漏洞不是「代码写错了」，是「某个假设被打破了」。

---

## 计划

- [x] Solidity 安全基础（重入 / 访问控制 / 钓鱼 / DoS / 随机数）
- [x] 手动审计 4 个合约并输出报告
- [ ] 完成 [Ethernaut](https://ethernaut.openzeppelin.com/) 全部 31 关
- [ ] 完成 [Damn Vulnerable DeFi](https://www.damnvulnerabledefi.xyz/) 全部 18 关
- [ ] 参加公开审计竞赛（Code4rena / Sherlock），提交第一个有效 finding
- [ ] 研究真实项目审计报告（进行中：[SSV Network](https://github.com/ssvlabs/ssv-network) Quantstamp v1.2.0，21 项 findings）

---

## 联系方式

- Email: 1878212774@qq.com

## 免责声明

本仓库所有代码与报告**仅用于安全教育与授权测试**。`targets/` 下的合约是刻意构造的有缺陷教学靶场，请勿用于任何未经授权的场景。
