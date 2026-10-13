# Escrow 审计报告

| 项目 | 内容 |
|---|---|
| **目标合约** | [`targets/Escrow.sol`](../targets/Escrow.sol) |
| **审计日期** | 2026-10 |
| **审计方式** | 手动代码审计 + 攻击合约验证（PoC） |
| **漏洞总数** | **3**（高危 3） |

---

## 摘要

| ID | 标题 | 严重性 | 位置 | 类型 |
|---|---|---|---|---|
| [ES-01](#es-01-转账前没有扣减余额可无限重复领取) | 转账前没有扣减余额，可无限重复领取 | 🔴 **High** | `withdrawTo()` L28 | 缺失状态更新 |
| [ES-02](#es-02-require-只检查金额不检查调用者) | `require` 只检查金额，不检查调用者 | 🔴 **High** | `resolve()` L33 | 访问控制缺失 |
| [ES-03](#es-03-使用-txorigin-判断身份遭钓鱼) | 使用 `tx.origin` 判断身份，遭钓鱼 | 🔴 **High** | `changeArbiter()` L39 | 访问控制 |

## 函数概览

| 函数 | 判定 |
|---|---|
| `deposit()` | ✅ 干净 |
| `withdrawTo()` | 🔴 缺失状态更新 |
| `resolve()` | 🔴 访问控制缺失 |
| `changeArbiter()` | 🔴 `tx.origin` 钓鱼 |

---

## ES-01 转账前没有扣减余额，可无限重复领取

**位置** `withdrawTo()`，L28
**严重性** 🔴 High
**类型** Missing State Update

### 描述

```solidity
function withdrawTo(address to, uint amount) public {
    require(amount <= balances[msg.sender], "not enough balance");   // L27  检查
    payable(to).transfer(amount);                                   // L28  转账
}
```

用「三类行」拆开看：

| 类型 | 长什么样 | 本函数里有没有 |
|---|---|---|
| **读** | `uint amount = balances[msg.sender];` | 无（L27 直接在条件里读） |
| **检查** | `require(...)` | ✅ L27 |
| **改账** | `balances[msg.sender] = balances[msg.sender] - amount;` | ❌ **不存在** |

**判断标准只有一条：看 `mapping` 在等号的哪一边。**

- 在等号**左边** = 改账
- 在等号**右边** = 只是在看

L27 里 `balances` 出现在 `<=` 的右侧 —— 整个函数里，**`balances` 从来没有出现在等号左边过。**

**所以：`withdrawTo()` 里「改账」那一行根本不存在。**

### 攻击路径

**不需要写攻击合约，手动点击即可。**

设合约里共有 10 ETH，攻击者存入 1 ETH：

| 步骤 | 调用 | L27 检查 | 结果 |
|---|---|---|---|
| 1 | `withdrawTo(自己, 1 ether)` | `1 <= balances[自己] = 1` ✅ | 拿走 1 ETH |
| 2 | `withdrawTo(自己, 1 ether)` | `1 <= 1` ✅ | 再拿 1 ETH |
| 3 | 重复 10 次 | …… | **拿走 11 ETH** |

`balances[msg.sender]` **永远是 1**，因为从来没有任何代码改动过它。

### 影响

**攻击者只存入 1 ETH，却可以取走合约里的全部资金（11 ETH）。**

**这个漏洞比重入更严重** —— 重入至少还需要写一个攻击合约来制造循环，而这里**手点就行**。

### 修复

在 L27 之后、L28 之前补上状态更新（**这就是 CEI**）：

```solidity
function withdrawTo(address to, uint amount) public {
    require(amount <= balances[msg.sender], "not enough balance");

    balances[msg.sender] = balances[msg.sender] - amount;   // 先扣账
    total = total - amount;
    payable(to).transfer(amount);                           // 再转账
}
```

### 通用教训

> **「读一行、检查一行」不等于「改了一行」。**
>
> `uint amount = tips[msg.sender];` 是**看**
> `require(amount > 0);` 是**拦**
> `tips[msg.sender] = 0;` 是**改**
>
> **只有第三种会改变世界，前两种什么都不改变。**

排查方法：找出函数里所有涉及金额的 `mapping`，逐个问 —— **它在这一行被改了吗，还是只是被看了一眼？**

---

## ES-02 `require` 只检查金额，不检查调用者

**位置** `resolve()`，L33
**严重性** 🔴 High
**类型** Access Control

### 描述

```solidity
function resolve(address to, uint amount) public {
    require(amount <= total / 100, "dispute fee too high");   // L33
    payable(to).transfer(amount);                             // L34
}
```

L33 的 `require` 检查的是**金额上限**（不能超过总额的 1%），**一个字都没提「谁可以调用」**。

名称 `resolve`、参数 `to` 都暗示这是一个「仲裁者处理争议」的函数，但**代码里没有任何仲裁者检查**。

### 攻击路径

**任何人都可以调用，且可以指定任意收款地址 `to`。**

即使把 `to` 固定为自己，由于函数从不修改 `total`，`total / 100` 的上限始终不变 —— **可以反复调用，直到合约归零。**

> 这一条与 [Savings SV-02](Savings.md#sv-02-require-只检查金额不检查调用者) 是**同一个模式换了名字和行号** —— 识别它的方法完全相同：看到 `require` 先问「它查的是人、是钱、还是状态」。

### 影响

**任何人可反复提取合约余额的 1%，直至合约资金耗尽。**

### 修复

```solidity
function resolve(address to, uint amount) public {
    require(msg.sender == arbiter, "not arbiter");            // 补上「人」的检查
    require(amount <= total / 100, "dispute fee too high");
    total = total - amount;                                   // 并扣账
    payable(to).transfer(amount);
}
```

---

## ES-03 使用 `tx.origin` 判断身份遭钓鱼

**位置** `changeArbiter()`，L39
**严重性** 🔴 High
**类型** Access Control / Phishing

### 描述

```solidity
function changeArbiter(address newArbiter) public {
    if (tx.origin == arbiter) {          // L39
        arbiter = newArbiter;
    }
}
```

`tx.origin` = **点火的人**（整条调用链的起点）
`msg.sender` = **敲门的人**（直接调用者）

### 攻击路径

```solidity
contract EscrowPhisher {
    Escrow public target;
    address public hacker;

    constructor(address _target) {
        target = Escrow(_target);
        hacker = msg.sender;
    }

    function fakeAirdrop() public {
        target.changeArbiter(hacker);    // 包装成「领取奖励」
    }
}
```

1. 攻击者部署 `EscrowPhisher`
2. 诱导 arbiter 点击 `fakeAirdrop()`
3. 调用链：`arbiter` → `EscrowPhisher` → `Escrow`
   - `tx.origin` = arbiter ✅ 通过
   - `msg.sender` = EscrowPhisher（无人检查）
4. **`arbiter` 被替换为攻击者地址**

攻击者随即取得 `resolve()` 的完整权限（在修复 ES-02 的前提下），可反复提取资金。

### 影响

**仲裁者身份被劫持，托管合约的管理权完全失守。**

### 修复

```solidity
if (msg.sender == arbiter) {
    arbiter = newArbiter;
}
```

更好的写法是显式 revert 而不是静默失败：

```solidity
require(msg.sender == arbiter, "not arbiter");
arbiter = newArbiter;
```

---

## 结论

`Escrow` 一共 **3 个高危问题**，`deposit()` 干净。

| ID | 类型 | 危害 | 修法 |
|---|---|---|---|
| ES-01 | 缺失状态更新 | 存 1 ETH 取走全部 | 补 2 行扣账 |
| ES-02 | 访问控制缺失 | 任何人反复提取 1% | 补 1 行 `require` + 扣账 |
| ES-03 | `tx.origin` 钓鱼 | 管理权被劫持 | 改 1 个词 |

**ES-01 是最值得记住的一条**：它没有重入那么「有名」，也不需要任何攻击工具，**只是忘了一行扣账** —— 而这一行的缺失，让整个合约变成了一个任何人都能无限取款的提款机。

> **审计时最容易被忽略的，不是写错的代码，是没写的代码。**
