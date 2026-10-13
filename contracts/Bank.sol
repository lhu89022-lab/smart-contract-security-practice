// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title Bank —— 存取款合约（含手续费）
/// @notice 设计要求：
///         1. 任何人都能存款
///         2. 只能提取自己的余额，先扣账再转账（CEI）
///         3. 只有 owner 能提取手续费
///         4. 不使用 tx.origin 做身份判断
contract Bank {
    mapping(address => uint) public balances;
    address public owner;

    /// @dev 手续费池。与 balances 完全分离，这是本合约最关键的设计。
    uint public fees;

    constructor() {
        owner = msg.sender;
    }

    /// @notice 存款。每笔收取 1% 手续费，其余计入存款人余额。
    function deposit() public payable {
        uint fee = msg.value / 100;
        balances[msg.sender] = balances[msg.sender] + msg.value - fee;
        fees = fees + fee;
    }

    /// @notice 提取自己的余额。
    /// @dev CEI：先扣账，再转账。若顺序反过来（先转账后扣账），
    ///      攻击者可通过 receive() 回调重复调用本函数，把合约掏空。
    function withdraw(uint amount) public {
        require(amount <= balances[msg.sender], "not enough balance");

        balances[msg.sender] = balances[msg.sender] - amount;
        payable(msg.sender).transfer(amount);
    }

    /// @notice 提取手续费，仅限 owner。
    /// @dev 关键：取的是 fees 这个独立账本，不是 address(this).balance。
    ///      如果取 address(this).balance / 100，就会动用用户的钱，
    ///      导致「账本数字没变、真实余额变少」的坏账。
    function collectFee() public {
        require(msg.sender == owner, "not owner");

        uint amount = fees;
        fees = 0;
        payable(owner).transfer(amount);
    }
}

/*
 * 不变量（任何时刻都必须成立）：
 *
 *     address(this).balance == Σ balances[user] + fees
 *
 * 验证过程：
 *   存入 1 ether  → balances[你] = 0.99 ether, fees = 0.01 ether
 *                    余额 1 ether == 0.99 + 0.01          ✓
 *   取出 0.99     → balances[你] = 0,          fees = 0.01 ether
 *                    余额 0.01 ether == 0 + 0.01          ✓
 *   collectFee    → balances = 0,              fees = 0
 *                    余额 0 == 0 + 0                      ✓
 */
