// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/*
 * ⚠️ 教学靶场 —— 本合约刻意包含安全缺陷，请勿部署到主网。
 *
 * 审计报告：audit-reports/Savings.md
 */

contract Savings {
    address public manager;
    mapping(address => uint) public deposits;
    uint public totalDeposits;

    constructor() {
        manager = msg.sender;
    }

    // ---- 干净：只修改调用者自己的账本 ----
    function save() public payable {
        deposits[msg.sender] = deposits[msg.sender] + msg.value;
        totalDeposits = totalDeposits + msg.value;
    }

    // ---- 缺陷 ①：先转账、后扣账 → 重入 ----
    function withdraw() public {
        uint amount = deposits[msg.sender];
        require(amount > 0, "nothing saved");

        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "failed");

        deposits[msg.sender] = 0;
        totalDeposits = totalDeposits - amount;
    }

    // ---- 缺陷 ②：require 查的是「金额」，不是「人」 ----
    function collectFee(uint amount) public {
        require(amount <= totalDeposits / 10, "fee too high");
        payable(msg.sender).transfer(amount);
    }

    // ---- 缺陷 ③：使用 tx.origin 判断身份 ----
    function changeManager(address newManager) public {
        if (tx.origin == manager) {
            manager = newManager;
        }
    }
}
