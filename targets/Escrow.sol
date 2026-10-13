// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/*
 * ⚠️ 教学靶场 —— 本合约刻意包含安全缺陷，请勿部署到主网。
 *
 * 审计报告：audit-reports/Escrow.md
 */

contract Escrow {
    address public arbiter;
    mapping(address => uint) public balances;
    uint public total;

    constructor() {
        arbiter = msg.sender;
    }

    // ---- 干净：只修改调用者自己的账本 ----
    function deposit() public payable {
        balances[msg.sender] = balances[msg.sender] + msg.value;
        total = total + msg.value;
    }

    // ---- 缺陷 ①：require 是「检查」不是「改账」；改账那一行根本不存在 ----
    function withdrawTo(address to, uint amount) public {
        require(amount <= balances[msg.sender], "not enough balance");
        payable(to).transfer(amount);
    }

    // ---- 缺陷 ②：require 查的是「金额」，不是「人」 ----
    function resolve(address to, uint amount) public {
        require(amount <= total / 100, "dispute fee too high");
        payable(to).transfer(amount);
    }

    // ---- 缺陷 ③：使用 tx.origin 判断身份 ----
    function changeArbiter(address newArbiter) public {
        if (tx.origin == arbiter) {
            arbiter = newArbiter;
        }
    }
}
