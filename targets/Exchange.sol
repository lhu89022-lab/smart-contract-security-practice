// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/*
 * ⚠️ 教学靶场 —— 本合约刻意包含安全缺陷，请勿部署到主网。
 *
 * 审计报告：audit-reports/Exchange.md
 *
 * 注意：transferTo() 是一个「误报陷阱」——
 *       它同时在改两个人的账，看起来很像重入，但函数里
 *       没有 .call{value: / .transfer( / .send(，
 *       一分钱都没有真的转出去，所以不可能重入。
 */

contract Exchange {
    address public owner;
    mapping(address => uint) public balances;

    constructor() {
        owner = msg.sender;
    }

    // ---- 干净：只修改调用者自己的账本 ----
    function deposit() public payable {
        balances[msg.sender] = balances[msg.sender] + msg.value;
    }

    // ---- 干净（误报陷阱）：改两个人的账，但没有任何外部调用 ----
    function transferTo(address to, uint amount) public {
        require(amount <= balances[msg.sender], "not enough");

        balances[to] = balances[to] + amount;
        balances[msg.sender] = balances[msg.sender] - amount;
    }

    // ---- 缺陷 ①：先转账、后扣账 → 重入 ----
    function withdraw(uint amount) public {
        require(amount <= balances[msg.sender], "not enough");

        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "failed");

        balances[msg.sender] = balances[msg.sender] - amount;
    }

    // ---- 缺陷 ②：使用 tx.origin 判断身份 ----
    function rescue(address to) public {
        if (tx.origin == owner) {
            payable(to).transfer(address(this).balance);
        }
    }
}
