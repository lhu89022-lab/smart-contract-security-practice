// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/*
 * ⚠️ 教学靶场 —— 本合约刻意包含安全缺陷，请勿部署到主网。
 *
 * 审计报告：audit-reports/TipJar.md
 */

contract TipJar {
    address public owner;
    mapping(address => uint) public tips;

    constructor() {
        owner = msg.sender;
    }

    // ---- 干净：只修改调用者自己的账本 ----
    function tip() public payable {
        tips[msg.sender] = tips[msg.sender] + msg.value;
    }

    // ---- 缺陷 ①：先转账、后扣账 → 重入 ----
    function cashOut() public {
        uint amount = tips[msg.sender];
        require(amount > 0, "nothing to cash out");

        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");

        tips[msg.sender] = 0;
    }

    // ---- 缺陷 ②：tx.origin 钓鱼 ／ 缺陷 ③：提取合约全部余额 ----
    function withdrawFees() public {
        require(tx.origin == owner, "not owner");
        payable(msg.sender).transfer(address(this).balance);
    }
}
