// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

interface IERC20 {
    function transfer(address recipient, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract Vault {
    IERC20 public token;
    mapping(address => uint256) public balances;

    constructor(address _token) {
        token = IERC20(_token);
    }

    function deposit(uint256 amount) external {
        token.transfer(address(this), amount);
        balances[msg.sender] += amount;
    }

    function changeBalance(address account, uint256 amount) external {
        balances[account] = amount;
    }

    function addBalance(address account, uint256 amount) external {
        balances[account] += amount;
    }

    function withdraw(uint256 _amount) external {
        uint256 amount = _amount;
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
    }
}