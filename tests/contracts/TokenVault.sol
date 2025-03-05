// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TokenVault {
    // The critical balance variable we want to track
    mapping(address => uint256) public balances;
    
    address public owner;
    uint256 public totalSupply;
    uint256 public feePercentage;
    bool public paused;
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }
    
    modifier whenNotPaused() {
        require(!paused, "Contract is paused");
        _;
    }
    
    constructor(uint256 initialSupply) {
        owner = msg.sender;
        totalSupply = initialSupply;
        balances[msg.sender] = initialSupply;
        feePercentage = 1; // 1% fee
    }
    
    function deposit() external payable whenNotPaused {
        // Calculate tokens based on ETH sent
        uint256 tokens = msg.value * 100; // 1 ETH = 100 tokens
        balances[msg.sender] += tokens;
        totalSupply += tokens;
    }
    
    function transfer(address to, uint256 amount) external whenNotPaused {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // Calculate fee
        uint256 fee = (amount * feePercentage) / 100;
        uint256 transferAmount = amount - fee;
        
        // Update balances
        balances[msg.sender] -= amount;
        balances[to] += transferAmount;
        balances[owner] += fee;
    }
    
    function withdraw(uint256 amount) external whenNotPaused {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        balances[msg.sender] -= amount;
        totalSupply -= amount;
        
        // Send ETH equivalent
        uint256 ethAmount = amount / 100;
        payable(msg.sender).transfer(ethAmount);
    }
    
    function setFeePercentage(uint256 newFeePercentage) external onlyOwner {
        require(newFeePercentage <= 5, "Fee too high");
        feePercentage = newFeePercentage;
    }
    
    function setPaused(bool _paused) external onlyOwner {
        paused = _paused;
    }
    
    function adminAdjustBalance(address user, uint256 newBalance) external onlyOwner {
        balances[user] = newBalance;
    }
    
    function batchAirdrop(address[] calldata recipients, uint256 amount) external onlyOwner {
        for (uint i = 0; i < recipients.length; i++) {
            balances[recipients[i]] += amount;
        }
        totalSupply += amount * recipients.length;
    }
}