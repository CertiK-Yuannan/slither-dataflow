<<<<<<< HEAD
# slither-dataflow
## Token Flow Analyzer

A static analysis tool to trace token amount flows in Solidity smart contracts using Slither.

### Overview

Token Flow Analyzer identifies variables and code that influence token amounts in Solidity smart contracts. It analyzes:

1. Input parameters that affect token amounts
2. State variables that are read or modified in relation to token amounts 
3. Cross-function interactions that affect these state variables

This tool is useful for:
- Security auditing of DeFi contracts
- Understanding token flow in complex contracts
- Identifying potential vulnerabilities in token handling

### Installation

#### Prerequisites

- Python 3.8 or higher
- [Poetry](https://python-poetry.org/docs/#installation) for dependency management

#### Setup

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/slither-dataflow.git
   cd slither-dataflow
   ```

2. Install dependencies using Poetry:
   ```
   poetry install
   ```

This will install all required dependencies, including Slither.

### Usage

Run the analyzer on a Solidity contract using:

```
poetry run python token_flow_analysis.py <contract_file.sol> <contract_name> <function_name> [amount_variable]
```

#### Parameters:

- `contract_file.sol`: Path to the Solidity file
- `contract_name`: Name of the contract to analyze
- `function_name`: Name of the function to analyze for token flow
- `amount_variable` (optional): Name of the variable to track (defaults to "amount")

#### Example:

```
poetry run python token_flow_analysis.py Vault.sol Vault withdraw amount
```

This will analyze the `withdraw` function in the `Vault` contract, tracing all variables that affect the `amount` parameter.

### Example Output

```
AMOUNT VARIABLE ANALYSIS
Function: withdraw
Target Variable: amount

1. Input parameters affecting amount:
  - _amount
  - amount = _amount

2. State variables affecting amount:
  - balances
    Relevant code in current function:
      * require(balances[msg.sender] >= amount, "Insufficient balance")
      * balances[msg.sender] -= amount

3. Inputs in other functions affecting these state variables:
  State variable: balances
    Modified in function 'deposit':
      Expression: balances[msg.sender] += amount
      Parameters:
        - amount
    Modified in function 'changeBalance':
      Expression: balances[account] = amount
      Parameters:
        - account
        - amount
    Modified in function 'addBalance':
      Expression: balances[account] += amount
      Parameters:
        - account
        - amount
```

## Features

- **Input Parameter Tracking**: Identifies function parameters and local variables that influence token amounts
- **State Variable Analysis**: Determines which state variables are read or modified in relation to token amounts
- **Cross-Function Flow**: Traces how state variables are modified by other functions
- **Special Handling for Common Patterns**: Automatically detects common token patterns like balance mappings

## Limitations

- The analysis is static and may not capture all dynamic behaviors
- Complex inheritance patterns might not be fully analyzed
- External contract calls are not followed beyond the analyzed contract

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

[MIT License](LICENSE)
>>>>>>> 10c0245 (initial commit)
