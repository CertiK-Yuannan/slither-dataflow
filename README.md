# Slither DataFlow Analysis

A collection of data flow analysis tools for Solidity smart contracts built on top of [Slither](https://github.com/crytic/slither).

## Overview

Slither DataFlow extends Slither's capabilities with specialized data flow analysis tools targeting specific security concerns in smart contracts. The project currently includes:

- **Token Flow Analysis**: Identifies variables that influence token amounts in transfer operations
- **Taint Analysis**:  Tracks the flow of potentially tainted data through a contract

## Installation

### Prerequisites

- Python 3.8+
- [Poetry](https://python-poetry.org/docs/#installation)

### Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/slither-dataflow.git
cd slither-dataflow

# Install dependencies
poetry install

# Activate the virtual environment
poetry shell
```

## Usage

### Token Flow Analysis

The token flow analyzer identifies variables that affect token amounts in smart contracts.

```bash
# Basic usage
slither-dataflow token-flow <contract_file.sol> <contract_name> <function_name> [amount_variable]

# Example
poetry run slither-dataflow token-flow tests/contracts/Vault.sol Vault withdraw amount
```

Output:

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

### Taint Analysis (Coming Soon)

Taint analysis will track the flow of potentially tainted data through a contract to identify security risks.

```bash
# Future usage
slither-dataflow taint <contract_file.sol> <contract_name> <entry_point> <taint_source>

# Example
poetry run slither-dataflow taint tests/contracts/Vault.sol Vault deposit amount withdraw amount
```



## Project Structure

```
slither-dataflow/
├── slither_dataflow/         # Main package
│   ├── analyzers/            # Specific analyzer implementations
│   │   ├── token_flow.py     # Token flow analysis
│   │   └── taint.py          # Taint analysis (future)
│   └── utils/                # Utility functions
├── tests/                    # Tests directory
```

## Extending the Framework

New analyzers can be added by:

1. Creating a new analyzer in the `slither_dataflow/analyzers/` directory
2. Implementing the analyzer interface defined in `slither_dataflow/analyzer.py`
3. Registering the analyzer in the CLI module

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
