#!/usr/bin/env python3

from slither import Slither
from slither.analyses.data_dependency.data_dependency import is_dependent
from slither.core.declarations import Function, Contract
from slither.core.variables.state_variable import StateVariable
from slither.core.variables.local_variable import LocalVariable
from slither.core.expressions import Identifier

import sys
import os
from typing import Dict, Optional, List


class TokenAmountAnalyzer:
    """
    A simplified tool for analyzing variables that affect token amounts in smart contracts
    """
    
    def __init__(self, contract_file: str):
        """Initialize the analyzer with a contract file"""
        try:
            self.slither = Slither(contract_file)
            print(f"Loaded {contract_file}")
        except Exception as e:
            print(f"Error loading contract: {str(e)}")
            sys.exit(1)
    
    def get_contract(self, contract_name: str) -> Optional[Contract]:
        """Get a contract by name"""
        contracts = self.slither.get_contract_from_name(contract_name)
        return contracts[0] if contracts else None
    
    def analyze_amount_relevant_variables(self, contract: Contract, function_name: str, amount_var: str = "amount") -> Dict:
        """
        Analyze variables relevant to the specified amount variable
        """
        result = {
            "function": function_name,
            "target_variable": amount_var,
            "inputs": [],
            "state_variables": [],
            "variable_modifications": {}
        }
        
        # Find the function
        target_function = None
        for function in contract.functions:
            if function.name == function_name:
                target_function = function
                break
        
        if not target_function:
            print(f"Error: Function '{function_name}' not found in contract")
            return result
        
        # Find input parameters affecting amount
        for param in target_function.parameters:
            if param.name == amount_var or param.name == f"_{amount_var}":
                result["inputs"].append({
                    "name": param.name,
                    "type": str(param.type)
                })
        
        # Find local variables derived from parameters or related to amount
        for node in target_function.nodes:
            for local_var in node.local_variables_written:
                if local_var.name == amount_var:
                    # Found a local variable for the amount
                    if hasattr(node, 'expression'):
                        expr = str(node.expression)
                        if "=" in expr and local_var.name in expr.split("=")[0]:
                            right_side = expr.split("=")[1].strip()
                            
                            if not any(i["name"] == local_var.name for i in result["inputs"]):
                                result["inputs"].append({
                                    "name": local_var.name,
                                    "type": str(local_var.type),
                                    "value": right_side
                                })
        
        # Find the amount variable object (param or local)
        amount_var_obj = None
        
        # Try to find the amount variable
        for param in target_function.parameters:
            if param.name == amount_var or param.name == f"_{amount_var}":
                amount_var_obj = param
                break
        
        if not amount_var_obj:
            for node in target_function.nodes:
                for local_var in node.local_variables_written:
                    if local_var.name == amount_var:
                        amount_var_obj = local_var
                        break
                if amount_var_obj:
                    break
        
        # Trace state variables connected to amount
        if amount_var_obj:
            for node in target_function.nodes:
                for state_var in node.state_variables_read + node.state_variables_written:
                    # Check if state variable is related to amount via data dependency
                    if (is_dependent(amount_var_obj, state_var, target_function) and 
                        state_var.name not in [v["name"] for v in result["state_variables"]]):
                        
                        result["state_variables"].append({
                            "name": state_var.name,
                            "type": str(state_var.type)
                        })
                
                # Also check expression to find state variables that might be missed by is_dependent
                if hasattr(node, 'expression') and node.expression:
                    expr_str = str(node.expression)
                    if amount_var in expr_str:
                        for state_var in contract.state_variables:
                            if state_var.name in expr_str and state_var.name not in [v["name"] for v in result["state_variables"]]:
                                result["state_variables"].append({
                                    "name": state_var.name,
                                    "type": str(state_var.type)
                                })
        
        # Special case for balances mapping (common in token contracts)
        balances_found = False
        for var in result["state_variables"]:
            if var["name"] == "balances":
                balances_found = True
                break
        
        if not balances_found:
            for state_var in contract.state_variables:
                if state_var.name == "balances":
                    result["state_variables"].append({
                        "name": "balances",
                        "type": str(state_var.type)
                    })
                    break
        
        # Find all modifications to these state variables
        for state_var in result["state_variables"]:
            var_name = state_var["name"]
            result["variable_modifications"][var_name] = []
            
            # Check in the target function
            for node in target_function.nodes:
                for var in node.state_variables_written:
                    if var.name == var_name:
                        if hasattr(node, 'expression'):
                            result["variable_modifications"][var_name].append({
                                "function": function_name,
                                "expression": str(node.expression)
                            })
            
            # Check across other functions
            for function in contract.functions:
                if function.name == function_name:
                    continue  # Skip target function as we already processed it
                
                for node in function.nodes:
                    for var in node.state_variables_written:
                        if var.name == var_name:
                            if hasattr(node, 'expression'):
                                result["variable_modifications"][var_name].append({
                                    "function": function.name,
                                    "expression": str(node.expression)
                                })
        
        return result
    
    def trace_inputs_across_functions(self, contract: Contract, analysis_result: Dict) -> Dict:
        """
        Trace back inputs that affect state variables across functions
        """
        result = {
            "function": analysis_result["function"],
            "state_variable_inputs": {}
        }
        
        # For each state variable, find functions that modify it and their inputs
        for state_var in analysis_result["state_variables"]:
            var_name = state_var["name"]
            result["state_variable_inputs"][var_name] = []
            
            # Check each function that modifies this state variable
            for modification in analysis_result["variable_modifications"].get(var_name, []):
                modifying_function_name = modification["function"]
                
                # Skip the target function
                if modifying_function_name == analysis_result["function"]:
                    continue
                
                # Find the function
                modifying_function = None
                for function in contract.functions:
                    if function.name == modifying_function_name:
                        modifying_function = function
                        break
                
                if modifying_function:
                    # Check inputs of this function
                    input_params = []
                    for param in modifying_function.parameters:
                        if str(param.name) in str(modification["expression"]):
                            input_params.append({
                                "name": param.name,
                                "type": str(param.type)
                            })
                    
                    if input_params:
                        result["state_variable_inputs"][var_name].append({
                            "function": modifying_function_name,
                            "expression": modification["expression"],
                            "parameters": input_params
                        })
        
        return result
    
    def print_analysis_results(self, analysis_result: Dict, cross_function_inputs: Dict) -> None:
        """
        Print analysis results in a simple format
        """
        print("\nAMOUNT VARIABLE ANALYSIS")
        print("Function:", analysis_result["function"])
        print("Target Variable:", analysis_result["target_variable"])
        
        # 1. Print input parameters
        print("\n1. Input parameters affecting amount:")
        if analysis_result["inputs"]:
            for input_var in analysis_result["inputs"]:
                if "value" in input_var:
                    print(f"  - {input_var['name']} = {input_var['value']}")
                else:
                    print(f"  - {input_var['name']}")
        else:
            print("  None found")
        
        # 2. Print state variables and relevant code
        print("\n2. State variables affecting amount:")
        if analysis_result["state_variables"]:
            for var in analysis_result["state_variables"]:
                print(f"  - {var['name']}")
                
                # Show relevant code in the target function
                relevant_code = [
                    mod["expression"] for mod in analysis_result["variable_modifications"].get(var["name"], [])
                    if mod["function"] == analysis_result["function"]
                ]
                
                if relevant_code:
                    print("    Relevant code in current function:")
                    for code in relevant_code:
                        print(f"      * {code}")
        else:
            print("  None found")
        
        # 3. Trace back to inputs in other functions
        print("\n3. Inputs in other functions affecting these state variables:")
        has_inputs = False
        
        for var_name, inputs in cross_function_inputs["state_variable_inputs"].items():
            if inputs:
                has_inputs = True
                print(f"  State variable: {var_name}")
                
                for input_info in inputs:
                    print(f"    Modified in function '{input_info['function']}':")
                    print(f"      Expression: {input_info['expression']}")
                    print("      Parameters:")
                    for param in input_info["parameters"]:
                        print(f"        - {param['name']}")
        
        if not has_inputs:
            print("  None found")


def main():
    """Main entry point for the token amount analyzer"""
    if len(sys.argv) < 4:
        print("Usage: python amount_analyzer.py <contract_file.sol> <contract_name> <function_name> [amount_variable]")
        print("Example: python amount_analyzer.py Vault.sol Vault withdraw amount")
        sys.exit(1)
    
    contract_file = sys.argv[1]
    contract_name = sys.argv[2]
    function_name = sys.argv[3]
    amount_var = sys.argv[4] if len(sys.argv) > 4 else "amount"
    
    if not os.path.isfile(contract_file):
        print(f"Error: File {contract_file} does not exist")
        sys.exit(1)
    
    analyzer = TokenAmountAnalyzer(contract_file)
    contract = analyzer.get_contract(contract_name)
    
    if not contract:
        print(f"Error: Contract '{contract_name}' not found in {contract_file}")
        sys.exit(1)
    
    # Run the analysis
    analysis_result = analyzer.analyze_amount_relevant_variables(contract, function_name, amount_var)
    cross_function_inputs = analyzer.trace_inputs_across_functions(contract, analysis_result)
    
    # Print results
    analyzer.print_analysis_results(analysis_result, cross_function_inputs)


if __name__ == "__main__":
    main()