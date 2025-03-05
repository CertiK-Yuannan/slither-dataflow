"""
Token flow analyzer for tracking variables that affect token amounts
"""

from typing import Dict, List, Set

from slither.analyses.data_dependency.data_dependency import is_dependent
from slither.core.declarations import Contract, Function

from slither_dataflow.analyzer import DataFlowAnalyzer


class TokenFlowAnalyzer(DataFlowAnalyzer):
    """
    Analyzer for tracking variables that influence token amounts in smart contracts
    """

    def analyze(self, contract: Contract, function_name: str, amount_var: str = "amount") -> Dict:
        """
        Analyze variables relevant to the specified token amount
        
        Args:
            contract: The contract to analyze
            function_name: The function containing the token operation
            amount_var: The variable representing the token amount
            
        Returns:
            Dict: Analysis results including affected variables and their relationships
        """
        # Main result structure
        result = {
            "function": function_name,
            "target_variable": amount_var,
            "inputs": [],
            "state_variables": [],
            "variable_modifications": {},
            "cross_function_inputs": {}
        }
        
        # Find the target function
        target_function = None
        for function in contract.functions:
            if function.name == function_name:
                target_function = function
                break
        
        if not target_function:
            raise ValueError(f"Function '{function_name}' not found in contract")
        
        # 1. Find input parameters affecting amount
        self._find_input_parameters(target_function, amount_var, result)
        
        # 2. Find state variables affecting amount
        self._find_state_variables(contract, target_function, amount_var, result)
        
        # 3. Find modifications across all functions
        self._find_variable_modifications(contract, function_name, result)
        
        # 4. Trace inputs across functions
        result["cross_function_inputs"] = self._trace_cross_function_inputs(contract, result)
        
        return result
    
    def _find_input_parameters(self, function: Function, amount_var: str, result: Dict) -> None:
        """Find input parameters affecting the amount variable"""
        # First, check if the amount variable is itself a parameter
        for param in function.parameters:
            if param.name == amount_var or param.name == f"_{amount_var}":
                result["inputs"].append({
                    "name": param.name,
                    "type": str(param.type)
                })
        
        # Trace both forward and backward dependencies
        # 1. Forward: Local variables derived from parameters
        # 2. Backward: Parameters that affect the amount variable
        
        # Find all parameter and local variables 
        all_params = {param.name: param for param in function.parameters}
        
        # Find the target variable assignments and usages
        target_assignments = []
        target_usages = []
        
        for node in function.nodes:
            if hasattr(node, 'expression') and node.expression:
                expr_str = str(node.expression)
                
                # Forward: Look for target being assigned
                if "=" in expr_str and amount_var in expr_str.split("=")[0].strip():
                    right_side = expr_str.split("=")[1].strip()
                    target_assignments.append((node, right_side))
                    
                    # Add the local variable if it's our target
                    for local_var in node.local_variables_written:
                        if local_var.name == amount_var:
                            if not any(i["name"] == local_var.name for i in result["inputs"]):
                                result["inputs"].append({
                                    "name": local_var.name,
                                    "type": str(local_var.type),
                                    "value": right_side
                                })
                
                # Backward: Look for parameters used in computing the target
                if amount_var in expr_str:
                    target_usages.append(node)
        
        # For each assignment to the target, look for parameters on the right side
        for node, right_side in target_assignments:
            for param_name, param in all_params.items():
                if param_name in right_side and not any(i["name"] == param_name for i in result["inputs"]):
                    result["inputs"].append({
                        "name": param_name,
                        "type": str(param.type)
                    })
        
        # Look for other variables assigned from our target (backward tracing)
        for node in function.nodes:
            if hasattr(node, 'expression') and node.expression:
                expr_str = str(node.expression)
                
                # If this expression computes a value using our target variable
                if "=" in expr_str and amount_var in expr_str.split("=")[1]:
                    left_side = expr_str.split("=")[0].strip()
                    
                    # Find the local variable being assigned
                    for local_var in node.local_variables_written:
                        if local_var.name in left_side:
                            # We found a variable derived from our target
                            # Now we need to find parameters that affect this variable
                            for param_name, param in all_params.items():
                                # If this parameter directly affects our target
                                # (Check all nodes for expressions using this parameter to compute the local variable)
                                for check_node in function.nodes:
                                    if (hasattr(check_node, 'expression') and 
                                        param_name in str(check_node.expression) and 
                                        local_var.name in str(check_node.expression)):
                                        
                                        if not any(i["name"] == param_name for i in result["inputs"]):
                                            result["inputs"].append({
                                                "name": param_name,
                                                "type": str(param.type)
                                            })
                            
                            # Add the derived variable to our inputs
                            if not any(i["name"] == local_var.name for i in result["inputs"]):
                                result["inputs"].append({
                                    "name": local_var.name,
                                    "type": str(local_var.type),
                                    "value": f"derived from {amount_var}"
                                })
    
    def _find_state_variables(self, contract: Contract, function: Function, amount_var: str, result: Dict) -> None:
        """Find state variables affecting the amount variable"""
        # Find the amount variable object (param or local)
        amount_var_obj = None
        
        # Try to find the amount variable in parameters
        for param in function.parameters:
            if param.name == amount_var or param.name == f"_{amount_var}":
                amount_var_obj = param
                break
        
        # If not found in parameters, look in local variables
        if not amount_var_obj:
            for node in function.nodes:
                for local_var in node.local_variables_written:
                    if local_var.name == amount_var:
                        amount_var_obj = local_var
                        break
                if amount_var_obj:
                    break
        
        # If we found the amount variable, trace dependent state variables
        if amount_var_obj:
            for node in function.nodes:
                # Check state variables via data dependency
                for state_var in node.state_variables_read + node.state_variables_written:
                    if (is_dependent(amount_var_obj, state_var, function) and 
                        state_var.name not in [v["name"] for v in result["state_variables"]]):
                        result["state_variables"].append({
                            "name": state_var.name,
                            "type": str(state_var.type)
                        })
                
                # Also check expressions directly
                if hasattr(node, 'expression') and node.expression:
                    expr_str = str(node.expression)
                    if amount_var in expr_str:
                        for state_var in contract.state_variables:
                            if (state_var.name in expr_str and 
                                state_var.name not in [v["name"] for v in result["state_variables"]]):
                                result["state_variables"].append({
                                    "name": state_var.name,
                                    "type": str(state_var.type)
                                })
        
        # Special case for balances mapping
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
    
    def _find_variable_modifications(self, contract: Contract, function_name: str, result: Dict) -> None:
        """Find all modifications to relevant state variables"""
        for state_var in result["state_variables"]:
            var_name = state_var["name"]
            result["variable_modifications"][var_name] = []
            
            # Check all functions in the contract
            for function in contract.functions:
                for node in function.nodes:
                    for var in node.state_variables_written:
                        if var.name == var_name:
                            if hasattr(node, 'expression'):
                                result["variable_modifications"][var_name].append({
                                    "function": function.name,
                                    "expression": str(node.expression)
                                })
    
    def _trace_cross_function_inputs(self, contract: Contract, analysis_result: Dict) -> Dict:
        """Trace inputs that affect state variables across functions"""
        result = {}
        
        # For each state variable, find other functions that modify it and their inputs
        for state_var in analysis_result["state_variables"]:
            var_name = state_var["name"]
            result[var_name] = []
            
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
                        result[var_name].append({
                            "function": modifying_function_name,
                            "expression": modification["expression"],
                            "parameters": input_params
                        })
        
        return result
    
    def print_results(self, results: Dict) -> None:
        """
        Print token flow analysis results in a readable format
        
        Args:
            results: The analysis results to print
        """
        print("\nAMOUNT VARIABLE ANALYSIS")
        print("Function:", results["function"])
        print("Target Variable:", results["target_variable"])
        
        # 1. Print input parameters
        print("\n1. Input parameters affecting amount:")
        if results["inputs"]:
            for input_var in results["inputs"]:
                if "value" in input_var:
                    print(f"  - {input_var['name']} = {input_var['value']}")
                else:
                    print(f"  - {input_var['name']}")
        else:
            print("  None found")
        
        # 2. Print state variables and relevant code
        print("\n2. State variables affecting amount:")
        if results["state_variables"]:
            for var in results["state_variables"]:
                print(f"  - {var['name']}")
                
                # Show relevant code in the target function
                relevant_code = [
                    mod["expression"] for mod in results["variable_modifications"].get(var["name"], [])
                    if mod["function"] == results["function"]
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
        
        for var_name, inputs in results["cross_function_inputs"].items():
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