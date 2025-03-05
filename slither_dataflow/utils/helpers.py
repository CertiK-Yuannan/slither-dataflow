"""
Helper functions for data flow analysis
"""

from typing import Optional, Union, List, Set

from slither.core.declarations import Function, Contract
# Fix import for Expression
from slither.core.expressions.expression import Expression
from slither.core.expressions.identifier import Identifier
from slither.core.variables.local_variable import LocalVariable
from slither.core.variables.state_variable import StateVariable
from slither.core.variables.variable import Variable


def find_variable_by_name(
    function: Function, var_name: str
) -> Optional[Union[LocalVariable, StateVariable]]:
    """
    Find a variable by name in a function's scope
    
    Args:
        function: The function to search in
        var_name: The name of the variable to find
        
    Returns:
        The variable if found, None otherwise
    """
    # Check parameters
    for param in function.parameters:
        if param.name == var_name or param.name == f"_{var_name}":
            return param
    
    # Check local variables
    for node in function.nodes:
        for local_var in node.local_variables_written + node.local_variables_read:
            if local_var.name == var_name:
                return local_var
    
    # Check state variables accessed in the function
    for node in function.nodes:
        for state_var in node.state_variables_read + node.state_variables_written:
            if state_var.name == var_name:
                return state_var
    
    return None


def find_function_by_name(contract: Contract, function_name: str) -> Optional[Function]:
    """
    Find a function by name in a contract
    
    Args:
        contract: The contract to search in
        function_name: The name of the function to find
        
    Returns:
        The function if found, None otherwise
    """
    for function in contract.functions:
        if function.name == function_name:
            return function
    return None


def get_expression_variables(expression: Expression) -> Set[Variable]:
    """
    Extract all variables used in an expression
    
    Args:
        expression: The expression to analyze
        
    Returns:
        Set of variables used in the expression
    """
    result = set()
    
    # Process based on expression type
    if isinstance(expression, Identifier) and isinstance(expression.value, Variable):
        result.add(expression.value)
    
    # Process members and sub-expressions
    for member in [m for m in dir(expression) if not m.startswith('_')]:
        try:
            member_value = getattr(expression, member)
            
            # Check if it's a variable
            if isinstance(member_value, Variable):
                result.add(member_value)
            
            # Check if it's another expression
            elif isinstance(member_value, Expression):
                result.update(get_expression_variables(member_value))
            
            # Check if it's a list of expressions
            elif isinstance(member_value, list):
                for item in member_value:
                    if isinstance(item, Expression):
                        result.update(get_expression_variables(item))
        except (AttributeError, TypeError):
            # Skip any attributes that can't be accessed
            continue
    
    return result


def is_token_operation(expression: Expression) -> bool:
    """
    Check if an expression is related to token operations
    
    Args:
        expression: The expression to check
        
    Returns:
        True if the expression is related to token operations, False otherwise
    """
    expression_str = str(expression).lower()
    token_keywords = ['transfer', 'transferfrom', 'approve', 'balanceof', 'token']
    
    return any(keyword in expression_str for keyword in token_keywords)