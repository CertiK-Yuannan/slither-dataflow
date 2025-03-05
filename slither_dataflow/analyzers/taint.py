"""
Taint analyzer for tracking taint propagation through contracts
"""

from typing import Dict, List, Set, Tuple, Optional
import networkx as nx

from slither.analyses.data_dependency.data_dependency import is_dependent
from slither.core.declarations import Contract, Function
# Fix the import error by using correct Expression imports
from slither.core.expressions.expression import Expression 
from slither.core.variables.variable import Variable
from slither.core.variables.state_variable import StateVariable
from slither.core.variables.local_variable import LocalVariable

from slither_dataflow.analyzer import DataFlowAnalyzer
from slither_dataflow.utils.helpers import find_variable_by_name, find_function_by_name, get_expression_variables


class TaintAnalyzer(DataFlowAnalyzer):
    """
    Analyzer for tracking taint propagation in smart contracts
    """

    def analyze(self, contract: Contract, 
                source_function: str, source_variable: str, 
                sink_function: str, sink_variable: str) -> Dict:
        """
        Analyze taint propagation from a source variable to a sink
        
        Args:
            contract: The contract to analyze
            source_function: The function containing the source
            source_variable: The variable to consider as tainted
            sink_function: The function containing the sink
            sink_variable: The variable that should not be tainted
            
        Returns:
            Dict: Analysis results including tainted variables and propagation paths
        """
        # Initialize result structure
        result = {
            "source": {
                "function": source_function,
                "variable": source_variable
            },
            "sink": {
                "function": sink_function,
                "variable": sink_variable
            },
            "tainted_variables": [],
            "taint_path": [],
            "vulnerable": False
        }
        
        # Get functions
        source_func = find_function_by_name(contract, source_function)
        sink_func = find_function_by_name(contract, sink_function)
        
        if not source_func:
            raise ValueError(f"Source function '{source_function}' not found in contract")
        if not sink_func:
            raise ValueError(f"Sink function '{sink_function}' not found in contract")
        
        # Get source and sink variables
        source_var = find_variable_by_name(source_func, source_variable)
        sink_var = find_variable_by_name(sink_func, sink_variable)
        
        if not source_var:
            raise ValueError(f"Source variable '{source_variable}' not found in function '{source_function}'")
        if not sink_var:
            raise ValueError(f"Sink variable '{sink_variable}' not found in function '{sink_function}'")
        
        # Build taint propagation graph
        self.taint_graph = self._build_taint_graph(contract, source_func, source_var)
        
        # Check if sink is tainted and get propagation path
        sink_tainted, taint_path = self._check_sink_tainted(
            self.taint_graph, source_var, sink_var, sink_func)
            
        # Fill in result data
        result["vulnerable"] = sink_tainted
        result["tainted_variables"] = self._get_tainted_variables(self.taint_graph, source_var)
        
        if sink_tainted:
            # Convert path to readable format
            result["taint_path"] = self._format_taint_path(taint_path)
        
        return result
    
    def _build_taint_graph(self, contract: Contract, source_func: Function, source_var: Variable) -> nx.DiGraph:
        """
        Build a directed graph representing taint propagation
        
        Args:
            contract: The contract to analyze
            source_func: The function containing the source
            source_var: The initial tainted variable
            
        Returns:
            nx.DiGraph: A graph where nodes are variables and edges represent taint propagation
        """
        # Create directed graph
        G = nx.DiGraph()
        
        # Add source variable as first node
        G.add_node(self._node_key(source_var, source_func), 
                   var=source_var, 
                   function=source_func, 
                   var_type=self._get_var_type(source_var))
        
        # Initial set of variables to process
        to_process = [(source_var, source_func)]
        processed = set()
        
        # Process direct taint propagation in the same function
        while to_process:
            var, func = to_process.pop(0)
            if (var, func) in processed:
                continue
                
            processed.add((var, func))
            current_key = self._node_key(var, func)
            
            # Process taint propagation within the function
            self._process_function_taint(G, contract, func, var, current_key, to_process, processed)
            
            # Process taint propagation through state variables to other functions
            if isinstance(var, StateVariable):
                self._process_state_var_taint(G, contract, func, var, current_key, to_process, processed)
            
            # If this is a parameter, check for cross-function calls
            if var in func.parameters:
                self._process_parameter_taint(G, contract, func, var, current_key, to_process, processed)
        
        return G
    
    def _process_function_taint(self, G, contract, func, var, current_key, 
                                to_process, processed):
        """Process taint propagation within a single function"""
        for node in func.nodes:
            # Check expressions for taint propagation
            if hasattr(node, 'expression') and node.expression:
                expr_vars = get_expression_variables(node.expression)
                
                # Check if var is used in this expression
                if var in expr_vars:
                    # This expression uses the tainted variable
                    # Find variables that are tainted by this expression
                    for written_var in node.local_variables_written + node.state_variables_written:
                        if written_var not in expr_vars:
                            # This variable is written to in an expression that uses the tainted variable
                            next_key = self._node_key(written_var, func)
                            
                            # Add to graph
                            G.add_node(next_key, 
                                      var=written_var, 
                                      function=func, 
                                      var_type=self._get_var_type(written_var))
                            G.add_edge(current_key, next_key, 
                                      expression=str(node.expression),
                                      line=node.source_mapping.lines[0] if node.source_mapping.lines else None)
                            
                            # Add to processing queue
                            if (written_var, func) not in processed:
                                to_process.append((written_var, func))
            
            # Direct data dependency
            for written_var in node.local_variables_written + node.state_variables_written:
                if is_dependent(written_var, var, func):
                    next_key = self._node_key(written_var, func)
                    
                    # Add to graph
                    G.add_node(next_key, 
                              var=written_var, 
                              function=func, 
                              var_type=self._get_var_type(written_var))
                    
                    expr_str = str(node.expression) if hasattr(node, 'expression') and node.expression else "unknown expression"
                    G.add_edge(current_key, next_key, 
                              expression=expr_str,
                              line=node.source_mapping.lines[0] if node.source_mapping.lines else None)
                    
                    # Add to processing queue
                    if (written_var, func) not in processed:
                        to_process.append((written_var, func))
    
    def _process_state_var_taint(self, G, contract, func, var, current_key, 
                                to_process, processed):
        """Process taint propagation through state variables to other functions"""
        for other_func in contract.functions:
            if other_func != func:
                # For each node in the other function
                for node in other_func.nodes:
                    # Check if it reads the state variable
                    if var in node.state_variables_read:
                        # This function reads our tainted state variable
                        # The variable is tainted in this function too
                        next_key = self._node_key(var, other_func)
                        
                        # Add to graph
                        G.add_node(next_key, 
                                  var=var, 
                                  function=other_func, 
                                  var_type=self._get_var_type(var))
                        G.add_edge(current_key, next_key, 
                                  expression=f"State variable read in {other_func.name}",
                                  line=None)
                        
                        # Add to processing queue
                        if (var, other_func) not in processed:
                            to_process.append((var, other_func))
    
    def _process_parameter_taint(self, G, contract, func, var, current_key, 
                                to_process, processed):
        """Process taint propagation through function parameters"""
        param_idx = func.parameters.index(var)
        
        # Find calls to this function
        for other_func in contract.functions:
            for node in other_func.nodes:
                # Check for calls to our function
                for internal_call in node.internal_calls:
                    if isinstance(internal_call, Function) and internal_call == func:
                        # A call to our function with the tainted parameter
                        if hasattr(node, 'expression') and node.expression:
                            expr_str = str(node.expression)
                            if hasattr(node.expression, 'arguments') and param_idx < len(node.expression.arguments):
                                arg = node.expression.arguments[param_idx]
                                arg_vars = get_expression_variables(arg)
                                
                                # Taint propagates from the argument to our parameter
                                for arg_var in arg_vars:
                                    arg_key = self._node_key(arg_var, other_func)
                                    
                                    # Add to graph (reverse direction as taint flows from arg to param)
                                    G.add_node(arg_key, 
                                              var=arg_var, 
                                              function=other_func, 
                                              var_type=self._get_var_type(arg_var))
                                    G.add_edge(arg_key, current_key, 
                                              expression=f"Parameter {var.name} in call to {func.name}",
                                              line=node.source_mapping.lines[0] if node.source_mapping.lines else None)
                                    
                                    # Add to processing queue
                                    if (arg_var, other_func) not in processed:
                                        to_process.append((arg_var, other_func))
    
    def _check_sink_tainted(self, taint_graph: nx.DiGraph, source_var: Variable, 
                          sink_var: Variable, sink_func: Function) -> Tuple[bool, List]:
        """
        Check if the sink is tainted by the source
        
        Args:
            taint_graph: The taint propagation graph
            source_var: The source variable
            sink_var: The sink variable
            sink_func: The function containing the sink
            
        Returns:
            Tuple[bool, List]: Whether the sink is tainted and the propagation path
        """
        source_key = self._node_key(source_var, None)  # Function is irrelevant for source key
        sink_key = self._node_key(sink_var, sink_func)
        
        # Check if sink is in the graph
        if sink_key not in taint_graph:
            return False, []
        
        # Check if there is a path from source to sink
        try:
            path = nx.shortest_path(taint_graph, source_key, sink_key)
            return True, path
        except nx.NetworkXNoPath:
            return False, []
    
    def _get_tainted_variables(self, taint_graph: nx.DiGraph, source_var: Variable) -> List[Dict]:
        """
        Get all variables tainted by the source
        
        Args:
            taint_graph: The taint propagation graph
            source_var: The source variable
            
        Returns:
            List[Dict]: List of tainted variables with metadata
        """
        tainted_vars = []
        
        for node in taint_graph.nodes:
            var = taint_graph.nodes[node].get('var')
            func = taint_graph.nodes[node].get('function')
            var_type = taint_graph.nodes[node].get('var_type')
            
            if var and func:
                tainted_vars.append({
                    "name": var.name,
                    "function": func.name,
                    "type": var_type
                })
        
        return tainted_vars
    
    def _format_taint_path(self, path: List) -> List[Dict]:
        """
        Format the taint path into a readable format
        
        Args:
            path: List of node keys in the taint graph
            
        Returns:
            List[Dict]: Formatted taint path
        """
        formatted_path = []
        
        for i in range(len(path) - 1):
            source_node = path[i]
            target_node = path[i + 1]
            
            # Get edge data
            edge_data = self.taint_graph.get_edge_data(source_node, target_node)
            expression = edge_data.get('expression', 'unknown expression')
            line = edge_data.get('line')
            
            # Get source and target variable info
            source_var = self.taint_graph.nodes[source_node].get('var')
            source_func = self.taint_graph.nodes[source_node].get('function')
            target_var = self.taint_graph.nodes[target_node].get('var')
            target_func = self.taint_graph.nodes[target_node].get('function')
            
            # Create a step in the path
            path_step = {
                "from": {
                    "variable": source_var.name if source_var else "unknown",
                    "function": source_func.name if source_func else "unknown"
                },
                "to": {
                    "variable": target_var.name if target_var else "unknown",
                    "function": target_func.name if target_func else "unknown"
                },
                "expression": expression,
                "line": line
            }
            
            formatted_path.append(path_step)
        
        return formatted_path
    
    def _node_key(self, var: Variable, func: Optional[Function]) -> str:
        """
        Create a unique key for a graph node
        
        Args:
            var: The variable
            func: The function containing the variable (can be None for global scope)
            
        Returns:
            str: A unique key for the variable in the function
        """
        func_name = func.name if func else "global"
        return f"{var.name}@{func_name}"
    
    def _get_var_type(self, var: Variable) -> str:
        """Get the type of a variable (state, local, parameter)"""
        if isinstance(var, StateVariable):
            return "state"
        elif isinstance(var, LocalVariable):
            if hasattr(var, 'function') and var in var.function.parameters:
                return "parameter"
            return "local"
        else:
            return "unknown"
    
    def print_results(self, results: Dict) -> None:
        """
        Print taint analysis results in a readable format
        
        Args:
            results: The analysis results to print
        """
        print("\nTAINT ANALYSIS RESULTS")
        print(f"Source: {results['source']['variable']} in function {results['source']['function']}")
        print(f"Sink: {results['sink']['variable']} in function {results['sink']['function']}")
        print(f"Vulnerability Detected: {'Yes' if results['vulnerable'] else 'No'}")
        
        if results["vulnerable"]:
            print("\nTaint Propagation Path:")
            for i, step in enumerate(results["taint_path"]):
                print(f"  {i+1}. {step['from']['variable']} ({step['from']['function']}) → ", end="")
                print(f"{step['to']['variable']} ({step['to']['function']})")
                print(f"     Expression: {step['expression']}")
                if step['line']:
                    print(f"     Line: {step['line']}")
        
        print("\nTainted Variables:")
        for var in results["tainted_variables"]:
            print(f"  - {var['name']} ({var['type']}) in function {var['function']}")