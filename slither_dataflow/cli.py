"""
Command line interface for slither-dataflow
"""

import argparse
import os
import sys
from typing import List, Optional

from slither_dataflow.analyzers.token_flow import TokenFlowAnalyzer
from slither_dataflow.analyzers.taint import TaintAnalyzer


def parse_args(args: Optional[List[str]] = None) -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Slither DataFlow Analysis - Analyze data flow in Solidity smart contracts"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Analysis command")
    subparsers.required = True
    
    # Token Flow command
    token_flow_parser = subparsers.add_parser(
        "token-flow", help="Analyze token flow in a smart contract"
    )
    token_flow_parser.add_argument("contract_file", help="Solidity contract file")
    token_flow_parser.add_argument("contract_name", help="Contract name within the file")
    token_flow_parser.add_argument("function_name", help="Function to analyze")
    token_flow_parser.add_argument(
        "amount_var", nargs="?", default="amount", help="Variable representing token amount (default: amount)"
    )
    
    # Taint Analysis command
    taint_parser = subparsers.add_parser(
        "taint", help="Perform taint analysis between source and sink"
    )
    taint_parser.add_argument("contract_file", help="Solidity contract file")
    taint_parser.add_argument("contract_name", help="Contract name within the file")
    taint_parser.add_argument("source_function", help="Function containing the taint source")
    taint_parser.add_argument("source_variable", help="Variable to consider as taint source")
    taint_parser.add_argument("sink_function", help="Function containing the taint sink")
    taint_parser.add_argument("sink_variable", help="Variable that should not be tainted")
    
    return parser.parse_args(args)


def main(args: Optional[List[str]] = None) -> int:
    """Main entry point for the CLI"""
    parsed_args = parse_args(args)
    
    # Check that the contract file exists
    if not os.path.isfile(parsed_args.contract_file):
        print(f"Error: File {parsed_args.contract_file} does not exist")
        return 1
    
    try:
        if parsed_args.command == "token-flow":
            # Initialize token flow analyzer
            analyzer = TokenFlowAnalyzer(parsed_args.contract_file)
            contract = analyzer.get_contract(parsed_args.contract_name)
            
            if not contract:
                print(f"Error: Contract '{parsed_args.contract_name}' not found in {parsed_args.contract_file}")
                return 1
            
            # Run the analysis
            analysis_result = analyzer.analyze(
                contract, 
                parsed_args.function_name, 
                parsed_args.amount_var
            )
            
            # Print the results
            analyzer.print_results(analysis_result)
            
        elif parsed_args.command == "taint":
            # Initialize taint analyzer
            analyzer = TaintAnalyzer(parsed_args.contract_file)
            contract = analyzer.get_contract(parsed_args.contract_name)
            
            if not contract:
                print(f"Error: Contract '{parsed_args.contract_name}' not found in {parsed_args.contract_file}")
                return 1
            
            # Run the analysis
            analysis_result = analyzer.analyze(
                contract, 
                parsed_args.source_function,
                parsed_args.source_variable,
                parsed_args.sink_function,
                parsed_args.sink_variable
            )
            
            # Print the results
            analyzer.print_results(analysis_result)
        
    except Exception as e:
        print(f"Error during analysis: {str(e)}")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())