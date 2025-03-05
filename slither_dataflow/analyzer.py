"""
Base analyzer class for data flow analysis
"""

from abc import ABC, abstractmethod
from typing import Dict, Optional

from slither import Slither
from slither.core.declarations import Contract


class DataFlowAnalyzer(ABC):
    """
    Abstract base class for all data flow analyzers
    """

    def __init__(self, contract_file: str):
        """Initialize the analyzer with a contract file"""
        try:
            self.slither = Slither(contract_file)
            print(f"Loaded {contract_file}")
        except Exception as e:
            raise RuntimeError(f"Error loading contract: {str(e)}")

    def get_contract(self, contract_name: str) -> Optional[Contract]:
        """Get a contract by name"""
        contracts = self.slither.get_contract_from_name(contract_name)
        return contracts[0] if contracts else None

    @abstractmethod
    def analyze(self, contract: Contract, *args, **kwargs) -> Dict:
        """
        Perform the analysis on the contract
        
        Args:
            contract: The contract to analyze
            *args: Additional positional arguments
            **kwargs: Additional keyword arguments
            
        Returns:
            Dict: Analysis results
        """
        pass

    @abstractmethod
    def print_results(self, results: Dict) -> None:
        """
        Print analysis results
        
        Args:
            results: The analysis results to print
        """
        pass