#!/usr/bin/env python3
"""
    advanced_taint_mapping_new.py
    该脚本重新实现了数据依赖计算逻辑，借鉴 Slither 的 compute_dependency，
    同时在脚本中构造直接依赖图，并使用 DFS（逆向）查找从输入变量到指定 state variable 的依赖路径。
    
    用法:
      python advanced_taint_mapping_new.py <solidity_file> <contract_name> <state_variable_name>
      
    注意：
      1. 脚本中重新计算的直接依赖图只记录 IR 操作产生的直接依赖边，
         因此能够避免由于传递闭包导致"间接依赖"混入而使得边被错误过滤的问题。
      2. 输入变量集合从 Slither 编译单元的上下文中获取，通常包括 public/external 函数的参数。
"""

import sys
from collections import defaultdict
from typing import List, Set, Dict, Any

from slither.slither import Slither
from slither.core.declarations import Contract
from slither.slithir.operations import OperationWithLValue, Index, InternalCall
from slither.slithir.variables import Constant, LocalIRVariable, ReferenceVariable

# 类型别名，统一使用非 SSA 版本
VariableType = Any
# 直接依赖映射：变量 -> set(直接影响它的变量)
DirectDepMap = Dict[VariableType, Set[VariableType]]

def non_ssa(v: VariableType) -> VariableType:
    """返回变量的非 SSA 版本（若存在），否则返回自身"""
    try:
        return v.non_ssa_version
    except AttributeError:
        return v

def compute_direct_dependencies(slither: Slither, target_contract_name: str) -> DirectDepMap:
    """
    计算目标合约中所有函数（包括 modifier）的直接依赖关系。
    对于每个 IR 操作（OperationWithLValue），记录左值直接依赖 IR 中读取的变量（排除常量）。
    返回的映射中的边均为直接依赖边。
    """
    direct_dep: DirectDepMap = defaultdict(set)
    
    # 查找目标合约
    target_contract: Contract = None
    for contract in slither.contracts:
        if contract.name == target_contract_name:
            target_contract = contract
            break
    if not target_contract:
        print(f"Contract {target_contract_name} not found.")
        sys.exit(-1)
    
    # 遍历合约中的所有函数和 modifier
    for function in target_contract.functions + list(target_contract.modifiers):
        for node in function.nodes:
            for ir in node.irs_ssa:
                if isinstance(ir, OperationWithLValue) and ir.lvalue:
                    # 过滤 storage 类型的 IR（例如直接存储的 state variable），根据需要可调整
                    if hasattr(ir.lvalue, "is_storage") and ir.lvalue.is_storage:
                        continue
                    lval = ir.lvalue
                    if hasattr(lval, "points_to"):
                        pts = lval.points_to
                        if pts:
                            lval = pts
                    lval = non_ssa(lval)
                    
                    # 根据 IR 类型获取读取的变量列表
                    if isinstance(ir, Index):
                        reads = [ir.variable_left]
                    elif isinstance(ir, InternalCall) and ir.function:
                        reads = ir.function.return_values_ssa
                    else:
                        reads = ir.read
                    for r in reads:
                        if isinstance(r, Constant):
                            continue
                        direct_dep[lval].add(non_ssa(r))
    return direct_dep

def find_dependency_paths(
    target: VariableType,
    direct_dep: DirectDepMap,
    input_set: Set[VariableType]
) -> List[List[VariableType]]:
    """
    从目标变量沿直接依赖"逆向"查找路径，直到遇到输入变量。
    DFS 遍历：若当前变量在 input_set 中，则视为路径终止，返回一条路径。
    返回的每条路径为从输入到目标的顺序列表。
    """
    def dfs(current: VariableType, visited: Set[VariableType]) -> List[List[VariableType]]:
        # 若当前变量已为输入变量，则返回该路径（以列表形式）
        if current in input_set:
            return [[current]]
        if current not in direct_dep:
            return []  # 无依赖关系则终止
        paths = []
        for precursor in direct_dep[current]:
            if precursor in visited:
                continue
            subpaths = dfs(precursor, visited | {precursor})
            for sp in subpaths:
                paths.append(sp + [current])
        return paths

    return dfs(target, {target})

def main():
    if len(sys.argv) != 4:
        print("Usage: python advanced_taint_mapping_new.py <solidity_file> <contract_name> <state_variable_name>")
        sys.exit(-1)
    
    solidity_file = sys.argv[1]
    contract_name = sys.argv[2]
    state_variable_name = sys.argv[3]
    
    try:
        # 注意：Slither(solidity_file) 会自动计算依赖信息
        slither = Slither(solidity_file)
    except Exception as e:
        print(f"Error parsing solidity file: {e}")
        sys.exit(-1)
    
    # 计算直接依赖映射
    direct_dep = compute_direct_dependencies(slither, contract_name)
    
    # 输出直接依赖映射用于调试
    print("Direct dependency mapping:")
    for k, deps in direct_dep.items():
        print(f"  {k.name}: {', '.join([d.name for d in deps])}")
    
    # 从 Slither 的编译单元上下文中获取输入变量集合
    input_set = slither.compilation_units[0].context.get("DATA_DEPENDENCY_INPUT", set())
    print(f"Input set: {', '.join([i.name for i in input_set])}")
    
    # 查找目标合约和指定 state variable（取非 SSA 版本）
    target_contract = None
    target_var = None
    for c in slither.contracts:
        if c.name == contract_name:
            target_contract = c
            for var in c.state_variables:
                if var.name == state_variable_name:
                    target_var = non_ssa(var)
                    break
            break
    if not target_contract:
        print(f"Contract {contract_name} not found.")
        sys.exit(-1)
    if not target_var:
        print(f"State variable {state_variable_name} not found in contract {contract_name}.")
        sys.exit(-1)
    
    # 计算所有从输入到目标变量的依赖路径（基于直接依赖图）
    paths = find_dependency_paths(target_var, direct_dep, input_set)
    
    if not paths:
        print("No dependency paths found from input to the state variable.")
    else:
        print(f"Dependency paths from input to state variable '{state_variable_name}':")
        for p in paths:
            # p 为从输入到目标的路径
            print(" -> ".join(var.name for var in p))
    
if __name__ == "__main__":
    main()