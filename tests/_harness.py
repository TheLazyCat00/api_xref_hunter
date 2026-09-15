"""
Enough of a fake Binary Ninja to exercise `branches.py` off-line.

The plugin's analysis is a walk over MLIL SSA def-use chains and a basic block
graph. Both are ordinary object graphs, so the walk can be tested against
hand-built instructions without a Binary Ninja install — which is the only way
this logic gets checked on a machine that has no licence.

The fakes mirror the shape of the real API, not its behaviour: expressions
carry `operation`/`operands` so the recursive operand walk in `branches.py` is
genuinely exercised, while `get_ssa_var_uses` is backed by an explicit `reads`
list on each instruction, the same way Binary Ninja keeps its own SSA use
index rather than re-deriving it.
"""

import importlib.util
import os
import sys
import types

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKAGE = "api_xref_hunter"


# --------------------------------------------------------------------------
# The stub modules
# --------------------------------------------------------------------------

class SymbolType:
    ImportedFunctionSymbol = "ImportedFunctionSymbol"
    ImportAddressSymbol = "ImportAddressSymbol"
    ExternalSymbol = "ExternalSymbol"
    FunctionSymbol = "FunctionSymbol"
    LibraryFunctionSymbol = "LibraryFunctionSymbol"
    DataSymbol = "DataSymbol"


class _Settings:
    def register_group(self, *_a):
        return True

    def register_setting(self, *_a):
        return True

    def get_string(self, *_a):
        return ""

    def set_string(self, *_a):
        return True


class BinaryView:
    pass


def _install_stubs():
    if "binaryninja" in sys.modules:
        return
    bn = types.ModuleType("binaryninja")
    bn.BinaryView = BinaryView
    bn.Settings = _Settings
    bn.SymbolType = SymbolType
    bn.core_ui_enabled = lambda: False
    bn.user_directory = lambda: "/tmp"
    bn.execute_on_main_thread = lambda fn: fn()

    log = types.ModuleType("binaryninja.log")
    for name in ("log_error", "log_info", "log_warn", "log_debug"):
        setattr(log, name, lambda *_a, **_kw: None)

    plugin = types.ModuleType("binaryninja.plugin")

    class BackgroundTaskThread:
        def __init__(self, *_a, **_kw):
            self.cancelled = False
            self.progress = ""

        def start(self):
            self.run()

    class PluginCommand:
        """Records what the plugin registers, so tests can assert on it."""

        registered = []

        @classmethod
        def register(cls, name, *_a, **_kw):
            cls.registered.append(name)

        @classmethod
        def register_for_function(cls, name, *_a, **_kw):
            cls.registered.append(name)

    plugin.BackgroundTaskThread = BackgroundTaskThread
    plugin.PluginCommand = PluginCommand

    interaction = types.ModuleType("binaryninja.interaction")

    bn.log = log
    bn.plugin = plugin
    bn.interaction = interaction
    sys.modules["binaryninja"] = bn
    sys.modules["binaryninja.log"] = log
    sys.modules["binaryninja.plugin"] = plugin
    sys.modules["binaryninja.interaction"] = interaction


def registered_commands():
    """Command names the plugin registered at import time."""
    return list(sys.modules["binaryninja.plugin"].PluginCommand.registered)


def load_plugin():
    """
    Import the plugin as the package it ships as, whatever the checkout is
    called, so the relative imports inside it resolve.
    """
    _install_stubs()
    if PACKAGE in sys.modules:
        return sys.modules[PACKAGE]
    spec = importlib.util.spec_from_file_location(
        PACKAGE, os.path.join(REPO, "__init__.py"),
        submodule_search_locations=[REPO],
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[PACKAGE] = module
    spec.loader.exec_module(module)
    return module


# --------------------------------------------------------------------------
# Fake IL
# --------------------------------------------------------------------------

class Token:
    def __init__(self, text):
        self.text = text


class Operation:
    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return self.name


class Variable:
    """A source-level variable; SSA versions of it share one identity."""

    def __init__(self, name, identifier=None):
        self.name = name
        self.identifier = identifier if identifier is not None else name

    def __eq__(self, other):
        return isinstance(other, Variable) and other.identifier == self.identifier

    def __hash__(self):
        return hash(self.identifier)

    def __str__(self):
        return self.name


class SSAVariable:
    def __init__(self, var, version):
        self.var = var
        self.version = version

    def __str__(self):
        return f"{self.var}#{self.version}"


class Expr:
    """An MLIL expression or instruction — the real API barely distinguishes."""

    def __init__(self, operation, operands=(), address=0, text=None, **kwargs):
        self.operation = Operation(operation)
        self.operands = list(operands)
        self.address = address
        self.instr_index = None
        self.reads = []
        self.tokens = [Token(text)] if text else []
        for key, value in kwargs.items():
            setattr(self, key, value)

    def __str__(self):
        return "".join(t.text for t in self.tokens) or self.operation.name


def const(value):
    return Expr("MLIL_CONST", [value], constant=value, text=str(value))


def var_ssa(ssa_var):
    return Expr("MLIL_VAR_SSA", [ssa_var], text=str(ssa_var))


def address_of(variable):
    return Expr("MLIL_ADDRESS_OF", [variable], src=variable, text=f"&{variable}")


def cmp_expr(op, left, right, symbol):
    return Expr(op, [left, right], text=f"{left} {symbol} {right}")


class Edge:
    def __init__(self, target):
        self.target = target


class BasicBlock:
    def __init__(self, index, start, end):
        self.index = index
        self.start = start
        self.end = end
        self.outgoing_edges = []


class ILFunction:
    def __init__(self, instructions, blocks):
        self.instructions = instructions
        self.basic_blocks = blocks
        for i, inst in enumerate(instructions):
            inst.instr_index = i

    @property
    def ssa_form(self):
        return self

    def __getitem__(self, index):
        return self.instructions[index]

    def get_basic_block_at(self, instr_index):
        for block in self.basic_blocks:
            if block.start <= instr_index < block.end:
                return block
        return None

    def get_ssa_var_uses(self, ssa_var):
        key = (ssa_var.var.identifier, ssa_var.version)
        return [inst for inst in self.instructions
                if any((r.var.identifier, r.version) == key for r in inst.reads)]


class Function:
    def __init__(self, name, start, il):
        self.name = name
        self.start = start
        self.mlil = il


class Symbol:
    def __init__(self, name, address, type_=SymbolType.ImportedFunctionSymbol):
        self.name = name
        self.short_name = name
        self.raw_name = name
        self.full_name = name
        self.address = address
        self.type = type_


class CodeRef:
    def __init__(self, function, address):
        self.function = function
        self.address = address


class FakeBinaryView:
    def __init__(self, symbols=(), functions=(), code_refs=None):
        self._symbols = list(symbols)
        self._functions = list(functions)
        self._code_refs = code_refs or {}

    def get_symbols(self):
        return self._symbols

    def get_symbol_at(self, address):
        for sym in self._symbols:
            if sym.address == address:
                return sym
        return None

    def get_function_at(self, address):
        for func in self._functions:
            if func.start == address:
                return func
        return None

    def get_code_refs(self, address):
        return self._code_refs.get(address, [])
