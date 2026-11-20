"""``calculate``: arithmetic through an AST whitelist, never ``eval``.

The expression is parsed with :func:`ast.parse` and walked by a small interpreter that knows
only numeric literals, ``+ - * / // % **``, unary signs, a few named constants and a fixed
set of ``math`` functions. Attribute access, subscripts, comprehensions, lambdas and every
other node type are rejected before anything runs. Integer growth is bounded so ``9**9**9``
fails fast instead of eating memory.
"""

from __future__ import annotations

import ast
import math
import operator
from collections.abc import Callable

from pydantic import Field

from rawmcp.context import ToolContext
from rawmcp.tools.base import Tool, ToolError, ToolInput, ToolOutput

MAX_CHARS = 500
MAX_NODES = 200
MAX_INT_BITS = 4_096

Number = int | float

_CONSTANTS: dict[str, float] = {"pi": math.pi, "e": math.e, "tau": math.tau}


def _factorial(n: Number) -> int:
    if not isinstance(n, int) or n < 0 or n > 500:
        raise ToolError("factorial() needs an integer between 0 and 500")
    return math.factorial(n)


_FUNCTIONS: dict[str, Callable[..., Number]] = {
    "abs": abs, "round": round, "min": min, "max": max,
    "sqrt": math.sqrt, "exp": math.exp, "log": math.log, "log2": math.log2, "log10": math.log10,
    "sin": math.sin, "cos": math.cos, "tan": math.tan, "asin": math.asin, "acos": math.acos,
    "atan": math.atan, "atan2": math.atan2, "hypot": math.hypot, "floor": math.floor, "ceil": math.ceil,
    "degrees": math.degrees, "radians": math.radians, "factorial": _factorial,
}


def _check_int(value: Number) -> Number:
    if isinstance(value, int) and value.bit_length() > MAX_INT_BITS:
        raise ToolError(f"intermediate result exceeds {MAX_INT_BITS} bits")
    return value


def _mul(a: Number, b: Number) -> Number:
    if isinstance(a, int) and isinstance(b, int) and a.bit_length() + b.bit_length() > MAX_INT_BITS + 1:
        raise ToolError(f"product would exceed {MAX_INT_BITS} bits")
    return a * b


def _pow(base: Number, exponent: Number) -> Number:
    if isinstance(base, int) and isinstance(exponent, int):
        if exponent < 0:
            return float(base) ** exponent
        if abs(base) > 1 and exponent * math.log2(abs(base)) > MAX_INT_BITS:
            raise ToolError(f"power would exceed {MAX_INT_BITS} bits")
        return int(base**exponent)
    return float(math.pow(base, exponent))


_BINARY: dict[type[ast.operator], Callable[[Number, Number], Number]] = {
    ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: _mul, ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv, ast.Mod: operator.mod, ast.Pow: _pow,
}
_UNARY: dict[type[ast.unaryop], Callable[[Number], Number]] = {ast.UAdd: operator.pos, ast.USub: operator.neg}


def _eval(node: ast.AST) -> Number:
    if isinstance(node, ast.Expression):
        return _eval(node.body)
    if isinstance(node, ast.Constant):
        if isinstance(node.value, bool) or not isinstance(node.value, (int, float)):
            raise ToolError(f"unsupported literal {node.value!r}; only numbers are allowed")
        return _check_int(node.value)
    if isinstance(node, ast.Name):
        if node.id not in _CONSTANTS:
            raise ToolError(f"unknown name {node.id!r}; constants are {', '.join(sorted(_CONSTANTS))}")
        return _CONSTANTS[node.id]
    if isinstance(node, ast.BinOp) and type(node.op) in _BINARY:
        return _check_int(_BINARY[type(node.op)](_eval(node.left), _eval(node.right)))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _UNARY:
        return _UNARY[type(node.op)](_eval(node.operand))
    if isinstance(node, ast.Call):
        if not isinstance(node.func, ast.Name) or node.func.id not in _FUNCTIONS:
            raise ToolError(f"unknown function; allowed: {', '.join(sorted(_FUNCTIONS))}")
        if node.keywords:
            raise ToolError("keyword arguments are not supported")
        args = [_eval(arg) for arg in node.args]
        try:
            return _check_int(_FUNCTIONS[node.func.id](*args))
        except TypeError:
            raise ToolError(f"wrong number or type of arguments for {node.func.id}()") from None
    raise ToolError(f"unsupported syntax: {type(node).__name__}")


def evaluate(expression: str) -> Number:
    """Evaluate an arithmetic expression safely. Raises :class:`ToolError` on anything else."""
    if len(expression) > MAX_CHARS:
        raise ToolError(f"expression is longer than {MAX_CHARS} characters")
    try:
        tree = ast.parse(expression.strip(), mode="eval")
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        raise ToolError("could not parse the expression") from None
    if sum(1 for _ in ast.walk(tree)) > MAX_NODES:
        raise ToolError(f"expression has more than {MAX_NODES} syntax nodes")
    try:
        value = _eval(tree)
    except ZeroDivisionError:
        raise ToolError("division by zero") from None
    except (OverflowError, ValueError) as exc:
        raise ToolError(f"math error: {exc}") from None
    if isinstance(value, float) and not math.isfinite(value):
        raise ToolError("result is not a finite number")
    return value


class CalculateInput(ToolInput):
    expression: str = Field(min_length=1, max_length=MAX_CHARS,
                            description="Arithmetic such as '2 * (3 + 4) ** 2' or 'sqrt(2) * pi'.")


class CalculateOutput(ToolOutput):
    expression: str = Field(description="The expression as parsed (normalised spacing).")
    result: int | float
    type: str = Field(description="'int' or 'float'.")


class Calculate(Tool):
    name = "calculate"
    title = "Calculate"
    description = (
        "Evaluate an arithmetic expression: numbers, + - * / // % **, parentheses, the constants "
        "pi, e and tau, and math functions such as sqrt, log, sin, hypot, factorial."
    )
    input_model = CalculateInput
    output_model = CalculateOutput

    async def run(self, args: CalculateInput, ctx: ToolContext) -> CalculateOutput:
        value = evaluate(args.expression)
        normalised = ast.unparse(ast.parse(args.expression.strip(), mode="eval"))
        return CalculateOutput(expression=normalised, result=value, type=type(value).__name__)

