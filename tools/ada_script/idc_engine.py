import logging
import re

from lark import Lark, Token, Transformer, Tree, v_args
from lark.exceptions import UnexpectedCharacters, UnexpectedToken

# Comprehensive IDC grammar: Covers commands from tests/egame.idc, full expressions in args, recursive statements.
IDC_GRAMMAR = r"""
// Terminals first
NUMBER: /\d+/

ADD_FUNC: "add_func"
MAKE_STRUCT: "MakeStruct"
CREATE_INSN: "create_insn"
OP_HEX: "op_hex"
OP_STKVAR: "op_stkvar"
OP_ENUM: "op_enum"
OP_PLAIN_OFFSET: "op_plain_offset"
SET_CMT: "set_cmt"
SET_NAME: "set_name"
SET_INF_ATTR: "set_inf_attr"
ADD_SEGM_EX: "add_segm_ex"
SEG_RENAME: "SegRename"
SEG_CLASS: "SegClass"
DELETE_ALL_SEGMENTS: "delete_all_segments"
SET_PROCESSOR_TYPE: "set_processor_type"
GET_INF_ATTR: "get_inf_attr"

NAME: /[a-zA-Z_][a-zA-Z0-9_]*/
STRING: ESCAPED_STRING

// Operators
BITWISE_OR: "|"
BITWISE_AND: "&"
EQ: "=="
NEQ: "!="
LE: "<="
GE: ">="
LSHIFT: "<<"
RSHIFT: ">>"
PLUS: "+"
MINUS: "-"
MUL: "*"
DIV: "/"
MOD: "%"
BITWISE_NOT: "~"
NOT: "!"
DOT: "."
LSBRACKET: "["
RSBRACKET: "]"
LBRACE: "{"
RBRACE: "}"
COMMA: ","
SEMI: ";"
ASSIGN: "="
HASH: "#"
DEFINE: "define"
INCLUDE: "include"
RETURN: "return"
STATIC: "static"
AUTO: "auto"
VOID: "void"
BYTE: "byte"
WORD: "word"
DWORD: "dword"
QWORD: "qword"
LP: "("
RP: ")"
LT: "<"
GT: ">"

// Hex with case-insensitive x/X
hex_addr: /0[xX][0-9A-Fa-f]+/
hex_value: /0[xX][0-9A-Fa-f]+/

path: NAME (DOT NAME)*
path_content: /[^<>\s]+/  // Avoid < > in path

%import common.ESCAPED_STRING
%import common.NEWLINE
%import common.WS
%ignore WS
%ignore /\/\/[^\n]*/
%ignore /\/\*[\s\S]*?\*\//

// Rules
start: (statement | NEWLINE)*

statement: statement_content SEMI? NEWLINE?

statement_content: include
                 | define_stmt
                 | declaration
                 | function_def
                 | command_stmt
                 | function_call_stmt
                 | assignment_stmt
                 | return_stmt
                 | empty_stmt

// Expanded: All known IDC cmds from tests (set_inf_attr, add_segm_ex, SegRename, SegClass, delete_all_segments, set_processor_type, etc.)
command_stmt: command_name LP arg_list RP

command_name: ADD_FUNC | MAKE_STRUCT | CREATE_INSN | OP_HEX | OP_STKVAR | OP_ENUM | OP_PLAIN_OFFSET
            | SET_CMT | SET_NAME | SET_INF_ATTR | ADD_SEGM_EX | SEG_RENAME | SEG_CLASS
            | DELETE_ALL_SEGMENTS | SET_PROCESSOR_TYPE | GET_INF_ATTR

arg: expression | NAME ASSIGN expression

arg_list: arg? (COMMA arg)*

include: HASH INCLUDE LT path_content GT

define_stmt: HASH DEFINE NAME [expression]

declaration: decl_with_type_and_init
            | decl_with_type_no_init
            | decl_no_type_with_init
            | decl_no_type_no_init

decl_with_type_and_init: (STATIC | AUTO) type NAME ASSIGN expression
decl_with_type_no_init: (STATIC | AUTO) type NAME
decl_no_type_with_init: (STATIC | AUTO) NAME ASSIGN expression
decl_no_type_no_init: (STATIC | AUTO) NAME

return_stmt: RETURN [expression]

assignment_stmt: NAME ASSIGN expression

function_def: STATIC NAME LP (VOID | param_list)? RP LBRACE statements RBRACE

function_call_stmt: function_call

empty_stmt: SEMI

?statements: (statement | NEWLINE)*  // Recursive for body

?param_list: param (COMMA param)*
?param: [type] NAME

type: BYTE | WORD | DWORD | QWORD | "void"

?expression: bitwise_or
?bitwise_or: bitwise_and (BITWISE_OR bitwise_and)*
?bitwise_and: equality (BITWISE_AND equality)*
?equality: relational (EQ | NEQ relational)*
?relational: shift ("<" | ">" | LE | GE shift)*
?shift: additive (LSHIFT | RSHIFT additive)*
?additive: multiplicative ((PLUS | MINUS) multiplicative)*
?multiplicative: unary (MUL | DIV | MOD unary)*
?unary: (PLUS | MINUS | BITWISE_NOT | NOT) unary | postfix
?postfix: primary (LSBRACKET expression RSBRACKET | DOT NAME | function_call)*
?primary: NUMBER
         | hex_value
         | STRING
         | NAME
         | LP expression RP
         | function_call

function_call: NAME LP arg_list RP
"""

class IDCTransformer(Transformer):
    def __init__(self):
        super().__init__(visit_tokens=True)

    def start(self, children):
        import logging
        logging.debug(f"Transformer start: {len(children)} children, types={[type(c).__name__ for c in children[:5]]}")
        script = IDCScript()
        processed = 0
        for child in children:
            if isinstance(child, Tree):
                logging.debug(f"Processing Tree: data={child.data}, children_len={len(child.children)}")
                payload = self.transform(child)
                logging.debug(f"Tree {child.data} transformed: {type(payload).__name__ if payload else 'None'}{' (payload: ' + str(payload) + ')' if isinstance(payload, str) else ''}")
                if isinstance(payload, str):
                    if payload.strip():
                        script.includes.append(payload.strip())
                        processed += 1
                elif isinstance(payload, Token):
                    token_value = payload.value
                    if token_value.strip():
                        script.includes.append(token_value.strip())
                        processed += 1
                elif isinstance(payload, dict):
                    self._add_item_to_script(script, payload)
                    processed += 1
                elif isinstance(payload, list):
                    for p in payload:
                        if isinstance(p, dict):
                            self._add_item_to_script(script, p)
                            processed += 1
            elif isinstance(child, str) and child.strip():
                script.includes.append(child.strip())
                processed += 1
            elif isinstance(child, Token):
                token_value = child.value
                if token_value.strip():
                    script.includes.append(token_value.strip())
                    processed += 1
            elif isinstance(child, dict):
                self._add_item_to_script(script, child)
                processed += 1
            elif isinstance(child, list):
                for p in child:
                    if isinstance(p, dict):
                        self._add_item_to_script(script, p)
                        processed += 1
        logging.debug(f"Processed {processed} items; script summary: includes={len(script.includes)}, defines={len(script.defines)}, vars={len(script.variables)}, funcs={len(script.functions)}")
        return script

    def _add_item_to_script(self, script, item):
        import logging
        item_type = item.get('type')
        logging.debug(f"Adding to script: type={item_type}, item={item}")
        if item_type == 'define':
            script.defines.append(item)
            if not hasattr(script, 'calls'):
                script.calls = []
            script.calls.append(item)
        elif item_type == 'function':
            script.functions.append(item)
            # Recurse into statements to extract inner calls to top-level lists
            for stmt in item.get('statements', []):
                if isinstance(stmt, dict):
                    self._add_item_to_script(script, stmt)
        elif 'modifier' in item:
            script.variables.append(item)
        elif item_type in ('call', 'assign'):
            # Keep an ordered event stream: calls, assignments and defines are
            # applied to the DB in source order (IDC semantics).
            if not hasattr(script, 'calls'):
                script.calls = []
            script.calls.append(item)
            if item_type == 'assign':
                return
            name = item.get('name', '')
            if name == 'add_func':
                script.functions.append(item)
            elif name == 'MakeStruct':
                script.variables.append(item)
            elif name == 'create_insn':
                if not hasattr(script, 'instructions'):
                    script.instructions = []
                script.instructions.append(item)
            elif name == 'set_cmt':
                if not hasattr(script, 'comments'):
                    script.comments = []
                script.comments.append(item)
            elif name == 'set_name':
                if not hasattr(script, 'names'):
                    script.names = {}
                args = item.get('args', [])
                if len(args) >= 2:
                    addr = args[0] if isinstance(args[0], (int, str)) else 0
                    name_val = args[1] if isinstance(args[1], str) else ''
                    script.names[addr] = name_val
            else:
                if not hasattr(script, 'operands'):
                    script.operands = []
                script.operands.append(item)
        elif item_type == 'return':
            pass  # Ignore top-level in functions

    def statement(self, children):
        import logging
        logging.debug(f"Statement children: {len(children)}, filtered={[type(c).__name__ for c in children]}")
        content = [c for c in children if c not in [';', '\n']]
        if content:
            return content[0]
        return None

    def statement_content(self, children):
        import logging
        logging.debug(f"Statement_content: {len(children)} children, first={children[0] if children else 'None'}")
        return children[0] if children else None

    def include(self, children):
        import logging
        path_idx = 3 if len(children) == 5 else 2 if len(children) == 3 else None
        path = children[path_idx] if path_idx is not None else ''
        if isinstance(path, Token):
            path = path.value
        logging.debug(f"Include parsed: children={children}, path={path}")
        return path

    def path(self, children):
        names = [c for c in children if c != '.']
        return '.'.join(names)

    def define_stmt(self, children):
        import logging
        name = children[2] if len(children) >= 3 else ''
        value = children[3] if len(children) > 3 else None
        result = {'type': 'define', 'name': name, 'value': str(value) if value is not None else None}
        logging.debug(f"Define parsed: {result}")
        return result

    def _create_decl(self, modifier, dtype, name, init_expr):
        return {'modifier': modifier, 'type': dtype, 'name': name, 'init': init_expr}

    def decl_with_type_and_init(self, children):
        if len(children) == 5:
            return self._create_decl(children[0], children[1], children[2], children[4])
        return {}

    def decl_with_type_no_init(self, children):
        if len(children) == 3:
            return self._create_decl(children[0], children[1], children[2], None)
        return {}

    def decl_no_type_with_init(self, children):
        if len(children) == 4:
            return self._create_decl(children[0], None, children[1], children[3])
        return {}

    def decl_no_type_no_init(self, children):
        if len(children) == 2:
            return self._create_decl(children[0], None, children[1], None)
        return {}

    def declaration(self, children):
        import logging
        logging.debug(f"Declaration children: {[type(c).__name__ for c in children]}")
        for child in children:
            if child:
                logging.debug(f"Declaration returning: {child}")
                return child
        return {}

    def function_def(self, children):
        import logging
        name = children[1]
        # Handle params
        params = []
        if len(children) > 3:
            params_tree = children[3]
            if isinstance(params_tree, Token):
                if params_tree.value in ['void', ')']:
                    params = []
                else:
                    params = [params_tree]
            elif isinstance(params_tree, Tree):
                params = [c for c in params_tree.children if c is not None]
            else:
                params = params_tree or []
        # Handle statements
        statements = []
        if len(children) > 5:
            if len(children) == 7:  # no params
                statements_tree = children[5]
            else:  # with params or VOID
                statements_tree = children[6]
            if isinstance(statements_tree, Tree):
                statements = [c for c in statements_tree.children if c and not (isinstance(c, Token) and c.type == 'NEWLINE')]
            else:
                statements = statements_tree or []
        if not isinstance(statements, list):
            statements = [statements]
        result = {'type': 'function', 'name': name, 'params': params, 'modifier': 'static', 'statements': statements}
        logging.debug(f"Function_def parsed: {result['name']}, params_len={len(params)}")
        return result

    def statements(self, children):
        return [c for c in children if c and not (isinstance(c, Token) and c.type == 'NEWLINE')]

    def _flatten_statements(self, tree):
        if isinstance(tree, Tree) and tree.data == 'statements':
            flattened = []
            for child in tree.children:
                if not child or (isinstance(child, Token) and child.type == 'NEWLINE'):
                    continue
                flattened.append(self.transform(child) if isinstance(child, Tree) else child)
            return flattened
        elif isinstance(tree, list):
            return tree
        else:
            return []

    @v_args(inline=True)
    def command_stmt(self, name, lp, args, rp):
        import logging
        logging.debug(f"command_stmt name: {name}, args: {args}")
        result = {'type': 'call', 'name': name, 'args': args or []}
        logging.debug(f"Command parsed: {name}, args_len={len(result['args'])}")
        return result

    @v_args(inline=True)
    def arg_list(self, *args):
        return [a for a in args if a is not None and not (isinstance(a, Token) and a.type == 'COMMA')]

    @v_args(inline=True)
    def arg(self, *children):
        if len(children) == 3 and children[1] == '=':
            return {'type': 'assign', 'left': children[0], 'op': '=', 'right': children[2]}
        elif len(children) == 1:
            return children[0]
        else:
            raise ValueError(f"Unexpected arg children: {children}")

    @v_args(inline=True)
    def return_stmt(self, kw, expr=None):
        return {'type': 'return', 'expr': expr}

    @v_args(inline=True)
    def assignment_stmt(self, name, op, expr):
        return {'type': 'assign', 'name': name, 'op': op, 'expr': expr}

    @v_args(inline=True)
    def function_call(self, name, lp, args, rp):
        import logging
        logging.debug(f"function_call name: {name}, args: {args}")
        return {'type': 'call', 'name': name, 'args': args or []}

    def function_call_stmt(self, children):
        return children[0] if children else {'type': 'call', 'name': '', 'args': []}

    def assignment(self, children):
        if len(children) == 1:
            return children[0]
        left = children[0]
        i = 1
        while i < len(children):
            op = children[i]
            right = children[i + 1]
            left = {'type': 'assign', 'left': left, 'op': op, 'right': right}
            i += 2
        return left

    @v_args(inline=True)
    def bitwise_or(self, *children):
        if len(children) == 1:
            return children[0]
        left = children[0]
        i = 1
        while i < len(children):
            op = children[i]
            right = children[i + 1]
            left = {'type': 'binary', 'op': op, 'left': left, 'right': right}
            i += 2
        return left

    @v_args(inline=True)
    def bitwise_and(self, *children):
        if len(children) == 1:
            return children[0]
        left = children[0]
        i = 1
        while i < len(children):
            op = children[i]
            right = children[i + 1]
            left = {'type': 'binary', 'op': op, 'left': left, 'right': right}
            i += 2
        return left

    @v_args(inline=True)
    def equality(self, *children):
        if len(children) == 1:
            return children[0]
        left = children[0]
        i = 1
        while i < len(children):
            op = children[i]
            right = children[i + 1]
            left = {'type': 'binary', 'op': op, 'left': left, 'right': right}
            i += 2
        return left

    @v_args(inline=True)
    def relational(self, *children):
        if len(children) == 1:
            return children[0]
        left = children[0]
        i = 1
        while i < len(children):
            op = children[i]
            right = children[i + 1]
            left = {'type': 'binary', 'op': op, 'left': left, 'right': right}
            i += 2
        return left

    @v_args(inline=True)
    def shift(self, *children):
        if len(children) == 1:
            return children[0]
        left = children[0]
        i = 1
        while i < len(children):
            op = children[i]
            right = children[i + 1]
            left = {'type': 'binary', 'op': op, 'left': left, 'right': right}
            i += 2
        return left

    @v_args(inline=True)
    def additive(self, *children):
        if len(children) == 1:
            return children[0]
        left = children[0]
        i = 1
        while i < len(children):
            op = children[i]
            right = children[i + 1]
            left = {'type': 'binary', 'op': op, 'left': left, 'right': right}
            i += 2
        return left

    @v_args(inline=True)
    def multiplicative(self, *children):
        if len(children) == 1:
            return children[0]
        left = children[0]
        i = 1
        while i < len(children):
            op = children[i]
            right = children[i + 1]
            left = {'type': 'binary', 'op': op, 'left': left, 'right': right}
            i += 2
        return left


    @v_args(inline=True)
    def unary(self, op, operand):
        return {'type': 'unary', 'op': op, 'operand': operand}

    def conditional_expr(self, children):
        return self.bitwise_or(children)

    def postfix(self, children):
        base = children[0]
        i = 1
        while i < len(children):
            op = children[i]
            if op == '[':
                index = children[i + 1]
                base = {'type': 'index', 'base': base, 'index': index}
                i += 3
            elif op == '.':
                member = children[i + 1]
                base = {'type': 'dot', 'base': base, 'member': member}
                i += 2
            elif op == '(':
                args = children[i + 1] if isinstance(children[i + 1], list) else [children[i + 1]]
                base = {'type': 'call', 'base': base, 'args': args}
                i += 3
            else:
                i += 1
        return base

    @v_args(inline=True)
    def primary(self, value):
        return value

    def simple_assign(self, children):
        left = children[0]
        op = children[1]
        right = children[2]
        return {'type': 'assign', 'left': left, 'op': op, 'right': right}

    def simple_assignment(self, children):
        left = children[0]
        op = children[1]
        right = children[2]
        return {'type': 'assign', 'left': left, 'op': op, 'right': right}

    @v_args(inline=True)
    def NUMBER(self, n): return int(n)

    @v_args(inline=True)
    def hex_value(self, s): return int(s, 16)

    @v_args(inline=True)
    def hex_addr(self, s): return int(s, 16)

    @v_args(inline=True)
    def STRING(self, s):
        if s.startswith('"') and s.endswith('"'):
            s = s[1:-1]
        s = s.replace('\\\\', '\\').replace('\\"', '"').replace('\\n', '\n').replace('\\t', '\t')
        return s

    @v_args(inline=True)
    def NAME(self, n): return n

    @v_args(inline=True)
    def path_content(self, s): return s

    @v_args(inline=True)
    def STATIC(self, s): return s

    @v_args(inline=True)
    def AUTO(self, s): return s

    @v_args(inline=True)
    def BYTE(self, s): return s

    @v_args(inline=True)
    def WORD(self, s): return s

    @v_args(inline=True)
    def DWORD(self, s): return s

    @v_args(inline=True)
    def QWORD(self, s): return s

    @v_args(inline=True)
    def VOID(self, s): return s

    @v_args(inline=True)
    def LT(self, s): return s

    @v_args(inline=True)
    def GT(self, s): return s

    @v_args(inline=True)
    def HASH(self, s): return s

    @v_args(inline=True)
    def INCLUDE(self, s): return s

    @v_args(inline=True)
    def DEFINE(self, s): return s

    @v_args(inline=True)
    def RETURN(self, s): return s

    @v_args(inline=True)
    def lt(self, s): return s

    @v_args(inline=True)
    def gt(self, s): return s

    @v_args(inline=True)
    def ADD_FUNC(self, s): return s
    @v_args(inline=True)
    def MAKE_STRUCT(self, s): return s
    @v_args(inline=True)
    def CREATE_INSN(self, s): return s
    @v_args(inline=True)
    def OP_HEX(self, s): return s
    @v_args(inline=True)
    def OP_STKVAR(self, s): return s
    @v_args(inline=True)
    def OP_ENUM(self, s): return s
    @v_args(inline=True)
    def OP_PLAIN_OFFSET(self, s): return s
    @v_args(inline=True)
    def SET_CMT(self, s): return s
    @v_args(inline=True)
    def SET_NAME(self, s): return s
    @v_args(inline=True)
    def SET_INF_ATTR(self, s): return s
    @v_args(inline=True)
    def ADD_SEGM_EX(self, s): return s
    @v_args(inline=True)
    def SEG_RENAME(self, s): return s
    @v_args(inline=True)
    def SEG_CLASS(self, s): return s
    @v_args(inline=True)
    def DELETE_ALL_SEGMENTS(self, s): return s
    @v_args(inline=True)
    def SET_PROCESSOR_TYPE(self, s): return s
    @v_args(inline=True)
    def GET_INF_ATTR(self, s): return s

    def param_list(self, children):
        params = [self.transform(c) for c in children if c != ',']
        return params

    def param(self, children):
        if len(children) == 2:
            return {'type': children[0], 'name': children[1]}
        elif len(children) == 1:
            return {'type': None, 'name': children[0]}
        return {}

    def __default__(self, data, children, meta):
        non_none = [c for c in children if c is not None]
        if not non_none:
            return None
        if len(non_none) == 1:
            return non_none[0]
        return non_none if data in ['statements', 'arg_list', 'param_list'] else Tree(data, non_none)



class IDCScript:
    def __init__(self, includes=None, defines=None, variables=None, functions=None, operands=None, comments=None, names=None, instructions=None, calls=None, db=None):
        self.includes = includes or []
        self.defines = defines or []
        self.variables = variables or []
        self.functions = functions or []
        self.operands = operands or []
        self.comments = comments or []
        self.names = names or {}
        self.instructions = instructions or []
        self.calls = calls or []
        self.db = db
        # IDC evaluation state (temporaries like `x`, `id`, defines).
        self.env = {}
        self.defines_map = {}

    @staticmethod
    def _token_value(value):
        if isinstance(value, Token):
            return value.value
        return value

    # Well-known IDC constants (values only need to be self-consistent).
    _CONSTANTS = {
        'E_PREV': 1000, 'E_NEXT': 2000,
        'BADADDR': 0xFFFFFFFF,
        'SN_LOCAL': 0x800, 'SN_CHECK': 0x1, 'SN_PUBLIC': 0x2, 'SN_WEAK': 0x4,
        'FUNC_FAR': 0x2, 'FUNC_FRAME': 0x10, 'FUNC_USERFAR': 0x400,
        'ADDSEG_NOSREG': 0x2000, 'ADDSEG_SPARSE': 0x8000, 'ADDSEG_OR_DIE': 1,
        'SETPROC_USER': 2, 'SETPROC_COMPAT': 1, 'SETPROC_ALL': 0,
        'UTP_ENUM': 0x4, 'UTP_STRUCT': 0x8,
        'SCF_ALLCMT': 0x8,
        'OFLG_SHOW_VOID': 0x2, 'OFLG_SHOW_AUTO': 0x40,
        'INFFL_LOADIDC': 0x10,
    }

    def _eval(self, node):
        """Evaluate an IDC expression tree to a Python value.

        Returns int/str for concrete values, or the raw node when unknown.
        Side-effect calls used inside expressions (add_enum, get_struc_id, ...)
        are executed so that their return value can be tracked in env vars.
        """
        node = self._token_value(node)
        if node is None:
            return None
        if isinstance(node, bool):
            return int(node)
        if isinstance(node, (int, float)):
            return int(node)
        if isinstance(node, str):
            raw = node.strip()
            if not raw:
                return raw
            # preprocessor defines alias other names (e.g. `#define id x`)
            if raw in self.defines_map:
                return self._eval(self.defines_map[raw])
            if raw in self.env:
                return self.env[raw]
            if raw in self._CONSTANTS:
                return self._CONSTANTS[raw]
            if raw.startswith(("0x", "0X")):
                try:
                    return int(raw, 16)
                except ValueError:
                    return raw
            if raw.lstrip('-').isdigit():
                return int(raw, 10)
            return raw
        if isinstance(node, dict):
            t = node.get('type')
            if t == 'assign':
                # two producer rules: arg -> left/right, assignment_stmt -> name/expr
                val = self._eval(node.get('right', node.get('expr')))
                key = str(self._token_value(node.get('left', node.get('name'))))
                self.env[key] = val
                return val
            if t == 'binary':
                lv = self._eval(node.get('left'))
                r = self._eval(node.get('right'))
                return self._apply_binop(node.get('op'), lv, r)
            if t == 'unary':
                v = self._eval(node.get('operand'))
                if not isinstance(v, int):
                    return 0
                op = node.get('op')
                return {'~': ~v, '!': int(not v), '-': -v, '+': v}.get(str(op), v)
            if t == 'call':
                return self._eval_call(node)
            return node
        if isinstance(node, list):
            return [self._eval(n) for n in node]
        return node

    def _apply_binop(self, op, lv, r):
        if not isinstance(lv, int) or not isinstance(r, int):
            return 0
        try:
            return {
                '|': lv | r, '&': lv & r, '+': lv + r, '-': lv - r, '*': lv * r,
                '<<': lv << r, '>>': lv >> r,
                '==': int(lv == r), '!=': int(lv != r),
                '<': int(lv < r), '>': int(lv > r), '<=': int(lv <= r), '>=': int(lv >= r),
                '/': int(lv / r) if r else 0, '%': lv % r if r else 0,
            }.get(str(op), 0)
        except Exception:
            return 0

    def _eval_call(self, node):
        """Evaluate calls that appear inside expressions."""
        name = str(self._token_value(node.get('name', '')))
        args = [self._eval(a) for a in (node.get('args') or [])]
        name_l = name.lower()
        if name_l == 'get_inf_attr' and args:
            row = self.db.conn.execute(
                "SELECT value FROM config WHERE key=?", (f"inf_attr:{args[0]}",)).fetchone() \
                if self.db is not None else None
            try:
                return int(row[0]) if row else 0
            except (ValueError, TypeError):
                return 0
        if name_l in ('getenum', 'get_enum') and args:
            return self._enum_id(str(args[0]))
        if name_l == 'get_struc_id' and args:
            return self._struc_id(str(args[0]))
        if name_l == 'get_member_id' and len(args) >= 2:
            return f"mid:{args[0]}:{args[1]}"
        if self.db is not None:
            # Side-effect builtins used inside expressions (add_enum,
            # add_struc_member, ...): apply them and use their return value.
            return self._apply_named(name, args)
        return 0

    def _enum_id(self, name):
        if self.db is None:
            return 0
        row = self.db.conn.execute("SELECT id FROM enums WHERE name=?", (name,)).fetchone()
        if row:
            return row[0]
        cur = self.db.execute("INSERT INTO enums (name) VALUES (?)", (name,))
        return cur.lastrowid or 0

    def _struc_id(self, name):
        if self.db is None:
            return 0
        row = self.db.conn.execute("SELECT id FROM strucs WHERE name=?", (name,)).fetchone()
        if row:
            return row[0]
        cur = self.db.execute("INSERT INTO strucs (name) VALUES (?)", (name,))
        return cur.lastrowid or 0

    def _resolve_arg(self, arg):
        return self._eval(arg)

    def _as_int(self, value):
        value = self._eval(value)
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            raw = value.strip()
            base = 16 if raw.startswith(("0x", "0X")) else 10
            try:
                return int(raw, base)
            except ValueError:
                return None
        return None

    def _int_args(self, args, n):
        out = []
        for a in args[:n]:
            v = self._as_int(a)
            if v is None:
                return None
            out.append(v)
        return out

    def _apply_named(self, name, args):
        """Handle a builtin call with already-evaluated args."""
        handler = self._IDC_CMDS.get(name.lower())
        if handler is not None:
            return handler(self, args)
        # Everything else (add_default_til, type-updating, unknown user calls)
        # is intentionally ignored.
        return None

    # ---- segments -----------------------------------------------------
    def _cmd_delete_all_segments(self, args):
        db = self.db
        db.execute("DELETE FROM segments")
        db.execute("DELETE FROM sregs")
        db.execute("DELETE FROM sreg_ranges")

    def _cmd_add_segm_ex(self, args):
        if len(args) < 3:
            return
        start, end = self._as_int(args[0]), self._as_int(args[1])
        base = self._as_int(args[2]) or 0
        align = self._as_int(args[4]) if len(args) > 4 else 1
        comb = self._as_int(args[5]) if len(args) > 5 else 2
        align = 1 if align is None else align
        comb = 2 if comb is None else comb
        if start is None or end is None:
            return
        self.db.execute(
            "INSERT OR REPLACE INTO segments (start_addr, end_addr, base, class, type, executable, align, comb, name) "
            "VALUES (?, ?, ?, COALESCE((SELECT class FROM segments WHERE start_addr=?), 'UNKNOWN'), "
            "COALESCE((SELECT type FROM segments WHERE start_addr=?), 'code'), "
            "COALESCE((SELECT executable FROM segments WHERE start_addr=?), 0), ?, ?, "
            "COALESCE((SELECT name FROM segments WHERE start_addr=?), NULL))",
            (start, end, base, start, start, start, align, comb, start))

    def _cmd_segrename(self, args):
        if len(args) < 2:
            return
        start = self._as_int(args[0])
        if start is not None:
            self.db.execute("UPDATE segments SET name=? WHERE start_addr=?",
                            (str(args[1]), start))

    def _cmd_segclass(self, args):
        if len(args) < 2:
            return
        start = self._as_int(args[0])
        if start is None:
            return
        cls = str(args[1]).upper()
        self.db.execute("UPDATE segments SET class=? WHERE start_addr=?", (cls, start))
        if cls == 'CODE':
            self.db.execute("UPDATE segments SET type='code', executable=1 WHERE start_addr=?",
                            (start,))
        elif cls in ('DATA', 'STACK'):
            self.db.execute("UPDATE segments SET type=?, executable=0 WHERE start_addr=?",
                            ('stack' if cls == 'STACK' else 'data', start))

    def _cmd_segdefreg(self, args):
        if len(args) < 3:
            return
        start = self._as_int(args[0])
        val = self._as_int(args[2])
        if start is not None and val is not None:
            self.db.execute("INSERT OR REPLACE INTO sregs (seg_start, reg, value) VALUES (?, ?, ?)",
                            (start, str(args[1]).lower(), val))

    def _cmd_set_segm_type(self, args):
        if len(args) < 2:
            return
        start, t = self._as_int(args[0]), self._as_int(args[1])
        if start is None or t is None:
            return
        # SEG_CODE=2, SEG_DATA=3, SEG_BSS=6, SEG_STACK=9
        cls = {2: ('CODE', 'code', 1), 3: ('DATA', 'data', 0),
               6: ('DATA', 'data', 0), 9: ('STACK', 'stack', 0)}.get(t)
        if cls:
            self.db.execute("UPDATE segments SET class=?, type=?, executable=? WHERE start_addr=?",
                            (cls[0], cls[1], cls[2], start))

    def _cmd_split_sreg_range(self, args):
        if len(args) < 3:
            return
        ea = self._as_int(args[0])
        val = self._as_int(args[2])
        if ea is not None and val is not None:
            if val in (0xFFFFFFFF, -1, 0xFFFFFFFFFFFFFFFF):
                val = -1  # unknown sreg value
            self.db.execute("INSERT OR REPLACE INTO sreg_ranges (start_addr, end_addr, reg, value) "
                            "VALUES (?, ?, ?, ?)", (ea, -1, str(args[1]).lower(), val))

    # ---- items (code/data boundaries) ---------------------------------
    def _cmd_create_insn(self, args):
        if not args:
            return
        ea = self._as_int(args[0])
        if ea is not None:
            self.db.execute("INSERT OR IGNORE INTO code_seeds (addr) VALUES (?)", (ea,))
            self.db.execute("DELETE FROM data_items WHERE addr=?", (ea,))

    _ITEM_SIZES = {'create_byte': 1, 'create_word': 2, 'create_dword': 4, 'create_qword': 8}

    def _cmd_create_item(self, args, name_l):
        if not args:
            return
        ea = self._as_int(args[0])
        if ea is None:
            return
        size = self._ITEM_SIZES[name_l]
        self.db.execute("INSERT OR REPLACE INTO data_items (addr, size, kind, count) "
                        "VALUES (?, ?, ?, 1)",
                        (ea, size, {1: 'byte', 2: 'word', 4: 'dword', 8: 'qword'}[size]))
        self.db.execute("DELETE FROM code_seeds WHERE addr=?", (ea,))

    def _cmd_create_byte(self, args):
        self._cmd_create_item(args, 'create_byte')

    def _cmd_create_word(self, args):
        self._cmd_create_item(args, 'create_word')

    def _cmd_create_dword(self, args):
        self._cmd_create_item(args, 'create_dword')

    def _cmd_create_qword(self, args):
        self._cmd_create_item(args, 'create_qword')

    def _cmd_make_array(self, args):
        if len(args) < 2:
            return
        ea, count = self._as_int(args[0]), self._as_int(args[1])
        if ea is not None and count:
            row = self.db.conn.execute("SELECT kind FROM data_items WHERE addr=?",
                                       (ea,)).fetchone()
            if row:
                self.db.execute("UPDATE data_items SET count=? WHERE addr=?", (count, ea))
            else:
                self.db.execute("INSERT OR REPLACE INTO data_items (addr, size, kind, count) "
                                "VALUES (?, 1, 'byte', ?)", (ea, count))

    def _cmd_create_strlit(self, args):
        if not args:
            return
        ea = self._as_int(args[0])
        length = self._as_int(args[1]) if len(args) > 1 else 0
        if ea is not None:
            self.db.execute("INSERT OR REPLACE INTO data_items (addr, size, kind, count) "
                            "VALUES (?, ?, 'str', 1)", (ea, length or 1))

    def _cmd_makestruct(self, args):
        if len(args) < 2:
            return
        ea = self._as_int(args[0])
        if ea is not None:
            sid = self._struc_id(str(args[1]))
            size = self.db.conn.execute(
                "SELECT COALESCE(MAX(offset+size), 1) FROM struc_members WHERE struc_id=?",
                (sid,)).fetchone()[0]
            self.db.execute("INSERT OR REPLACE INTO data_items (addr, size, kind, count) "
                            "VALUES (?, ?, ?, 1)", (ea, size, f"struct:{args[1]}"))

    # ---- names / comments / functions ---------------------------------
    def _cmd_set_name(self, args):
        if len(args) < 2:
            return
        ea = self._as_int(args[0])
        if ea is None:
            return
        sym = str(args[1])
        if not sym:
            self.db.execute("DELETE FROM symbols WHERE addr=?", (ea,))
            return
        self.db.execute(
            "INSERT OR REPLACE INTO symbols (addr, name, auto, kind) VALUES (?, ?, 0, 'name')",
            (ea, sym))
        self.db.execute("UPDATE functions SET name=? WHERE start=?", (sym, ea))

    def _cmd_set_cmt(self, args):
        if len(args) < 2:
            return
        ea = self._as_int(args[0])
        if ea is not None:
            rep = self._as_int(args[2]) if len(args) > 2 else 0
            self.db.execute(
                "INSERT OR REPLACE INTO comments (addr, comment, repeatable) VALUES (?, ?, ?)",
                (ea, str(args[1]), rep or 0))

    def _cmd_set_func_cmt(self, args):
        if len(args) < 2:
            return
        ea = self._as_int(args[0])
        if ea is not None:
            # anterior comment on the proc line
            self.db.execute("INSERT OR REPLACE INTO extra_comments (addr, line, comment) "
                            "VALUES (?, 500, ?)", (ea, str(args[1])))

    def _cmd_update_extra_cmt(self, args):
        if len(args) < 3:
            return
        ea = self._as_int(args[0])
        line = self._as_int(args[1])
        if ea is not None and line is not None:
            self.db.execute("INSERT OR REPLACE INTO extra_comments (addr, line, comment) "
                            "VALUES (?, ?, ?)", (ea, line, str(args[2])))

    def _cmd_add_func(self, args):
        if len(args) < 2:
            return
        start, end = self._as_int(args[0]), self._as_int(args[1])
        if start is None:
            return
        if end is None or end <= start or end > 0xFFFFFFFF:
            end = start
        self.db.execute(
            "INSERT INTO functions (start, end, name) VALUES (?, ?, "
            "COALESCE((SELECT name FROM functions WHERE start=?), "
            "(SELECT name FROM symbols WHERE addr=?), ?)) "
            "ON CONFLICT(start) DO UPDATE SET end=excluded.end",
            (start, end, start, start, f"sub_{start:X}"))
        self.db.execute("INSERT OR IGNORE INTO code_seeds (addr) VALUES (?)", (start,))

    def _cmd_set_func_flags(self, args):
        if len(args) < 2:
            return
        start, flags = self._as_int(args[0]), self._as_int(args[1])
        if start is not None and flags is not None:
            self.db.execute("UPDATE functions SET flags=? WHERE start=?", (flags, start))

    def _cmd_set_frame_size(self, args):
        if len(args) < 4:
            return
        vals = self._int_args(args, 4)
        if vals:
            self.db.execute("INSERT OR REPLACE INTO frames (func_start, frsize, frregs, argsize) "
                            "VALUES (?, ?, ?, ?)", tuple(vals))

    def _cmd_define_local_var(self, args):
        if len(args) < 4:
            return
        fstart = self._as_int(args[0])
        loc, vname = str(args[2]), str(args[3])
        m = re.search(r'\[bp([+-]\s*0[xX][0-9A-Fa-f]+|[+-]\s*\d+)\]', loc)
        if fstart is not None and m:
            off = int(m.group(1).replace(' ', ''), 0)
            self.db.execute("INSERT OR REPLACE INTO frame_vars (func_start, offset, name) "
                            "VALUES (?, ?, ?)", (fstart, off, vname))

    # ---- operand formatting -------------------------------------------
    def _cmd_op_hex(self, args):
        if len(args) >= 2:
            self._add_op_override(args[0], args[1], 'hex')

    def _cmd_op_dec(self, args):
        if len(args) >= 2:
            self._add_op_override(args[0], args[1], 'dec')

    def _cmd_op_char(self, args):
        if len(args) >= 2:
            self._add_op_override(args[0], args[1], 'char')

    def _cmd_op_seg(self, args):
        if len(args) >= 2:
            self._add_op_override(args[0], args[1], 'seg')

    def _cmd_op_stkvar(self, args):
        if len(args) >= 2:
            self._add_op_override(args[0], args[1], 'stkvar')

    def _cmd_op_plain_offset(self, args):
        if len(args) >= 3:
            self._add_op_override(args[0], args[1], 'offset', self._as_int(args[2]) or 0)

    def _cmd_op_offset(self, args):
        if len(args) >= 3:
            self._add_op_override(args[0], args[1], 'offset', self._as_int(args[2]) or 0)

    def _cmd_op_enum(self, args):
        if len(args) >= 3:
            enum_id = args[2] if isinstance(args[2], int) else 0
            self._add_op_override(args[0], args[1], 'enum', enum_id)

    def _cmd_op_stroff(self, args):
        if len(args) >= 3:
            sid = self._struc_id(str(args[2])) if not isinstance(args[2], int) else args[2]
            self._add_op_override(args[0], args[1], 'struct', sid)

    # ---- enums / structures -------------------------------------------
    def _cmd_add_enum(self, args):
        if len(args) >= 2:
            return self._enum_id(str(args[1]))
        return None

    def _cmd_add_enum_member(self, args):
        if len(args) < 3:
            return
        eid = self._as_int(args[0])
        val = self._as_int(args[2])
        if eid is not None and val is not None:
            self.db.execute("INSERT OR REPLACE INTO enum_members (enum_id, name, value) "
                            "VALUES (?, ?, ?)", (eid, str(args[1]), val))

    def _cmd_add_struc(self, args):
        if len(args) >= 2:
            return self._struc_id(str(args[1]))
        return None

    def _cmd_add_struc_member(self, args):
        if len(args) < 3:
            return
        sid = self._as_int(args[0])
        off = self._as_int(args[2])
        nbytes = self._as_int(args[5]) if len(args) > 5 else 1
        if sid is not None and off is not None:
            self.db.execute("INSERT OR REPLACE INTO struc_members (struc_id, name, offset, size) "
                            "VALUES (?, ?, ?, ?)", (sid, str(args[1]), off, nbytes or 1))

    def _cmd_settype(self, args):
        if len(args) < 2:
            return
        target = args[0]
        if isinstance(target, str) and target.startswith('mid:'):
            return  # member type info: not rendered
        ea = self._as_int(target)
        if ea is not None:
            self.db.execute("INSERT OR REPLACE INTO extra_comments (addr, line, comment) "
                            "VALUES (?, -1, ?)", (ea, f"; {args[1]}"))

    # ---- config --------------------------------------------------------
    def _cmd_set_processor_type(self, args):
        if args:
            self.db.execute("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
                            ("processor_type", str(args[0])))

    def _cmd_set_inf_attr(self, args):
        if len(args) < 2:
            return
        self.db.execute("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
                        (f"inf_attr:{args[0]}", str(args[1])))
        if str(args[0]) == 'INF_HIGH_OFF':
            v = self._as_int(args[1])
            if v:
                self.db.execute("INSERT OR REPLACE INTO config (key, value) VALUES ('image_end', ?)",
                                (str(v),))

    def _cmd_set_flag(self, args):
        if len(args) >= 3:
            self.db.execute("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
                            (f"flag:{args[0]}", str(args[2])))

    _IDC_CMDS = {
        'delete_all_segments': _cmd_delete_all_segments,
        'add_segm_ex': _cmd_add_segm_ex,
        'segrename': _cmd_segrename,
        'segclass': _cmd_segclass,
        'segdefreg': _cmd_segdefreg,
        'set_segm_type': _cmd_set_segm_type,
        'split_sreg_range': _cmd_split_sreg_range,
        'create_insn': _cmd_create_insn,
        'create_byte': _cmd_create_byte,
        'create_word': _cmd_create_word,
        'create_dword': _cmd_create_dword,
        'create_qword': _cmd_create_qword,
        'make_array': _cmd_make_array,
        'create_strlit': _cmd_create_strlit,
        'makestruct': _cmd_makestruct,
        'set_name': _cmd_set_name,
        'set_cmt': _cmd_set_cmt,
        'set_func_cmt': _cmd_set_func_cmt,
        'update_extra_cmt': _cmd_update_extra_cmt,
        'add_func': _cmd_add_func,
        'set_func_flags': _cmd_set_func_flags,
        'set_frame_size': _cmd_set_frame_size,
        'define_local_var': _cmd_define_local_var,
        'op_hex': _cmd_op_hex,
        'op_dec': _cmd_op_dec,
        'op_char': _cmd_op_char,
        'op_seg': _cmd_op_seg,
        'op_stkvar': _cmd_op_stkvar,
        'op_plain_offset': _cmd_op_plain_offset,
        'op_offset': _cmd_op_offset,
        'op_enum': _cmd_op_enum,
        'op_stroff': _cmd_op_stroff,
        'add_enum': _cmd_add_enum,
        'add_enum_member': _cmd_add_enum_member,
        'add_struc': _cmd_add_struc,
        'add_struc_member': _cmd_add_struc_member,
        'settype': _cmd_settype,
        'set_processor_type': _cmd_set_processor_type,
        'set_inf_attr': _cmd_set_inf_attr,
        'set_flag': _cmd_set_flag,
    }

    def _add_op_override(self, ea_arg, n_arg, kind, arg=0):
        ea, n = self._as_int(ea_arg), self._as_int(n_arg)
        if ea is None or n is None:
            return
        self.db.execute(
            "INSERT OR REPLACE INTO op_overrides (addr, opnum, kind, arg, arg2) VALUES (?, ?, ?, ?, ?)",
            (ea, n & 0x7F, kind, arg, n & 0x80))

    def _apply_call(self, call):
        if self.db is None:
            return
        name = str(self._token_value(call.get('name', '')))
        args = [self._eval(a) for a in (call.get('args') or [])]
        self._apply_named(name, args)

    def _apply_event(self, ev):
        t = ev.get('type')
        if t == 'call':
            self._apply_call(ev)
        elif t == 'assign':
            key = str(self._token_value(ev.get('left', ev.get('name'))))
            self.env[key] = self._eval(ev.get('right', ev.get('expr')))
        elif t == 'define':
            name = str(self._token_value(ev.get('name', '')))
            self.defines_map[name] = ev.get('value')

    def insert_to_db(self):
        if not self.db:
            return
        # Process the ordered event stream (calls/assigns/defines) so that
        # variables such as `x`/`id` behave like real IDC temporaries.
        for ev in self.calls:
            if isinstance(ev, dict):
                self._apply_event(ev)
        # A set_name() may precede the matching add_func(): propagate names.
        self.db.execute("UPDATE functions SET name=(SELECT name FROM symbols WHERE addr=start) "
                        "WHERE EXISTS (SELECT 1 FROM symbols WHERE addr=start AND auto=0)")
        logging.info(f"IDC DB inserts: {len(self.functions)} funcs, {len(self.names)} names, "
                     f"{len(self.comments)} comments, {len(self.calls)} events")


    def __repr__(self):
        return f"IDCScript(includes={len(self.includes)}, defines={len(self.defines)}, variables={len(self.variables)}, functions={len(self.functions)}, operands={len(self.operands)}, comments={len(self.comments)}, names={len(self.names)})"


class IDCGrammar:
    def __init__(self, strict=True):  # Default to strict for better error handling in tests
        self.strict = strict
        self.parser = Lark(IDC_GRAMMAR, start='start', parser='lalr')
        self.transformer = IDCTransformer()

    def parse(self, text, strict=None):
        import logging
        strict = strict or self.strict
        try:
            tree = self.parser.parse(text)
            logging.debug(f"Parser tree: data={tree.data}, children_len={len(tree.children)}")
            script = self.transformer.transform(tree)
            logging.debug(f"Parse result type: {type(script).__name__}, summary: {script}")
            if strict and (len(script.includes) + len(script.defines) + len(script.variables) + len(script.functions) + len(getattr(script, 'operands', [])) + len(getattr(script, 'comments', [])) + len(script.names) + len(getattr(script, 'instructions', []))) == 0:
                logging.warning("Empty script detected in strict mode")
                raise SyntaxError("Parse resulted in empty script")
            return script
        except (UnexpectedToken, UnexpectedCharacters) as e:
            logging.exception("Parse warning")
            if strict:
                raise SyntaxError(str(e)) from e
            return IDCScript()
        except Exception as e:
            logging.exception("Parse error")
            if strict:
                raise SyntaxError(str(e)) from e
            return IDCScript()


class IDCEngine:
    def __init__(self, strict=False):
        self.grammar = IDCGrammar(strict=strict)

    def parse(self, content: str, db=None, mz_data=None, strict=False):
        self.grammar.strict = strict
        try:
            script = self.grammar.parse(content, strict=strict)
            if script is None and strict:
                raise SyntaxError("Parse failed completely")
            logging.debug("Lark parse success")
        except (UnexpectedToken, UnexpectedCharacters) as e:
            logging.exception(f"Lark failed: {e}. Falling back to regex if not strict.")
            if strict:
                raise SyntaxError(str(e)) from e
            script = self._regex_fallback(content, db)
        if script is None:
            script = IDCScript()
        script.db = db
        if db:
            script.insert_to_db()
        return script

    def _regex_fallback(self, content, db):
        import re
        script = IDCScript(db=db)
        # Expanded regex for more cmds
        patterns = {
            'add_func': re.compile(r'add_func\s*\(\s*0X([0-9A-Fa-f]+)\s*,\s*0X([0-9A-Fa-f]+)\s*\);?', re.IGNORECASE),
            'MakeStruct': re.compile(r'MakeStruct\s*\(\s*"([^"]+)"\s*,\s*(\d+)\s*\);?', re.IGNORECASE),
            'set_name': re.compile(r'set_name\s*\(0X([0-9A-Fa-f]+),\s*"([^"]*)"\);?', re.IGNORECASE),
            'set_cmt': re.compile(r'set_cmt\s*\(0X([0-9A-Fa-f]+),\s*"([^"]*)",\s*0\);?', re.IGNORECASE),
            'create_insn': re.compile(r'create_insn\s*\(0X([0-9A-Fa-f]+)\);?', re.IGNORECASE),
            'set_inf_attr': re.compile(r'set_inf_attr\s*\(\s*(\w+),\s*(.+?)\s*\);?', re.IGNORECASE),
            'add_segm_ex': re.compile(r'add_segm_ex\s*\(\s*0X([0-9A-Fa-f]+),\s*0X([0-9A-Fa-f]+),\s*0X([0-9A-Fa-f]+),\s*(\d+),\s*(\d+),\s*(\d+),\s*(\w+)\s*\);?', re.IGNORECASE),
            'SegRename': re.compile(r'SegRename\s*\(\s*0X([0-9A-Fa-f]+),\s*"([^"]*)"\s*\);?', re.IGNORECASE),
            'SegClass': re.compile(r'SegClass\s*\(\s*0X([0-9A-Fa-f]+),\s*"([^"]*)"\s*\);?', re.IGNORECASE),
        }
        lines = content.splitlines()
        for line in lines:
            line = re.sub(r'\t', ' ', line.strip())
            if not line:
                continue
            for cmd, pat in patterns.items():
                match = pat.search(line)
                if match:
                    groups = match.groups()
                    if cmd == 'add_func':
                        script.functions.append({'type': cmd, 'start': int(groups[0], 16), 'end': int(groups[1], 16)})
                    elif cmd == 'MakeStruct':
                        script.variables.append({'type': cmd, 'name': groups[0], 'size': int(groups[1])})
                    elif cmd == 'set_name':
                        addr = int(groups[0], 16)
                        script.names[addr] = groups[1]
                    elif cmd == 'set_cmt':
                        addr = int(groups[0], 16)
                        script.comments.append({'type': cmd, 'addr': addr, 'text': groups[1]})
                    elif cmd == 'create_insn':
                        script.instructions.append({'type': cmd, 'addr': int(groups[0], 16)})
                    elif cmd == 'set_inf_attr':
                        attr = groups[0]
                        val = groups[1].strip()
                        script.operands.append({'type': cmd, 'attr': attr, 'value': val})
                    elif cmd == 'add_segm_ex':
                        addrs = [int(g, 16) for g in groups[:3]]
                        nums = [int(g) for g in groups[3:6]]
                        flag = groups[6]
                        script.operands.append({'type': cmd, 'start': addrs[0], 'end': addrs[1], 'align': addrs[2], 'flags': nums, 'sa': flag})
                    elif cmd in ['SegRename', 'SegClass']:
                        addr = int(groups[0], 16)
                        name = groups[1]
                        script.names[addr] = name if cmd == 'SegRename' else f"class_{name}"
                    break
        logging.info(f"Regex fallback: Parsed {len(script.functions)} funcs, {len(script.operands)} ops, etc.")
        return script


# Main parsing function
def parse_idc(content: str, db=None, mz_data=None, strict=False):
    engine = IDCEngine()
    return engine.parse(content, db, mz_data, strict)


if __name__ == "__main__":
    # Example usage
    from tools.ada_script.database import Database
    db = Database(':memory:')
    result = parse_idc("""
    #include <some_header.idc>
    #define UNLOADED_FILE 1
    static byte my_var;
    __ANON_0 = 0x10013;
    static main() {
        set_name(0x10000, "Test");
        create_insn(x=0x10000);
        op_hex(x, 1);
        set_cmt(0x10000, "Test comment", 0);
    }
    """, db)
    print(result)
