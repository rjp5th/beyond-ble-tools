################################################################################
# TopSM Assembler
# Created by Robert Pafford (rjp5th)
#
# Compiles as assembly file into a TopSM binary
# Use topsm_create_patch.py to convert the binary into a RF Patch
#
# SPDX-FileCopyrightText: 2024 Robert Pafford
# SPDX-License-Identifier: MIT
################################################################################

import os
import re
import sys

class ParserLocation:
    def __init__(self, ctx: 'ParserContext', lineidx: int, line: str):
        self.ctx = ctx
        self.lineno = lineidx + 1
        self.line = line
        self.macro = None

    def attach_macro(self, macro: 'MacroDefinition'):
        self.macro = macro

    def create_stack_trace(self, ctx_type = None) -> str:
        if self.macro is None:
            return self.ctx.fmt_location(self.line, self.lineno, ctx_type)
        else:
            msg = self.ctx.fmt_location(self.line, self.lineno, ctx_type)
            msg += "\n\n"
            msg += self.macro.macro_loc.create_stack_trace(ParserContext.CTX_MACRO_DEFINITION)
            return msg

    def __repr__(self):
        in_macro_str = "(MACRO) " if self.ctx.in_macro else ""
        return f"<ParserLoc: {in_macro_str}{self.ctx.filename}:{self.lineno}>"

class ParserContext:
    CTX_FILE_PROCESSING = 1
    CTX_INCLUDE_PROCESSING = 2
    CTX_MACRO_INSTANTIATION = 3
    CTX_MACRO_DEFINITION = 4

    def __init__(self, filename: str, parent_location: 'ParserLocation' = None, parent_ctx_type: int = None,
                 in_macro: bool = False):
        assert (parent_location is not None and parent_ctx_type is not None) or \
               (parent_location is None and parent_ctx_type is None and not in_macro)

        self.filename = filename
        self.parent_location = parent_location
        self.parent_ctx_type = parent_ctx_type
        self.in_macro = in_macro

    def fmt_location(self, line: int, lineno: str, ctx_type):
        if self.in_macro:
            msg = f"In expanded macro '{self.filename}' line {lineno}\n\t{line}"
        elif ctx_type is None or ctx_type == self.CTX_FILE_PROCESSING:
            msg = f"In file '{self.filename}:{lineno}'\n\t{line}"
        elif ctx_type == self.CTX_INCLUDE_PROCESSING:
            msg = f"Included from '{self.filename}:{lineno}'\n\t{line}"
        elif ctx_type == self.CTX_MACRO_INSTANTIATION:
            msg = f"From macro instantiated on '{self.filename}:{lineno}'\n\t{line}"
        elif ctx_type == self.CTX_MACRO_DEFINITION:
            msg = f"Using macro defined on '{self.filename}:{lineno}'\n\t{line}"
        else:
            raise RuntimeError("Invalid stack trace formatter context")

        if self.parent_location is not None:
            parent_ctx_type = self.parent_ctx_type
            msg += "\n" + self.parent_location.create_stack_trace(parent_ctx_type)
        return msg

class CompileError(RuntimeError):
    def __init__(self, loc: 'ParserLocation', err: str):
        self.loc = loc
        self.err = err

    def fmt_compile_trace(self):
        return f"Compilation Error: {self.err}\n" + self.loc.create_stack_trace()

C_IDENTIFIER = re.compile(r"^\s*([_a-zA-Z][_a-zA-Z0-9]{0,255})(\s|$)")
IDENTIFIER_WITH_DOT = re.compile(r"^\s*(\.?[_a-zA-Z][_a-zA-Z0-9]{0,255})(\s|$)")
MATCH_NUMBER = re.compile(r"^\s*(0x[0-9a-fA-F]+|[0-9]+)(\s|$)")
MATCH_QUOTED_STR = re.compile(r'^\s*("(?:[^"\\]|\\.)*")(\s|$)')
MATCH_QUOTED_STR_COMMA = re.compile(r'^\s*("(?:[^"\\]|\\.)*")(\s|$|,)')
COMMA_SEPARATED_ARG = re.compile(r'^\s*([_a-zA-Z0-9]{1,255})(\s|$|,)')
MATCH_DBG_PRINT = re.compile(r"^dbg_print(\d)$")

MATCH_LABEL = re.compile(r"^\s*([_a-zA-Z][_a-zA-Z0-9]{0,255})\:")
MATCH_INST = C_IDENTIFIER
MATCH_OPERAND = re.compile(r"^\s*([_a-zA-Z0-9\(\)\-]{1,255})\s*(,|$)")

REGISTER_LIST = [f"r{i}" for i in range(16)]

class NumberOperand:
    MATCH = re.compile(r"^(0x[0-9a-fA-F]+|\-?[0-9]+)$")
    def __init__(self, psrloc: 'ParserLocation', num: int):
        self.psrloc = psrloc
        self.num = num

    @classmethod
    def try_decode(cls, psrloc, token: str) -> 'NumberOperand | None':
        if cls.MATCH.match(token):
            return cls(psrloc, CompileUnit.decode_integer(psrloc, token))
        else:
            return None

    def encode(self, bitcnt):
        # TODO: signed numbers?
        if self.num < 0 or self.num >= (1 << bitcnt):
            raise CompileError(self.psrloc, "Immediate out of range")
        return self.num

    def __repr__(self):
        return f"<NumberOperand: {self.num}>"

class RegisterOperand:
    def __init__(self, psrloc: 'ParserLocation', regnum: int):
        self.psrloc = psrloc
        self.regnum = regnum

    @classmethod
    def try_decode(cls, psrloc, token: str) -> 'RegisterOperand | None':
        token = token.lower()
        if token in REGISTER_LIST:
            return cls(psrloc, REGISTER_LIST.index(token))
        else:
            return None

    def __repr__(self):
        return f"<RegisterOperand: r{self.regnum}>"

class RegisterPCOperand:
    def __init__(self, psrloc: 'ParserLocation'):
        self.psrloc = psrloc

    @classmethod
    def try_decode(cls, psrloc, token: str) -> 'RegisterOperand | None':
        if token == "pc":
            return cls(psrloc)
        else:
            return None

    def __repr__(self):
        return f"<RegisterPCOperand: pc>"

class IndirectRegisterOperand:
    def __init__(self, psrloc: 'ParserLocation', regnum: int):
        self.psrloc = psrloc
        self.regnum = regnum

    @classmethod
    def try_decode(cls, psrloc, token: str) -> 'IndirectRegisterOperand | None':
        if not len(token) > 3 or token[0] != "(" or token[-1] != ")":
            return None
        token = token[1:-1]
        if token in REGISTER_LIST:
            return cls(psrloc, REGISTER_LIST.index(token))
        else:
            return None

    def __repr__(self):
        return f"<IndirectRegisterOperand: (r{self.regnum})>"

class IdentifierOperand:
    MATCH = re.compile(r"^[_a-zA-Z][_a-zA-Z0-9]{0,255}$")
    def __init__(self, psrloc: 'ParserLocation', identifier: str):
        self.psrloc = psrloc
        self.identifier = identifier

    @classmethod
    def try_decode(cls, psrloc, token: str) -> 'IdentifierOperand | None':
        if cls.MATCH.match(token):
            return cls(psrloc, token)
        else:
            return None

    def __repr__(self):
        return f"<IdentifierOperand: {self.identifier}>"

OPERAND_DECODE_ORDER = [NumberOperand, RegisterOperand, IndirectRegisterOperand, RegisterPCOperand, IdentifierOperand]

########################################
# Instructions
########################################

class InstructionAssembler:
    def __init__(self, ctx: 'CompileUnit', psrloc: 'ParserLocation', inst: str, args: list):
        self.ctx = ctx
        self.psrloc = psrloc
        self.inst = inst.lower()
        self.args = args
        self.pending_labels: 'list[tuple[str, int, int]]' = []

        if self.inst in self.INST_MAP:
            self.opcode = self.INST_MAP[self.inst](self)
        else:
            raise CompileError(psrloc, f"Illegal Instruction: {self.inst}")

    @property
    def opcode_bytes(self):
        return self.opcode.to_bytes(2, 'little')

    def finalize_labels(self):
        for label, start_bit, max_bits in self.pending_labels:
            # We reached finalization. If label doesn't exist now, then that's an error
            if label not in self.ctx.labels:
                raise CompileError(self.psrloc, f"{self.inst}: Undefined label reference")

            addr = self.ctx.labels[label]
            if addr < 0 or addr >= (1 << max_bits):
                raise CompileError(self.psrloc, f"{self.inst}: Label out of range")

            self.opcode |= addr << start_bit

    def _check_optype(self, expected_types):
        if len(self.args) != len(expected_types):
            raise CompileError(self.psrloc, f"{self.inst}: Bad operand count (Expected {len(expected_types)})")

        for i, arg in enumerate(self.args):
            if type(arg) != expected_types[i]:
                raise CompileError(self.psrloc, f"{self.inst}: Operand {i} invalid. Expected {expected_types[i].__name__}")

    def _lkup_optype(self, type_map: 'dict[int, type]'):
        for key, expected_types in type_map.items():
            if len(expected_types) != len(self.args):
                continue

            fail = False
            for i, arg in enumerate(self.args):
                if type(arg) != expected_types[i]:
                    fail = True
                    break
            if fail:
                continue

            return key

        # Couldn't find a match, report error
        raise CompileError(self.psrloc, f"{self.inst}: Bad operand(s)")

    def _lkup_label(self, label, start_bit, max_bits = 10):
        if label in self.ctx.labels:
            addr = self.ctx.labels[label]
            if addr < 0 or addr >= (1 << max_bits):
                raise CompileError(self.psrloc, f"{self.inst}: Label out of range")
            return addr << start_bit
        else:
            self.pending_labels.append((label, start_bit, max_bits))
            return 0

    def _asm_template_alu(self, reg_opcode, imm_opcode):
        TYPE_REGISTER = 1
        TYPE_IMMEDIATE = 2
        optype = self._lkup_optype({
            TYPE_REGISTER: [RegisterOperand, RegisterOperand],
            TYPE_IMMEDIATE: [NumberOperand, RegisterOperand]
        })

        if optype == TYPE_REGISTER:
            opcode = reg_opcode
            opcode |= self.args[0].regnum << 4
            opcode |= self.args[1].regnum
            return opcode
        elif optype == TYPE_IMMEDIATE:
            opcode = imm_opcode
            opcode |= self.args[0].encode(4) << 4
            opcode |= self.args[1].regnum
            return opcode
        else:
            assert False

    def asm_or(self):
        return self._asm_template_alu(0x0000, 0x0200)
    def asm_nop(self):
        self._check_optype([])
        return 0x0000
    def asm_and(self):
        return self._asm_template_alu(0x0400, 0x0600)
    def asm_xor(self):
        return self._asm_template_alu(0x0800, 0x0A00)
    def asm_add(self):
        return self._asm_template_alu(0x1400, 0x1600)
    def asm_sub(self):
        return self._asm_template_alu(0x1800, 0x1A00)
    def asm_cmp(self):
        return self._asm_template_alu(0x1C00, 0x1E00)
    def asm_sad(self):
        return self._asm_template_alu(0x2400, 0x2600)
    def asm_sl0(self):
        return self._asm_template_alu(0x3000, 0x3100)
    def asm_slx(self):
        return self._asm_template_alu(0x3400, 0x3500)
    def asm_sr0(self):
        return self._asm_template_alu(0x3800, 0x3900)
    def asm_srx(self):
        return self._asm_template_alu(0x3C00, 0x3D00)

    def asm_mov(self):
        TYPE_REGISTER = 1
        TYPE_PC_RELATIVE = 2
        TYPE_IMMEDIATE = 3
        optype = self._lkup_optype({
            TYPE_REGISTER: [RegisterOperand, RegisterOperand],
            TYPE_PC_RELATIVE: [RegisterPCOperand, RegisterOperand],
            TYPE_IMMEDIATE: [NumberOperand, RegisterOperand]
        })

        if optype == TYPE_REGISTER:
            opcode = 0x1000  # mov.r
            opcode |= self.args[0].regnum << 4
            opcode |= self.args[1].regnum
            return opcode
        if optype == TYPE_PC_RELATIVE:
            opcode = 0x1100  # mov.pc
            opcode |= self.args[1].regnum
            return opcode
        elif optype == TYPE_IMMEDIATE:
            opcode = 0x1200  # mov.i
            opcode |= self.args[0].encode(5) << 4
            opcode |= self.args[1].regnum
            return opcode
        else:
            assert False

    def _asm_template_bitop(self, opcode):
        self._check_optype([NumberOperand, RegisterOperand])

        opcode |= self.args[0].encode(4) << 4
        opcode |= self.args[1].regnum
        return opcode

    def asm_btst(self):
        return self._asm_template_bitop(0x2200)
    def asm_bclr(self):
        return self._asm_template_bitop(0x2A00)

    # branch instructions

    def asm_jmp(self):
        TYPE_IMMEDIATE = 1
        TYPE_INDIRECT = 2
        optype = self._lkup_optype({
            TYPE_IMMEDIATE: [IdentifierOperand],
            TYPE_INDIRECT: [IndirectRegisterOperand]
        })

        if optype == TYPE_IMMEDIATE:
            dest_label = self.args[0].identifier
            opcode = 0x6000  # jmp.i
            opcode |= self._lkup_label(dest_label, 0)
            return opcode
        elif optype == TYPE_INDIRECT:
            opcode = 0x6C00  # jmp.r
            opcode |= self.args[0].regnum
            return opcode
        else:
            assert False

    def _asm_template_branch(self, opcode):
        self._check_optype([IdentifierOperand])
        dest_label = self.args[0].identifier
        opcode |= self._lkup_label(dest_label, 0)
        return opcode

    def asm_beq(self):
        return self._asm_template_branch(0x4000)
    def asm_bne(self):
        return self._asm_template_branch(0x4400)
    def asm_bmi(self):
        return self._asm_template_branch(0x4800)
    def asm_bpl(self):
        return self._asm_template_branch(0x4C00)
    def asm_jsr(self):
        return self._asm_template_branch(0x6400)
    def asm_loop(self):
        return self._asm_template_branch(0x6800)

    def asm_lmd(self):
        TYPE_IMMEDIATE = 1
        TYPE_INDIRECT = 2
        optype = self._lkup_optype({
            TYPE_IMMEDIATE: [IdentifierOperand, RegisterOperand],
            TYPE_INDIRECT: [IndirectRegisterOperand, RegisterOperand]
        })

        if optype == TYPE_IMMEDIATE:
            dest_label = self.args[0].identifier
            opcode = 0x7800  # lmd.i
            opcode |= self._lkup_label(dest_label, 4, 7)
            opcode |= self.args[1].regnum
            return opcode
        elif optype == TYPE_INDIRECT:
            opcode = 0x6F00  # lmd.r
            opcode |= self.args[0].regnum << 4
            opcode |= self.args[1].regnum
            return opcode
        else:
            assert False

    def asm_rts(self):
        self._check_optype([])
        return 0x7000
    def asm_wait(self):
        self._check_optype([])
        return 0x7100

    def asm_outclr(self):
        self._check_optype([NumberOperand])
        opcode = 0x7200
        opcode |= self.args[0].encode(8)
        return opcode
    def asm_outset(self):
        self._check_optype([NumberOperand])
        opcode = 0x7300
        opcode |= self.args[0].encode(8)
        return opcode
    def asm_input(self):
        self._check_optype([NumberOperand, RegisterOperand])
        opcode = 0x8000
        opcode |= self.args[0].encode(8) << 4
        opcode |= self.args[1].regnum
        return opcode
    def asm_output(self):
        TYPE_IMMEDIATE = 1
        TYPE_INDIRECT = 2
        optype = self._lkup_optype({
            TYPE_IMMEDIATE: [RegisterOperand, NumberOperand],
            TYPE_INDIRECT: [RegisterOperand, IndirectRegisterOperand]
        })

        if optype == TYPE_IMMEDIATE:
            opcode = 0x9000
            opcode |= self.args[0].regnum
            opcode |= self.args[1].encode(8) << 4
            return opcode
        elif optype == TYPE_INDIRECT:
            opcode = 0x6E00
            opcode |= self.args[0].regnum
            opcode |= self.args[1].regnum << 4
            return opcode
        else:
            assert False
    def asm_outbclr(self):
        self._check_optype([NumberOperand, NumberOperand])
        opcode = 0xA000
        opcode |= self.args[1].encode(8) << 4
        opcode |= self.args[0].encode(4)
        return opcode
    def asm_outbset(self):
        self._check_optype([NumberOperand, NumberOperand])
        opcode = 0xB000
        opcode |= self.args[1].encode(8) << 4
        opcode |= self.args[0].encode(4)
        return opcode

    def asm_lli(self):
        TYPE_NUMBER = 1
        TYPE_LABEL = 2
        optype = self._lkup_optype({
            TYPE_NUMBER: [NumberOperand, RegisterOperand],
            TYPE_LABEL: [IdentifierOperand, RegisterOperand]
        })

        opcode = 0xC000
        opcode |= self.args[1].regnum
        if optype == TYPE_NUMBER:
            opcode |= self.args[0].encode(10) << 4
        elif optype == TYPE_LABEL:
            dest_label = self.args[0].identifier
            opcode |= self._lkup_label(dest_label, 4, 10)
        else:
            assert False
        return opcode


    INST_MAP = {
        # Opcode 0X
        "or": asm_or,
        "nop": asm_nop,
        "and": asm_and,
        "xor": asm_xor,
        # Opcode 1X
        "mov": asm_mov,
        "add": asm_add,
        "sub": asm_sub,
        "cmp": asm_cmp,
        # Opcode 2X
        "btst": asm_btst,
        "sad": asm_sad,
        "bclr": asm_bclr,
        # Opcode 3X
        "sl0": asm_sl0,
        "slx": asm_slx,
        "sr0": asm_sr0,
        "srx": asm_srx,
        # Opcode 4X
        "beq": asm_beq,
        "bne": asm_bne,
        "bmi": asm_bmi,
        "bpl": asm_bpl,
        # Opcode 6X
        "jmp": asm_jmp,
        "jsr": asm_jsr,
        "loop": asm_loop,
        # Opcode 7X
        "rts": asm_rts,
        "wait": asm_wait,
        "outclr": asm_outclr,
        "outset": asm_outset,
        "lmd": asm_lmd,
        # Higher Opcodes (8X-FX)
        "input": asm_input,
        "output": asm_output,
        "outbclr": asm_outbclr,
        "outbset": asm_outbset,
        "lli": asm_lli
    }

########################################
# Assembler
########################################

class MacroDefinition:

    def __init__(self, location: 'ParserLocation', name: str, args: 'list[str]'):
        self.name = name
        self.args = args
        self.lines: 'list[str]' = []
        self.macro_loc = location

    def append_line(self, line: str):
        self.lines.append(line)

    def create_local_defines(self, psrloc, inst_args):
        if len(inst_args) != len(self.args):
            raise CompileError(psrloc, "Argument count does not match macro")
        return dict(zip(self.args, inst_args))

class CompileUnit:
    _compiled = False
    MEMORY_SIZE = 0x400

    def __init__(self, src_filename: str):
        self.src_filename = src_filename
        self.defines = {}
        self.dbg_strings = []
        self.macros: 'dict[str, MacroDefinition]' = {}
        self.cur_block = None
        self.cur_addr = 0
        self.next_invalid_addr = self.MEMORY_SIZE
        self.memory_blocks = {}
        self.labels = {}

    def _add_dbg_str(self, string, cnt) -> int:
        self.dbg_strings.append((string, cnt))
        return len(self.dbg_strings) + 2

    def _write_word(self, psrloc, word):
        if self.cur_addr >= self.next_invalid_addr:
            if self.next_invalid_addr == self.MEMORY_SIZE:
                reason = "No more program memory available"
            else:
                reason = "Overlaps with other memory block"
            raise CompileError(psrloc, f"Cannot allocate space for word in program memory ({reason})")

        if self.cur_block is None:
            self.cur_block = []
            self.memory_blocks[self.cur_addr] = self.cur_block
        if not isinstance(word, InstructionAssembler) and (word < 0 or word >= (1 << 16)):
            raise CompileError(psrloc, "Cannot write requested word (does not fit into 16-bits)")

        self.cur_block.append(word)
        self.cur_addr += 1

    def _create_label(self, psrloc, label):
        if label in self.labels:
            raise CompileError(psrloc, "Label is already defined")
        if self.cur_addr >= self.MEMORY_SIZE:
            raise CompileError(psrloc, "Cannot create label outside of program memory")
        self.labels[label] = self.cur_addr

    def _set_addr(self, addr):
        # Clear current block
        self.cur_block = None
        self.cur_addr = addr

        # See what the next invalid address
        # Note this also checks for current address. We won't error out here, in case they want to define labels
        # at address, but any attempts to write will error
        try:
            self.next_invalid_addr = next(i for i in sorted(self.memory_blocks.keys()) if i >= addr)
        except StopIteration:
            # Nothing above us, set next invalid to end of code memory
            self.next_invalid_addr = self.MEMORY_SIZE

    @staticmethod
    def preproc_next_token(line: str, pattern: 're.Pattern', startidx=0):
        result = pattern.match(line[startidx:])
        if not result:
            return startidx, None
        return startidx + result.end(), result.group(1)

    @staticmethod
    def strip_comment(line: str) -> str:
        in_quote = False
        in_escaped_quote = False
        for i, c in enumerate(line):
            if in_escaped_quote:
                in_escaped_quote = False
            elif in_quote:
                if c == "\"":
                    in_quote = False
                elif c == "\\":
                    in_escaped_quote = True
            else:
                if c == "\"":
                    in_quote = True
                elif c == ";":
                    # Found comment. kill rest of line
                    return line[:i]
        return line

    @staticmethod
    def decode_integer(psrloc, token: str):
        try:
            if token.lower().startswith("0x"):
                return int(token[2:], 16)
            else:
                return int(token)
        except ValueError:
            raise CompileError(psrloc, "Invalid integer")

    def _preprocess(self, file, context: 'ParserContext', local_defines={}):

        def fixup_dbgprint(line: str):
            nextidx, first_token = self.preproc_next_token(line, IDENTIFIER_WITH_DOT)

            # Before anything else, apply dbg print
            # I believe this is done with perl scripts before the compiler, but doing it here will have the same effect
            if first_token is None:
                return line
            result = MATCH_DBG_PRINT.match(first_token.lower())
            if result:
                arg_cnt = int(result.group(1))

                nextidx, dbg_str = self.preproc_next_token(line, MATCH_QUOTED_STR_COMMA, nextidx)
                if dbg_str is None:
                    raise CompileError(psrloc, "Expected quoted string after dbg_print statemenet")

                idx = self._add_dbg_str(dbg_str, arg_cnt)

                remaining = line[nextidx:]

                return (f"_DBG{arg_cnt} {idx} " + remaining).strip()
            else:
                return line


        def fixup_subst(line: str):
            in_token = False
            in_quote = False
            in_escaped_quote = False
            token_start = None
            line_out = ""
            for i,c in enumerate(line):
                if in_escaped_quote:
                    in_escaped_quote = False
                elif in_quote:
                    if c == "\"":
                        in_quote = False
                    elif c == "\\":
                        in_escaped_quote = True
                    line_out += c
                elif in_token:
                    if not (c.isalnum() or c == "_"):
                        in_token = False
                        token = line[token_start:i]
                        if token in local_defines and len(line_out) > 0 and line_out[-1] == "\\":
                            line_out = line_out[:-1]
                            line_out += local_defines[token]
                        elif token in self.defines:
                            line_out += self.defines[token]
                        else:
                            line_out += token
                        line_out += c
                        if c == "\"":
                            in_quote = True
                else:
                    if c == "\"":
                        in_quote = True
                        line_out += c
                    elif c.isalnum() or c == "_":
                        in_token = True
                        token_start = i
                    else:
                        line_out += c
            if in_token:
                token = line[token_start:]
                if token in local_defines and len(line_out) > 0 and line_out[-1] == "\\":
                    line_out = line_out[:-1]
                    line_out += local_defines[token]
                elif token in self.defines:
                    line_out += self.defines[token]
                else:
                    line_out += token
            return line_out

        current_macro: 'None | MacroDefinition' = None

        code_eval_disabled = False
        if_stack = []
        def add_if(evaluate_true: bool):
            nonlocal code_eval_disabled, if_stack
            if_stack.append(evaluate_true)
            code_eval_disabled = not all(if_stack)
        def add_endif():
            nonlocal code_eval_disabled, if_stack
            if len(if_stack) == None:
                raise CompileError(psrloc, "Unexpected endif")
            if_stack.pop()
            code_eval_disabled = not all(if_stack)

        for lineidx, line in enumerate(file):
            # Strip line and whitespace at end
            line = self.strip_comment(line).strip()
            psrloc = ParserLocation(context, lineidx, line)
            if current_macro is not None:
                psrloc.attach_macro(current_macro)

            line = fixup_dbgprint(line)
            nextidx, first_token = self.preproc_next_token(line, IDENTIFIER_WITH_DOT)

            if current_macro is not None:
                if first_token is None:
                    current_macro.append_line(line)
                    continue
                first_token_lower = first_token.lower()
                if first_token_lower == ".macro":
                    raise CompileError(psrloc, "Cannot nest macros")
                elif first_token_lower == ".endm":
                    self.macros[current_macro.name] = current_macro
                    current_macro = None
                else:
                    current_macro.append_line(line)
                continue
            if code_eval_disabled:
                if first_token is None:
                    continue
                first_token_lower = first_token.lower()
                if first_token_lower == ".endif":
                    add_endif()
                elif first_token_lower == ".ifdef" or first_token_lower == ".ifndef":
                    # Add an if, but evaluate to False since we're in a code eval disabled block
                    add_if(False)
                continue

            if first_token is None:
                fixed = fixup_subst(line)
                if len(fixed) > 0:
                    yield psrloc, fixed
            elif first_token[0] == ".":
                # Preprocessor token, handle it
                token_lower = first_token.lower()
                if token_lower == ".include":
                    nextidx, second_token = self.preproc_next_token(line, MATCH_QUOTED_STR, nextidx)
                    if second_token is None:
                        raise CompileError(psrloc, "Invalid include string")
                    if nextidx != len(line):
                        raise CompileError(psrloc, "Unexpected token after include location")
                    if context.in_macro:
                        raise CompileError(psrloc, "Cannot include from within macro")

                    filepath = os.path.join(os.path.dirname(context.filename), second_token.strip("\""))
                    if not os.path.exists(filepath):
                        raise CompileError(psrloc, f"Cannot locate include file \"{filepath}\"")
                    with open(filepath) as included_file:
                        new_ctx = ParserContext(filepath, psrloc, ParserContext.CTX_INCLUDE_PROCESSING)
                        yield from self._preprocess(included_file, new_ctx)
                elif token_lower == ".ifdef":
                    nextidx, name_token = self.preproc_next_token(line, C_IDENTIFIER, nextidx)
                    if name_token is None:
                        raise CompileError(psrloc, "Invalid identifier for ifdef")
                    elif nextidx != len(line):
                        raise CompileError(psrloc, "Unexpected token after ifdef")
                    add_if(name_token in self.defines)
                elif token_lower == ".ifndef":
                    nextidx, name_token = self.preproc_next_token(line, C_IDENTIFIER, nextidx)
                    if name_token is None:
                        raise CompileError(psrloc, "Invalid identifier for ifndef")
                    elif nextidx != len(line):
                        raise CompileError(psrloc, "Unexpected token after ifndef")
                    add_if(name_token not in self.defines)
                elif token_lower == ".endif":
                    add_endif()
                elif token_lower == ".define":
                    nextidx, name_token = self.preproc_next_token(line, C_IDENTIFIER, nextidx)
                    if name_token is None:
                        raise CompileError(psrloc, "Invalid identifier for define")
                    value = line[nextidx:].strip()
                    self.defines[name_token] = value
                elif token_lower == ".macro":
                    nextidx, name_token = self.preproc_next_token(line, C_IDENTIFIER, nextidx)
                    if name_token is None:
                        raise CompileError(psrloc, "Invalid identifier for macro")
                    macro_args = []
                    while nextidx != len(line):
                        nextidx, arg = self.preproc_next_token(line, COMMA_SEPARATED_ARG, nextidx)
                        if arg is None:
                            raise CompileError(psrloc, "Invalid macro argument")
                        macro_args.append(arg)
                    current_macro = MacroDefinition(psrloc, name_token.lower(), macro_args)
                elif token_lower == ".org":
                    preprocessed = fixup_subst(line[nextidx:])
                    preproc_nextidx, dest_str = self.preproc_next_token(preprocessed, MATCH_NUMBER)
                    if dest_str is None:
                        raise CompileError(psrloc, "Invalid destination address")
                    if preproc_nextidx != len(dest_str):
                        raise CompileError(psrloc, "Unexpected token after destination address")
                    dest = self.decode_integer(psrloc, dest_str)
                    self._set_addr(dest)

                elif token_lower == ".data":
                    preprocessed = fixup_subst(line[nextidx:])
                    preproc_nextidx, val_str = self.preproc_next_token(preprocessed, MATCH_NUMBER)
                    if val_str is None:
                        raise CompileError(psrloc, "Invalid data value")
                    if preproc_nextidx != len(val_str):
                        raise CompileError(psrloc, "Unexpected token after data value")
                    val = self.decode_integer(psrloc, val_str)
                    self._write_word(psrloc, val)

                else:
                    raise CompileError(psrloc, "Invalid preprocessor directive")
            else:
                token_lower = first_token.lower()

                if token_lower in self.macros:
                    macro = self.macros[token_lower]
                    psrloc.attach_macro(macro)
                    macro_args = []
                    while nextidx != len(line):
                        nextidx, arg = self.preproc_next_token(line, COMMA_SEPARATED_ARG, nextidx)
                        if arg is None:
                            raise CompileError(psrloc, "Invalid macro argument")
                        macro_args.append(arg)
                    macro_defs = macro.create_local_defines(psrloc, macro_args)
                    new_ctx = ParserContext(token_lower, psrloc, ParserContext.CTX_MACRO_INSTANTIATION, in_macro=True)
                    yield from self._preprocess(macro.lines, new_ctx, macro_defs)
                else:
                    # Not preprocessor token, check for assign statement)
                    nextidx, second_token = self.preproc_next_token(line, IDENTIFIER_WITH_DOT, nextidx)
                    if second_token is None or second_token.lower() != ".assign":
                        fixed = fixup_subst(line)
                        if len(fixed) > 0:
                            yield psrloc, fixed
                    else:
                        # This is an assign statement
                        nextidx, num_token = self.preproc_next_token(line, MATCH_NUMBER, nextidx)
                        if num_token is None or nextidx != len(line):
                            raise CompileError(psrloc, "Unexpected sign right operand. Must be integer")

                        if first_token in self.defines and num_token != self.defines[first_token]:
                            raise CompileError(psrloc, "Token already defined")

                        self.defines[first_token] = num_token

        if len(if_stack) > 0:
            raise CompileError(psrloc, "End of file reached before finding .endif")
        elif current_macro is not None:
            raise CompileError(psrloc, "End of file reached before finding .endm")

    def _handle_line(self, psrloc, line: str):
        # Process leading label
        nextidx, label_token = self.preproc_next_token(line, MATCH_LABEL)
        if label_token is not None:
            self._create_label(psrloc, label_token)

        # Found end of line, break here
        if nextidx == len(line):
            return

        # Cut off instruction token
        nextidx, inst_token = self.preproc_next_token(line, MATCH_INST, nextidx)

        if inst_token is None:
            raise CompileError(psrloc, "Illegal instruction token")

        args = []
        while nextidx != len(line):
            nextidx, arg_token = self.preproc_next_token(line, MATCH_OPERAND, nextidx)
            if arg_token is None:
                raise CompileError(psrloc, "Illegal instruction operand")

            for opcls in OPERAND_DECODE_ORDER:
                operand = opcls.try_decode(psrloc, arg_token)
                if operand is not None:
                    break

            if operand is None:
                raise CompileError(psrloc, "Illegal instruction operand")

            args.append(operand)

        asm = InstructionAssembler(self, psrloc, inst_token, args)
        self._write_word(psrloc, asm)

    def _finalize_labels(self):
        for block in self.memory_blocks.values():
            for entry in block:
                if isinstance(entry, InstructionAssembler):
                    entry.finalize_labels()

    def compile(self):
        if self._compiled:
            raise RuntimeError("File already compiled")

        root_ctx = ParserContext(self.src_filename)
        with open(self.src_filename) as f:
            for loc, line in self._preprocess(f, root_ctx):
                self._handle_line(loc, line)
        self._finalize_labels()
        self._compiled = True

    def write_output(self, f):
        if not self._compiled:
            raise RuntimeError("File must be compiled first")
        cur_addr = 0
        for i, block in sorted(self.memory_blocks.items()):
            padding_bytes = (i - cur_addr) * 2
            assert padding_bytes >= 0, "Multiple memory regions defined with overlapping contents"
            f.write(b"\0" * padding_bytes)
            data = b"".join(map(lambda x: (x.opcode_bytes if isinstance(x, InstructionAssembler) else x.to_bytes(2, 'little')), block))
            f.write(data)
            cur_addr = i + len(block)

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} [input asm] [output bin]", file=sys.stderr)
        exit(1)

    try:
        unit = CompileUnit(sys.argv[1])
        unit.compile()
        with open(sys.argv[2], "wb") as f:
            unit.write_output(f)

    except CompileError as err:
        print(err.fmt_compile_trace())

if __name__ == "__main__":
    main()
