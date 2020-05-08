from ..xtensa_instruction import RRR, RRRN, RRI8, CALLX
from ..xtensa_register import GPR
from ..utils import *

from binaryninja import LLIL_TEMP, LowLevelILLabel, InstructionTextTokenType, InstructionTextToken, InstructionInfo, BranchType

class BREAKN(RRRN):
    mnemonic = "break.n"

    def get_instruction_text(self, data, addr):
        tokens = []
        opcode = InstructionTextTokenType.TextToken
        imm = InstructionTextTokenType.IntegerToken
        filler = InstructionTextTokenType.TextToken

        justify = ' ' * (self.justify - len(self.mnemonic))
        tokens.append(InstructionTextToken(opcode, self.mnemonic))
        tokens.append(InstructionTextToken(filler, justify))
        tokens.append(InstructionTextToken(imm, "{}".format(self.s)))
        return [tokens, self.length]

    def get_instruction_low_level_il(self, data, addr, il):
        il.append(il.unimplemented())
        return self.length

class NOPN(RRRN):
    mnemonic = "nop.n"

    def get_instruction_text(self, data, addr):
        tokens = []
        opcode = InstructionTextTokenType.TextToken
        filler = InstructionTextTokenType.TextToken

        justify = ' ' * (self.justify - len(self.mnemonic))
        tokens.append(InstructionTextToken(opcode, self.mnemonic))
        tokens.append(InstructionTextToken(filler, justify))
        return [tokens, self.length]

    def get_instruction_low_level_il(self, data, addr, il):
        il.append(il.nop())
        return self.length

class RETN(RRRN):
    mnemonic = "ret.n"

    def get_instruction_text(self, data, addr):
        tokens = []
        opcode = InstructionTextTokenType.TextToken
        filler = InstructionTextTokenType.TextToken

        justify = ' ' * (self.justify - len(self.mnemonic))
        tokens.append(InstructionTextToken(opcode, self.mnemonic))
        tokens.append(InstructionTextToken(filler, justify))
        return [tokens, self.length]

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.add_branch(BranchType.FunctionReturn)
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):
        il.append(il.ret(il.reg(4, GPR[0])))

        return self.length

class RETWN(RRRN):
    mnemonic = "retw.n"

    def get_instruction_text(self, data, addr):
        tokens = []
        opcode = InstructionTextTokenType.TextToken
        filler = InstructionTextTokenType.TextToken

        justify = ' ' * (self.justify - len(self.mnemonic))
        tokens.append(InstructionTextToken(opcode, self.mnemonic))
        tokens.append(InstructionTextToken(filler, justify))
        return [tokens, self.length]

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.add_branch(BranchType.FunctionReturn)
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):
        # TODO Need to make sure Windowed Returns have no other affects I need to account for in
        # the IL
        a0_prep = il.and_expr(4, il.reg(4, GPR[0]), il.const(4, 0x3FFFFFFF))
        addr_prep = il.const(4, addr & 0xC0000000)
        il.append(il.ret(il.or_expr(4, a0_prep, addr_prep)))

