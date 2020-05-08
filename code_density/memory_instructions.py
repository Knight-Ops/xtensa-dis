from ..xtensa_instruction import RRR, RRRN, RRI8, RI7
from ..xtensa_register import GPR
from ..utils import *

from binaryninja import LLIL_TEMP, LowLevelILLabel, InstructionTextTokenType, InstructionTextToken

class L32IN(RRRN):
    mnemonic = "l32i.n"

    def get_instruction_text(self, data, addr):
        tokens = []
        opcode = InstructionTextTokenType.TextToken
        register = InstructionTextTokenType.RegisterToken
        filler = InstructionTextTokenType.TextToken
        sep = InstructionTextTokenType.OperandSeparatorToken
        imm = InstructionTextTokenType.IntegerToken

        justify = ' ' * (self.justify - len(self.mnemonic))
        tokens.append(InstructionTextToken(opcode, self.mnemonic))
        tokens.append(InstructionTextToken(filler, justify))
        tokens.append(InstructionTextToken(register, GPR[self.t]))
        tokens.append(InstructionTextToken(sep, ','))
        tokens.append(InstructionTextToken(register, GPR[self.s]))
        tokens.append(InstructionTextToken(sep, ','))
        tokens.append(InstructionTextToken(imm, "{}".format(self.r << 2)))
        return [tokens, self.length]

    def get_instruction_low_level_il(self, data, addr, il):
        il.append(il.set_reg(4, GPR[self.t], il.load(4, il.add(4, il.reg(4, GPR[self.s]), il.const(4, self.r << 2)))))
        return self.length

class MOVN(RRRN):
    mnemonic = "mov.n"

    def get_instruction_text(self, data, addr):
        tokens = []
        opcode = InstructionTextTokenType.TextToken
        register = InstructionTextTokenType.RegisterToken
        filler = InstructionTextTokenType.TextToken
        sep = InstructionTextTokenType.OperandSeparatorToken

        justify = ' ' * (self.justify - len(self.mnemonic))
        tokens.append(InstructionTextToken(opcode, self.mnemonic))
        tokens.append(InstructionTextToken(filler, justify))
        tokens.append(InstructionTextToken(register, GPR[self.t]))
        tokens.append(InstructionTextToken(sep, ','))
        tokens.append(InstructionTextToken(register, GPR[self.s]))
        return [tokens, self.length]

    def get_instruction_low_level_il(self, data, addr, il):
        il.append(il.set_reg(4, GPR[self.t], il.reg(4, GPR[self.s])))
        return self.length

class MOVIN(RI7):
    mnemonic = "movi.n"

    def get_instruction_low_level_il(self, data, addr, il):
        imm_prep = extend_with_msb(self.imm7)
        # TODO Make sure that this negative number is properly translated in the IL
        il.append(il.set_reg(4, GPR[self.s], il.const(4, imm_prep)))
        return self.length

class S32IN(RRRN):
    mnemonic = "s32i.n"

    def get_instruction_text(self, data, addr):
        tokens = []
        opcode = InstructionTextTokenType.TextToken
        register = InstructionTextTokenType.RegisterToken
        filler = InstructionTextTokenType.TextToken
        sep = InstructionTextTokenType.OperandSeparatorToken
        imm = InstructionTextTokenType.IntegerToken

        justify = ' ' * (self.justify - len(self.mnemonic))
        tokens.append(InstructionTextToken(opcode, self.mnemonic))
        tokens.append(InstructionTextToken(filler, justify))
        tokens.append(InstructionTextToken(register, GPR[self.t]))
        tokens.append(InstructionTextToken(sep, ','))
        tokens.append(InstructionTextToken(register, GPR[self.s]))
        tokens.append(InstructionTextToken(sep, ','))

        imm_prep = self.r << 2
        tokens.append(InstructionTextToken(imm, "{}".format(imm_prep)))
        return [tokens, self.length]

    def get_instruction_low_level_il(self, data, addr, il):
        imm_prep = self.r << 2
        il.append(il.store(4, il.add(4, il.reg(4, GPR[self.s]), il.const(4, imm_prep)), il.reg(4, GPR[self.t])))
        return self.length