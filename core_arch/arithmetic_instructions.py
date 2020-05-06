from ..xtensa_instruction import RRR, RRRN, RRI8
from ..xtensa_register import GPR
from ..utils import *

from binaryninja import LLIL_TEMP, LowLevelILLabel, InstructionTextTokenType, InstructionTextToken


class ABS(RRR):
    mnemonic = "abs"

    def get_instruction_text(self, data, addr):
        tokens = []
        opcode = InstructionTextTokenType.TextToken
        register = InstructionTextTokenType.RegisterToken
        filler = InstructionTextTokenType.TextToken
        sep = InstructionTextTokenType.OperandSeparatorToken

        justify = ' ' * (self.justify - len(self.mnemonic))
        tokens.append(InstructionTextToken(opcode, self.mnemonic))
        tokens.append(InstructionTextToken(filler, justify))
        tokens.append(InstructionTextToken(register, GPR[self.r]))
        tokens.append(InstructionTextToken(sep, ','))
        tokens.append(InstructionTextToken(register, GPR[self.t]))
        return [tokens, self.length]

    def get_instruction_low_level_il(self, data, addr, il):
        negative_label = LowLevelILLabel()
        positive_label = LowLevelILLabel()
        post_label = LowLevelILLabel()

        # Check if we have a positive or negative number
        cmp_expr = il.compare_signed_greater_equal(
            4, il.sign_extend(4, il.reg(4, GPR[self.t])), il.const(4, 0))
        if_expr = il.if_expr(cmp_expr, positive_label, negative_label)
        il.append(if_expr)

        # if it is negative, we want to negate it
        il.mark_label(negative_label)
        il.append(il.set_reg(4, GPR[self.r], il.neg_expr(4, il.reg(4, GPR[self.t]))))
        il.append(il.goto(post_label))

        # otherwise, just move the value
        il.mark_label(positive_label)
        il.append(il.set_reg(4, GPR[self.r], il.reg(4, GPR[self.t])))
        il.append(il.goto(post_label))

        il.mark_label(post_label)

        return self.length


class ADD(RRR):
    mnemonic = "add"

    def get_instruction_low_level_il(self, data, addr, il):
        il.append(il.set_reg(4, GPR[self.r], il.add(
            4, il.reg(4, GPR[self.s]), il.reg(4, GPR[self.t]))))

        return self.length


class ADDI(RRI8):
    mnemonic = "addi"

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
        tokens.append(InstructionTextToken(imm, "{}".format(twos_comp(self.imm8, 8))))
        return [tokens, self.length]

    def get_instruction_low_level_il(self, data, addr, il):
        il.append(il.set_reg(4, GPR[self.t], il.add(4, il.reg(4, GPR[self.s]),
                                               il.sign_extend(4, il.const(1, self.imm8)))))

        return self.length


class ADDMI(RRI8):
    mnemonic = "addmi"

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
        tokens.append(InstructionTextToken(imm, hex(twos_comp(self.imm8, 8) << 8), value=twos_comp(self.imm8, 8) << 8))
        return [tokens, self.length]

    def get_instruction_low_level_il(self, data, addr, il):
        il.append(il.set_reg(4, GPR[self.t], il.add(4, il.reg(4, GPR[self.s]), il.shift_left(
            4, il.sign_extend(4, il.const(1, self.imm8)), il.const(4, 8)))))

        return self.length


class ADDX2(RRR):
    mnemonic = "addx2"

    def get_instruction_low_level_il(self, data, addr, il):
        il.append(il.set_reg(4, GPR[self.r], il.add(4, il.shift_left(
            4, il.reg(4, GPR[self.s]), il.const(4, 1)), il.reg(4, GPR[self.t]))))

        return self.length


class ADDX4(RRR):
    mnemonic = "addx4"

    def get_instruction_low_level_il(self, data, addr, il):
        il.append(il.set_reg(4, GPR[self.r], il.add(4, il.shift_left(
            4, il.reg(4, GPR[self.s]), il.const(4, 2)), il.reg(4, GPR[self.t]))))

        return self.length


class ADDX8(RRR):
    mnemonic = "addx8"

    def get_instruction_low_level_il(self, data, addr, il):
        il.append(il.set_reg(4, GPR[self.r], il.add(4, il.shift_left(
            4, il.reg(4, GPR[self.s]), il.const(4, 3)), il.reg(4, GPR[self.t]))))

        return self.length

class SLL(RRR):
    mnemonic = "sll"

    def get_instruction_text(self, data, addr):
        tokens = []
        opcode = InstructionTextTokenType.TextToken
        register = InstructionTextTokenType.RegisterToken
        filler = InstructionTextTokenType.TextToken
        sep = InstructionTextTokenType.OperandSeparatorToken

        justify = ' ' * (self.justify - len(self.mnemonic))
        tokens.append(InstructionTextToken(opcode, self.mnemonic))
        tokens.append(InstructionTextToken(filler, justify))
        tokens.append(InstructionTextToken(register, GPR[self.r]))
        tokens.append(InstructionTextToken(sep, ','))
        tokens.append(InstructionTextToken(register, GPR[self.s]))
        return [tokens, self.length]

    def get_instruction_low_level_il(self, data, addr, il):
        il.append(il.set_reg(4, GPR[self.r], il.shift_left(4, il.reg(4, GPR[self.s]), il.reg(4, "sar"))))
        return self.length


class SLLI(RRR):
    mnemonic = "slli"

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
        tokens.append(InstructionTextToken(register, GPR[self.r]))
        tokens.append(InstructionTextToken(sep, ','))
        tokens.append(InstructionTextToken(register, GPR[self.s]))
        tokens.append(InstructionTextToken(sep, ','))

        imm_prep = self.t + ((self.op2 & 0x1) << 4)
        tokens.append(InstructionTextToken(imm, "{}".format(imm_prep)))
        return [tokens, self.length]

    def get_instruction_low_level_il(self, data, addr, il):
        imm_prep = self.t + ((self.op2 & 0x1) << 4)
        il.append(il.set_reg(4, GPR[self.r], il.shift_left(4, il.reg(4, GPR[self.s]), il.const(4, imm_prep))))
        return self.length

class SRA(RRR):
    mnemonic = "sra"

    def get_instruction_text(self, data, addr):
        tokens = []
        opcode = InstructionTextTokenType.TextToken
        register = InstructionTextTokenType.RegisterToken
        filler = InstructionTextTokenType.TextToken
        sep = InstructionTextTokenType.OperandSeparatorToken

        justify = ' ' * (self.justify - len(self.mnemonic))
        tokens.append(InstructionTextToken(opcode, self.mnemonic))
        tokens.append(InstructionTextToken(filler, justify))
        tokens.append(InstructionTextToken(register, GPR[self.r]))
        tokens.append(InstructionTextToken(sep, ','))
        tokens.append(InstructionTextToken(register, GPR[self.t]))
        return [tokens, self.length]

    def get_instruction_low_level_il(self, data, addr, il):
        il.append(il.set_reg(4, GPR[self.r], il.arith_shift_right(4, il.reg(4, GPR[self.t]), il.reg(4, "sar"))))
        return self.length


class SRAI(RRR):
    mnemonic = "srai"

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
        tokens.append(InstructionTextToken(register, GPR[self.r]))
        tokens.append(InstructionTextToken(sep, ','))
        tokens.append(InstructionTextToken(register, GPR[self.t]))
        tokens.append(InstructionTextToken(sep, ','))

        imm_prep = self.s + ((self.op2 & 0x1) << 4)
        tokens.append(InstructionTextToken(imm, "{}".format(imm_prep)))
        return [tokens, self.length]

    def get_instruction_low_level_il(self, data, addr, il):
        imm_prep = self.s + ((self.op2 & 0x1) << 4)
        il.append(il.set_reg(4, GPR[self.r], il.arith_shift_right(4, il.reg(4, GPR[self.t]), il.const(4, imm_prep))))
        return self.length

class SRC(RRR):
    mnemonic = "src"

    def get_instruction_low_level_il(self, data, addr, il):
        big_reg = LLIL_TEMP(il.temp_reg_count)

        big_reg_expr = il.set_reg(8, big_reg, il.add(8, il.reg(4, GPR[self.t]), il.shift_left(8, il.reg(4, GPR[self.s]), il.const(4, 32))))
        il.append(il.set_reg(4, GPR[self.r], il.logical_shift_right(4, big_reg_expr, il.reg(4, "sar"))))
        return self.length

class SRL(RRR):
    mnemonic = "srl"

    def get_instruction_text(self, data, addr):
        tokens = []
        opcode = InstructionTextTokenType.TextToken
        register = InstructionTextTokenType.RegisterToken
        filler = InstructionTextTokenType.TextToken
        sep = InstructionTextTokenType.OperandSeparatorToken

        justify = ' ' * (self.justify - len(self.mnemonic))
        tokens.append(InstructionTextToken(opcode, self.mnemonic))
        tokens.append(InstructionTextToken(filler, justify))
        tokens.append(InstructionTextToken(register, GPR[self.r]))
        tokens.append(InstructionTextToken(sep, ','))
        tokens.append(InstructionTextToken(register, GPR[self.t]))
        return [tokens, self.length]

    def get_instruction_low_level_il(self, data, addr, il):
        il.append(il.set_reg(4, GPR[self.r], il.logical_shift_right(4, il.reg(4, GPR[self.t]), il.reg(4, "sar"))))
        return self.length


class SRLI(RRR):
    mnemonic = "srli"

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
        tokens.append(InstructionTextToken(register, GPR[self.r]))
        tokens.append(InstructionTextToken(sep, ','))
        tokens.append(InstructionTextToken(register, GPR[self.t]))
        tokens.append(InstructionTextToken(sep, ','))
        tokens.append(InstructionTextToken(imm, "{}".format(self.s)))
        return [tokens, self.length]

    def get_instruction_low_level_il(self, data, addr, il):
        il.append(il.set_reg(4, GPR[self.r], il.arith_shift_right(4, il.reg(4, GPR[self.t]), il.const(4, self.s))))
        return self.length

class SUB(RRR):
    mnemonic = "sub"

    def get_instruction_low_level_il(self, data, addr, il):
        il.append(il.set_reg(4, GPR[self.r], il.sub(
            4, il.reg(4, GPR[self.s]), il.reg(4, GPR[self.t]))))

        return self.length

class SUBX2(RRR):
    mnemonic = "subx2"

    def get_instruction_low_level_il(self, data, addr, il):
        il.append(il.set_reg(4, GPR[self.r], il.sub(4, il.shift_left(
            4, il.reg(4, GPR[self.s]), il.const(4, 1)), il.reg(4, GPR[self.t]))))

        return self.length


class SUBX4(RRR):
    mnemonic = "subx4"

    def get_instruction_low_level_il(self, data, addr, il):
        il.append(il.set_reg(4, GPR[self.r], il.sub(4, il.shift_left(
            4, il.reg(4, GPR[self.s]), il.const(4, 2)), il.reg(4, GPR[self.t]))))

        return self.length


class SUBX8(RRR):
    mnemonic = "subx8"

    def get_instruction_low_level_il(self, data, addr, il):
        il.append(il.set_reg(4, GPR[self.r], il.sub(4, il.shift_left(
            4, il.reg(4, GPR[self.s]), il.const(4, 3)), il.reg(4, GPR[self.t]))))

        return self.length