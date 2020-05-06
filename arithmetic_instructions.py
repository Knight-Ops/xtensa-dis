from .xtensa_instruction import RRR, RRRN, RRI8
from .xtensa_register import GPR
from .utils import twos_comp

from binaryninja import LLIL_TEMP, LowLevelILLabel, InstructionTextTokenType, InstructionTextToken


class ABSS(RRR):
    mnemonic = "abs.s"

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

    # TODO Check if these registers are correctly Floating Point registers
    def get_instruction_low_level_il(self, data, addr, il):
        il.append(il.set_reg(4, GPR[self.r], il.float_abs(4, il.reg(4, GPR[self.t]))))

        return self.length



class ADDN(RRRN):
    mnemonic = "add.n"

    def get_instruction_low_level_il(self, data, addr, il):
        il.append(il.set_reg(4, GPR[self.r], il.add(
            4, il.reg(4, GPR[self.s]), il.reg(4, GPR[self.t]))))

        return self.length


class ADDS(RRR):
    mnemonic = "add.s"

    def get_instruction_low_level_il(self, data, addr, il):
        il.append(il.set_reg(4, GPR[self.r], il.float_add(
            4, il.reg(4, GPR[self.s]), il.reg(4, GPR[self.t]))))

        return self.length

# TODO Why is this result in t instead of r?


class ADDIN(RRRN):
    mnemonic = "addi.n"

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

        if self.t == 0:
            imm_val = -1
        else:
            imm_val = self.t

        # tokens.append(InstructionTextToken(imm, hex(imm_val), value= hex(immva)))
        return [tokens, self.length]

    def get_instruction_low_level_il(self, data, addr, il):
        zero_label = LowLevelILLabel()
        nonzero_label = LowLevelILLabel()
        post_label = LowLevelILLabel()

        cmp_expr = il.compare_unsigned_greater_equal(
            4, il.reg(4, GPR[self.t]), il.const(4, 1))
        if_expr = il.if_expr(cmp_expr, nonzero_label, zero_label)
        il.append(if_expr)

        il.mark_label(zero_label)
        il.append(il.set_reg(4, GPR[self.r], il.add(
            4, il.reg(4, GPR[self.s]), il.const(4, -1))))
        il.append(il.goto(post_label))

        il.mark_label(nonzero_label)
        il.append(il.set_reg(4, GPR[self.r], il.add(
            4, il.reg(4, GPR[self.s]), il.const(4, self.t))))
        il.append(il.goto(post_label))

        il.mark_label(post_label)

        return self.length
