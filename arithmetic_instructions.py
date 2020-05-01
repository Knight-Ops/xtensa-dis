from .xtensa_instruction import RRR, RRRN
from .xtensa_register import GPR

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
        cmp_expr = il.compare_signed_greater_equal(4, il.reg(4, self.t), il.const(4, 0))
        if_expr = il.if_expr(cmp_expr, positive_label, negative_label)
        il.append(if_expr)

        # if it is negative, we want to negate it
        il.mark_label(negative_label)
        il.append(il.set_reg(4, self.r, il.neg_expr(4, il.reg(4, self.t))))
        il.append(il.goto(post_label))

        # otherwise, just move the value
        il.mark_label(positive_label)
        il.append(il.set_reg(4, self.r, il.reg(4, self.t)))
        il.append(il.goto(post_label))

        il.mark_label(post_label)

        return self.length

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
        il.append(il.set_reg(4, self.r, il.float_abs(4, il.reg(4, self.t))))

        return self.length

class ADD(RRR):
    mnemonic = "add"

    def get_instruction_low_level_il(self, data, addr, il):
        il.append(il.set_reg(4, self.r, il.add(4, il.reg(4, self.s), il.reg(4, self.t))))

        return self.length

class ADDN(RRRN):
    mnemonic = "add.n"

    def get_instruction_low_level_il(self, data, addr, il):
        il.append(il.set_reg(4, self.r, il.add(4, il.reg(4, self.s), il.reg(4, self.t))))

        return self.length