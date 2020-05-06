from .xtensa_instruction import RRR, RRRN, RRI8, CALLX, BRI12, RI6
from .xtensa_register import GPR
from .utils import *

from binaryninja import LLIL_TEMP, LowLevelILLabel, InstructionTextTokenType, InstructionTextToken, InstructionInfo, BranchType

class BALL(RRI8):
    mnemonic = "ball"

    def get_instruction_text(self, data, addr):
        tokens = []
        opcode = InstructionTextTokenType.TextToken
        register = InstructionTextTokenType.RegisterToken
        filler = InstructionTextTokenType.TextToken
        sep = InstructionTextTokenType.OperandSeparatorToken
        imm = InstructionTextTokenType.CodeRelativeAddressToken

        justify = ' ' * (self.justify - len(self.mnemonic))
        tokens.append(InstructionTextToken(opcode, self.mnemonic))
        tokens.append(InstructionTextToken(filler, justify))
        tokens.append(InstructionTextToken(register, GPR[self.s]))
        tokens.append(InstructionTextToken(sep, ','))
        tokens.append(InstructionTextToken(register, GPR[self.t]))
        tokens.append(InstructionTextToken(sep, ','))
        tokens.append(InstructionTextToken(imm, hex(twos_comp(self.imm8, 8) + 4), value=(twos_comp(self.imm8, 8))))
        return [tokens, self.length]

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.add_branch(BranchType.TrueBranch, addr + twos_comp(self.imm8, 8) + 4)
        info.add_branch(BranchType.FalseBranch, addr + self.length)
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):
        true_label = LowLevelILLabel()
        false_label = LowLevelILLabel()

        cmp_expr = il.compare_equal(4, il.and_expr(4, il.not_expr(4, il.reg(4, GPR[self.s])), il.reg(4, GPR[self.t])), il.const(4, 0))
        if_expr = il.if_expr(cmp_expr, true_label, false_label)
        il.append(if_expr)

        il.mark_label(true_label)
        sign_extend_expr = il.sign_extend(4, il.const(1, self.imm8))
        when_true_expr = il.add(4, sign_extend_expr, il.const(4, 4))
        il.append(il.set_reg(4, "pc" , il.add(4, il.reg(4, "pc"), when_true_expr)))

        il.mark_label(false_label)

        return self.length

class BANY(RRI8):
    mnemonic = "bany"

    def get_instruction_text(self, data, addr):
        tokens = []
        opcode = InstructionTextTokenType.TextToken
        register = InstructionTextTokenType.RegisterToken
        filler = InstructionTextTokenType.TextToken
        sep = InstructionTextTokenType.OperandSeparatorToken
        imm = InstructionTextTokenType.CodeRelativeAddressToken

        justify = ' ' * (self.justify - len(self.mnemonic))
        tokens.append(InstructionTextToken(opcode, self.mnemonic))
        tokens.append(InstructionTextToken(filler, justify))
        tokens.append(InstructionTextToken(register, GPR[self.s]))
        tokens.append(InstructionTextToken(sep, ','))
        tokens.append(InstructionTextToken(register, GPR[self.t]))
        tokens.append(InstructionTextToken(sep, ','))
        tokens.append(InstructionTextToken(imm, hex(twos_comp(self.imm8, 8) + 4), value=(twos_comp(self.imm8, 8))))
        return [tokens, self.length]

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.add_branch(BranchType.TrueBranch, addr + twos_comp(self.imm8, 8) + 4)
        info.add_branch(BranchType.FalseBranch, addr + self.length)
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):
        true_label = LowLevelILLabel()
        false_label = LowLevelILLabel()

        cmp_expr = il.compare_not_equal(4, il.and_expr(4, il.reg(4, GPR[self.s]), il.reg(4, GPR[self.t])), il.const(4, 0))
        if_expr = il.if_expr(cmp_expr, true_label, false_label)
        il.append(if_expr)

        il.mark_label(true_label)
        sign_extend_expr = il.sign_extend(4, il.const(1, self.imm8))
        when_true_expr = il.add(4, sign_extend_expr, il.const(4, 4))
        il.append(il.set_reg(4, "pc" , il.add(4, il.reg(4, "pc"), when_true_expr)))

        il.mark_label(false_label)

        return self.length

class BBC(RRI8):
    mnemonic = "bbc"

    def get_instruction_text(self, data, addr):
        tokens = []
        opcode = InstructionTextTokenType.TextToken
        register = InstructionTextTokenType.RegisterToken
        filler = InstructionTextTokenType.TextToken
        sep = InstructionTextTokenType.OperandSeparatorToken
        imm = InstructionTextTokenType.CodeRelativeAddressToken

        justify = ' ' * (self.justify - len(self.mnemonic))
        tokens.append(InstructionTextToken(opcode, self.mnemonic))
        tokens.append(InstructionTextToken(filler, justify))
        tokens.append(InstructionTextToken(register, GPR[self.s]))
        tokens.append(InstructionTextToken(sep, ','))
        tokens.append(InstructionTextToken(register, GPR[self.t]))
        tokens.append(InstructionTextToken(sep, ','))
        tokens.append(InstructionTextToken(imm, hex(twos_comp(self.imm8, 8) + 4), value=(twos_comp(self.imm8, 8))))
        return [tokens, self.length]

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.add_branch(BranchType.TrueBranch, addr + twos_comp(self.imm8, 8) + 4)
        info.add_branch(BranchType.FalseBranch, addr + self.length)
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):
        true_label = LowLevelILLabel()
        false_label = LowLevelILLabel()

        low_reg_bits = il.and_expr(4, il.reg(4, GPR[self.t]), il.const(4, 0x1F))
        bit_field = il.shift_left(4, il.const(4, 1), low_reg_bits)
        and_expr = il.and_expr(4, il.reg(4, GPR[self.s]), bit_field)
        cmp_expr = il.compare_equal(4, and_expr, il.const(4, 0))
        if_expr = il.if_expr(cmp_expr, true_label, false_label)
        il.append(if_expr)

        il.mark_label(true_label)
        sign_extend_expr = il.sign_extend(4, il.const(1, self.imm8))
        when_true_expr = il.add(4, sign_extend_expr, il.const(4, 4))
        il.append(il.set_reg(4, "pc" , il.add(4, il.reg(4, "pc"), when_true_expr)))

        il.mark_label(false_label)

        return self.length

class BBCI(RRI8):
    mnemonic = "bbci"

    def __init__(self, data, addr):
        super().__init__(data, addr)
        self.bbi = (data[0] >> 4) & 0xF
        self.bbi += (data[1] >> 8) & 0x10

    def get_instruction_text(self, data, addr):
        tokens = []
        opcode = InstructionTextTokenType.TextToken
        register = InstructionTextTokenType.RegisterToken
        filler = InstructionTextTokenType.TextToken
        sep = InstructionTextTokenType.OperandSeparatorToken
        imm = InstructionTextTokenType.CodeRelativeAddressToken

        justify = ' ' * (self.justify - len(self.mnemonic))
        tokens.append(InstructionTextToken(opcode, self.mnemonic))
        tokens.append(InstructionTextToken(filler, justify))
        tokens.append(InstructionTextToken(register, GPR[self.s]))
        tokens.append(InstructionTextToken(sep, ','))
        tokens.append(InstructionTextToken(imm, hex(self.bbi), value=self.bbi))
        tokens.append(InstructionTextToken(sep, ','))
        tokens.append(InstructionTextToken(imm, hex(twos_comp(self.imm8, 8) + 4), value=(twos_comp(self.imm8, 8))))
        return [tokens, self.length]

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.add_branch(BranchType.TrueBranch, addr + twos_comp(self.imm8, 8) + 4)
        info.add_branch(BranchType.FalseBranch, addr + self.length)
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):
        true_label = LowLevelILLabel()
        false_label = LowLevelILLabel()

        bit_field = il.shift_left(4, il.const(4, 1), il.const(4, self.bbi))
        and_expr = il.and_expr(4, il.reg(4, GPR[self.s]), bit_field)
        cmp_expr = il.compare_equal(4, and_expr, il.const(4, 0))
        if_expr = il.if_expr(cmp_expr, true_label, false_label)
        il.append(if_expr)

        il.mark_label(true_label)
        sign_extend_expr = il.sign_extend(4, il.const(1, self.imm8))
        when_true_expr = il.add(4, sign_extend_expr, il.const(4, 4))
        il.append(il.set_reg(4, "pc" , il.add(4, il.reg(4, "pc"), when_true_expr)))

        il.mark_label(false_label)

        return self.length

class BBS(RRI8):
    mnemonic = "bbs"

    def get_instruction_text(self, data, addr):
        tokens = []
        opcode = InstructionTextTokenType.TextToken
        register = InstructionTextTokenType.RegisterToken
        filler = InstructionTextTokenType.TextToken
        sep = InstructionTextTokenType.OperandSeparatorToken
        imm = InstructionTextTokenType.CodeRelativeAddressToken

        justify = ' ' * (self.justify - len(self.mnemonic))
        tokens.append(InstructionTextToken(opcode, self.mnemonic))
        tokens.append(InstructionTextToken(filler, justify))
        tokens.append(InstructionTextToken(register, GPR[self.s]))
        tokens.append(InstructionTextToken(sep, ','))
        tokens.append(InstructionTextToken(register, GPR[self.t]))
        tokens.append(InstructionTextToken(sep, ','))
        tokens.append(InstructionTextToken(imm, hex(twos_comp(self.imm8, 8) + 4), value=(twos_comp(self.imm8, 8))))
        return [tokens, self.length]

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.add_branch(BranchType.TrueBranch, addr + twos_comp(self.imm8, 8) + 4)
        info.add_branch(BranchType.FalseBranch, addr + self.length)
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):
        true_label = LowLevelILLabel()
        false_label = LowLevelILLabel()

        low_reg_bits = il.and_expr(4, il.reg(4, GPR[self.t]), il.const(4, 0x1F))
        bit_field = il.shift_left(4, il.const(4, 1), low_reg_bits)
        and_expr = il.and_expr(4, il.reg(4, GPR[self.s]), bit_field)
        cmp_expr = il.compare_not_equal(4, and_expr, il.const(4, 0))
        if_expr = il.if_expr(cmp_expr, true_label, false_label)
        il.append(if_expr)

        il.mark_label(true_label)
        sign_extend_expr = il.sign_extend(4, il.const(1, self.imm8))
        when_true_expr = il.add(4, sign_extend_expr, il.const(4, 4))
        il.append(il.set_reg(4, "pc" , il.add(4, il.reg(4, "pc"), when_true_expr)))

        il.mark_label(false_label)

        return self.length

class BBSI(RRI8):
    mnemonic = "bbsi"

    def __init__(self, data, addr):
        super().__init__(data, addr)
        self.bbi = (data[0] >> 4) & 0xF
        self.bbi += (data[1] >> 8) & 0x10

    def get_instruction_text(self, data, addr):
        tokens = []
        opcode = InstructionTextTokenType.TextToken
        register = InstructionTextTokenType.RegisterToken
        filler = InstructionTextTokenType.TextToken
        sep = InstructionTextTokenType.OperandSeparatorToken
        imm = InstructionTextTokenType.CodeRelativeAddressToken

        justify = ' ' * (self.justify - len(self.mnemonic))
        tokens.append(InstructionTextToken(opcode, self.mnemonic))
        tokens.append(InstructionTextToken(filler, justify))
        tokens.append(InstructionTextToken(register, GPR[self.s]))
        tokens.append(InstructionTextToken(sep, ','))
        tokens.append(InstructionTextToken(imm, hex(self.bbi), value=self.bbi))
        tokens.append(InstructionTextToken(sep, ','))
        tokens.append(InstructionTextToken(imm, hex(twos_comp(self.imm8, 8) + 4), value=(twos_comp(self.imm8, 8))))
        return [tokens, self.length]

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.add_branch(BranchType.TrueBranch, addr + twos_comp(self.imm8, 8) + 4)
        info.add_branch(BranchType.FalseBranch, addr + self.length)
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):
        true_label = LowLevelILLabel()
        false_label = LowLevelILLabel()

        bit_field = il.shift_left(4, il.const(4, 1), il.const(4, self.bbi))
        and_expr = il.and_expr(4, il.reg(4, GPR[self.s]), bit_field)
        cmp_expr = il.compare_not_equal(4, and_expr, il.const(4, 0))
        if_expr = il.if_expr(cmp_expr, true_label, false_label)
        il.append(if_expr)

        il.mark_label(true_label)
        sign_extend_expr = il.sign_extend(4, il.const(1, self.imm8))
        when_true_expr = il.add(4, sign_extend_expr, il.const(4, 4))
        il.append(il.set_reg(4, "pc" , il.add(4, il.reg(4, "pc"), when_true_expr)))

        il.mark_label(false_label)

        return self.length

class BEQ(RRI8):
    mnemonic = "beq"

    def get_instruction_text(self, data, addr):
        tokens = []
        opcode = InstructionTextTokenType.TextToken
        register = InstructionTextTokenType.RegisterToken
        filler = InstructionTextTokenType.TextToken
        sep = InstructionTextTokenType.OperandSeparatorToken
        imm = InstructionTextTokenType.CodeRelativeAddressToken

        justify = ' ' * (self.justify - len(self.mnemonic))
        tokens.append(InstructionTextToken(opcode, self.mnemonic))
        tokens.append(InstructionTextToken(filler, justify))
        tokens.append(InstructionTextToken(register, GPR[self.s]))
        tokens.append(InstructionTextToken(sep, ','))
        tokens.append(InstructionTextToken(register, GPR[self.t]))
        tokens.append(InstructionTextToken(sep, ','))
        tokens.append(InstructionTextToken(imm, hex(twos_comp(self.imm8, 8) + 4), value=(twos_comp(self.imm8, 8))))
        return [tokens, self.length]

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.add_branch(BranchType.TrueBranch, addr + twos_comp(self.imm8, 8) + 4)
        info.add_branch(BranchType.FalseBranch, addr + self.length)
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):
        true_label = LowLevelILLabel()
        false_label = LowLevelILLabel()

        cmp_expr = il.compare_equal(4, il.reg(4, GPR[self.s]), il.reg(4, GPR[self.t]))
        if_expr = il.if_expr(cmp_expr, true_label, false_label)
        il.append(if_expr)

        il.mark_label(true_label)
        sign_extend_expr = il.sign_extend(4, il.const(1, self.imm8))
        when_true_expr = il.add(4, sign_extend_expr, il.const(4, 4))
        il.append(il.set_reg(4, "pc" , il.add(4, il.reg(4, "pc"), when_true_expr)))

        il.mark_label(false_label)

        return self.length

class BEQI(RRI8):
    mnemonic = "beqi"

    def get_instruction_text(self, data, addr):

        tokens = []
        opcode = InstructionTextTokenType.TextToken
        register = InstructionTextTokenType.RegisterToken
        filler = InstructionTextTokenType.TextToken
        sep = InstructionTextTokenType.OperandSeparatorToken
        imm = InstructionTextTokenType.CodeRelativeAddressToken

        justify = ' ' * (self.justify - len(self.mnemonic))
        tokens.append(InstructionTextToken(opcode, self.mnemonic))
        tokens.append(InstructionTextToken(filler, justify))
        tokens.append(InstructionTextToken(register, GPR[self.s]))
        tokens.append(InstructionTextToken(sep, ','))
        tokens.append(InstructionTextToken(imm, hex(B4CONST_TABLE[self.r]), value=B4CONST_TABLE[self.r]))
        tokens.append(InstructionTextToken(sep, ','))
        tokens.append(InstructionTextToken(imm, hex(twos_comp(self.imm8, 8) + 4), value=(twos_comp(self.imm8, 8))))
        return [tokens, self.length]

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.add_branch(BranchType.TrueBranch, addr + twos_comp(self.imm8, 8) + 4)
        info.add_branch(BranchType.FalseBranch, addr + self.length)
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):
        true_label = LowLevelILLabel()
        false_label = LowLevelILLabel()

        cmp_expr = il.compare_equal(4, il.reg(4, GPR[self.s]), il.reg(4, B4CONST_TABLE[self.r]))
        if_expr = il.if_expr(cmp_expr, true_label, false_label)
        il.append(if_expr)

        il.mark_label(true_label)
        sign_extend_expr = il.sign_extend(4, il.const(1, self.imm8))
        when_true_expr = il.add(4, sign_extend_expr, il.const(4, 4))
        il.append(il.set_reg(4, "pc" , il.add(4, il.reg(4, "pc"), when_true_expr)))

        il.mark_label(false_label)

        return self.length

class BEQZ(BRI12):
    mnemonic = "beqz"

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.add_branch(BranchType.TrueBranch, addr + twos_comp(self.imm12, 12) + 4)
        info.add_branch(BranchType.FalseBranch, addr + self.length)
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):
        true_label = LowLevelILLabel()
        false_label = LowLevelILLabel()

        cmp_expr = il.compare_equal(4, il.reg(4, GPR[self.s]), il.const(4, 0))
        if_expr = il.if_expr(cmp_expr, true_label, false_label)
        il.append(if_expr)

        il.mark_label(true_label)
        sign_extend_expr = il.sign_extend(4, il.const(2, twos_comp(self.imm12, 12)))
        when_true_expr = il.add(4, sign_extend_expr, il.const(4, 4))
        il.append(il.set_reg(4, "pc" , il.add(4, il.reg(4, "pc"), when_true_expr)))

        il.mark_label(false_label)

        return self.length


class BEQZN(RI6):
    mnemonic = "beqz.n"

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.add_branch(BranchType.TrueBranch, addr + self.imm6 + 4)
        info.add_branch(BranchType.FalseBranch, addr + self.length)
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):
        true_label = LowLevelILLabel()
        false_label = LowLevelILLabel()

        cmp_expr = il.compare_equal(4, il.reg(4, GPR[self.s]), il.const(4, 0))
        if_expr = il.if_expr(cmp_expr, true_label, false_label)
        il.append(if_expr)

        il.mark_label(true_label)
        when_true_expr = il.add(4, il.const(1, self.imm6), il.const(4, 4))
        il.append(il.set_reg(4, "pc" , il.add(4, il.reg(4, "pc"), when_true_expr)))

        il.mark_label(false_label)

        return self.length


class RET(CALLX):
    mnemonic = "ret"

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
        il.append(il.ret(il.reg(4, 0)))

        return self.length