from ..xtensa_instruction import RRR, RRRN, RRI8, CALLX, BRI12, RI6, BRI8
from ..xtensa_register import GPR
from ..utils import *

from binaryninja import LLIL_TEMP, LowLevelILLabel, InstructionTextTokenType, InstructionTextToken, InstructionInfo, BranchType, Architecture


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
        tokens.append(InstructionTextToken(
            imm, hex(addr + twos_comp(self.imm8, 8) + 4), value=(addr + twos_comp(self.imm8, 8))))
        return [tokens, self.length]

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.add_branch(BranchType.TrueBranch, addr +
                        twos_comp(self.imm8, 8) + 4)
        info.add_branch(BranchType.FalseBranch, addr + self.length)
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):
        false = addr + self.length
        false_label = il.get_label_for_address(Architecture['xtensa'], false)
        if false_label is None:
            il.add_label_for_address(Architecture['xtensa'], false)
            false_label = il.get_label_for_address(Architecture['xtensa'], false)

        true = addr + twos_comp(self.imm8, 8) + 4
        true_label = il.get_label_for_address(Architecture['xtensa'], true)
        if true_label is None:
            il.add_label_for_address(Architecture['xtensa'], true)
            true_label = il.get_label_for_address(Architecture['xtensa'], true)

        cmp_expr = il.compare_equal(4, il.and_expr(4, il.not_expr(
            4, il.reg(4, GPR[self.s])), il.reg(4, GPR[self.t])), il.const(4, 0))
        if_expr = il.if_expr(cmp_expr, true_label, false_label)
        il.append(if_expr)

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
        tokens.append(InstructionTextToken(
            imm, hex(addr + twos_comp(self.imm8, 8) + 4), value=(addr + twos_comp(self.imm8, 8))))
        return [tokens, self.length]

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.add_branch(BranchType.TrueBranch, addr +
                        twos_comp(self.imm8, 8) + 4)
        info.add_branch(BranchType.FalseBranch, addr + self.length)
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):
        false = addr + self.length
        false_label = il.get_label_for_address(Architecture['xtensa'], false)
        if false_label is None:
            il.add_label_for_address(Architecture['xtensa'], false)
            false_label = il.get_label_for_address(Architecture['xtensa'], false)

        true = addr + twos_comp(self.imm8, 8) + 4
        true_label = il.get_label_for_address(Architecture['xtensa'], true)
        if true_label is None:
            il.add_label_for_address(Architecture['xtensa'], true)
            true_label = il.get_label_for_address(Architecture['xtensa'], true)

        cmp_expr = il.compare_not_equal(4, il.and_expr(
            4, il.reg(4, GPR[self.s]), il.reg(4, GPR[self.t])), il.const(4, 0))
        if_expr = il.if_expr(cmp_expr, true_label, false_label)
        il.append(if_expr)

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
        tokens.append(InstructionTextToken(
            imm, hex(addr + twos_comp(self.imm8, 8) + 4), value=(addr + twos_comp(self.imm8, 8))))
        return [tokens, self.length]

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.add_branch(BranchType.TrueBranch, addr +
                        twos_comp(self.imm8, 8) + 4)
        info.add_branch(BranchType.FalseBranch, addr + self.length)
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):
        false = addr + self.length
        false_label = il.get_label_for_address(Architecture['xtensa'], false)
        if false_label is None:
            il.add_label_for_address(Architecture['xtensa'], false)
            false_label = il.get_label_for_address(Architecture['xtensa'], false)

        true = addr + twos_comp(self.imm8, 8) + 4
        true_label = il.get_label_for_address(Architecture['xtensa'], true)
        if true_label is None:
            il.add_label_for_address(Architecture['xtensa'], true)
            true_label = il.get_label_for_address(Architecture['xtensa'], true)

        low_reg_bits = il.and_expr(4, il.reg(4, GPR[self.t]), il.const(4, 0x1F))
        bit_field = il.shift_left(4, il.const(4, 1), low_reg_bits)
        and_expr = il.and_expr(4, il.reg(4, GPR[self.s]), bit_field)
        cmp_expr = il.compare_equal(4, and_expr, il.const(4, 0))
        if_expr = il.if_expr(cmp_expr, true_label, false_label)
        il.append(if_expr)

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
        tokens.append(InstructionTextToken(
            imm, hex(addr + twos_comp(self.imm8, 8) + 4), value=(addr + twos_comp(self.imm8, 8))))
        return [tokens, self.length]

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.add_branch(BranchType.TrueBranch, addr +
                        twos_comp(self.imm8, 8) + 4)
        info.add_branch(BranchType.FalseBranch, addr + self.length)
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):
        false = addr + self.length
        false_label = il.get_label_for_address(Architecture['xtensa'], false)
        if false_label is None:
            il.add_label_for_address(Architecture['xtensa'], false)
            false_label = il.get_label_for_address(Architecture['xtensa'], false)

        true = addr + twos_comp(self.imm8, 8) + 4
        true_label = il.get_label_for_address(Architecture['xtensa'], true)
        if true_label is None:
            il.add_label_for_address(Architecture['xtensa'], true)
            true_label = il.get_label_for_address(Architecture['xtensa'], true)

        low_reg_bits = il.and_expr(4, il.reg(4, GPR[self.t]), il.const(4, 0x1F))
        bit_field = il.shift_left(4, il.const(4, 1), low_reg_bits)
        and_expr = il.and_expr(4, il.reg(4, GPR[self.s]), bit_field)
        cmp_expr = il.compare_not_equal(4, and_expr, il.const(4, 0))
        if_expr = il.if_expr(cmp_expr, true_label, false_label)
        il.append(if_expr)

        return self.length


class BBCI(RRI8):
    mnemonic = "bbci"

    def __init__(self, data, addr):
        super().__init__(data, addr)
        self.bbi = (data[0] >> 4) & 0xF
        self.bbi += (data[1] & 0x10)

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
        tokens.append(InstructionTextToken(
            imm, hex(addr + twos_comp(self.imm8, 8) + 4), value=(addr + twos_comp(self.imm8, 8))))
        return [tokens, self.length]

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.add_branch(BranchType.TrueBranch, addr +
                        twos_comp(self.imm8, 8) + 4)
        info.add_branch(BranchType.FalseBranch, addr + self.length)
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):
        false = addr + self.length
        false_label = il.get_label_for_address(Architecture['xtensa'], false)
        if false_label is None:
            il.add_label_for_address(Architecture['xtensa'], false)
            false_label = il.get_label_for_address(Architecture['xtensa'], false)

        true = addr + twos_comp(self.imm8, 8) + 4
        true_label = il.get_label_for_address(Architecture['xtensa'], true)
        if true_label is None:
            il.add_label_for_address(Architecture['xtensa'], true)
            true_label = il.get_label_for_address(Architecture['xtensa'], true)

        bit_field = il.shift_left(4, il.const(4, 1), il.const(4, self.bbi))
        and_expr = il.and_expr(4, il.reg(4, GPR[self.s]), bit_field)
        cmp_expr = il.compare_equal(4, and_expr, il.const(4, 0))
        if_expr = il.if_expr(cmp_expr, true_label, false_label)
        il.append(if_expr)

        return self.length


class BBSI(RRI8):
    mnemonic = "bbsi"

    def __init__(self, data, addr):
        super().__init__(data, addr)
        self.bbi = (data[0] >> 4) & 0xF
        self.bbi += (data[1] & 0x10)

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
        tokens.append(InstructionTextToken(
            imm, hex(addr + twos_comp(self.imm8, 8) + 4), value=(addr + twos_comp(self.imm8, 8))))
        return [tokens, self.length]

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.add_branch(BranchType.TrueBranch, addr +
                        twos_comp(self.imm8, 8) + 4)
        info.add_branch(BranchType.FalseBranch, addr + self.length)
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):
        false = addr + self.length
        false_label = il.get_label_for_address(Architecture['xtensa'], false)
        if false_label is None:
            il.add_label_for_address(Architecture['xtensa'], false)
            false_label = il.get_label_for_address(Architecture['xtensa'], false)

        true = addr + twos_comp(self.imm8, 8) + 4
        true_label = il.get_label_for_address(Architecture['xtensa'], true)
        if true_label is None:
            il.add_label_for_address(Architecture['xtensa'], true)
            true_label = il.get_label_for_address(Architecture['xtensa'], true)

        bit_field = il.shift_left(4, il.const(4, 1), il.const(4, self.bbi))
        and_expr = il.and_expr(4, il.reg(4, GPR[self.s]), bit_field)
        cmp_expr = il.compare_not_equal(4, and_expr, il.const(4, 0))
        if_expr = il.if_expr(cmp_expr, true_label, false_label)
        il.append(if_expr)

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
        tokens.append(InstructionTextToken(
            imm, hex(addr + twos_comp(self.imm8, 8) + 4), value=(addr + twos_comp(self.imm8, 8))))
        return [tokens, self.length]

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.add_branch(BranchType.TrueBranch, addr +
                        twos_comp(self.imm8, 8) + 4)
        info.add_branch(BranchType.FalseBranch, addr + self.length)
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):
        false = addr + self.length
        false_label = il.get_label_for_address(Architecture['xtensa'], false)
        if false_label is None:
            il.add_label_for_address(Architecture['xtensa'], false)
            false_label = il.get_label_for_address(Architecture['xtensa'], false)

        true = addr + twos_comp(self.imm8, 8) + 4
        true_label = il.get_label_for_address(Architecture['xtensa'], true)
        if true_label is None:
            il.add_label_for_address(Architecture['xtensa'], true)
            true_label = il.get_label_for_address(Architecture['xtensa'], true)

        cmp_expr = il.compare_equal(4, il.reg(4, GPR[self.s]), il.reg(4, GPR[self.t]))
        if_expr = il.if_expr(cmp_expr, true_label, false_label)
        il.append(if_expr)

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
        tokens.append(InstructionTextToken(
            imm, hex(B4CONST_TABLE[self.r]), value=B4CONST_TABLE[self.r]))
        tokens.append(InstructionTextToken(sep, ','))
        tokens.append(InstructionTextToken(
            imm, hex(addr + twos_comp(self.imm8, 8) + 4), value=(addr + twos_comp(self.imm8, 8))))
        return [tokens, self.length]

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.add_branch(BranchType.TrueBranch, addr +
                        twos_comp(self.imm8, 8) + 4)
        info.add_branch(BranchType.FalseBranch, addr + self.length)
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):
        false = addr + self.length
        false_label = il.get_label_for_address(Architecture['xtensa'], false)
        if false_label is None:
            il.add_label_for_address(Architecture['xtensa'], false)
            false_label = il.get_label_for_address(Architecture['xtensa'], false)

        true = addr + twos_comp(self.imm8, 8) + 4
        true_label = il.get_label_for_address(Architecture['xtensa'], true)
        if true_label is None:
            il.add_label_for_address(Architecture['xtensa'], true)
            true_label = il.get_label_for_address(Architecture['xtensa'], true)

        cmp_expr = il.compare_equal(
            4, il.reg(4, GPR[self.s]), il.const(4, B4CONST_TABLE[self.r]))
        if_expr = il.if_expr(cmp_expr, true_label, false_label)
        il.append(if_expr)

        return self.length


class BEQZ(BRI12):
    mnemonic = "beqz"

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.add_branch(BranchType.TrueBranch, addr +
                        twos_comp(self.imm12, 12) + 4)
        info.add_branch(BranchType.FalseBranch, addr + self.length)
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):
        false = addr + self.length
        false_label = il.get_label_for_address(Architecture['xtensa'], false)
        if false_label is None:
            il.add_label_for_address(Architecture['xtensa'], false)
            false_label = il.get_label_for_address(Architecture['xtensa'], false)

        true = addr + twos_comp(self.imm12, 12) + 4
        true_label = il.get_label_for_address(Architecture['xtensa'], true)
        if true_label is None:
            il.add_label_for_address(Architecture['xtensa'], true)
            true_label = il.get_label_for_address(Architecture['xtensa'], true)

        cmp_expr = il.compare_equal(4, il.reg(4, GPR[self.s]), il.const(4, 0))
        if_expr = il.if_expr(cmp_expr, true_label, false_label)
        il.append(if_expr)

        return self.length

class BGE(RRI8):
    mnemonic = "bge"

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
        tokens.append(InstructionTextToken(
            imm, hex(addr + twos_comp(self.imm8, 8) + 4), value=(addr + twos_comp(self.imm8, 8))))
        return [tokens, self.length]

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.add_branch(BranchType.TrueBranch, addr +
                        twos_comp(self.imm8, 8) + 4)
        info.add_branch(BranchType.FalseBranch, addr + self.length)
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):
        false = addr + self.length
        false_label = il.get_label_for_address(Architecture['xtensa'], false)
        if false_label is None:
            il.add_label_for_address(Architecture['xtensa'], false)
            false_label = il.get_label_for_address(Architecture['xtensa'], false)

        true = addr + twos_comp(self.imm8, 8) + 4
        true_label = il.get_label_for_address(Architecture['xtensa'], true)
        if true_label is None:
            il.add_label_for_address(Architecture['xtensa'], true)
            true_label = il.get_label_for_address(Architecture['xtensa'], true)

        cmp_expr = il.compare_signed_greater_equal(
            4, il.reg(4, GPR[self.s]), il.reg(4, GPR[self.t]))
        if_expr = il.if_expr(cmp_expr, true_label, false_label)
        il.append(if_expr)

        return self.length

class BGEI(BRI8):
    mnemonic = "bgei"

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
        tokens.append(InstructionTextToken(
            imm, hex(B4CONST_TABLE[self.r]), value=B4CONST_TABLE[self.r]))
        tokens.append(InstructionTextToken(sep, ','))
        tokens.append(InstructionTextToken(
            imm, hex(addr + twos_comp(self.imm8, 8) + 4), value=(addr + twos_comp(self.imm8, 8))))
        return [tokens, self.length]

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.add_branch(BranchType.TrueBranch, addr +
                        twos_comp(self.imm8, 8) + 4)
        info.add_branch(BranchType.FalseBranch, addr + self.length)
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):
        false = addr + self.length
        false_label = il.get_label_for_address(Architecture['xtensa'], false)
        if false_label is None:
            il.add_label_for_address(Architecture['xtensa'], false)
            false_label = il.get_label_for_address(Architecture['xtensa'], false)

        true = addr + twos_comp(self.imm8, 8) + 4
        true_label = il.get_label_for_address(Architecture['xtensa'], true)
        if true_label is None:
            il.add_label_for_address(Architecture['xtensa'], true)
            true_label = il.get_label_for_address(Architecture['xtensa'], true)

        cmp_expr = il.compare_signed_greater_equal(
            4, il.reg(4, GPR[self.s]), il.const(4, B4CONST_TABLE[self.r]))
        if_expr = il.if_expr(cmp_expr, true_label, false_label)
        il.append(if_expr)

        return self.length

class BGEU(RRI8):
    mnemonic = "bgeu"

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
        tokens.append(InstructionTextToken(
            imm, hex(addr + twos_comp(self.imm8, 8) + 4), value=(addr + twos_comp(self.imm8, 8))))
        return [tokens, self.length]

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.add_branch(BranchType.TrueBranch, addr +
                        twos_comp(self.imm8, 8) + 4)
        info.add_branch(BranchType.FalseBranch, addr + self.length)
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):
        false = addr + self.length
        false_label = il.get_label_for_address(Architecture['xtensa'], false)
        if false_label is None:
            il.add_label_for_address(Architecture['xtensa'], false)
            false_label = il.get_label_for_address(Architecture['xtensa'], false)

        true = addr + twos_comp(self.imm8, 8) + 4
        true_label = il.get_label_for_address(Architecture['xtensa'], true)
        if true_label is None:
            il.add_label_for_address(Architecture['xtensa'], true)
            true_label = il.get_label_for_address(Architecture['xtensa'], true)

        cmp_expr = il.compare_unsigned_greater_equal(
            4, il.reg(4, GPR[self.s]), il.reg(4, GPR[self.t]))
        if_expr = il.if_expr(cmp_expr, true_label, false_label)
        il.append(if_expr)

        return self.length

class BGEUI(BRI8):
    mnemonic = "bgeui"

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
        tokens.append(InstructionTextToken(
            imm, hex(B4CONST_TABLE[self.r]), value=B4CONST_TABLE[self.r]))
        tokens.append(InstructionTextToken(sep, ','))
        tokens.append(InstructionTextToken(
            imm, hex(addr + twos_comp(self.imm8, 8) + 4), value=(addr + twos_comp(self.imm8, 8))))
        return [tokens, self.length]

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.add_branch(BranchType.TrueBranch, addr +
                        twos_comp(self.imm8, 8) + 4)
        info.add_branch(BranchType.FalseBranch, addr + self.length)
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):
        false = addr + self.length
        false_label = il.get_label_for_address(Architecture['xtensa'], false)
        if false_label is None:
            il.add_label_for_address(Architecture['xtensa'], false)
            false_label = il.get_label_for_address(Architecture['xtensa'], false)

        true = addr + twos_comp(self.imm8, 8) + 4
        true_label = il.get_label_for_address(Architecture['xtensa'], true)
        if true_label is None:
            il.add_label_for_address(Architecture['xtensa'], true)
            true_label = il.get_label_for_address(Architecture['xtensa'], true)

        cmp_expr = il.compare_unsigned_greater_equal(
            4, il.reg(4, GPR[self.s]), il.const(4, B4CONST_TABLE[self.r]))
        if_expr = il.if_expr(cmp_expr, true_label, false_label)
        il.append(if_expr)

        return self.length

class BGEZ(BRI12):
    mnemonic = "bgez"

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.add_branch(BranchType.TrueBranch, addr +
                        twos_comp(self.imm12, 12) + 4)
        info.add_branch(BranchType.FalseBranch, addr + self.length)
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):
        false = addr + self.length
        false_label = il.get_label_for_address(Architecture['xtensa'], false)
        if false_label is None:
            il.add_label_for_address(Architecture['xtensa'], false)
            false_label = il.get_label_for_address(Architecture['xtensa'], false)

        true = addr + twos_comp(self.imm12, 12) + 4
        true_label = il.get_label_for_address(Architecture['xtensa'], true)
        if true_label is None:
            il.add_label_for_address(Architecture['xtensa'], true)
            true_label = il.get_label_for_address(Architecture['xtensa'], true)

        cmp_expr = il.compare_signed_greater_equal(4, il.reg(4, GPR[self.s]), il.const(4, 0))
        if_expr = il.if_expr(cmp_expr, true_label, false_label)
        il.append(if_expr)

        return self.length

class BLT(RRI8):
    mnemonic = "blt"

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
        tokens.append(InstructionTextToken(
            imm, hex(addr + twos_comp(self.imm8, 8) + 4), value=(addr + twos_comp(self.imm8, 8))))
        return [tokens, self.length]

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.add_branch(BranchType.TrueBranch, addr +
                        twos_comp(self.imm8, 8) + 4)
        info.add_branch(BranchType.FalseBranch, addr + self.length)
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):
        false = addr + self.length
        false_label = il.get_label_for_address(Architecture['xtensa'], false)
        if false_label is None:
            il.add_label_for_address(Architecture['xtensa'], false)
            false_label = il.get_label_for_address(Architecture['xtensa'], false)

        true = addr + twos_comp(self.imm8, 8) + 4
        true_label = il.get_label_for_address(Architecture['xtensa'], true)
        if true_label is None:
            il.add_label_for_address(Architecture['xtensa'], true)
            true_label = il.get_label_for_address(Architecture['xtensa'], true)

        cmp_expr = il.compare_signed_less_than(
            4, il.reg(4, GPR[self.s]), il.reg(4, GPR[self.t]))
        if_expr = il.if_expr(cmp_expr, true_label, false_label)
        il.append(if_expr)

        return self.length

class BLTI(BRI8):
    mnemonic = "blti"

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
        tokens.append(InstructionTextToken(
            imm, hex(B4CONST_TABLE[self.r]), value=B4CONST_TABLE[self.r]))
        tokens.append(InstructionTextToken(sep, ','))
        tokens.append(InstructionTextToken(
            imm, hex(addr + twos_comp(self.imm8, 8) + 4), value=(addr + twos_comp(self.imm8, 8))))
        return [tokens, self.length]

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.add_branch(BranchType.TrueBranch, addr +
                        twos_comp(self.imm8, 8) + 4)
        info.add_branch(BranchType.FalseBranch, addr + self.length)
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):
        false = addr + self.length
        false_label = il.get_label_for_address(Architecture['xtensa'], false)
        if false_label is None:
            il.add_label_for_address(Architecture['xtensa'], false)
            false_label = il.get_label_for_address(Architecture['xtensa'], false)

        true = addr + twos_comp(self.imm8, 8) + 4
        true_label = il.get_label_for_address(Architecture['xtensa'], true)
        if true_label is None:
            il.add_label_for_address(Architecture['xtensa'], true)
            true_label = il.get_label_for_address(Architecture['xtensa'], true)

        cmp_expr = il.compare_signed_less_than(
            4, il.reg(4, GPR[self.s]), il.const(4, B4CONST_TABLE[self.r]))
        if_expr = il.if_expr(cmp_expr, true_label, false_label)
        il.append(if_expr)

        return self.length

class BLTU(RRI8):
    mnemonic = "bltu"

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
        tokens.append(InstructionTextToken(
            imm, hex(addr + twos_comp(self.imm8, 8) + 4), value=(addr + twos_comp(self.imm8, 8))))
        return [tokens, self.length]

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.add_branch(BranchType.TrueBranch, addr +
                        twos_comp(self.imm8, 8) + 4)
        info.add_branch(BranchType.FalseBranch, addr + self.length)
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):
        false = addr + self.length
        false_label = il.get_label_for_address(Architecture['xtensa'], false)
        if false_label is None:
            il.add_label_for_address(Architecture['xtensa'], false)
            false_label = il.get_label_for_address(Architecture['xtensa'], false)

        true = addr + twos_comp(self.imm8, 8) + 4
        true_label = il.get_label_for_address(Architecture['xtensa'], true)
        if true_label is None:
            il.add_label_for_address(Architecture['xtensa'], true)
            true_label = il.get_label_for_address(Architecture['xtensa'], true)

        cmp_expr = il.compare_unsigned_less_than(
            4, il.reg(4, GPR[self.s]), il.reg(4, GPR[self.t]))
        if_expr = il.if_expr(cmp_expr, true_label, false_label)
        il.append(if_expr)

        return self.length

class BLTUI(BRI8):
    mnemonic = "bltui"

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
        tokens.append(InstructionTextToken(
            imm, hex(B4CONST_TABLE[self.r]), value=B4CONST_TABLE[self.r]))
        tokens.append(InstructionTextToken(sep, ','))
        tokens.append(InstructionTextToken(
            imm, hex(addr + twos_comp(self.imm8, 8) + 4), value=(addr + twos_comp(self.imm8, 8))))
        return [tokens, self.length]

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.add_branch(BranchType.TrueBranch, addr +
                        twos_comp(self.imm8, 8) + 4)
        info.add_branch(BranchType.FalseBranch, addr + self.length)
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):
        false = addr + self.length
        false_label = il.get_label_for_address(Architecture['xtensa'], false)
        if false_label is None:
            il.add_label_for_address(Architecture['xtensa'], false)
            false_label = il.get_label_for_address(Architecture['xtensa'], false)

        true = addr + twos_comp(self.imm8, 8) + 4
        true_label = il.get_label_for_address(Architecture['xtensa'], true)
        if true_label is None:
            il.add_label_for_address(Architecture['xtensa'], true)
            true_label = il.get_label_for_address(Architecture['xtensa'], true)

        cmp_expr = il.compare_unsigned_less_than(
            4, il.reg(4, GPR[self.s]), il.const(4, B4CONST_TABLE[self.r]))
        if_expr = il.if_expr(cmp_expr, true_label, false_label)
        il.append(if_expr)

        return self.length

class BLTZ(BRI12):
    mnemonic = "bltz"

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.add_branch(BranchType.TrueBranch, addr +
                        twos_comp(self.imm12, 12) + 4)
        info.add_branch(BranchType.FalseBranch, addr + self.length)
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):
        false = addr + self.length
        false_label = il.get_label_for_address(Architecture['xtensa'], false)
        if false_label is None:
            il.add_label_for_address(Architecture['xtensa'], false)
            false_label = il.get_label_for_address(Architecture['xtensa'], false)

        true = addr + twos_comp(self.imm12, 12) + 4
        true_label = il.get_label_for_address(Architecture['xtensa'], true)
        if true_label is None:
            il.add_label_for_address(Architecture['xtensa'], true)
            true_label = il.get_label_for_address(Architecture['xtensa'], true)

        cmp_expr = il.compare_signed_less_than(4, il.reg(4, GPR[self.s]), il.const(4, 0))
        if_expr = il.if_expr(cmp_expr, true_label, false_label)
        il.append(if_expr)

        return self.length

class BNALL(RRI8):
    mnemonic = "bnall"

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
        tokens.append(InstructionTextToken(
            imm, hex(addr + twos_comp(self.imm8, 8) + 4), value=(addr + twos_comp(self.imm8, 8))))
        return [tokens, self.length]

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.add_branch(BranchType.TrueBranch, addr +
                        twos_comp(self.imm8, 8) + 4)
        info.add_branch(BranchType.FalseBranch, addr + self.length)
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):
        false = addr + self.length
        false_label = il.get_label_for_address(Architecture['xtensa'], false)
        if false_label is None:
            il.add_label_for_address(Architecture['xtensa'], false)
            false_label = il.get_label_for_address(Architecture['xtensa'], false)

        true = addr + twos_comp(self.imm8, 8) + 4
        true_label = il.get_label_for_address(Architecture['xtensa'], true)
        if true_label is None:
            il.add_label_for_address(Architecture['xtensa'], true)
            true_label = il.get_label_for_address(Architecture['xtensa'], true)

        cmp_expr = il.compare_not_equal(4, il.and_expr(4, il.not_expr(
            4, il.reg(4, GPR[self.s])), il.reg(4, GPR[self.t])), il.const(4, 0))
        if_expr = il.if_expr(cmp_expr, true_label, false_label)
        il.append(if_expr)

        return self.length

class BNE(RRI8):
    mnemonic = "bne"

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
        tokens.append(InstructionTextToken(
            imm, hex(addr + twos_comp(self.imm8, 8) + 4), value=(addr + twos_comp(self.imm8, 8))))
        return [tokens, self.length]

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.add_branch(BranchType.TrueBranch, addr +
                        twos_comp(self.imm8, 8) + 4)
        info.add_branch(BranchType.FalseBranch, addr + self.length)
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):
        false = addr + self.length
        false_label = il.get_label_for_address(Architecture['xtensa'], false)
        if false_label is None:
            il.add_label_for_address(Architecture['xtensa'], false)
            false_label = il.get_label_for_address(Architecture['xtensa'], false)

        true = addr + twos_comp(self.imm8, 8) + 4
        true_label = il.get_label_for_address(Architecture['xtensa'], true)
        if true_label is None:
            il.add_label_for_address(Architecture['xtensa'], true)
            true_label = il.get_label_for_address(Architecture['xtensa'], true)

        cmp_expr = il.compare_not_equal(4, il.reg(4, GPR[self.s]), il.reg(4, GPR[self.t]))
        if_expr = il.if_expr(cmp_expr, true_label, false_label)
        il.append(if_expr)

        return self.length


class BNEI(RRI8):
    mnemonic = "bnei"

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
        tokens.append(InstructionTextToken(
            imm, hex(B4CONST_TABLE[self.r]), value=B4CONST_TABLE[self.r]))
        tokens.append(InstructionTextToken(sep, ','))
        tokens.append(InstructionTextToken(
            imm, hex(addr + twos_comp(self.imm8, 8) + 4), value=(addr + twos_comp(self.imm8, 8))))
        return [tokens, self.length]

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.add_branch(BranchType.TrueBranch, addr +
                        twos_comp(self.imm8, 8) + 4)
        info.add_branch(BranchType.FalseBranch, addr + self.length)
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):
        false = addr + self.length
        false_label = il.get_label_for_address(Architecture['xtensa'], false)
        if false_label is None:
            il.add_label_for_address(Architecture['xtensa'], false)
            false_label = il.get_label_for_address(Architecture['xtensa'], false)

        true = addr + twos_comp(self.imm8, 8) + 4
        true_label = il.get_label_for_address(Architecture['xtensa'], true)
        if true_label is None:
            il.add_label_for_address(Architecture['xtensa'], true)
            true_label = il.get_label_for_address(Architecture['xtensa'], true)

        cmp_expr = il.compare_not_equal(
            4, il.reg(4, GPR[self.s]), il.const(4, B4CONST_TABLE[self.r]))
        if_expr = il.if_expr(cmp_expr, true_label, false_label)
        il.append(if_expr)

        return self.length


class BNEZ(BRI12):
    mnemonic = "bnez"

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.add_branch(BranchType.TrueBranch, addr +
                        twos_comp(self.imm12, 12) + 4)
        info.add_branch(BranchType.FalseBranch, addr + self.length)
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):
        false = addr + self.length
        false_label = il.get_label_for_address(Architecture['xtensa'], false)
        if false_label is None:
            il.add_label_for_address(Architecture['xtensa'], false)
            false_label = il.get_label_for_address(Architecture['xtensa'], false)

        true = addr + twos_comp(self.imm12, 12) + 4
        true_label = il.get_label_for_address(Architecture['xtensa'], true)
        if true_label is None:
            il.add_label_for_address(Architecture['xtensa'], true)
            true_label = il.get_label_for_address(Architecture['xtensa'], true)

        cmp_expr = il.compare_not_equal(4, il.reg(4, GPR[self.s]), il.const(4, 0))
        if_expr = il.if_expr(cmp_expr, true_label, false_label)
        il.append(if_expr)

        return self.length


class BNONE(RRI8):
    mnemonic = "bnone"

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
        tokens.append(InstructionTextToken(
            imm, hex(addr + twos_comp(self.imm8, 8) + 4), value=(addr + twos_comp(self.imm8, 8))))
        return [tokens, self.length]

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.add_branch(BranchType.TrueBranch, addr +
                        twos_comp(self.imm8, 8) + 4)
        info.add_branch(BranchType.FalseBranch, addr + self.length)
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):
        false = addr + self.length
        false_label = il.get_label_for_address(Architecture['xtensa'], false)
        if false_label is None:
            il.add_label_for_address(Architecture['xtensa'], false)
            false_label = il.get_label_for_address(Architecture['xtensa'], false)

        true = addr + twos_comp(self.imm8, 8) + 4
        true_label = il.get_label_for_address(Architecture['xtensa'], true)
        if true_label is None:
            il.add_label_for_address(Architecture['xtensa'], true)
            true_label = il.get_label_for_address(Architecture['xtensa'], true)

        cmp_expr = il.compare_equal(4, il.and_expr(4, il.reg(4, GPR[self.s]), il.reg(4, GPR[self.t])), il.const(4, 0))
        if_expr = il.if_expr(cmp_expr, true_label, false_label)
        il.append(if_expr)

        return self.length