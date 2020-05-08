from ..xtensa_instruction import RRR, RRRN, RRI8, RI6, RI16, RSR_TYPE
from ..xtensa_register import GPR
from ..utils import twos_comp, get_mask

from binaryninja import LLIL_TEMP, LowLevelILLabel, InstructionTextTokenType, InstructionTextToken

class DSYNC(RRR):
    mnemonic = "dsync"

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

class ESYNC(RRR):
    mnemonic = "esync"

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

class EXTUI(RRR):
    mnemonic = "extui"

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
        shiftimm = self.s + ((self.op1 << 4) & 0x10)
        tokens.append(InstructionTextToken(imm, "{}".format(shiftimm)))
        tokens.append(InstructionTextToken(sep, ','))
        tokens.append(InstructionTextToken(imm, "{}".format(self.op2 + 1)))
        return [tokens, self.length]

    def get_instruction_low_level_il(self, data, addr, il):

        mask = get_mask(self.op2 + 1)
        shiftimm = self.s + ((self.op1 << 4) & 0x10)


        il.append(il.set_reg(4, GPR[self.r], il.and_expr(4, il.logical_shift_right(4, il.reg(4, GPR[self.t]), il.const(4, shiftimm)) , il.const(4, mask))))

        return self.length


class EXTW(RRR):
    mnemonic = "extw"

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

class ISYNC(RRR):
    mnemonic = "isync"

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

class L8UI(RRI8):
    mnemonic = "l8ui"

    def get_instruction_low_level_il(self, data, addr, il):
        il.append(il.set_reg(4, GPR[self.t], il.load(1, il.add(4, il.reg(4, GPR[self.s]), il.const(4, self.imm8)))))
        return self.length

class L16SI(RRI8):
    mnemonic = "l16si"

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
        tokens.append(InstructionTextToken(imm, "{}".format(self.imm8 << 1)))
        return [tokens, self.length]

    def get_instruction_low_level_il(self, data, addr, il):
        il.append(il.set_reg(4, GPR[self.t], il.sign_extend(4, il.load(2, il.add(4, il.reg(4, GPR[self.s]), il.const(4, self.imm8 << 1))))))
        return self.length

class L16UI(RRI8):
    mnemonic = "l16ui"

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
        tokens.append(InstructionTextToken(imm, "{}".format(self.imm8 << 1)))
        return [tokens, self.length]

    def get_instruction_low_level_il(self, data, addr, il):
        il.append(il.set_reg(4, GPR[self.t],il.load(2, il.add(4, il.reg(4, GPR[self.s]), il.const(4, self.imm8 << 1)))))
        return self.length

class L32I(RRI8):
    mnemonic = "l32i"

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
        tokens.append(InstructionTextToken(imm, "{}".format(self.imm8 << 2)))
        return [tokens, self.length]

    def get_instruction_low_level_il(self, data, addr, il):
        il.append(il.set_reg(4, GPR[self.t], il.load(4, il.add(4, il.reg(4, GPR[self.s]), il.const(4, self.imm8 << 2)))))
        return self.length

#TODO Check this for the Extended L32R Option (4.3.3)
class L32R(RI16):
    mnemonic = "l32r"

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
        offset_calc = ((addr + 3) & 0xFFFFFFFC) + (0xFFFFFFFF & (self.imm16 << 2))
        tokens.append(InstructionTextToken(imm, hex(offset_calc), value=offset_calc))
        return [tokens, self.length]

    def get_instruction_low_level_il(self, data, addr, il):
        offset_calc = ((addr + 3) & 0xFFFFFFFC) + (0xFFFFFFFF & (self.imm16 << 2))

        il.append(il.set_reg(4, GPR[self.t], il.load(4, il.const(4, offset_calc))))
        return self.length

class MEMW(RRR):
    mnemonic = "memw"

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

class MOVEQZ(RRR):
    mnemonic = "moveqz"

    def get_instruction_low_level_il(self, data, addr, il):
        true_label = LowLevelILLabel()
        false_label = LowLevelILLabel()

        cmp_expr = il.compare_equal(4, il.reg(4, GPR[self.t]), il.const(4, 0))
        if_expr = il.if_expr(cmp_expr, true_label, false_label)
        il.append(if_expr)

        il.mark_label(true_label)
        il.append(il.set_reg(4, GPR[self.r], il.reg(4, GPR[self.s])))

        il.mark_label(false_label)
        return self.length

class MOVGEZ(RRR):
    mnemonic = "movgez"

    def get_instruction_low_level_il(self, data, addr, il):
        true_label = LowLevelILLabel()
        false_label = LowLevelILLabel()

        cmp_expr = il.compare_signed_greater_equal(4, il.reg(4, GPR[self.t]), il.const(4, 0))
        if_expr = il.if_expr(cmp_expr, true_label, false_label)
        il.append(if_expr)

        il.mark_label(true_label)
        il.append(il.set_reg(4, GPR[self.r], il.reg(4, GPR[self.s])))

        il.mark_label(false_label)
        return self.length

class MOVI(RRI8):
    mnemonic = "movi"

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

        imm_prep = self.imm8 + (self.s << 8)
        imm12 = twos_comp(imm_prep, 12)

        tokens.append(InstructionTextToken(imm, "{}".format(imm12)))
        return [tokens, self.length]

    def get_instruction_low_level_il(self, data, addr, il):

        imm_prep = self.imm8 + (self.s << 8)
        imm12 = twos_comp(imm_prep, 12)

        il.append(il.set_reg(4, GPR[self.t], il.const(4, imm12)))

        return self.length

class MOVLTZ(RRR):
    mnemonic = "movltz"

    def get_instruction_low_level_il(self, data, addr, il):
        true_label = LowLevelILLabel()
        false_label = LowLevelILLabel()

        cmp_expr = il.compare_signed_less_than(4, il.reg(4, GPR[self.t]), il.const(4, 0))
        if_expr = il.if_expr(cmp_expr, true_label, false_label)
        il.append(if_expr)

        il.mark_label(true_label)
        il.append(il.set_reg(4, GPR[self.r], il.reg(4, GPR[self.s])))

        il.mark_label(false_label)
        return self.length

class MOVNEZ(RRR):
    mnemonic = "movnez"

    def get_instruction_low_level_il(self, data, addr, il):
        true_label = LowLevelILLabel()
        false_label = LowLevelILLabel()

        cmp_expr = il.compare_not_equal(4, il.reg(4, GPR[self.t]), il.const(4, 0))
        if_expr = il.if_expr(cmp_expr, true_label, false_label)
        il.append(if_expr)

        il.mark_label(true_label)
        il.append(il.set_reg(4, GPR[self.r], il.reg(4, GPR[self.s])))

        il.mark_label(false_label)
        return self.length

class NEG(RRR):
    mnemonic = "neg"

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
        il.append(il.set_reg(4, GPR[self.r], il.neg_expr(4, il.reg(4, GPR[self.t]))))
        return self.length

class NOP(RRR):
    mnemonic = "nop"

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

#TODO Actually implement this once we build out all the "special registers"
class RSR(RSR_TYPE):
    mnemonic = "rsr"

    def get_instruction_low_level_il(self, data, addr, il):
        il.append(il.unimplemented())
        return self.length

class RSYNC(RRR):
    mnemonic = "rsync"

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

class S8I(RRI8):
    mnemonic = "s8i"

    def get_instruction_low_level_il(self, data, addr, il):
        il.append(il.store(1, il.add(4, il.reg(4, GPR[self.s]), il.const(4, self.imm8)), il.reg(4, GPR[self.t])))
        return self.length


class S16I(RRI8):
    mnemonic = "s16i"

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

        imm_prep = self.imm8 << 1
        tokens.append(InstructionTextToken(imm, "{}".format(imm_prep)))
        return [tokens, self.length]

    def get_instruction_low_level_il(self, data, addr, il):
        imm_prep = self.imm8 << 1
        il.append(il.store(2, il.add(4, il.reg(4, GPR[self.s]), il.const(4, imm_prep)), il.reg(4, GPR[self.t])))
        return self.length

class S32I(RRI8):
    mnemonic = "s32i"

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

        imm_prep = self.imm8 << 2
        tokens.append(InstructionTextToken(imm, "{}".format(imm_prep)))
        return [tokens, self.length]

    def get_instruction_low_level_il(self, data, addr, il):
        imm_prep = self.imm8 << 2
        il.append(il.store(4, il.add(4, il.reg(4, GPR[self.s]), il.const(4, imm_prep)), il.reg(4, GPR[self.t])))
        return self.length

class SSA8B(RRR):
    mnemonic = "ssa8b"

    def get_instruction_text(self, data, addr):
        tokens = []
        opcode = InstructionTextTokenType.TextToken
        register = InstructionTextTokenType.RegisterToken
        filler = InstructionTextTokenType.TextToken

        justify = ' ' * (self.justify - len(self.mnemonic))
        tokens.append(InstructionTextToken(opcode, self.mnemonic))
        tokens.append(InstructionTextToken(filler, justify))
        tokens.append(InstructionTextToken(register, GPR[self.s]))
        return [tokens, self.length]

    def get_instruction_low_level_il(self, data, addr, il):

        shift_prep = il.sub(1, il.const(1, 32), il.shift_left(1, il.and_expr(4, il.reg(4, GPR[self.s]), il.const(4, 0x00000003)), il.const(1, 3)))

        il.append(il.set_reg(1, "sar", shift_prep))

        return self.length

class SSA8L(RRR):
    mnemonic = "ssa8l"

    def get_instruction_text(self, data, addr):
        tokens = []
        opcode = InstructionTextTokenType.TextToken
        register = InstructionTextTokenType.RegisterToken
        filler = InstructionTextTokenType.TextToken

        justify = ' ' * (self.justify - len(self.mnemonic))
        tokens.append(InstructionTextToken(opcode, self.mnemonic))
        tokens.append(InstructionTextToken(filler, justify))
        tokens.append(InstructionTextToken(register, GPR[self.s]))
        return [tokens, self.length]

    def get_instruction_low_level_il(self, data, addr, il):

        two_bits = il.and_expr(4, il.reg(4, GPR[self.s]), il.const(4, 0x00000003))
        times_eight = il.shift_left(1, two_bits, il.const(1, 3))
        il.append(il.set_reg(1, "sar", times_eight))
        return self.length

class SSAI(RRR):
    mnemonic = "ssai"

    def get_instruction_text(self, data, addr):
        tokens = []
        opcode = InstructionTextTokenType.TextToken
        register = InstructionTextTokenType.RegisterToken
        filler = InstructionTextTokenType.TextToken
        imm = InstructionTextTokenType.IntegerToken

        justify = ' ' * (self.justify - len(self.mnemonic))
        tokens.append(InstructionTextToken(opcode, self.mnemonic))
        tokens.append(InstructionTextToken(filler, justify))

        imm_prep = self.s + ((self.t & 0x1) << 4)
        tokens.append(InstructionTextToken(imm, "{}".format(imm_prep)))
        return [tokens, self.length]

    def get_instruction_low_level_il(self, data, addr, il):
        imm_prep = self.s + ((self.t & 0x1) << 4)
        il.append(il.set_reg(1, "sar", il.const(4, imm_prep)))

        return self.length

class SSL(RRR):
    mnemonic = "ssl"

    def get_instruction_text(self, data, addr):
        tokens = []
        opcode = InstructionTextTokenType.TextToken
        register = InstructionTextTokenType.RegisterToken
        filler = InstructionTextTokenType.TextToken

        justify = ' ' * (self.justify - len(self.mnemonic))
        tokens.append(InstructionTextToken(opcode, self.mnemonic))
        tokens.append(InstructionTextToken(filler, justify))
        tokens.append(InstructionTextToken(register, GPR[self.s]))
        return [tokens, self.length]

    def get_instruction_low_level_il(self, data, addr, il):

        shift_prep = il.sub(1, il.const(1, 32), il.and_expr(1, il.reg(4, GPR[self.s]), il.const(4, 0x0000001F)))

        il.append(il.set_reg(1, "sar", shift_prep))

        return self.length

class SSR(RRR):
    mnemonic = "ssr"

    def get_instruction_text(self, data, addr):
        tokens = []
        opcode = InstructionTextTokenType.TextToken
        register = InstructionTextTokenType.RegisterToken
        filler = InstructionTextTokenType.TextToken

        justify = ' ' * (self.justify - len(self.mnemonic))
        tokens.append(InstructionTextToken(opcode, self.mnemonic))
        tokens.append(InstructionTextToken(filler, justify))
        tokens.append(InstructionTextToken(register, GPR[self.s]))
        return [tokens, self.length]

    def get_instruction_low_level_il(self, data, addr, il):

        shift_prep = il.and_expr(1, il.reg(4, GPR[self.s]), il.const(4, 0x0000001F))

        il.append(il.set_reg(1, "sar", shift_prep))

        return self.length

#TODO Actually implement this once we build out all the "special registers"
class WSR(RSR_TYPE):
    mnemonic = "wsr"

    def get_instruction_low_level_il(self, data, addr, il):
        il.append(il.unimplemented())
        return self.length

#TODO Actually implement this once we build out all the "special registers"
class XSR(RSR_TYPE):
    mnemonic = "xsr"

    def get_instruction_low_level_il(self, data, addr, il):
        il.append(il.unimplemented())
        return self.length