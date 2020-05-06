from ..xtensa_instruction import RRR, RRRN, RRI8, RI6, RI16
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


        il.append(il.set_reg(4, self.r, il.and_expr(4, il.logical_shift_right(4, il.reg(4, self.t), il.const(4, shiftimm)) , il.const(4, mask))))

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
        il.append(il.set_reg(4, self.t, il.load(1, il.add(4, il.reg(4, self.s), il.const(4, self.imm8)))))
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
        il.append(il.set_reg(4, self.t, il.sign_extend(4, il.load(2, il.add(4, il.reg(4, self.s), il.const(4, self.imm8 << 1))))))
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
        il.append(il.set_reg(4, self.t,il.load(2, il.add(4, il.reg(4, self.s), il.const(4, self.imm8 << 1)))))
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
        il.append(il.set_reg(4, self.t, il.load(4, il.add(4, il.reg(4, self.s), il.const(4, self.imm8 << 2)))))
        return self.length

#TODO Check this for the Extended L32R Option (4.3.3)
class L32R(RI16):
    mnemonic = "l32r"

    def get_instruction_low_level_il(self, data, addr, il):
        addr_prep = (addr + 3) & 0xFFFFFFFC
        imm_prep = 0xFFFFFFFF & (self.imm16 << 2)

        offset = addr_prep + imm_prep

        il.append(il.set_reg(4, self.t, il.load(4, il.const(4, offset))))
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