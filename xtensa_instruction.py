from struct import unpack

from binaryninja import InstructionInfo, InstructionTextToken, log_error
from binaryninja.enums import InstructionTextTokenType

from .xtensa_register import GPR


class XtensaInstruction:
    """
    Our base type for decoding instructions. Implements the decoding functions,
    and the necessary get_instruction_text, get_instruction_info, and
    get_instruction_low_level_il, which are all called from their respective
    functions in our architecture.
    """
    opcode: int = None
    mnemonic: str = ""
    justify: int = 10
    length: int = 0

    @classmethod
    def decode(cls, data, addr):
        """
        Our default decoder. Written so that THIS particular one will never return an object
        but classes with defined opcodes and mnemonics can inherit this and use it.
        """
        if len(data) < cls.length:
            return None
        # if cls.op0 is None:
        #     return None
        if data[0] & 0x0f != cls.opcode:
            log_error("Opcode doesn't match data[0]")
            return None
        return cls(data, addr)

    def __init__(self, data, addr):
        """
        We never actually use this one, so it is empty
        :param data:
        :param addr:
        """
        pass

    def get_instruction_info(self, data, addr):
        """
        Default get_instruction_info, which sets up the InstructionInfo object and does not
        add a branch.
        :param data:
        :param addr:
        :return:
        """
        info = InstructionInfo()
        info.length = self.length
        return info

    def get_instruction_text(self, data, addr):
        """
        Default (empty) tokenization
        :param data:
        :param addr:
        :return:
        """
        return ['', self.length]

    def get_instruction_low_level_il(self, data, addr, il):
        """
        Default Low Level IL
        :param data:
        :param addr:
        :param il:
        :return:
        """
        return self.length

    def get_op0(self, data):
        return data[0] & 0xF


class RRR(XtensaInstruction):
    length = 3
    op0 = None
    t = None
    s = None
    r = None
    op1 = None
    op2 = None

    def __init__(self, data, addr):
        self.op0 = self.get_op0(data)
        self.t = self.get_t(data)
        self.s = self.get_s(data)
        self.r = self.get_r(data)
        self.op1 = self.get_op1(data)
        self.op2 = self.get_op2(data)

    def get_t(self, data):
        return (data[0] >> 4) & 0xF

    def get_s(self, data):
        return data[1] & 0xF

    def get_r(self, data):
        return (data[1] >> 4) & 0xF

    def get_op1(self, data):
        return data[2] & 0xF

    def get_op2(self, data):
        return (data[2] >> 4) & 0xF

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


class RRI4(XtensaInstruction):
    length = 3
    op0 = None
    t = None
    s = None
    r = None
    op1 = None
    imm4 = None

    def __init__(self, data, addr):
        self.op0 = self.get_op0(data)
        self.t = self.get_t(data)
        self.s = self.get_s(data)
        self.r = self.get_r(data)
        self.op1 = self.get_op1(data)
        self.imm4 = self.get_imm4(data)

    def get_t(self, data):
        return (data[0] >> 4) & 0xF

    def get_s(self, data):
        return data[1] & 0xF

    def get_r(self, data):
        return (data[1] >> 4) & 0xF

    def get_op1(self, data):
        return data[2] & 0xF

    def get_imm4(self, data):
        return (data[2] >> 4) & 0xF

    def get_instruction_text(self, data, addr):

        tokens = []
        # opcode = InstructionTextTokenType.TextToken
        # register = InstructionTextTokenType.RegisterToken
        # filler = InstructionTextTokenType.TextToken
        # sep = InstructionTextTokenType.OperandSeparatorToken
        # imm = InstructionTextTokenType.IntegerToken

        # justify = ' ' * (self.justify - len(self.mnemonic))
        # tokens.append(InstructionTextToken(opcode, self.mnemonic))
        # tokens.append(InstructionTextToken(filler, justify))
        # tokens.append(InstructionTextToken(register, GPR[self.r]))
        # tokens.append(InstructionTextToken(sep, ','))
        # tokens.append(InstructionTextToken(imm, self.imm4))
        return [tokens, self.length]

class RRI8(XtensaInstruction):
    length = 3
    op0 = None
    t = None
    s = None
    r = None
    imm8 = None

    def __init__(self, data, addr):
        self.op0 = self.get_op0(data)
        self.t = self.get_t(data)
        self.s = self.get_s(data)
        self.r = self.get_r(data)
        self.imm8 = self.get_imm8(data)

    def get_t(self, data):
        return (data[0] >> 4) & 0xF

    def get_s(self, data):
        return data[1] & 0xF

    def get_r(self, data):
        return (data[1] >> 4) & 0xF

    def get_imm8(self, data):
        return data[2] & 0xFF

    def get_instruction_text(self, data, addr):

        tokens = []
        # opcode = InstructionTextTokenType.TextToken
        # register = InstructionTextTokenType.RegisterToken
        # filler = InstructionTextTokenType.TextToken
        # sep = InstructionTextTokenType.OperandSeparatorToken
        # imm = InstructionTextTokenType.IntegerToken

        # justify = ' ' * (self.justify - len(self.mnemonic))
        # tokens.append(InstructionTextToken(opcode, self.mnemonic))
        # tokens.append(InstructionTextToken(filler, justify))
        # tokens.append(InstructionTextToken(register, GPR[self.r]))
        # tokens.append(InstructionTextToken(sep, ','))
        # tokens.append(InstructionTextToken(imm, self.imm8))
        return [tokens, self.length]

class RI16(XtensaInstruction):
    length = 3
    op0 = None
    t = None
    imm16 = None

    def __init__(self, data, addr):
        self.op0 = self.get_op0(data)
        self.t = self.get_t(data)
        self.imm16 = self.get_imm16(data)

    def get_t(self, data):
        return (data[0] >> 4) & 0xF

    def get_imm16(self, data):
        return data[1:3] & 0xFFFF

    def get_instruction_text(self, data, addr):

        tokens = []
        # opcode = InstructionTextTokenType.TextToken
        # register = InstructionTextTokenType.RegisterToken
        # filler = InstructionTextTokenType.TextToken
        # sep = InstructionTextTokenType.OperandSeparatorToken
        # imm = InstructionTextTokenType.IntegerToken

        # justify = ' ' * (self.justify - len(self.mnemonic))
        # tokens.append(InstructionTextToken(opcode, self.mnemonic))
        # tokens.append(InstructionTextToken(filler, justify))
        # tokens.append(InstructionTextToken(register, GPR[self.t]))
        # tokens.append(InstructionTextToken(sep, ','))
        # tokens.append(InstructionTextToken(imm, self.imm16))
        return [tokens, self.length]

class RSR(XtensaInstruction):
    length = 3
    op0 = None
    t = None
    rs = None
    op1 = None
    op2 = None

    def __init__(self, data, addr):
        self.op0 = self.get_op0(data)
        self.t = self.get_t(data)
        self.rs = self.get_rs(data)
        self.op1 = self.get_op1(data)
        self.op2 = self.get_op2(data)

    def get_t(self, data):
        return (data[0] >> 4) & 0xF

    def get_rs(self, data):
        return data[1] & 0xFF

    def get_op1(self, data):
        return data[2] & 0xF

    def get_op2(self, data):
        return (data[2] >> 4) & 0xF

    def get_instruction_text(self, data, addr):

        tokens = []
        # opcode = InstructionTextTokenType.TextToken
        # register = InstructionTextTokenType.RegisterToken
        # filler = InstructionTextTokenType.TextToken
        # sep = InstructionTextTokenType.OperandSeparatorToken
        # imm = InstructionTextTokenType.IntegerToken

        # justify = ' ' * (self.justify - len(self.mnemonic))
        # tokens.append(InstructionTextToken(opcode, self.mnemonic))
        # tokens.append(InstructionTextToken(filler, justify))
        # tokens.append(InstructionTextToken(register, GPR[self.t]))
        # tokens.append(InstructionTextToken(sep, ','))
        # tokens.append(InstructionTextToken(imm, self.rs))
        return [tokens, self.length]


class CALL(XtensaInstruction):
    length = 3
    op0 = None
    n = None
    offset = None

    def __init__(self, data, addr):
        self.op0 = self.get_op0(data)
        self.n = self.get_n(data)
        self.offset = self.get_offset(data)

    def get_n(self, data):
        return (data[0] >> 4) & 0x3

    def get_offset(self, data):
        return (data[0:3] >> 6) & 0x3FFFF

    def get_instruction_text(self, data, addr):

        tokens = []
        # opcode = InstructionTextTokenType.TextToken
        # filler = InstructionTextTokenType.TextToken
        # call_loc = InstructionTextTokenType.PossibleAddressToken

        # justify = ' ' * (self.justify - len(self.mnemonic))
        # tokens.append(InstructionTextToken(opcode, self.mnemonic))
        # tokens.append(InstructionTextToken(filler, justify))
        # tokens.append(InstructionTextToken(call_loc, self.offset))
        return [tokens, self.length]

class CALLX(XtensaInstruction):
    length = 3
    op0 = None
    n = None
    m = None
    s = None
    t = None
    op1 = None
    op2 = None

    def __init__(self, data, addr):
        self.op0 = self.get_op0(data)
        self.n = self.get_n(data)
        self.m = self.get_m(data)
        self.s = self.get_s(data)
        self.r = self.get_r(data)
        self.op1 = self.get_op1(data)
        self.op2 = self.get_op2(data)

    def get_n(self, data):
        return (data[0] >> 4) & 0x3

    def get_m(self, data):
        return (data[0] >> 6) & 0x3

    def get_s(self, data):
        return data[1] & 0xF

    def get_r(self, data):
        return (data[1] >> 4) & 0xF

    def get_op1(self, data):
        return data[2] & 0xF

    def get_op2(self, data):
        return (data[2] >> 4) & 0xF

    def get_instruction_text(self, data, addr):

        tokens = []
        # opcode = InstructionTextTokenType.TextToken
        # register = InstructionTextTokenType.RegisterToken
        # filler = InstructionTextTokenType.TextToken
        # sep = InstructionTextTokenType.OperandSeparatorToken
        # call_loc = InstructionTextTokenType.PossibleAddressToken

        # justify = ' ' * (self.justify - len(self.mnemonic))
        # tokens.append(InstructionTextToken(opcode, self.mnemonic))
        # tokens.append(InstructionTextToken(filler, justify))
        # tokens.append(InstructionTextToken(call_loc, self.call_loc))
        return [tokens, self.length]

class BRI8(XtensaInstruction):
    length = 3
    op0 = None
    n = None
    m = None
    s = None
    r = None
    imm8 = None

    def __init__(self, data, addr):
        self.op0 = self.get_op0(data)
        self.n = self.get_n(data)
        self.m = self.get_m(data)
        self.s = self.get_s(data)
        self.r = self.get_r(data)
        self.imm8 = self.get_imm8(data)

    def get_n(self, data):
        return (data[0] >> 4) & 0x3

    def get_m(self, data):
        return (data[0] >> 6) & 0x3

    def get_s(self, data):
        return data[1] & 0xF

    def get_r(self, data):
        return (data[1] >> 4) & 0xF

    def get_imm8(self, data):
        return data[2] & 0xFF

    def get_instruction_text(self, data, addr):

        tokens = []
        # opcode = InstructionTextTokenType.TextToken
        # register = InstructionTextTokenType.RegisterToken
        # filler = InstructionTextTokenType.TextToken
        # sep = InstructionTextTokenType.OperandSeparatorToken
        # call_loc = InstructionTextTokenType.PossibleAddressToken

        # justify = ' ' * (self.justify - len(self.mnemonic))
        # tokens.append(InstructionTextToken(opcode, self.mnemonic))
        # tokens.append(InstructionTextToken(filler, justify))
        # tokens.append(InstructionTextToken(call_loc, self.call_loc))
        return [tokens, self.length]

class BRI12(XtensaInstruction):
    length = 3
    op0 = None
    n = None
    m = None
    s = None
    imm12 = None

    def __init__(self, data, addr):
        self.op0 = self.get_op0(data)
        self.n = self.get_n(data)
        self.m = self.get_m(data)
        self.s = self.get_s(data)
        self.imm12 = self.get_imm12(data)

    def get_n(self, data):
        return (data[0] >> 4) & 0x3

    def get_m(self, data):
        return (data[0] >> 6) & 0x3

    def get_s(self, data):
        return data[1] & 0xF

    def get_imm12(self, data):
        return (data[1:3] >> 12) & 0xFFF

    def get_instruction_text(self, data, addr):

        tokens = []
        # opcode = InstructionTextTokenType.TextToken
        # register = InstructionTextTokenType.RegisterToken
        # filler = InstructionTextTokenType.TextToken
        # sep = InstructionTextTokenType.OperandSeparatorToken
        # call_loc = InstructionTextTokenType.PossibleAddressToken

        # justify = ' ' * (self.justify - len(self.mnemonic))
        # tokens.append(InstructionTextToken(opcode, self.mnemonic))
        # tokens.append(InstructionTextToken(filler, justify))
        # tokens.append(InstructionTextToken(call_loc, self.call_loc))
        return [tokens, self.length]

class RRRN(XtensaInstruction):
    length = 2
    op0 = None
    t = None
    s = None
    r = None

    def __init__(self, data, addr):
        self.op0 = self.get_op0(data)
        self.t = self.get_t(data)
        self.s = self.get_s(data)
        self.r = self.get_r(data)

    def get_t(self, data):
        return (data[0] >> 4) & 0xF

    def get_s(self, data):
        return data[1] & 0xF

    def get_r(self, data):
        return (data[1] >> 4) & 0xF

    def get_instruction_text(self, data, addr):

        tokens = []
        # opcode = InstructionTextTokenType.TextToken
        # register = InstructionTextTokenType.RegisterToken
        # filler = InstructionTextTokenType.TextToken
        # sep = InstructionTextTokenType.OperandSeparatorToken

        # justify = ' ' * (self.justify - len(self.mnemonic))
        # tokens.append(InstructionTextToken(opcode, self.mnemonic))
        # tokens.append(InstructionTextToken(filler, justify))
        # tokens.append(InstructionTextToken(register, GPR[self.r]))
        # tokens.append(InstructionTextToken(sep, ','))
        # tokens.append(InstructionTextToken(register, GPR[self.s]))
        return [tokens, self.length]

class RI7(XtensaInstruction):
    length = 2
    op0 = None
    s = None
    i = None
    imm7 = None

    def __init__(self, data, addr):
        self.op0 = self.get_op0(data)
        self.s = self.get_s(data)
        self.i = self.get_i(data)
        self.imm7 = self.get_imm7(data)

    def get_s(self, data):
        return data[1] & 0xF

    def get_i(self, data):
        return (data[0] >> 7) & 0x1

    def get_imm7(self, data):
        low = (data[1] >> 4) & 0xF
        high = data[0] & 0x70
        return (high | low)

    def get_instruction_text(self, data, addr):

        tokens = []
        # opcode = InstructionTextTokenType.TextToken
        # register = InstructionTextTokenType.RegisterToken
        # filler = InstructionTextTokenType.TextToken
        # sep = InstructionTextTokenType.OperandSeparatorToken

        # justify = ' ' * (self.justify - len(self.mnemonic))
        # tokens.append(InstructionTextToken(opcode, self.mnemonic))
        # tokens.append(InstructionTextToken(filler, justify))
        # tokens.append(InstructionTextToken(register, GPR[self.r]))
        # tokens.append(InstructionTextToken(sep, ','))
        # tokens.append(InstructionTextToken(register, GPR[self.s]))
        return [tokens, self.length]

class RI6(XtensaInstruction):
    length = 2
    op0 = None
    s = None
    i = None
    z = None
    imm6 = None

    def __init__(self, data, addr):
        self.op0 = self.get_op0(data)
        self.s = self.get_s(data)
        self.i = self.get_i(data)
        self.z = self.get_z(data)
        self.imm6 = self.get_imm6(data)

    def get_s(self, data):
        return data[1] & 0xF

    def get_i(self, data):
        return (data[0] >> 7) & 0x1

    def get_z(self, data):
        return(data[0] >> 6) & 0x1

    def get_imm6(self, data):
        low = (data[1] >> 4) & 0xF
        high = data[0] & 0x30
        return (high | low)

    def get_instruction_text(self, data, addr):

        tokens = []
        # opcode = InstructionTextTokenType.TextToken
        # register = InstructionTextTokenType.RegisterToken
        # filler = InstructionTextTokenType.TextToken
        # sep = InstructionTextTokenType.OperandSeparatorToken

        # justify = ' ' * (self.justify - len(self.mnemonic))
        # tokens.append(InstructionTextToken(opcode, self.mnemonic))
        # tokens.append(InstructionTextToken(filler, justify))
        # tokens.append(InstructionTextToken(register, GPR[self.r]))
        # tokens.append(InstructionTextToken(sep, ','))
        # tokens.append(InstructionTextToken(register, GPR[self.s]))
        return [tokens, self.length]