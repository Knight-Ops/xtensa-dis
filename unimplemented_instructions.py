from .xtensa_instruction import XtensaInstruction

from binaryninja import LLIL_TEMP, LowLevelILLabel, InstructionTextTokenType, InstructionTextToken

class UNIMPLEMENTED(XtensaInstruction):
    length = 3

    def __init__(self, data, addr):
        pass

    def get_instruction_text(self, data, addr):
        tokens = []

        opcode = InstructionTextTokenType.TextToken
        filler = InstructionTextTokenType.TextToken
        unimpl = InstructionTextTokenType.TextToken

        justify = ' ' * (self.justify - len(self.mnemonic))
        tokens.append(InstructionTextToken(opcode, self.mnemonic))
        tokens.append(InstructionTextToken(filler, justify))
        tokens.append(InstructionTextToken(unimpl, 'unimplemented'))
        return [tokens, self.length]



class RETN(UNIMPLEMENTED):
    mnemonic = "RETN"
class RETWN(UNIMPLEMENTED):
    mnemonic = "RETWN"
class BREAKN(UNIMPLEMENTED):
    mnemonic = "BREAKN"
class NOPN(UNIMPLEMENTED):
    mnemonic = "NOPN"
class ILLN(UNIMPLEMENTED):
    mnemonic = "ILLN"
class MOVN(UNIMPLEMENTED):
    mnemonic = "MOVN"
class MOVIN(UNIMPLEMENTED):
    mnemonic = "MOVIN"
class BNEZN(UNIMPLEMENTED):
    mnemonic = "BNEZN"
class BEGU(UNIMPLEMENTED):
    mnemonic = "BEGU"
class BF(UNIMPLEMENTED):
    mnemonic = "BF"
class BT(UNIMPLEMENTED):
    mnemonic = "BT"
class LOOP(UNIMPLEMENTED):
    mnemonic = "lLOOPoop"
class LOOPNEZ(UNIMPLEMENTED):
    mnemonic = "looLOOPNEZpnez"
class LOOPGTZ(UNIMPLEMENTED):
    mnemonic = "loopLOOPGTZgtz"
class ENTRY(UNIMPLEMENTED):
    mnemonic = "entENTRYry"
class BNEI(UNIMPLEMENTED):
    mnemonic = "BNEI"
class BNEZ(UNIMPLEMENTED):
    mnemonic = "BNEZ"
class J(UNIMPLEMENTED):
    mnemonic = "J"
class CALL4(UNIMPLEMENTED):
    mnemonic = "CALL4"
class CALL8(UNIMPLEMENTED):
    mnemonic = "CALL8"
class CALL12(UNIMPLEMENTED):
    mnemonic = "CALL12"
class LDDEC(UNIMPLEMENTED):
    mnemonic = "LDDEC"
class LDINC(UNIMPLEMENTED):
    mnemonic = "LDINC"
class UMULAALL(UNIMPLEMENTED):
    mnemonic = "UMULAALL"
class UMULAAHL(UNIMPLEMENTED):
    mnemonic = "UMULAAHL"
class UMULAALH(UNIMPLEMENTED):
    mnemonic = "UMULAALH"
class UMULAAHH(UNIMPLEMENTED):
    mnemonic = "UMULAAHH"
class MULAALL(UNIMPLEMENTED):
    mnemonic = "MULAALL"
class MULAAHL(UNIMPLEMENTED):
    mnemonic = "MULAAHL"
class MULAALH(UNIMPLEMENTED):
    mnemonic = "MULAALH"
class MULAAHH(UNIMPLEMENTED):
    mnemonic = "MULAAHH"
class MULAAALL(UNIMPLEMENTED):
    mnemonic = "MULAAALL"
class MULAAAHL(UNIMPLEMENTED):
    mnemonic = "MULAAAHL"
class MULAAALH(UNIMPLEMENTED):
    mnemonic = "MULAAALH"
class MULAAAHH(UNIMPLEMENTED):
    mnemonic = "MULAAAHH"
class MULSAALL(UNIMPLEMENTED):
    mnemonic = "MULSAALL"
class MULSAAHL(UNIMPLEMENTED):
    mnemonic = "MULSAAHL"
class MULSAALH(UNIMPLEMENTED):
    mnemonic = "MULSAALH"
class MULSAAHH(UNIMPLEMENTED):
    mnemonic = "MULSAAHH"
class MULDALL(UNIMPLEMENTED):
    mnemonic = "MULDALL"
class MULDAHL(UNIMPLEMENTED):
    mnemonic = "MULDAHL"
class MULDALH(UNIMPLEMENTED):
    mnemonic = "MULDALH"
class MULDAHH(UNIMPLEMENTED):
    mnemonic = "MULDAHH"
class MULADALL(UNIMPLEMENTED):
    mnemonic = "MULADALL"
class MULADAHL(UNIMPLEMENTED):
    mnemonic = "MULADAHL"
class MULADALH(UNIMPLEMENTED):
    mnemonic = "MULADALH"
class MULADAHH(UNIMPLEMENTED):
    mnemonic = "MULADAHH"
class MULSDALL(UNIMPLEMENTED):
    mnemonic = "MULSDALL"
class MULSDAHL(UNIMPLEMENTED):
    mnemonic = "MULSDAHL"
class MULSDALH(UNIMPLEMENTED):
    mnemonic = "MULSDALH"
class MULSDAHH(UNIMPLEMENTED):
    mnemonic = "MULSDAHH"
class MULADALLLDDEC(UNIMPLEMENTED):
    mnemonic = "MULADALLLDDEC"
class MULADAHLLDDEC(UNIMPLEMENTED):
    mnemonic = "MULADAHLLDDEC"
class MULADALHLDDEC(UNIMPLEMENTED):
    mnemonic = "MULADALHLDDEC"
class MULADAHHLDDEC(UNIMPLEMENTED):
    mnemonic = "MULADAHHLDDEC"
class MULADDLLLDDEC(UNIMPLEMENTED):
    mnemonic = "MULADDLLLDDEC"
class MULADDHLLDDEC(UNIMPLEMENTED):
    mnemonic = "MULADDHLLDDEC"
class MULADDLHLDDEC(UNIMPLEMENTED):
    mnemonic = "MULADDLHLDDEC"
class MULADDHHLDDEC(UNIMPLEMENTED):
    mnemonic = "MULADDHHLDDEC"
class MULADLL(UNIMPLEMENTED):
    mnemonic = "MULADLL"
class MULADHL(UNIMPLEMENTED):
    mnemonic = "MULADHL"
class MULADLH(UNIMPLEMENTED):
    mnemonic = "MULADLH"
class MULADHH(UNIMPLEMENTED):
    mnemonic = "MULADHH"
class MULAADLL(UNIMPLEMENTED):
    mnemonic = "MULAADLL"
class MULAADHL(UNIMPLEMENTED):
    mnemonic = "MULAADHL"
class MULAADLH(UNIMPLEMENTED):
    mnemonic = "MULAADLH"
class MULAADHH(UNIMPLEMENTED):
    mnemonic = "MULAADHH"
class MULSADLL(UNIMPLEMENTED):
    mnemonic = "MULSADLL"
class MULSADHL(UNIMPLEMENTED):
    mnemonic = "MULSADHL"
class MULSADLH(UNIMPLEMENTED):
    mnemonic = "MULSADLH"
class MULSADHH(UNIMPLEMENTED):
    mnemonic = "MULSADHH"
class MULDDLL(UNIMPLEMENTED):
    mnemonic = "MULDDLL"
class MULDDHL(UNIMPLEMENTED):
    mnemonic = "MULDDHL"
class MULDDLH(UNIMPLEMENTED):
    mnemonic = "MULDDLH"
class MULDDHH(UNIMPLEMENTED):
    mnemonic = "MULDDHH"
class MULADDLL(UNIMPLEMENTED):
    mnemonic = "MULADDLL"
class MULADDHL(UNIMPLEMENTED):
    mnemonic = "MULADDHL"
class MULADDLH(UNIMPLEMENTED):
    mnemonic = "MULADDLH"
class MULADDHH(UNIMPLEMENTED):
    mnemonic = "MULADDHH"
class MULSDDLL(UNIMPLEMENTED):
    mnemonic = "MULSDDLL"
class MULSDDHL(UNIMPLEMENTED):
    mnemonic = "MULSDDHL"
class MULSDDLH(UNIMPLEMENTED):
    mnemonic = "MULSDDLH"
class MULSDDHH(UNIMPLEMENTED):
    mnemonic = "MULSDDHH"
class MULADALLLDINC(UNIMPLEMENTED):
    mnemonic = "MULADALLLDINC"
class MULADAHLLDINC(UNIMPLEMENTED):
    mnemonic = "MULADAHLLDINC"
class MULADALHLDINC(UNIMPLEMENTED):
    mnemonic = "MULADALHLDINC"
class MULADAHHLDINC(UNIMPLEMENTED):
    mnemonic = "MULADAHHLDINC"
class MULADDLLLDINC(UNIMPLEMENTED):
    mnemonic = "MULADDLLLDINC"
class MULADDHLLDINC(UNIMPLEMENTED):
    mnemonic = "MULADDHLLDINC"
class MULADDLHLDINC(UNIMPLEMENTED):
    mnemonic = "MULADDLHLDINC"
class MULADDHHLDINC(UNIMPLEMENTED):
    mnemonic = "MULADDHHLDINC"
class LSI(UNIMPLEMENTED):
    mnemonic = "LSI"
class SSI(UNIMPLEMENTED):
    mnemonic = "SSI"
class LSIU(UNIMPLEMENTED):
    mnemonic = "LSIU"
class SSIU(UNIMPLEMENTED):
    mnemonic = "SSIU"
class IPFL(UNIMPLEMENTED):
    mnemonic = "IPFL"
class IHU(UNIMPLEMENTED):
    mnemonic = "IHU"
class IIU(UNIMPLEMENTED):
    mnemonic = "IIU"
class DPFL(UNIMPLEMENTED):
    mnemonic = "DPFL"
class DHU(UNIMPLEMENTED):
    mnemonic = "DHU"
class DIU(UNIMPLEMENTED):
    mnemonic = "DIU"
class DIWB(UNIMPLEMENTED):
    mnemonic = "DIWB"
class DIWBI(UNIMPLEMENTED):
    mnemonic = "DIWBI"
class DPFR(UNIMPLEMENTED):
    mnemonic = "DPFR"
class DPFW(UNIMPLEMENTED):
    mnemonic = "DPFW"
class DPFRO(UNIMPLEMENTED):
    mnemonic = "DPFRO"
class DPFWO(UNIMPLEMENTED):
    mnemonic = "DPFWO"
class DHWB(UNIMPLEMENTED):
    mnemonic = "DHWB"
class DHWBI(UNIMPLEMENTED):
    mnemonic = "DHWBI"
class DHI(UNIMPLEMENTED):
    mnemonic = "DHI"
class DII(UNIMPLEMENTED):
    mnemonic = "DII"
class IPF(UNIMPLEMENTED):
    mnemonic = "IPF"
class IHI(UNIMPLEMENTED):
    mnemonic = "IHI"
class III(UNIMPLEMENTED):
    mnemonic = "III"
class L8UI(UNIMPLEMENTED):
    mnemonic = "L8UI"
class L16UI(UNIMPLEMENTED):
    mnemonic = "6"
class L32I(UNIMPLEMENTED):
    mnemonic = "L32I"
class S8I(UNIMPLEMENTED):
    mnemonic = "S8I"
class S16I(UNIMPLEMENTED):
    mnemonic = "S16I"
class S32I(UNIMPLEMENTED):
    mnemonic = "S32I"
class L16SI(UNIMPLEMENTED):
    mnemonic = "L16SI"
class MOVI(UNIMPLEMENTED):
    mnemonic = "MOVI"
class L32AI(UNIMPLEMENTED):
    mnemonic = "L32AI"
class S32C1I(UNIMPLEMENTED):
    mnemonic = "S32C1I"
class S32RI(UNIMPLEMENTED):
    mnemonic = "S32RI"
class UNS(UNIMPLEMENTED):
    mnemonic = "UNS"
class OEQS(UNIMPLEMENTED):
    mnemonic = "OEQS"
class UEQS(UNIMPLEMENTED):
    mnemonic = "UEQS"
class OLTS(UNIMPLEMENTED):
    mnemonic = "OLTS"
class UTLS(UNIMPLEMENTED):
    mnemonic = "UTLS"
class OLES(UNIMPLEMENTED):
    mnemonic = "OLES"
class ULES(UNIMPLEMENTED):
    mnemonic = "ULES"
class MOVEQZS(UNIMPLEMENTED):
    mnemonic = "MOVEQZS"
class MOVNEZS(UNIMPLEMENTED):
    mnemonic = "MOVNEZS"
class MOVLTZS(UNIMPLEMENTED):
    mnemonic = "MOVLTZS"
class MOVGEZS(UNIMPLEMENTED):
    mnemonic = "MOVGEZS"
class MOVFS(UNIMPLEMENTED):
    mnemonic = "MOVFS"
class MOVTS(UNIMPLEMENTED):
    mnemonic = "MOVTS"
class MOVS(UNIMPLEMENTED):
    mnemonic = "MOVS"
class RFR(UNIMPLEMENTED):
    mnemonic = "RFR"
class WRF(UNIMPLEMENTED):
    mnemonic = "WRF"
class NEGS(UNIMPLEMENTED):
    mnemonic = "NEGS"
class SUBS(UNIMPLEMENTED):
    mnemonic = "SUBS"
class MULS(UNIMPLEMENTED):
    mnemonic = "MULS"
class MADDS(UNIMPLEMENTED):
    mnemonic = "MADDS"
class MSUBS(UNIMPLEMENTED):
    mnemonic = "MSUBS"
class ROUNDS(UNIMPLEMENTED):
    mnemonic = "ROUNDS"
class TRUNCS(UNIMPLEMENTED):
    mnemonic = "TRUNCS"
class FLOORS(UNIMPLEMENTED):
    mnemonic = "FLOORS"
class CEILS(UNIMPLEMENTED):
    mnemonic = "CEILS"
class FLOATS(UNIMPLEMENTED):
    mnemonic = "FLOATS"
class UFLOATS(UNIMPLEMENTED):
    mnemonic = "UFLOATS"
class UNTRUNCS(UNIMPLEMENTED):
    mnemonic = "UNTRUNCS"
class L32E(UNIMPLEMENTED):
    mnemonic = "L32E"
class S32E(UNIMPLEMENTED):
    mnemonic = "S32E"
class LSX(UNIMPLEMENTED):
    mnemonic = "LSX"
class LSXU(UNIMPLEMENTED):
    mnemonic = "LSXU"
class SSX(UNIMPLEMENTED):
    mnemonic = "SSX"
class SSXU(UNIMPLEMENTED):
    mnemonic = "SSXU"
class RSR(UNIMPLEMENTED):
    mnemonic = "RSR"
class WSR(UNIMPLEMENTED):
    mnemonic = "WSR"
class SEXT(UNIMPLEMENTED):
    mnemonic = "SEXT"
class CLAMPS(UNIMPLEMENTED):
    mnemonic = "CLAMPS"
class MIN(UNIMPLEMENTED):
    mnemonic = "MIN"
class MAX(UNIMPLEMENTED):
    mnemonic = "MAX"
class MINU(UNIMPLEMENTED):
    mnemonic = "MINU"
class MAXU(UNIMPLEMENTED):
    mnemonic = "MAXU"
class MOVEQZ(UNIMPLEMENTED):
    mnemonic = "MOVEQZ"
class MOVNEZ(UNIMPLEMENTED):
    mnemonic = "MOVNEZ"
class MOVLTZ(UNIMPLEMENTED):
    mnemonic = "MOVLTZ"
class MOVGEZ(UNIMPLEMENTED):
    mnemonic = "MOVGEZ"
class MOVF(UNIMPLEMENTED):
    mnemonic = "MOVF"
class MOVT(UNIMPLEMENTED):
    mnemonic = "MOVT"
class RUR(UNIMPLEMENTED):
    mnemonic = "RUR"
class WUR(UNIMPLEMENTED):
    mnemonic = "WUR"
class ANDB(UNIMPLEMENTED):
    mnemonic = "ANDB"
class ANDBC(UNIMPLEMENTED):
    mnemonic = "ANDBC"
class ORB(UNIMPLEMENTED):
    mnemonic = "ORB"
class ORBC(UNIMPLEMENTED):
    mnemonic = "ORBC"
class XORB(UNIMPLEMENTED):
    mnemonic = "XORB"
class MULL(UNIMPLEMENTED):
    mnemonic = "MULL"
class MULUH(UNIMPLEMENTED):
    mnemonic = "MULUH"
class MULSH(UNIMPLEMENTED):
    mnemonic = "MULSH"
class QUOU(UNIMPLEMENTED):
    mnemonic = "QUOU"
class QUOS(UNIMPLEMENTED):
    mnemonic = "QUOS"
class REMU(UNIMPLEMENTED):
    mnemonic = "REMU"
class REMS(UNIMPLEMENTED):
    mnemonic = "REMS"
class RFDO(UNIMPLEMENTED):
    mnemonic = "RFDO"
class RFDD(UNIMPLEMENTED):
    mnemonic = "RFDD"
class LICT(UNIMPLEMENTED):
    mnemonic = "LICT"
class SICT(UNIMPLEMENTED):
    mnemonic = "SICT"
class LICW(UNIMPLEMENTED):
    mnemonic = "LICW"
class SICW(UNIMPLEMENTED):
    mnemonic = "SICW"
class LDCT(UNIMPLEMENTED):
    mnemonic = "LDCT"
class SDCT(UNIMPLEMENTED):
    mnemonic = "SDCT"
class RER(UNIMPLEMENTED):
    mnemonic = "RER"
class WER(UNIMPLEMENTED):
    mnemonic = "WER"
class SLLI(UNIMPLEMENTED):
    mnemonic = "SLLI"
class SRAI(UNIMPLEMENTED):
    mnemonic = "SRAI"
class SRLI(UNIMPLEMENTED):
    mnemonic = "SRLI"
class XSR(UNIMPLEMENTED):
    mnemonic = "XSR"
class SRC(UNIMPLEMENTED):
    mnemonic = "SRC"
class SRL(UNIMPLEMENTED):
    mnemonic = "SRL"
class SLL(UNIMPLEMENTED):
    mnemonic = "SLL"
class SRA(UNIMPLEMENTED):
    mnemonic = "SRA"
class MUL16U(UNIMPLEMENTED):
    mnemonic = "MUL16U"
class MUL16S(UNIMPLEMENTED):
    mnemonic = "MUL16S"
class NEG(UNIMPLEMENTED):
    mnemonic = "NEG"
class RITLB0(UNIMPLEMENTED):
    mnemonic = "RITLB0"
class IITLB(UNIMPLEMENTED):
    mnemonic = "IITLB"
class PITLB(UNIMPLEMENTED):
    mnemonic = "PITLB"
class WITLB(UNIMPLEMENTED):
    mnemonic = "WITLB"
class RITLB1(UNIMPLEMENTED):
    mnemonic = "RITLB1"
class RDTLB0(UNIMPLEMENTED):
    mnemonic = "RDTLB0"
class IDTLB(UNIMPLEMENTED):
    mnemonic = "IDTLB"
class PDTLB(UNIMPLEMENTED):
    mnemonic = "PDTLB"
class WDTLB(UNIMPLEMENTED):
    mnemonic = "WDTLB"
class RDTLB1(UNIMPLEMENTED):
    mnemonic = "RDTLB1"
class SSR(UNIMPLEMENTED):
    mnemonic = "SSR"
class SSL(UNIMPLEMENTED):
    mnemonic = "SSL"
class SSA8L(UNIMPLEMENTED):
    mnemonic = "SSA8L"
class SSA8B(UNIMPLEMENTED):
    mnemonic = "SSA8B"
class SSAI(UNIMPLEMENTED):
    mnemonic = "SSAI"
class ROTW(UNIMPLEMENTED):
    mnemonic = "ROTW"
class NSA(UNIMPLEMENTED):
    mnemonic = "NSA"
class NSAU(UNIMPLEMENTED):
    mnemonic = "NSAU"
class RFE(UNIMPLEMENTED):
    mnemonic = "RFE"
class RFUE(UNIMPLEMENTED):
    mnemonic = "RFUE"
class RFDE(UNIMPLEMENTED):
    mnemonic = "RFDE"
class RFWO(UNIMPLEMENTED):
    mnemonic = "RFWO"
class RFWU(UNIMPLEMENTED):
    mnemonic = "RFWU"
class RFET(UNIMPLEMENTED):
    mnemonic = "RFET"
class RFI(UNIMPLEMENTED):
    mnemonic = "RFI"
class RFME(UNIMPLEMENTED):
    mnemonic = "RFME"
class ISYNC(UNIMPLEMENTED):
    mnemonic = "ISYNC"
class RSYNC(UNIMPLEMENTED):
    mnemonic = "RSYNC"
class ESYNC(UNIMPLEMENTED):
    mnemonic = "ESYNC"
class DSYNC(UNIMPLEMENTED):
    mnemonic = "DSYNC"
class EXCW(UNIMPLEMENTED):
    mnemonic = "EXCW"
class MEMW(UNIMPLEMENTED):
    mnemonic = "MEMW"
class EXTW(UNIMPLEMENTED):
    mnemonic = "EXTW"
class CALLX0(UNIMPLEMENTED):
    mnemonic = "CALLX0"
class CALLX4(UNIMPLEMENTED):
    mnemonic = "CALLX4"
class CALLX8(UNIMPLEMENTED):
    mnemonic = "CALLX8"
class CALLX12(UNIMPLEMENTED):
    mnemonic = "CALLX12"
class RETW(UNIMPLEMENTED):
    mnemonic = "RETW"
class JX(UNIMPLEMENTED):
    mnemonic = "JX"
class ILL(UNIMPLEMENTED):
    mnemonic = "ILL"
class MOVSP(UNIMPLEMENTED):
    mnemonic = "MOVSP"
class BREAK(UNIMPLEMENTED):
    mnemonic = "BREAK"
class SYSCALL(UNIMPLEMENTED):
    mnemonic = "SYSCALL"
class RSIL(UNIMPLEMENTED):
    mnemonic = "RSIL"
class WAITI(UNIMPLEMENTED):
    mnemonic = "WAITI"
class ANY4(UNIMPLEMENTED):
    mnemonic = "ANY4"
class ALL4(UNIMPLEMENTED):
    mnemonic = "ALL4"
class ANY8(UNIMPLEMENTED):
    mnemonic = "ANY8"
class ALL8(UNIMPLEMENTED):
    mnemonic = "ALL8"
class OR(UNIMPLEMENTED):
    mnemonic = "OR"
class XOR(UNIMPLEMENTED):
    mnemonic = "XOR"
class SUB(UNIMPLEMENTED):
    mnemonic = "SUB"
class SUBX2(UNIMPLEMENTED):
    mnemonic = "SUBX2"
class SUBX4(UNIMPLEMENTED):
    mnemonic = "SUBX4"
class SUBX8(UNIMPLEMENTED):
    mnemonic = "SUBX8"
class EXTUI(UNIMPLEMENTED):
    mnemonic = "EXTUI"
class CUST0(UNIMPLEMENTED):
    mnemonic = "CUST0"
class CUST1(UNIMPLEMENTED):
    mnemonic = "CUST1"
class L32R(UNIMPLEMENTED):
    mnemonic = "L32R"
class L32IN(UNIMPLEMENTED):
    mnemonic = "L32IN"
class S32IN(UNIMPLEMENTED):
    mnemonic = "S32IN"