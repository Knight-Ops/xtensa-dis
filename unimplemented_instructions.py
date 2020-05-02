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
    mnemonic = ""
class RETWN(UNIMPLEMENTED):
    mnemonic = ""
class BREAKN(UNIMPLEMENTED):
    mnemonic = ""
class NOPN(UNIMPLEMENTED):
    mnemonic = ""
class ILLN(UNIMPLEMENTED):
    mnemonic = ""
class MOVN(UNIMPLEMENTED):
    mnemonic = ""
class MOVIN(UNIMPLEMENTED):
    mnemonic = ""
class BNEZN(UNIMPLEMENTED):
    mnemonic = ""
class BNONE(UNIMPLEMENTED):
    mnemonic = ""
class BLT(UNIMPLEMENTED):
    mnemonic = ""
class BLTU(UNIMPLEMENTED):
    mnemonic = ""
class BNE(UNIMPLEMENTED):
    mnemonic = ""
class BGE(UNIMPLEMENTED):
    mnemonic = ""
class BEGU(UNIMPLEMENTED):
    mnemonic = ""
class BNALL(UNIMPLEMENTED):
    mnemonic = ""
class BF(UNIMPLEMENTED):
    mnemonic = ""
class BT(UNIMPLEMENTED):
    mnemonic = ""
class LOOP(UNIMPLEMENTED):
    mnemonic = ""
class LOOPNEZ(UNIMPLEMENTED):
    mnemonic = ""
class LOOPGTZ(UNIMPLEMENTED):
    mnemonic = ""
class ENTRY(UNIMPLEMENTED):
    mnemonic = ""
class BLTUI(UNIMPLEMENTED):
    mnemonic = ""
class BGEUI(UNIMPLEMENTED):
    mnemonic = ""
class BNEI(UNIMPLEMENTED):
    mnemonic = ""
class BLTI(UNIMPLEMENTED):
    mnemonic = ""
class BGEI(UNIMPLEMENTED):
    mnemonic = ""
class BNEZ(UNIMPLEMENTED):
    mnemonic = ""
class BLTZ(UNIMPLEMENTED):
    mnemonic = ""
class BGEZ(UNIMPLEMENTED):
    mnemonic = ""
class J(UNIMPLEMENTED):
    mnemonic = "j"
class CALL0(UNIMPLEMENTED):
    mnemonic = ""
class CALL4(UNIMPLEMENTED):
    mnemonic = ""
class CALL8(UNIMPLEMENTED):
    mnemonic = ""
class CALL12(UNIMPLEMENTED):
    mnemonic = ""
class LDDEC(UNIMPLEMENTED):
    mnemonic = ""
class LDINC(UNIMPLEMENTED):
    mnemonic = ""
class UMULAALL(UNIMPLEMENTED):
    mnemonic = ""
class UMULAAHL(UNIMPLEMENTED):
    mnemonic = ""
class UMULAALH(UNIMPLEMENTED):
    mnemonic = ""
class UMULAAHH(UNIMPLEMENTED):
    mnemonic = ""
class MULAALL(UNIMPLEMENTED):
    mnemonic = ""
class MULAAHL(UNIMPLEMENTED):
    mnemonic = ""
class MULAALH(UNIMPLEMENTED):
    mnemonic = ""
class MULAAHH(UNIMPLEMENTED):
    mnemonic = ""
class MULAAALL(UNIMPLEMENTED):
    mnemonic = ""
class MULAAAHL(UNIMPLEMENTED):
    mnemonic = ""
class MULAAALH(UNIMPLEMENTED):
    mnemonic = ""
class MULAAAHH(UNIMPLEMENTED):
    mnemonic = ""
class MULSAALL(UNIMPLEMENTED):
    mnemonic = ""
class MULSAAHL(UNIMPLEMENTED):
    mnemonic = ""
class MULSAALH(UNIMPLEMENTED):
    mnemonic = ""
class MULSAAHH(UNIMPLEMENTED):
    mnemonic = ""
class MULDALL(UNIMPLEMENTED):
    mnemonic = ""
class MULDAHL(UNIMPLEMENTED):
    mnemonic = ""
class MULDALH(UNIMPLEMENTED):
    mnemonic = ""
class MULDAHH(UNIMPLEMENTED):
    mnemonic = ""
class MULADALL(UNIMPLEMENTED):
    mnemonic = ""
class MULADAHL(UNIMPLEMENTED):
    mnemonic = ""
class MULADALH(UNIMPLEMENTED):
    mnemonic = ""
class MULADAHH(UNIMPLEMENTED):
    mnemonic = ""
class MULSDALL(UNIMPLEMENTED):
    mnemonic = ""
class MULSDAHL(UNIMPLEMENTED):
    mnemonic = ""
class MULSDALH(UNIMPLEMENTED):
    mnemonic = ""
class MULSDAHH(UNIMPLEMENTED):
    mnemonic = ""
class MULADALLLDDEC(UNIMPLEMENTED):
    mnemonic = ""
class MULADAHLLDDEC(UNIMPLEMENTED):
    mnemonic = ""
class MULADALHLDDEC(UNIMPLEMENTED):
    mnemonic = ""
class MULADAHHLDDEC(UNIMPLEMENTED):
    mnemonic = ""
class MULADDLLLDDEC(UNIMPLEMENTED):
    mnemonic = ""
class MULADDHLLDDEC(UNIMPLEMENTED):
    mnemonic = ""
class MULADDLHLDDEC(UNIMPLEMENTED):
    mnemonic = ""
class MULADDHHLDDEC(UNIMPLEMENTED):
    mnemonic = ""
class MULADLL(UNIMPLEMENTED):
    mnemonic = ""
class MULADHL(UNIMPLEMENTED):
    mnemonic = ""
class MULADLH(UNIMPLEMENTED):
    mnemonic = ""
class MULADHH(UNIMPLEMENTED):
    mnemonic = ""
class MULAADLL(UNIMPLEMENTED):
    mnemonic = ""
class MULAADHL(UNIMPLEMENTED):
    mnemonic = ""
class MULAADLH(UNIMPLEMENTED):
    mnemonic = ""
class MULAADHH(UNIMPLEMENTED):
    mnemonic = ""
class MULSADLL(UNIMPLEMENTED):
    mnemonic = ""
class MULSADHL(UNIMPLEMENTED):
    mnemonic = ""
class MULSADLH(UNIMPLEMENTED):
    mnemonic = ""
class MULSADHH(UNIMPLEMENTED):
    mnemonic = ""
class MULDDLL(UNIMPLEMENTED):
    mnemonic = ""
class MULDDHL(UNIMPLEMENTED):
    mnemonic = ""
class MULDDLH(UNIMPLEMENTED):
    mnemonic = ""
class MULDDHH(UNIMPLEMENTED):
    mnemonic = ""
class MULADDLL(UNIMPLEMENTED):
    mnemonic = ""
class MULADDHL(UNIMPLEMENTED):
    mnemonic = ""
class MULADDLH(UNIMPLEMENTED):
    mnemonic = ""
class MULADDHH(UNIMPLEMENTED):
    mnemonic = ""
class MULSDDLL(UNIMPLEMENTED):
    mnemonic = ""
class MULSDDHL(UNIMPLEMENTED):
    mnemonic = ""
class MULSDDLH(UNIMPLEMENTED):
    mnemonic = ""
class MULSDDHH(UNIMPLEMENTED):
    mnemonic = ""
class MULADALLLDINC(UNIMPLEMENTED):
    mnemonic = ""
class MULADAHLLDINC(UNIMPLEMENTED):
    mnemonic = ""
class MULADALHLDINC(UNIMPLEMENTED):
    mnemonic = ""
class MULADAHHLDINC(UNIMPLEMENTED):
    mnemonic = ""
class MULADDLLLDINC(UNIMPLEMENTED):
    mnemonic = ""
class MULADDHLLDINC(UNIMPLEMENTED):
    mnemonic = ""
class MULADDLHLDINC(UNIMPLEMENTED):
    mnemonic = ""
class MULADDHHLDINC(UNIMPLEMENTED):
    mnemonic = ""
class LSI(UNIMPLEMENTED):
    mnemonic = "lsi"
class SSI(UNIMPLEMENTED):
    mnemonic = ""
class LSIU(UNIMPLEMENTED):
    mnemonic = ""
class SSIU(UNIMPLEMENTED):
    mnemonic = ""
class IPFL(UNIMPLEMENTED):
    mnemonic = ""
class IHU(UNIMPLEMENTED):
    mnemonic = ""
class IIU(UNIMPLEMENTED):
    mnemonic = ""
class DPFL(UNIMPLEMENTED):
    mnemonic = ""
class DHU(UNIMPLEMENTED):
    mnemonic = ""
class DIU(UNIMPLEMENTED):
    mnemonic = ""
class DIWB(UNIMPLEMENTED):
    mnemonic = ""
class DIWBI(UNIMPLEMENTED):
    mnemonic = ""
class DPFR(UNIMPLEMENTED):
    mnemonic = ""
class DPFW(UNIMPLEMENTED):
    mnemonic = ""
class DPFRO(UNIMPLEMENTED):
    mnemonic = ""
class DPFWO(UNIMPLEMENTED):
    mnemonic = ""
class DHWB(UNIMPLEMENTED):
    mnemonic = ""
class DHWBI(UNIMPLEMENTED):
    mnemonic = ""
class DHI(UNIMPLEMENTED):
    mnemonic = ""
class DII(UNIMPLEMENTED):
    mnemonic = ""
class IPF(UNIMPLEMENTED):
    mnemonic = ""
class IHI(UNIMPLEMENTED):
    mnemonic = ""
class III(UNIMPLEMENTED):
    mnemonic = ""
class L8UI(UNIMPLEMENTED):
    mnemonic = ""
class L16UI(UNIMPLEMENTED):
    mnemonic = ""
class L32I(UNIMPLEMENTED):
    mnemonic = ""
class S8I(UNIMPLEMENTED):
    mnemonic = ""
class S16I(UNIMPLEMENTED):
    mnemonic = ""
class S32I(UNIMPLEMENTED):
    mnemonic = ""
class L16SI(UNIMPLEMENTED):
    mnemonic = ""
class MOVI(UNIMPLEMENTED):
    mnemonic = ""
class L32AI(UNIMPLEMENTED):
    mnemonic = ""
class S32C1I(UNIMPLEMENTED):
    mnemonic = ""
class S32RI(UNIMPLEMENTED):
    mnemonic = ""
class UNS(UNIMPLEMENTED):
    mnemonic = ""
class OEQS(UNIMPLEMENTED):
    mnemonic = ""
class UEQS(UNIMPLEMENTED):
    mnemonic = ""
class OLTS(UNIMPLEMENTED):
    mnemonic = ""
class UTLS(UNIMPLEMENTED):
    mnemonic = ""
class OLES(UNIMPLEMENTED):
    mnemonic = ""
class ULES(UNIMPLEMENTED):
    mnemonic = ""
class MOVEQZS(UNIMPLEMENTED):
    mnemonic = ""
class MOVNEZS(UNIMPLEMENTED):
    mnemonic = ""
class MOVLTZS(UNIMPLEMENTED):
    mnemonic = ""
class MOVGEZS(UNIMPLEMENTED):
    mnemonic = ""
class MOVFS(UNIMPLEMENTED):
    mnemonic = ""
class MOVTS(UNIMPLEMENTED):
    mnemonic = ""
class MOVS(UNIMPLEMENTED):
    mnemonic = ""
class RFR(UNIMPLEMENTED):
    mnemonic = ""
class WRF(UNIMPLEMENTED):
    mnemonic = ""
class NEGS(UNIMPLEMENTED):
    mnemonic = ""
class SUBS(UNIMPLEMENTED):
    mnemonic = ""
class MULS(UNIMPLEMENTED):
    mnemonic = ""
class MADDS(UNIMPLEMENTED):
    mnemonic = ""
class MSUBS(UNIMPLEMENTED):
    mnemonic = ""
class ROUNDS(UNIMPLEMENTED):
    mnemonic = ""
class TRUNCS(UNIMPLEMENTED):
    mnemonic = ""
class FLOORS(UNIMPLEMENTED):
    mnemonic = ""
class CEILS(UNIMPLEMENTED):
    mnemonic = ""
class FLOATS(UNIMPLEMENTED):
    mnemonic = ""
class UFLOATS(UNIMPLEMENTED):
    mnemonic = ""
class UNTRUNCS(UNIMPLEMENTED):
    mnemonic = ""
class L32E(UNIMPLEMENTED):
    mnemonic = ""
class S32E(UNIMPLEMENTED):
    mnemonic = ""
class LSX(UNIMPLEMENTED):
    mnemonic = ""
class LSXU(UNIMPLEMENTED):
    mnemonic = ""
class SSX(UNIMPLEMENTED):
    mnemonic = ""
class SSXU(UNIMPLEMENTED):
    mnemonic = ""
class RSR(UNIMPLEMENTED):
    mnemonic = ""
class WSR(UNIMPLEMENTED):
    mnemonic = ""
class SEXT(UNIMPLEMENTED):
    mnemonic = ""
class CLAMPS(UNIMPLEMENTED):
    mnemonic = ""
class MIN(UNIMPLEMENTED):
    mnemonic = ""
class MAX(UNIMPLEMENTED):
    mnemonic = ""
class MINU(UNIMPLEMENTED):
    mnemonic = ""
class MAXU(UNIMPLEMENTED):
    mnemonic = ""
class MOVEQZ(UNIMPLEMENTED):
    mnemonic = ""
class MOVNEZ(UNIMPLEMENTED):
    mnemonic = ""
class MOVLTZ(UNIMPLEMENTED):
    mnemonic = ""
class MOVGEZ(UNIMPLEMENTED):
    mnemonic = ""
class MOVF(UNIMPLEMENTED):
    mnemonic = ""
class MOVT(UNIMPLEMENTED):
    mnemonic = ""
class RUR(UNIMPLEMENTED):
    mnemonic = ""
class WUR(UNIMPLEMENTED):
    mnemonic = ""
class ANDB(UNIMPLEMENTED):
    mnemonic = ""
class ANDBC(UNIMPLEMENTED):
    mnemonic = ""
class ORB(UNIMPLEMENTED):
    mnemonic = ""
class ORBC(UNIMPLEMENTED):
    mnemonic = ""
class XORB(UNIMPLEMENTED):
    mnemonic = ""
class MULL(UNIMPLEMENTED):
    mnemonic = ""
class MULUH(UNIMPLEMENTED):
    mnemonic = ""
class MULSH(UNIMPLEMENTED):
    mnemonic = ""
class QUOU(UNIMPLEMENTED):
    mnemonic = ""
class QUOS(UNIMPLEMENTED):
    mnemonic = ""
class REMU(UNIMPLEMENTED):
    mnemonic = ""
class REMS(UNIMPLEMENTED):
    mnemonic = ""
class RFDO(UNIMPLEMENTED):
    mnemonic = ""
class RFDD(UNIMPLEMENTED):
    mnemonic = ""
class LICT(UNIMPLEMENTED):
    mnemonic = ""
class SICT(UNIMPLEMENTED):
    mnemonic = ""
class LICW(UNIMPLEMENTED):
    mnemonic = ""
class SICW(UNIMPLEMENTED):
    mnemonic = ""
class LDCT(UNIMPLEMENTED):
    mnemonic = ""
class SDCT(UNIMPLEMENTED):
    mnemonic = ""
class RER(UNIMPLEMENTED):
    mnemonic = ""
class WER(UNIMPLEMENTED):
    mnemonic = ""
class SLLI(UNIMPLEMENTED):
    mnemonic = ""
class SRAI(UNIMPLEMENTED):
    mnemonic = ""
class SRLI(UNIMPLEMENTED):
    mnemonic = ""
class XSR(UNIMPLEMENTED):
    mnemonic = ""
class SRC(UNIMPLEMENTED):
    mnemonic = ""
class SRL(UNIMPLEMENTED):
    mnemonic = ""
class SLL(UNIMPLEMENTED):
    mnemonic = ""
class SRA(UNIMPLEMENTED):
    mnemonic = ""
class MUL16U(UNIMPLEMENTED):
    mnemonic = ""
class MUL16S(UNIMPLEMENTED):
    mnemonic = ""
class NEG(UNIMPLEMENTED):
    mnemonic = ""
class RITLB0(UNIMPLEMENTED):
    mnemonic = ""
class IITLB(UNIMPLEMENTED):
    mnemonic = ""
class PITLB(UNIMPLEMENTED):
    mnemonic = ""
class WITLB(UNIMPLEMENTED):
    mnemonic = ""
class RITLB1(UNIMPLEMENTED):
    mnemonic = ""
class RDTLB0(UNIMPLEMENTED):
    mnemonic = ""
class IDTLB(UNIMPLEMENTED):
    mnemonic = ""
class PDTLB(UNIMPLEMENTED):
    mnemonic = ""
class WDTLB(UNIMPLEMENTED):
    mnemonic = ""
class RDTLB1(UNIMPLEMENTED):
    mnemonic = ""
class SSR(UNIMPLEMENTED):
    mnemonic = ""
class SSL(UNIMPLEMENTED):
    mnemonic = ""
class SSA8L(UNIMPLEMENTED):
    mnemonic = ""
class SSA8B(UNIMPLEMENTED):
    mnemonic = ""
class SSAI(UNIMPLEMENTED):
    mnemonic = ""
class ROTW(UNIMPLEMENTED):
    mnemonic = ""
class NSA(UNIMPLEMENTED):
    mnemonic = ""
class NSAU(UNIMPLEMENTED):
    mnemonic = ""
class RFE(UNIMPLEMENTED):
    mnemonic = ""
class RFUE(UNIMPLEMENTED):
    mnemonic = ""
class RFDE(UNIMPLEMENTED):
    mnemonic = ""
class RFWO(UNIMPLEMENTED):
    mnemonic = ""
class RFWU(UNIMPLEMENTED):
    mnemonic = ""
class RFET(UNIMPLEMENTED):
    mnemonic = ""
class RFI(UNIMPLEMENTED):
    mnemonic = ""
class RFME(UNIMPLEMENTED):
    mnemonic = ""
class ISYNC(UNIMPLEMENTED):
    mnemonic = ""
class RSYNC(UNIMPLEMENTED):
    mnemonic = ""
class ESYNC(UNIMPLEMENTED):
    mnemonic = ""
class DSYNC(UNIMPLEMENTED):
    mnemonic = ""
class EXCW(UNIMPLEMENTED):
    mnemonic = ""
class MEMW(UNIMPLEMENTED):
    mnemonic = ""
class EXTW(UNIMPLEMENTED):
    mnemonic = ""
class CALLX0(UNIMPLEMENTED):
    mnemonic = ""
class CALLX4(UNIMPLEMENTED):
    mnemonic = ""
class CALLX8(UNIMPLEMENTED):
    mnemonic = ""
class CALLX12(UNIMPLEMENTED):
    mnemonic = ""
class RETW(UNIMPLEMENTED):
    mnemonic = ""
class JX(UNIMPLEMENTED):
    mnemonic = ""
class ILL(UNIMPLEMENTED):
    mnemonic = ""
class MOVSP(UNIMPLEMENTED):
    mnemonic = ""
class BREAK(UNIMPLEMENTED):
    mnemonic = ""
class SYSCALL(UNIMPLEMENTED):
    mnemonic = ""
class RSIL(UNIMPLEMENTED):
    mnemonic = ""
class WAITI(UNIMPLEMENTED):
    mnemonic = ""
class ANY4(UNIMPLEMENTED):
    mnemonic = ""
class ALL4(UNIMPLEMENTED):
    mnemonic = ""
class ANY8(UNIMPLEMENTED):
    mnemonic = ""
class ALL8(UNIMPLEMENTED):
    mnemonic = ""
class OR(UNIMPLEMENTED):
    mnemonic = ""
class XOR(UNIMPLEMENTED):
    mnemonic = ""
class SUB(UNIMPLEMENTED):
    mnemonic = ""
class SUBX2(UNIMPLEMENTED):
    mnemonic = ""
class SUBX4(UNIMPLEMENTED):
    mnemonic = ""
class SUBX8(UNIMPLEMENTED):
    mnemonic = ""
class EXTUI(UNIMPLEMENTED):
    mnemonic = "extui"
class CUST0(UNIMPLEMENTED):
    mnemonic = ""
class CUST1(UNIMPLEMENTED):
    mnemonic = ""
class L32R(UNIMPLEMENTED):
    mnemonic = ""
class L32IN(UNIMPLEMENTED):
    mnemonic = ""
class S32IN(UNIMPLEMENTED):
    mnemonic = ""