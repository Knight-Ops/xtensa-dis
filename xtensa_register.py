from binaryninja import RegisterInfo


def get_regs():
    regs = dict()
    for i in range(16):
        n = "a{}".format(i)
        regs[n] = RegisterInfo(n, 4)

    regs['pc'] = RegisterInfo('pc', 4)
    regs['sar'] = RegisterInfo('sar', 1)  # 6 bits?
    regs['lbeg'] = RegisterInfo('lbeg', 4)
    regs['lend'] = RegisterInfo('lend', 4)
    regs['lcount'] = RegisterInfo('lcount', 4)
    regs['acclo'] = RegisterInfo('acclo', 4)
    regs['acchi'] = RegisterInfo('acchi', 4)
    regs['m0'] = RegisterInfo('m0', 4)
    regs['m1'] = RegisterInfo('m1', 4)
    regs['m2'] = RegisterInfo('m2', 4)
    regs['m3'] = RegisterInfo('m3', 4)
    regs['br'] = RegisterInfo('br', 2)
    regs['litbase'] = RegisterInfo('litbase', 3)  # 21 bits?
    regs['scompare1'] = RegisterInfo('scompare1', 4)
    regs['ps'] = RegisterInfo('ps', 2)  # 15 bits?
    # Could do like ps.intlevel here too?
    # There are a bunch of other "Special registers" that we could implement here

    return regs


GPR = {
    0: 'a0',
    1: 'a1',
    2: 'a2',
    3: 'a3',
    4: 'a4',
    5: 'a5',
    6: 'a6',
    7: 'a7',
    8: 'a8',
    9: 'a9',
    10: 'a10',
    11: 'a11',
    12: 'a12',
    13: 'a13',
    14: 'a14',
    15: 'a15',
    16: 'a16',
    17: 'pc',
    18: 'sar'
    # 19: 'lbeg',
    # 20: 'lend',
    # 21: 'lcount',
    # 22: 'acclo',
    # 23: 'acchi',
    # 24: 'm0',
    # 25: 'm1',
    # 26: 'm2',
    # 27: 'm3',
    # 28: 'br',
    # 29: 'litbase',
    # 30: 'scompare1',
    # 31: 'ps',
    # Could do like ps.intlevel here too?
    # There are a bunch of other "Special registers" that we could implement here
}

SPR = {

}