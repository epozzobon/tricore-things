#!/usr/bin/env python3
import random
import struct
import pyftdi.ftdi
from pyftdi.ftdi import Ftdi

from ftdi_dap import (
    DAPBatch, DAPOperations, MiniWigglerBatch,
    AssertNone, AssertBytes, AssertInt
)


SBU_ID = 0xf0036008
SBU_MANID = 0xf0036144
SBU_CHIPID = 0xf0036140
UCB_IFX = 0xaf101000
OCD_BASE = 0xf0000400
CPU0_CSFR_BASE = 0xf8810000
CPU1_CSFR_BASE = 0xf8830000
CPU2_CSFR_BASE = 0xf8850000
CPU3_CSFR_BASE = 0xf8870000
CPU4_CSFR_BASE = 0xf8890000
CPU6_CSFR_BASE = 0xf88d0000
CPU0_CSFR_DBGSR = 0xf881fd00
CPU0_CSFR_TR0EVT = 0xf881f000
CPU0_CSFR_TR0ADR = 0xf881f004


CMD_KEY_EXCHANGE = 0x76d6e24a
UNLOCK_PASSWORD: None | list[int] = [
    0xCAFEBABE, 0xDEADBEEF, 0xAAAAAAAA, 0x55555555,
    0x00000000, 0xFFFFFFFF, 0x00000000, 0x00000000]


def main() -> None:
    RUN_SELF_TEST = True
    USE_MINIWIGGLER = True

    if USE_MINIWIGGLER:
        # Use Miniwiggler:
        ftdi = Ftdi()
        ftdi.open_mpsse(0x58b, 0x43, interface=1)
    else:
        # Use Tigard
        ftdi = Ftdi()
        ftdi.open_mpsse(0x403, 0x6010, interface=2)

    ftdi.set_latency_timer(2)
    ftdi.set_flowctrl('hw')
    ftdi.set_rts(True)
    ftdi.set_bitmode(0, pyftdi.ftdi.Ftdi.BitMode.RESET)
    ftdi.set_bitmode(0, pyftdi.ftdi.Ftdi.BitMode.MPSSE)
    assert ftdi.is_connected

    batch = DAPBatch(MiniWigglerBatch(ftdi))

    batch.test_reset()

    batch.mpsse_set_clk_divisor(42)
    batch.reset()
    batch.exec()

    batch.dap_t17(16, 0xf00).then(AssertNone())
    batch.dap_t17(48, 0x4abbaf530400).then(AssertInt(0x400))
    batch.dap_t28(1)
    batch.dap_readreg(0xb, 2).then(AssertInt(0xc0))
    batch.dap_t8_e(0x503)
    if UNLOCK_PASSWORD is not None:
        # See "3.1.1.7.7 Debug System handling" in TC3xx User's Manual
        batch.write_comdata(CMD_KEY_EXCHANGE)
    batch.dap_readreg(0xb, 2).then(AssertInt(0x80))
    # The specific time at which this register changes is not guaranteed
    batch.dap_readreg(0xb, 2)
    batch.dap_readreg(0xb, 2)
    batch.dap_readreg(0xb, 2)
    batch.dap_readreg(0xb, 2)
    batch.dap_readreg(0xb, 2)
    batch.dap_readreg(0xb, 2)
    batch.dap_readreg(0xb, 2)
    batch.dap_readreg(0xb, 2)
    batch.dap_readreg(0xb, 2)
    dap_status = batch.dap_readreg(0xb, 2)
    batch.exec()

    # Check if debug interface requires unlocking with password
    if dap_status.value == 0x400:
        print("DAP was already unlocked")
    elif dap_status.value == 0x80:
        # DAP is locked
        print("DAP is locked, attempting unlock")
        assert UNLOCK_PASSWORD is not None
        for pw in UNLOCK_PASSWORD:
            batch.dap_readreg(0xb, 2).then(AssertInt(0x80))
            batch.write_comdata(pw)
            batch.exec()
    else:
        raise Exception(f"Unexpected status: 0x{dap_status.value:x}")

    # DAP register 11 is some kind of status register, probably each bit has
    # some meaning, I found that 0x400 is good and 0x80 is bad but other values
    # can also appear which I didn't interpret yet
    batch.dap_t28(1)
    batch.dap_readreg(0xb, 2).then(AssertInt(0x400))
    batch.exec()

    batch.dap_t28(1)
    batch.dap_readreg(0xb, 2).then(AssertInt(0x400))
    batch.dap_t8_e(0x4501)
    batch.dap_t8_0(0xc1)
    batch.exec()

    batch.mpsse_set_clk_divisor(6)
    batch.read_gpios().then(AssertBytes('a05f'))
    batch.exec()

    # The DAPOperations class contains high-level operations,
    # such as read/write from RAM
    ops = DAPOperations(batch)

    BASE_ADDR = 0x7000002c

    if RUN_SELF_TEST:
        # Self-test that writes and reads back the RAM to make sure all
        # read/write implementations are actually working:
        ref = random.randbytes(0x400)
        ops.write(BASE_ADDR, ref)
        readback = ops.read(BASE_ADDR, 0x400)
        assert readback == ref

        assert ops.read8(BASE_ADDR) == ref[0]
        assert ops.read8(BASE_ADDR + 1) == ref[1]
        assert ops.read8(BASE_ADDR + 2) == ref[2]
        assert ops.read8(BASE_ADDR + 3) == ref[3]
        assert ops.read16(BASE_ADDR) == struct.unpack('<H', ref[0:2])[0]
        assert ops.read16(BASE_ADDR + 2) == struct.unpack('<H', ref[2:4])[0]
        assert ops.read32(BASE_ADDR) == struct.unpack('<I', ref[0:4])[0]
        assert ops.read32(BASE_ADDR + 4) == struct.unpack('<I', ref[4:8])[0]

        ops.write8(BASE_ADDR, 0xa5)
        assert 0xa5 == ops.read8(BASE_ADDR)

        ops.write16(BASE_ADDR, 0xc0fe)
        assert 0xc0fe == ops.read16(BASE_ADDR)

        ops.write32(BASE_ADDR, 0xcafebabe)
        assert 0xcafebabe == ops.read32(BASE_ADDR)

    # Send Software Debug Event on CPU0
    ops.write32(0xf881fd10, 0x2a)
    # Halt all 6 CPUs
    ops.write32(0xf881fd00, 6)
    ops.write32(0xf883fd00, 6)
    ops.write32(0xf885fd00, 6)
    ops.write32(0xf887fd00, 6)
    ops.write32(0xf889fd00, 6)
    ops.write32(0xf88dfd00, 6)

    # Set program counter on first CPU.
    # 0x80000000 is the reset vector for running from flash.
    ops.write32(0xf881fe08, 0x80000000)

    # Run CPU0 by resetting HALT[0].
    # CPU0 will start other CPUs in the code running from flash.
    ops.write(0xf881fd00, b'\4\0\0\0')

    # Read program counter on each CPU, to make sure they are all running
    print(hex(ops.read32(0xf881fe08)))
    print(hex(ops.read32(0xf883fe08)))
    print(hex(ops.read32(0xf885fe08)))
    print(hex(ops.read32(0xf887fe08)))
    print(hex(ops.read32(0xf889fe08)))
    print(hex(ops.read32(0xf88dfe08)))

    # For demo on stage, this code replaces the logo in RAM
    import zlib
    import base64
    logo = zlib.decompress(base64.decodebytes(
        b'eJytlVty0zAUhhtZx7JiJ07SJDwALdMn2ADXcllAYQVAWQB7YB3cpsMwrFP9z5EtK/Kl'
        b'ZeBBo3P5P0mWj6Qvbqb+OKVOXaZ+O63uO1K/0E7QrtAeIHaFRtDt0Qj2T/EztUXTja+h'
        b'3aCx/0PihLwW/3vT7ySfBX/f9N+aceYuo3kSsy4niz6LYoUrqBBdpr42+qGYcXZSl46X'
        b'JfMWYS2cI6xPRes7/Kb0my+xV+fJvrxH/yLZuw+InSf762N+7z+if4n+FD3br5p/dIn2'
        b'GmOcoH2C/QbswuVoM6ypBkPqHfwzd6yeB3urnqF/K/ZOPQ32Xj0ZtHPsgznw5/Af/6PP'
        b'411M+A9l3jiWq0eDMZK+jdmG5dgGtbR0hs6iXAV/1+TXjqh0JeXojdPEMW9z3M/F+eNI'
        b'P3cLIvS52KzPxWZ9gfE5v4n01tWkR/Wsq2ndfHMt9bZq9Fo0sd7I+CtaHehzrCcn1Kas'
        b'yzMm2MavRTSHnP/OMS6Xubym44z4HaepSjiCrryB4+/zXCF2ytUy9xCnaZFwWv7pIbdE'
        b'3vvDTOZsb66Y4bk8Y8W+HaNRa75+Zqi7llOuDPvouQLn08o/Hee2qL2U0cjrwCnYdeA0'
        b'/L/nFObzXIV1GlUkbNWMPc2W2JuY5TPTZ9leBZbXxOwc/z0P7FJqYJrNMG/HGmV6rN8L'
        b'CiyFNXeslfqeZsuIs8R5Pt95xFTShhmN2iiRtz2mwFwxU4X/7xl/ZjrmrtQP18mYvozu'
        b'rb7eyP61DPbslkx7BmLGKOox/jzznaJuYBbu3iTDd90wo0XfMlk40+OMdctGH983Y/pC'
        b'/ssY074HfcaiJjzTvxNv4mrR9+/g/8F1fsd57TTLZ8JGrOG7Ss6JPwfdW9O9Ty17R94q'
        b'zlf+jou4VfIGtsxe8XuX6nXvzWz1O8Xv6SLSG9Gnb3Kr32IvFqjVQz2FN5/f505fuTXu'
        b'9JIuULufpX6Pjq4BJegSDg=='))

    for i in range(0, len(logo), 1024):
        ops.write(BASE_ADDR+i, logo[i:i+1024])

    print("All tests passed")


if __name__ == "__main__":
    main()
