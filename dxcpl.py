#!/usr/bin/env python3
import time
import pyftdi
from pyftdi.ftdi import Ftdi
from bitarray import bitarray

from ftdi_dap import AssertInt, AssertNone, DAPBatch, DAPInterface, \
    DAPOperations, FtdiBatch, Promise


class TigardDxcplBatch(DAPInterface):
    # Tigard interface=2, low byte only (high byte is not connected)
    # 0x0001  BDBUS0 (TCK)      ---->
    # 0x0002  BDBUS1 (TDI)      ----> CAN.TX
    # 0x0004  BDBUS2 (TDO)      <---- CAN.RX
    # 0x0008  BDBUS3 (TMS)      ---->
    # 0x0010  BDBUS4 (TRST)     ----> Tricore TRST
    # 0x0020  BDBUS5 (SRST)     ----> Tricore PORST
    # 0x0040  BDBUS6 (ICE_DONE) <----
    # 0x0080  BDBUS7 (SRST)     <---- Tricore PORST

    def __init__(self, ftdi: Ftdi) -> None:
        FtdiBatch.__init__(self, ftdi)
        # Disable Clk Divide by 5
        # Disable adaptive clocking (return clock signal)
        # Disable 3 Phase Data Clocking (data only valid for 1 edge)
        self.append(b'\x8a\x97\x8d')
        # Outputs to 0x2A, so TDI, TMS and SRTS are high
        # (DXCPL expects TRST to be LOW)
        self.set_gpios(0x0a)
        self.set_gpios(0x2a)
        self.mpsse_set_clk_divisor(7)
        self.exec()

    def activate(self, bitlen: int = 4000) -> None:
        # Activation sequence for dxcpl is 1024 "zeroes".
        # But it's safe to send more, here we send 4000
        super().mpsse_set_clk_divisor(9)
        self.mpsse_clockout_bytes(b'\xaa' * (bitlen // 8))
        self.mpsse_set_clk_divisor(7)

    def mpsse_set_clk_divisor(self, div: int) -> None:
        # Ignore clock changes
        return super().mpsse_set_clk_divisor(7)

    def set_gpios(self, v: int) -> None:
        # Direction is 0x3B because this is interface 2 of the Tigard
        self.append(bytes([0x80, v & 0x3b, 0x3b]))

    def test_reset(self) -> None:
        self.set_gpios(0x3a)
        self.set_gpios(0x2a)
        self.exec()

    def reset(self) -> None:
        self.set_gpios(0x0a)
        self.set_gpios(0x2a)
        self.exec()

    def dap_output_bytes(self, b: bitarray) -> None:
        self.mpsse_clockout_bytes(dxcpl_encode(b))

    def dap_input_bytes(self, expected_bytes: int) -> Promise[bytes]:
        def decode(b: bytes) -> bytes:
            ba = bitarray(b, endian='little')
            assert len(ba) >= 8
            assert ba[0] == 1
            assert ba[-8:] == bitarray('11111111')
            edges = [i for i in range(1, len(ba)) if ba[i-1] != ba[i]]
            if len(edges) == 0:
                return b"\x00" * expected_bytes
            durations = [edges[i] - edges[i-1] for i in range(1, len(edges))]
            assert not any(d == 5 for d in durations)
            ba = bitarray([d > 5 for d in durations], endian='little')
            # TODO: responses in this protocol variant start with 10 instead
            # of 1, this probably breaks readmem responses too, maybe the unpad
            # function needs to become a method to account for this?
            assert ba[:2] == bitarray('10')
            ba = ba[:1] + ba[2:]
            b = ba.tobytes()
            return b
        a = self.mpsse_clockin_bytes(expected_bytes*6 + 12)
        return a.then(decode)


def dxcpl_encode(ba: bitarray) -> bytes:
    curr = 0
    out = bitarray(endian='little')
    for b in ba:
        # pulse width encoding
        if b:
            out.extend([curr]*6)
        else:
            out.extend([curr]*3)
        curr ^= 1
    if curr == 0:
        out.extend([curr]*3)
    out.append(1)
    if len(out) % 8:
        out = bitarray([1]*(8 - len(out) % 8), endian='little') + out
    return out.tobytes()


CMD_KEY_EXCHANGE = 0x76d6e24a

# PRO TIP: Upload your passwords to github to make sure you don't lose them!
UNLOCK_PASSWORD: list[int] = [
    0xCAFEBABE, 0xDEADBEEF, 0xAAAAAAAA, 0x55555555,
    0x00000000, 0xFFFFFFFF, 0x00000000, 0x00000000]


if __name__ == '__main__':
    ftdi = Ftdi()
    # We use a Tigard (or generic FT232H) connected to a CAN transceiver
    # FT232H.ADBUS1 == Tigard.TDI --> CAN Transceiver TX
    # FT232H.ADBUS2 == Tigard.TDO <-- CAN Transceiver RX
    # FT232H.ADBUS4 == Tigard.TRST --> Tricore TRST (or tie TRST low)
    # FT232H.ADBUS5 == Tigard.SRTS --> Tricore PORST
    for vendor, product, interface in [
            (0x403, 0x6010, 2),  # Tigard
            (0x403, 0x6014, 1)   # Generic FT232H breakout board
            ]:
        try:
            ftdi.open_mpsse(vendor, product, interface=interface)
        except OSError:
            continue
        else:
            break

    ftdi.set_latency_timer(2)
    ftdi.set_flowctrl('hw')
    ftdi.set_rts(True)
    ftdi.set_bitmode(0, pyftdi.ftdi.Ftdi.BitMode.RESET)
    ftdi.set_bitmode(0, pyftdi.ftdi.Ftdi.BitMode.MPSSE)
    assert ftdi.is_connected

    dxcpl = TigardDxcplBatch(ftdi)
    dap = DAPBatch(dxcpl)

    # Unlocking over DXCPL is tricky, I think I'm doing it with HARR here?
    # see https://documentation.infineon.com/aurixtc3xx/docs/fhj1710260288543
    # Regardless, it works on my locked TC297 application kit

    # mosfet mode
    #dap.reset()

    # turn off + sleep
    dxcpl.set_gpios(0x0a)
    dxcpl.exec()
    time.sleep(2)

    # turn on
    dxcpl.set_gpios(0x2a)

    dxcpl.activate(1024 * 60)

    dap.dap_dapisc(16, 0xf00).then(AssertNone())
    dap.dap_dapisc(48, 0x4abbaf530400).then(AssertInt(0x400))
    dap.dap_set_io_client(1)
    dap.dap_read_ioinfo().then(lambda x: print(f"IOINFO: 0x{x:x}"))
    dap.dap_write_ojconf(0x1303)  # Enable HARR???
    dap.dap_read_ioinfo().then(lambda x: print(f"IOINFO: 0x{x:x}"))
    dap.dap_read_ioinfo().then(lambda x: print(f"IOINFO: 0x{x:x}"))
    dap.dap_read_ioinfo().then(lambda x: print(f"IOINFO: 0x{x:x}"))
    dap.dap_read_ioinfo().then(lambda x: print(f"IOINFO: 0x{x:x}"))
    dap.dap_read_ioinfo().then(lambda x: print(f"IOINFO: 0x{x:x}"))
    
    dap.write_comdata(CMD_KEY_EXCHANGE)
    for pw in UNLOCK_PASSWORD:
        v11_1 = dap.dap_read_ioinfo().then(lambda x: print(f"IOINFO: 0x{x:x}"))
        dap.write_comdata(pw)
    dap.exec()

    ops = DAPOperations(dap)
    print(f"SBU_ID      = 0x{ops.read32(0xf0036008):08x}") # fails if not unlocked successfully
    print(f"SBU_MANID   = 0x{ops.read32(0xf0036144):08x}")
    print(f"SBU_CHIPID  = 0x{ops.read32(0xf0036140):08x}")
    print(f"CBS_OEC     = 0x{ops.read32(0xf0000478):08x}")
    print(f"CBS_COMDATA = 0x{ops.read32(0xf0000468):08x}")
    print(f"CBS_IOSR    = 0x{ops.read32(0xf000046C):08x}")
    print(f"CBS_OSTATE  = 0x{ops.read32(0xf0000480):08x}")
    print(f"CBS_MCDBBSS = 0x{ops.read32(0xf0000490):08x}")
    print(f"CBS_???     = 0x{ops.read32(0xf0000498):08x}")
