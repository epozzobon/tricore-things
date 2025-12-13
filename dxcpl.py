#!/usr/bin/env python3
import pyftdi
from pyftdi.ftdi import Ftdi
from bitarray import bitarray

from ftdi_dap import AssertInt, DAPBatch, DAPInterface, FtdiBatch, Promise


class TigardDxcplBatch(DAPInterface):
    # Tigard interface=2, low byte only (high byte is not connected)
    # 0x0001  BDBUS0 (TCK)      ---->
    # 0x0002  BDBUS1 (TDI)      ----> CAN.TX
    # 0x0004  BDBUS2 (TDO)      <---- CAN.RX
    # 0x0008  BDBUS3 (TMS)      ----> (optional oscilloscope trigger)
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
        self.set_gpios(0x2a)

        super().mpsse_set_clk_divisor(15)
        self.mpsse_clockout_bytes(b'\xff')
        self.exec()
        ba = bitarray("01" * 640, endian='little')
        self.mpsse_clockout_bytes(ba.tobytes())
        self.exec()
        self.mpsse_clockout_bytes(ba.tobytes())
        self.exec()
        self.mpsse_clockout_bytes(ba.tobytes())
        self.exec()
        self.mpsse_clockout_bytes(ba.tobytes())
        self.exec()
        self.mpsse_set_clk_divisor(7)
        self.mpsse_clockin_bytes(90)
        self.exec()

    def mpsse_set_clk_divisor(self, div):
        # Ignore clock changes
        return super().mpsse_set_clk_divisor(7)

    def set_gpios(self, v: int) -> None:
        # Direction is 0x3B because this is interface 2 of the Tigard
        self.append(bytes([0x80, v & 0x3b, 0x3b]))

    def test_reset(self) -> None:
        self.set_gpios(0x3a)
        self.set_gpios(0x2a)

    def reset(self) -> None:
        self.set_gpios(0x28)
        self.set_gpios(0x2a)

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
        a = self.mpsse_clockin_bytes(expected_bytes*4)
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


if __name__ == '__main__':
    ftdi = Ftdi()
    ftdi.open_mpsse(0x403, 0x6010, interface=2)
    # We use a Tigard connected to a CAN transceiver
    # Tigard.TDI --> CAN TX
    # Tigard.TDO --> CAN RX
    # Tigard.VTGT = 5V

    ftdi.set_latency_timer(2)
    ftdi.set_flowctrl('hw')
    ftdi.set_rts(True)
    ftdi.set_bitmode(0, pyftdi.ftdi.Ftdi.BitMode.RESET)
    ftdi.set_bitmode(0, pyftdi.ftdi.Ftdi.BitMode.MPSSE)
    assert ftdi.is_connected

    interface = TigardDxcplBatch(ftdi)
    dap = DAPBatch(interface)

    dap.dap_t17(48, 0x4abbaf530f00).then(AssertInt(0xf00))
    dap.dap_t16().then(AssertInt(0xaaaaaaaa))
    dap.exec()
