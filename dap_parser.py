from typing import IO, Iterator, TypeVar, TYPE_CHECKING
if TYPE_CHECKING:
    from _typeshed import SupportsWrite
from bitarray import bitarray
from bitarray.util import ba2int
import struct
import binascii
from scapy_ftdi import FtdiXfer
from mpsse_parser import (MpsseClkIn, MpsseClkOut,
                          MpsseSetGpioHigh, MpsseTransaction)


X = TypeVar('X')


class LookaheadList[X]:
    def __init__(self, q: 'Iterator[X]') -> None:
        self.__queue = q
        self.__buffer: list[X] = []

    def get(self) -> X | None:
        if len(self.__buffer):
            return self.__buffer.pop(0)
        try:
            return next(self.__queue)
        except StopIteration:
            return None

    def peek(self, index: int = 0) -> X:
        while len(self.__buffer) <= index:
            self.__buffer.append(next(self.__queue))
        return self.__buffer[index]


class MiniwigglerClkOutIn:
    def __init__(self, bufout: MpsseClkOut, bufin: MpsseClkIn) -> None:
        self._out = bufout
        self._in = bufin

    def __repr__(self) -> str:
        return (f"MiniwigglerClkOutIn(x'{self._out.data.hex()}')"
                + f" -> x'{self._in.rsp.hex()}'")


def parse_miniwiggler(capture: Iterator[FtdiXfer | MpsseTransaction]
                      ) -> Iterator[FtdiXfer | MpsseTransaction
                                    | MiniwigglerClkOutIn]:
    pkts = LookaheadList(capture)
    while 1:
        u = pkts.get()
        if u is None:
            return
        if isinstance(u, MpsseSetGpioHigh):
            # Look out for the typical clock-out and clock-in pattern of the
            # miniwiggler: first set direction to out (0x67), do a MPSSE
            # clock-out, then set dirfection to in (0x57) and do a MPSSE
            # clock-in
            u1 = pkts.peek(0)
            u2 = pkts.peek(1)
            u3 = pkts.peek(2)
            if u.direction == 0xf7 and u.values == 0x67 \
                    and isinstance(u1, MpsseClkOut) \
                    and isinstance(u2, MpsseSetGpioHigh) \
                    and u2.direction == 0xf7 \
                    and u2.values == 0x57 \
                    and isinstance(u3, MpsseClkIn):
                r = MiniwigglerClkOutIn(u1, u3)
                pkts.get()
                pkts.get()
                pkts.get()
                yield r
            else:
                yield u
        else:
            yield u


def compute_crc6(msg: int, msglen: int) -> int:
    crc = 0x3F
    for i in range(0, msglen):
        bit = ((msg >> i) ^ crc ^ (crc >> 1)) & 1
        crc = (bit << 5) | (crc >> 1)
    return crc ^ (crc >> 1)


def dap_unpad(b: bytes) -> bytes | None:
    # cut all the initial padding 0 bits and the start 1 bit
    ba = bitarray(b, endian='little')
    while len(ba) > 0 and ba[0] == 0:
        ba = ba[1:]
    if len(ba) == 0:
        # if no start bit is found, return None
        return None
    if len(ba) > 0:
        ba = ba[1:]
    return ba.tobytes()


class DapTelegramData:
    def __init__(self, x: MiniwigglerClkOutIn) -> None:
        b = x._out.data

        ba = bitarray(dap_unpad(b), endian='little')
        assert len(ba) >= 17
        cmd = ba2int(ba[0:5])
        arglen = ba2int(ba[5:11])
        arglen = arglen if arglen != 0x3f else 0
        assert len(ba) >= 17 + arglen
        arg = ba2int(ba[11:11+arglen]) if arglen > 0 else 0
        crc6 = ba2int(ba[11+arglen:17+arglen])
        comp = compute_crc6(ba2int(ba[:arglen+11]), arglen+11)
        assert comp == crc6

        self.transfer_out = x._out
        self.transfer_in = x._in
        self.rsp = dap_unpad(x._in.rsp)
        self.arg = arg
        self.arglen = arglen
        self.cmd = cmd


class DapTelegram:
    def __init__(self, t: DapTelegramData) -> None:
        self._out = t.transfer_out
        self._in = t.transfer_in
        self.cmd = t.cmd
        self.arglen = t.arglen
        self.arg = t.arg
        self.rsp = t.rsp

    def __repr__(self) -> str:
        return f"DapTelegram({self.cmd}, {self.arglen}, 0x{self.arg:x})" \
               + (f" -> x'{self.rsp.hex()}'" if self.rsp is not None else '')


class DapTelegramRead(DapTelegram):
    def __init__(self, x: DapTelegramData) -> None:
        assert x.cmd == 10
        assert x.arglen == 40
        DapTelegram.__init__(self, x)
        self.read_addr = (self.arg >> 8) & 0xfffffffc
        self.read_size = self.arg & 0x3fc
        if self.read_size == 0:
            self.read_size = 1024
        self.flags = self.arg & 3
        self.crcgood = False
        self.data: bytes | None = None
        self.rxcrc: int | None = None
        self.crc: int | None = None

        # The response for this telegram is different from others.
        # It is split into 32-bit payloads, each with a start bit, and no CRC6.
        outba = bitarray(0, endian='little')
        ba = bitarray(x.transfer_in.rsp, endian='little')
        while len(ba):
            while len(ba) and ba[0] == 0:
                ba = ba[1:]  # Remove padding zeroes
            if len(ba) > 0:
                ba = ba[1:]  # Remove start bit
            outba += ba[:32]
            ba = ba[32:]
        out = outba.tobytes()
        self.rsp = out

        if len(out) >= self.read_size:
            self.data = out[:self.read_size]
            if len(out) >= self.read_size + 4:
                crc = binascii.crc32(self.data) ^ 0xFFFFFFFF
                self.crc = int('{:032b}'.format(crc)[::-1], 2)
                rxcrc = out[self.read_size:self.read_size + 4]
                self.rxcrc, = struct.unpack('<I', rxcrc)
                if self.rxcrc == self.crc:
                    self.crcgood = True

    def __repr__(self) -> str:
        cmd = f"DapTelegramRead({hex(self.read_addr)}, "\
              + f"{self.read_size + self.flags},"\
              + f" {self.arg & 3})"
        if self.crcgood and self.data is not None:
            return cmd + f" -> x'{self.data.hex()}' (crc good)"
        if self.data is not None:
            return cmd + f" -> x'{self.data.hex()}' (crc bad)"
        if self.rsp is not None:
            return cmd + f" -> x'{self.rsp.hex()}' (crc bad)"
        return cmd


class DapTelegramWrite(DapTelegram):
    def __init__(self, x: DapTelegramData) -> None:
        assert x.cmd == 9
        assert x.arglen == 40
        DapTelegram.__init__(self, x)
        self.write_addr = (self.arg >> 8) & 0xfffffffc
        self.write_size = self.arg & 0x3fc
        if self.write_size == 0:
            self.write_size = 0x400

    def __repr__(self) -> str:
        return f"DapTelegramWrite({hex(self.write_addr)}, {self.write_size}"\
               + f", {self.arg & 3})"\
               + (f" -> x'{self.rsp.hex()}'" if self.rsp is not None else '')


class DapTelegramJtagSwapDR(DapTelegram):
    def __init__(self, x: DapTelegramData) -> None:
        assert x.cmd == 2
        assert x.arglen == 32
        DapTelegram.__init__(self, x)
        if x.rsp is not None:
            self.rx, = struct.unpack("<I", x.rsp[:4])
            assert 0 == sum(x.rsp[5:]), x
            crc = compute_crc6(self.rx, 32)
            rxcrc = x.rsp[4]
            assert crc == rxcrc
        else:
            self.rx = None

    def __repr__(self) -> str:
        return f"DapTelegramJtagSwapDR({hex(self.arg)})"\
               + (f" -> {hex(self.rx)}" if self.rx is not None else '')


class DapTelegramWriteReg(DapTelegram):
    def __init__(self, x: DapTelegramData) -> None:
        assert x.cmd == 8
        DapTelegram.__init__(self, x)

    def __repr__(self) -> str:
        return f"DapTelegramWriteReg({self.arg & 0xf}, {hex(self.arg >> 4)})"\
               + (f" -> x'{self.rsp.hex()}'" if self.rsp is not None else '')


class DapTelegramSync(DapTelegram):
    def __init__(self, x: DapTelegramData) -> None:
        assert x.cmd == 16
        assert x.arglen == 0
        DapTelegram.__init__(self, x)
        if x.rsp is not None:
            self.rx, = struct.unpack("<I", x.rsp[:4])
            assert 0 == sum(x.rsp[5:]), x
            crc = compute_crc6(self.rx, 32)
            assert crc == x.rsp[4]
            self.rsp = x.rsp[:3]
        else:
            self.rx = None

    def __repr__(self) -> str:
        return "DapTelegramSync()"\
               + (f" -> {hex(self.rx)}" if self.rx is not None else '')


class DapTelegramDAPISC(DapTelegram):
    def __init__(self, x: DapTelegramData) -> None:
        assert x.cmd == 17
        assert x.arglen == 48 or x.arglen == 16
        DapTelegram.__init__(self, x)
        if x.rsp is not None and len(x.rsp) >= 3:
            self.rx, = struct.unpack("<H", x.rsp[:2])
            assert 0 == sum(x.rsp[3:]), x
            crc = compute_crc6(self.rx, 16)
            assert crc == x.rsp[2]
            self.rsp = x.rsp[:2]
        else:
            self.rx = None

    def __repr__(self) -> str:
        return f"DapTelegramDAPISC({hex(self.arg)})"\
               + ((f" -> x'{self.rsp.hex()}'" if self.rx is None
                   else f" -> {hex(self.rx)}"
                   ) if self.rsp is not None else '')


class DapTelegramJtagSetIR(DapTelegram):
    def __init__(self, x: DapTelegramData) -> None:
        assert x.cmd == 19
        assert x.arglen == 8
        if x.rsp is not None:
            assert sum(x.rsp) == 0, x
        DapTelegram.__init__(self, x)

    def __repr__(self) -> str:
        return f"DapTelegramJtagSetIR(0x{self.arg:02x})"\
               + (" -> 0" if self.rsp is not None else '')


class DapTelegramJtagReset(DapTelegram):
    def __init__(self, x: DapTelegramData) -> None:
        assert x.cmd == 21
        assert x.arglen == 0
        if x.rsp is not None:
            assert sum(x.rsp) == 0, x
        DapTelegram.__init__(self, x)

    def __repr__(self) -> str:
        return "DapTelegramJtagReset()"\
               + (" -> 0" if self.rsp is not None else '')


class DapTelegramReadReg(DapTelegram):
    def __init__(self, x: DapTelegramData) -> None:
        assert x.cmd == 26, x
        assert x.arglen == 7, x
        DapTelegram.__init__(self, x)
        self.arg_high = x.arg >> 4
        self.arg_low = x.arg & 0xf

        self.rx: None | int = None
        if self.arg_high == 5 and x.rsp is not None:
            # response will be 32 bits:
            if len(x.rsp) >= 5 and 0 == sum(x.rsp[5:]):
                rx, = struct.unpack("<I", x.rsp[:4])
                crc = compute_crc6(rx, 32)
                if crc == x.rsp[4]:
                    self.rx = rx
        elif self.arg_high == 4 and x.rsp is not None:
            # response will be 16 bits:
            if len(x.rsp) >= 3 and 0 == sum(x.rsp[3:]):
                rx, = struct.unpack("<H", x.rsp[:2])
                crc = compute_crc6(rx, 16)
                if crc == x.rsp[2]:
                    self.rx = rx

    def __repr__(self) -> str:
        return f"DapTelegramReadReg({self.arg_low}, {self.arg_high})"\
               + (f" -> {hex(self.rx)}" if self.rx is not None else
                  ('' if self.rsp is None else f" -> x'{self.rsp.hex()}'"))


class DapTelegramClientSet(DapTelegram):
    def __init__(self, x: DapTelegramData) -> None:
        assert x.cmd == 28
        assert x.arglen == 3
        DapTelegram.__init__(self, x)

    def __repr__(self) -> str:
        return f"DapTelegramClientSet({self.arg})"\
               + (f" -> x'{self.rsp.hex()}'" if self.rsp is not None else '')


class DapPayload:
    def __init__(self, x: MiniwigglerClkOutIn) -> None:
        self._out = x._out
        self._in = x._in
        padded_data = x._out.data
        assert len(padded_data) == 5
        b = dap_unpad(padded_data)
        assert b is not None
        assert (len(b) % 4) == 1, b.hex()
        assert b[-1] == 0
        b = b[:-1]
        self.out_buf = b
        self.rsp = x._in.rsp

    def __repr__(self) -> str:
        return f"DapPayload(x'{self.out_buf.hex(' ')}')" \
               + (f" -> x'{self.rsp.hex()}'" if self.rsp is not None else '')


def parse_dap(capture: Iterator[FtdiXfer | MpsseTransaction
                                | MiniwigglerClkOutIn]
              ) -> Iterator[FtdiXfer | MpsseTransaction
                            | MiniwigglerClkOutIn
                            | DapTelegram | DapPayload]:
    pkts = LookaheadList(capture)
    expected_payload_bytes = 0
    while (u := pkts.get()) is not None:
        if isinstance(u, MiniwigglerClkOutIn):
            if expected_payload_bytes > 0:
                p = DapPayload(u)
                expected_payload_bytes -= 4
                yield p
            else:
                try:
                    x = DapTelegramData(u)
                except AssertionError:
                    yield u
                else:
                    try:
                        if x.cmd == 2:
                            yield DapTelegramJtagSwapDR(x)
                        elif x.cmd == 8:
                            yield DapTelegramWriteReg(x)
                        elif x.cmd == 9:
                            t = DapTelegramWrite(x)
                            expected_payload_bytes = t.write_size
                            yield t
                        elif x.cmd == 10:
                            yield DapTelegramRead(x)
                        elif x.cmd == 16:
                            yield DapTelegramSync(x)
                        elif x.cmd == 17:
                            yield DapTelegramDAPISC(x)
                        elif x.cmd == 19:
                            yield DapTelegramJtagSetIR(x)
                        elif x.cmd == 21:
                            yield DapTelegramJtagReset(x)
                        elif x.cmd == 26:
                            yield DapTelegramReadReg(x)
                        elif x.cmd == 28:
                            yield DapTelegramClientSet(x)
                        else:
                            yield DapTelegram(x)
                    except Exception:
                        yield u
        else:
            yield u


def parse_and_print(pcap: IO[bytes], fd: 'SupportsWrite[str] | None' = None
                    ) -> None:
    from scapy_ftdi import iterate_ftdi_usb_capture
    from mpsse_parser import (MpsseSendImmediate, parse_mpsse)
    pkts = iterate_ftdi_usb_capture(pcap)
    mpsse = parse_mpsse(pkts)
    cmds = parse_dap(parse_miniwiggler(mpsse))

    for u in cmds:
        print(u, file=fd)

        if isinstance(u, MpsseSendImmediate):
            t = u._raw.time
            print(f"        % time is {t:.6f}s %", file=fd)


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Process Miniwiggler "
                                     "USBpcap file, parsing DAP high-level "
                                     "operations")
    parser.add_argument("pcap_file", help="Path to the USBpcap file")
    args = parser.parse_args()

    parse_and_print(args.pcap_file)


if __name__ == "__main__":
    main()
