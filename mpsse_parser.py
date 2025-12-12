from typing import IO, Iterator
import struct
from scapy_ftdi import FtdiXfer


class MpsseTransaction:
    def __init__(self, f: FtdiXfer) -> None:
        self._raw = f


class MpsseClkIn(MpsseTransaction):
    def __init__(self, f: FtdiXfer) -> None:
        MpsseTransaction.__init__(self, f)
        sz, = struct.unpack("<H", f.arg)
        assert f.cmd == 0x28
        assert len(f.rsp) == sz + 1
        self.size = sz + 1
        self.rsp = f.rsp

    def __repr__(self) -> str:
        return f"MpsseClkIn() -> x'{self.rsp.hex()}'"


class MpsseClkOut(MpsseTransaction):
    def __init__(self, f: FtdiXfer) -> None:
        MpsseTransaction.__init__(self, f)
        assert f.cmd == 0x19
        assert not f.rsp
        sz, = struct.unpack("<H", f.arg[:2])
        assert len(f.arg) == 3 + sz
        self.size = sz + 1
        self.data = f.arg[2:]
        assert len(self.data) == self.size

    def __repr__(self) -> str:
        return f"MpsseClkOut(x'{self.data.hex()}')"


class MpsseClkOutBits(MpsseTransaction):
    def __init__(self, f: FtdiXfer) -> None:
        MpsseTransaction.__init__(self, f)
        assert f.cmd == 0x1b
        assert not f.rsp
        assert len(f.arg) == 2
        self.size = f.arg[0] + 1
        self.value = f.arg[1]

    def __repr__(self) -> str:
        return f"MpsseClkOutBits({self.size}, dir=0x{self.value:02x})"


class MpsseSendImmediate(MpsseTransaction):
    def __init__(self, f: FtdiXfer) -> None:
        MpsseTransaction.__init__(self, f)
        assert f.cmd == 0x87
        assert not f.rsp
        assert not f.arg

    def __repr__(self) -> str:
        return "<MPSSE SendImmediate>"


class MpsseSetGpioHigh(MpsseTransaction):
    def __init__(self, f: FtdiXfer) -> None:
        MpsseTransaction.__init__(self, f)
        assert f.cmd == 0x82
        assert not f.rsp
        assert len(f.arg) == 2
        self.values = f.arg[0]
        self.direction = f.arg[1]

    def __repr__(self) -> str:
        return f"MpsseSetGpioHigh(0x{self.values:02x}," \
               + f" dir=0x{self.direction:02x})"


class MpsseGetGpioHigh(MpsseTransaction):
    def __init__(self, f: FtdiXfer) -> None:
        MpsseTransaction.__init__(self, f)
        assert f.cmd == 0x83
        assert not f.arg
        assert len(f.rsp) == 1
        self.values = f.rsp[0]

    def __repr__(self) -> str:
        return f"MpsseGetGpioHigh() -> 0x{self.values:02x}"


class MpsseSetGpioLow(MpsseTransaction):
    def __init__(self, f: FtdiXfer) -> None:
        MpsseTransaction.__init__(self, f)
        assert f.cmd == 0x80
        assert not f.rsp
        assert len(f.arg) == 2
        self.values = f.arg[0]
        self.direction = f.arg[1]

    def __repr__(self) -> str:
        return f"MpsseSetGpioLow(0x{self.values:02x}, "\
               + f"dir=0x{self.direction:02x})"


class MpsseGetGpioLow(MpsseTransaction):
    def __init__(self, f: FtdiXfer) -> None:
        MpsseTransaction.__init__(self, f)
        assert f.cmd == 0x81
        assert not f.arg
        assert len(f.rsp) == 1
        self.values = f.rsp[0]

    def __repr__(self) -> str:
        return f"MpsseGetGpioLow() -> 0x{self.values:02x}"


class MpsseSetTckDivisor(MpsseTransaction):
    def __init__(self, f: FtdiXfer) -> None:
        MpsseTransaction.__init__(self, f)
        assert f.cmd == 0x86
        assert not f.rsp
        assert len(f.arg) == 2
        self.divisor, = struct.unpack("<H", f.arg)

    def __repr__(self) -> str:
        return f"MpsseSetTckDivider(0x{self.divisor})"


def parse_mpsse(fd: Iterator[FtdiXfer]) -> \
        Iterator[FtdiXfer | MpsseTransaction]:

    for u in fd:
        if isinstance(u, Exception):
            raise u
        elif u.cmd == 0x19:
            yield MpsseClkOut(u)
        elif u.cmd == 0x1b:
            yield MpsseClkOutBits(u)
        elif u.cmd == 0x28:
            yield MpsseClkIn(u)
        elif u.cmd == 0x80:
            yield MpsseSetGpioLow(u)
        elif u.cmd == 0x81:
            yield MpsseGetGpioLow(u)
        elif u.cmd == 0x82:
            yield MpsseSetGpioHigh(u)
        elif u.cmd == 0x83:
            yield MpsseGetGpioHigh(u)
        elif u.cmd == 0x86:
            yield MpsseSetTckDivisor(u)
        elif u.cmd == 0x87:
            yield MpsseSendImmediate(u)
        else:
            yield u


def parse_and_print(pcap: IO[bytes], fd=None) -> None:
    from scapy_ftdi import iterate_ftdi_usb_capture
    pkts = iterate_ftdi_usb_capture(pcap)
    mpsse = parse_mpsse(pkts)

    for u in mpsse:
        print(u, file=fd)

        if isinstance(u, MpsseSendImmediate):
            t = u._raw.time
            print(f"        % time is {t:.6f}s %", file=fd)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Process Miniwiggler"
                                     "USBpcap file, parsing DAP telegrams")
    parser.add_argument("pcap_file", help="Path to the USBpcap file")
    args = parser.parse_args()

    parse_and_print(args.pcap_file)


if __name__ == "__main__":
    main()
