from typing import IO, Iterator
from dap_parser import MiniwigglerClkOutIn, DapPayload, DapTelegram, \
                       DapTelegram19, DapTelegram2, DapTelegramReadReg, \
                       DapTelegram28, DapTelegramWriteReg, DapTelegramRead, \
                       DapTelegramWrite, parse_dap, parse_miniwiggler
from mpsse_parser import MpsseGetGpioHigh, MpsseGetGpioLow, \
                         MpsseSendImmediate, MpsseSetGpioHigh, \
                         MpsseSetGpioLow, MpsseTransaction, \
                         MpsseSetTckDivisor, parse_mpsse
from scapy_ftdi import FtdiXfer, iterate_ftdi_usb_capture


Cmd = (FtdiXfer | MpsseTransaction
       | MiniwigglerClkOutIn
       | DapTelegram | DapPayload)


class DapOperation:
    def __init__(self, time: float) -> None:
        self.time = time


class DapOperationWriteMemory(DapOperation):
    def __init__(self, time: float, addr: int, data: bytes) -> None:
        DapOperation.__init__(self, time)
        self.addr = addr
        self.data = data

    def __repr__(self) -> str:
        return f"*0x{self.addr:08x} ⬅️ x'{self.data.hex(' ')}'"


class DapOperationReadMemory(DapOperation):
    def __init__(self, time: float, addr: int, data: bytes, crcgood: bool):
        DapOperation.__init__(self, time)
        self.addr = addr
        self.data = data
        self.crcgood = crcgood

    def __repr__(self) -> str:
        return f"*0x{self.addr:08x} ➡️ x'{self.data.hex(' ')}'" + \
            (" (crc bad)" if not self.crcgood else "")


class DapOperationReadRegister(DapOperation):
    def __init__(self, time: float, reg: int, data: int):
        DapOperation.__init__(self, time)
        self.reg = reg
        self.data = data

    def __repr__(self) -> str:
        return f"DAP({self.reg:d}) ➡️ 0x{self.data:04x}"


class DapOperationReadReadRegister(DapOperation):
    def __init__(self, time: float, reg: int, data: int):
        DapOperation.__init__(self, time)
        self.reg = reg
        self.data = data

    def __repr__(self) -> str:
        return f"DAP(11), DAP({self.reg}) ➡️ 0, 0x{self.data:04x}"


class DapOperationRead8(DapOperation):
    def __init__(self, time: float, addr: int, data: int | None):
        DapOperation.__init__(self, time)
        self.addr = addr
        self.data = data & 0xff if data is not None else None

    def __repr__(self) -> str:
        if self.data is not None:
            return f"*0x{self.addr:08x} ➡️ (u8) 0x{self.data:02x}"
        else:
            return f"*0x{self.addr:08x} ➡️ (u8)  // no response"


class DapOperationRead16(DapOperation):
    def __init__(self, time: float, addr: int, data: int | None):
        DapOperation.__init__(self, time)
        self.addr = addr
        self.data = data & 0xffff if data is not None else None

    def __repr__(self) -> str:
        if self.data is not None:
            return f"*0x{self.addr:08x} ➡️ (u16) 0x{self.data:04x}"
        else:
            return f"*0x{self.addr:08x} ➡️ (u16)  // no response"


class DapOperationReadGpio(DapOperation):
    def __init__(self, time: float, low: int, high: int):
        DapOperation.__init__(self, time)
        self.low = low
        self.high = high

    def __repr__(self) -> str:
        return f"GPIO ➡️ 0x{self.low:02x}{self.high:02x}"


class DapOperationWriteGpio(DapOperation):
    def __init__(self, time: float, low: int, high: int):
        DapOperation.__init__(self, time)
        self.low = low
        self.high = high

    def __repr__(self) -> str:
        return f"GPIO ⬅️ 0x{self.low:02x}{self.high:02x}"


class DapOperationUnknownTelegram2(DapOperation):
    def __init__(self, time: float, data: int):
        DapOperation.__init__(self, time)
        self.data = data

    def __repr__(self) -> str:
        return f"DAPcmd2 ➡️ 0x{self.data:08x}"


def parse_dap_operations(cmds: Iterator[Cmd]) -> Iterator[Cmd | DapOperation]:
    cmdblock: list[Cmd] = []
    for u in cmds:
        cmdblock.append(u)
        if isinstance(u, MpsseSendImmediate):
            done = False
            if len(cmdblock) >= 6:
                cmd0 = cmdblock[0]
                cmd1 = cmdblock[1]
                cmd2 = cmdblock[2]
                payloads = cmdblock[3:-2]
                cmd4 = cmdblock[-2]
                if (isinstance(cmd0, DapTelegram28)
                        and cmd0.arg == 1
                        and isinstance(cmd1, DapTelegramWriteReg)
                        and cmd1.arg == 0xc10
                        and isinstance(cmd2, DapTelegramWrite)
                        and (all(isinstance(p, DapPayload) for p in payloads))
                        and isinstance(cmd4, DapTelegramWriteReg)
                        and (cmd4.arg & 0xf) == 1
                        and (cmd4.arg >> 4) == cmd2.write_addr):
                    payload = b''.join(p.out_buf for p in payloads
                                       if hasattr(p, 'out_buf'))
                    yield DapOperationWriteMemory(
                        u._raw.time, cmd2.write_addr, payload)
                    done = True

            if not done and len(cmdblock) == 4:
                cmd0 = cmdblock[0]
                cmd1 = cmdblock[1]
                cmd2 = cmdblock[2]
                if (isinstance(cmd0, DapTelegram28)
                        and cmd0.arg == 1
                        and isinstance(cmd1, DapTelegramReadReg)
                        and cmd1.rx is not None
                        and isinstance(cmd2, DapTelegramWriteReg)
                        and cmd2.arg == 0xc10):
                    yield DapOperationReadRegister(
                        u._raw.time, cmd1.arg_low, cmd1.rx)
                    done = True

            if not done and len(cmdblock) == 5:
                cmd0 = cmdblock[0]
                cmd1 = cmdblock[1]
                cmd2 = cmdblock[2]
                cmd3 = cmdblock[3]
                if (isinstance(cmd0, DapTelegram28)
                        and cmd0.arg == 2
                        and isinstance(cmd1, DapTelegramReadReg)
                        and cmd1.arg == 0x4b
                        and cmd1.rx is not None and cmd1.rx == 0
                        and isinstance(cmd2, DapTelegramReadReg)
                        and cmd2.rx is not None
                        and isinstance(cmd3, DapTelegram28)
                        and cmd3.arg == 1):
                    yield DapOperationReadReadRegister(
                        u._raw.time, cmd2.arg_low, cmd2.rx)
                    done = True

            if not done and len(cmdblock) == 5:
                cmd0 = cmdblock[0]
                cmd1 = cmdblock[1]
                cmd2 = cmdblock[2]
                cmd3 = cmdblock[3]
                if (isinstance(cmd0, DapTelegram28)
                        and cmd0.arg == 1
                        and isinstance(cmd1, DapTelegramWriteReg)
                        and cmd1.arg == 0xc10
                        and isinstance(cmd2, DapTelegramWriteReg)
                        and cmd2.arg & 0xf == 1
                        and isinstance(cmd3, DapTelegramReadReg)):
                    
                    if cmd3.arg == 0x59:
                        yield DapOperationRead8(
                            u._raw.time, cmd2.arg >> 4, cmd3.rx)
                        done = True
                    elif cmd3.arg == 0x57:
                        yield DapOperationRead16(
                            u._raw.time, cmd2.arg >> 4, cmd3.rx)
                        done = True

            if not done and len(cmdblock) == 4:
                cmd0 = cmdblock[0]
                cmd1 = cmdblock[1]
                cmd2 = cmdblock[2]
                if (isinstance(cmd0, DapTelegram28)
                        and cmd0.arg == 1
                        and isinstance(cmd1, DapTelegramWriteReg)
                        and cmd1.arg == 0xc10
                        and isinstance(cmd2, DapTelegramRead)
                        and cmd2.data is not None):
                    yield DapOperationReadMemory(
                        u._raw.time, cmd2.read_addr, cmd2.data, cmd2.crcgood)
                    done = True

            if not done and len(cmdblock) == 6:
                cmd0 = cmdblock[0]
                cmd1 = cmdblock[1]
                cmd2 = cmdblock[2]
                cmd3 = cmdblock[3]
                cmd4 = cmdblock[4]
                if (isinstance(cmd0, DapTelegram28)
                        and cmd0.arg == 1
                        and isinstance(cmd1, DapTelegramWriteReg)
                        and cmd1.arg == 0xc10
                        and isinstance(cmd3, DapTelegramRead)
                        and cmd3.crcgood
                        and cmd3.data is not None
                        and isinstance(cmd2, MpsseSetTckDivisor)
                        and isinstance(cmd4, MpsseSetTckDivisor)):
                    yield DapOperationReadMemory(
                        u._raw.time, cmd3.read_addr, cmd3.data)
                    done = True

            if not done and len(cmdblock) == 3:
                cmd0 = cmdblock[0]
                cmd1 = cmdblock[1]
                if (isinstance(cmd0, MpsseGetGpioLow)
                        and isinstance(cmd1, MpsseGetGpioHigh)):
                    yield DapOperationReadGpio(
                        u._raw.time, cmd0.values, cmd1.values)
                    done = True

            if not done and len(cmdblock) == 3:
                cmd0 = cmdblock[0]
                cmd1 = cmdblock[1]
                if (isinstance(cmd0, MpsseSetGpioHigh)
                        and isinstance(cmd1, MpsseSetGpioLow)):
                    yield DapOperationWriteGpio(
                        u._raw.time, cmd1.values, cmd0.values)
                    done = True

            if not done and len(cmdblock) == 3:
                cmd0 = cmdblock[0]
                cmd1 = cmdblock[1]
                if (isinstance(cmd0, DapTelegram19)
                        and cmd0.arg == 4
                        and cmd0.rsp is not None
                        and isinstance(cmd1, DapTelegram2)
                        and cmd1.arg == 0
                        and cmd1.rx is not None):
                    yield DapOperationUnknownTelegram2(
                        u._raw.time, cmd1.rx)
                    done = True

            if not done:
                for cmd in cmdblock:
                    yield cmd
            cmdblock = []


def parse_and_print(pcap: IO[bytes], fd=None) -> None:
    pkts = iterate_ftdi_usb_capture(pcap)
    mpsse = parse_mpsse(pkts)
    cmds = parse_dap(parse_miniwiggler(mpsse))
    ops = parse_dap_operations(cmds)

    for u in ops:
        if isinstance(u, DapOperation):
            print(f"{u.time:12.6f}s: {u}", file=fd)
        elif isinstance(u, MpsseSendImmediate):
            t = u._raw.time
            print(f"        % time is {t:.6f}s %", file=fd)
        else:
            print(u, file=fd)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Process Miniwiggler"
                                     "USBpcap file, parsing DAP telegrams")
    parser.add_argument("pcap_file", help="Path to the USBpcap file")
    args = parser.parse_args()

    parse_and_print(args.pcap_file)


if __name__ == "__main__":
    main()
