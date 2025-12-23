from typing import IO, Any, Callable, Iterator, Type
from multiprocessing import Process, Queue
from scapy.all import bind_layers, Packet, Raw, sniff
from scapy.fields import (PacketListField, LEShortField, ByteField,
                          XStrFixedLenField)
from scapy.layers.usb import USBpcap
from scapy.config import conf
conf.debug_dissector = True


class FTDI_FT_TX_Command(Packet):
    fields_desc = [ByteField("command", default=0)]

    @classmethod
    def dispatch_hook(cls, _pkt: bytes, *args: Any,
                      **kargs: Any) -> 'Type[Packet]':
        assert isinstance(_pkt, bytes) and len(_pkt) > 0
        if _pkt[0] == 0x19:
            return FTDI_ClockDataBytesOutOnNVeClockEdgeLSBFirstNoRead
        if _pkt[0] == 0x1b:
            return FTDI_ClockDataBitsOutOnNVeClockEdgeLSBFirstNoRead
        if _pkt[0] == 0x28:
            return FTDI_ClockDataBytesInOnPVeClockEdgeLSBFirstNoWrite
        if _pkt[0] == 0x80:
            return FTDI_SetDataBitsLowByte
        if _pkt[0] == 0x81:
            return FTDI_GetDataBitsLowByte
        if _pkt[0] == 0x82:
            return FTDI_SetDataBitsHighByte
        if _pkt[0] == 0x83:
            return FTDI_GetDataBitsHighByte
        if _pkt[0] == 0x84:
            return FTDI_StartLoopback
        if _pkt[0] == 0x85:
            return FTDI_StopLoopback
        if _pkt[0] == 0x86:
            return FTDI_SetClkDivisor
        if _pkt[0] == 0x87:
            return FTDI_SendImmediate
        if _pkt[0] == 0x8a:
            return FTDI_DisableClkDiv5
        if _pkt[0] == 0x8b:
            return FTDI_EnableClkDiv5
        if _pkt[0] == 0x8c:
            return FTDI_EnableClk3Phase
        if _pkt[0] == 0x8d:
            return FTDI_DisableClk3Phase
        if _pkt[0] == 0x97:
            return FTDI_DisableClockAdaptive
        if _pkt[0] == 0xaa:
            return FTDI_AA
        if _pkt[0] == 0xab:
            return FTDI_AB
        raise Exception(f"Command {_pkt[0]} not implemented")


class FTDI_FT_TX_Command_P(Packet):
    def extract_padding(self, s: bytes) -> tuple[bytes, bytes]:
        return b"", s

    def expected_response_size(self) -> int:
        return 0


class FTDI_ClockDataBytesOutOnNVeClockEdgeLSBFirstNoRead(FTDI_FT_TX_Command_P):
    fields_desc = [ByteField("command", default=0),
                   LEShortField("length", default=0x00),
                   XStrFixedLenField("data", b"", length_from=lambda p: (
                       p.length + 1))]


class FTDI_ClockDataBitsOutOnNVeClockEdgeLSBFirstNoRead(FTDI_FT_TX_Command_P):
    fields_desc = [ByteField("command", default=0),
                   ByteField("length", default=0x00),
                   XStrFixedLenField("data", b"", length_from=lambda p: (
                       p.length + 7 + 1) // 8)]


class FTDI_ClockDataBytesInOnPVeClockEdgeLSBFirstNoWrite(FTDI_FT_TX_Command_P):
    fields_desc = [ByteField("command", default=0),
                   LEShortField("length", default=0x00)]

    def expected_response_size(self) -> int:
        assert isinstance(self.length, int)
        return self.length+1


class FTDI_SetDataBitsLowByte(FTDI_FT_TX_Command_P):
    fields_desc = [ByteField("command", default=0),
                   ByteField("value", default=0x00),
                   ByteField("direction", default=0x00)]


class FTDI_GetDataBitsLowByte(FTDI_FT_TX_Command_P):
    fields_desc = [ByteField("command", default=0)]

    def expected_response_size(self) -> int:
        return 1


class FTDI_SetDataBitsHighByte(FTDI_FT_TX_Command_P):
    fields_desc = [ByteField("command", default=0),
                   ByteField("value", default=0x00),
                   ByteField("direction", default=0x00)]


class FTDI_GetDataBitsHighByte(FTDI_FT_TX_Command_P):
    fields_desc = [ByteField("command", default=0)]

    def expected_response_size(self) -> int:
        return 1


class FTDI_StartLoopback(FTDI_FT_TX_Command_P):
    fields_desc = [ByteField("command", default=0)]


class FTDI_StopLoopback(FTDI_FT_TX_Command_P):
    fields_desc = [ByteField("command", default=0)]


class FTDI_SetClkDivisor(FTDI_FT_TX_Command_P):
    fields_desc = [ByteField("command", default=0),
                   LEShortField("divisor", default=0x00)]


class FTDI_SendImmediate(FTDI_FT_TX_Command_P):
    fields_desc = [ByteField("command", default=0)]


class FTDI_DisableClkDiv5(FTDI_FT_TX_Command_P):
    fields_desc = [ByteField("command", default=0)]


class FTDI_EnableClkDiv5(FTDI_FT_TX_Command_P):
    fields_desc = [ByteField("command", default=0)]


class FTDI_EnableClk3Phase(FTDI_FT_TX_Command_P):
    fields_desc = [ByteField("command", default=0)]


class FTDI_DisableClk3Phase(FTDI_FT_TX_Command_P):
    fields_desc = [ByteField("command", default=0)]


class FTDI_DisableClockAdaptive(FTDI_FT_TX_Command_P):
    fields_desc = [ByteField("command", default=0)]


class FTDI_AA(FTDI_FT_TX_Command_P):
    fields_desc = [ByteField("command", default=0)]

    def expected_response_size(self) -> int:
        return 2


class FTDI_AB(FTDI_FT_TX_Command_P):
    fields_desc = [ByteField("command", default=0)]

    def expected_response_size(self) -> int:
        return 2


class FTDI_FT_TX_Payload(Packet):
    fields_desc = [PacketListField("commands", [],
                                   FTDI_FT_TX_Command, max_count=1 << 16)]

    def extract_padding(self, s: bytes) -> tuple[bytes, bytes]:
        return s, b""


bind_layers(USBpcap, FTDI_FT_TX_Payload, endpoint=2)


class FTDI_FT_RX_Payload(Packet):
    fields_desc = [ByteField("modem_status", default=0x00),
                   ByteField("line_status", default=0x00)]

    def extract_padding(self, s: bytes) -> tuple[bytes, bytes]:
        return s, b""


bind_layers(USBpcap, FTDI_FT_RX_Payload, endpoint=0x81)


class FtdiXfer:
    def __init__(self, time: float, cmdbuf: bytes, rspbuf: bytes) -> None:
        self.time = time
        self.cmd = cmdbuf[0]
        self.arg = cmdbuf[1:]
        self.rsp = rspbuf

    def __repr__(self) -> str:
        if len(self.arg) > 0:
            out = f"MPSSE(0x{self.cmd:02x}, x'{self.arg.hex()}')"
        else:
            out = f"MPSSE(0x{self.cmd:02x})"
        if self.rsp:
            return f"{out} -> x'{self.rsp.hex()}'"
        else:
            return out


class OnPkt:
    def __init__(self, on_exchange: Callable[[FtdiXfer], None]) -> None:
        self.active_reqs: list[tuple[USBpcap, FTDI_FT_TX_Command, int]] = []
        self.remainder = b''
        self.on_exchange = on_exchange
        self.start_time: Any = None

    def on_pkt(self, p: USBpcap) -> None:
        if self.start_time is None:
            self.start_time = p.time
        if p.haslayer(Raw):
            pass
        if 0x7f & p.endpoint == 0:
            pass
        elif p.endpoint == 0x81:
            if p.haslayer(FTDI_FT_RX_Payload):
                if p.haslayer(Raw):
                    load = self.remainder + p[FTDI_FT_RX_Payload][Raw].load
                    self.remainder = b''
                    while (len(self.active_reqs) > 0
                            and len(load) >= self.active_reqs[0][2]):
                        req, cmd, rsp_sz = self.active_reqs.pop(0)
                        rsp = load[:rsp_sz]
                        time = p.time - self.start_time
                        self.on_exchange(
                            FtdiXfer(float(time),
                                     bytes(cmd), rsp))
                        load = load[rsp_sz:]
                    self.remainder = load
        elif p.endpoint == 0x02:
            if p.haslayer(FTDI_FT_TX_Payload):
                assert not p.haslayer(Raw)
                # assert self.remainder == b''
                for cmd in p[FTDI_FT_TX_Payload].commands:
                    rsp_sz = cmd.expected_response_size()
                    self.active_reqs.append((p, cmd, rsp_sz))
        elif p.endpoint == 0x83:
            pass
        else:
            raise Exception("Unexpected FTDI endpoint 0x%02x" % p.endpoint)


def sniffproc(q: 'Queue[FtdiXfer|None|Exception]', fd: IO[bytes]) -> None:
    o = OnPkt(q.put)
    try:
        sniff(offline=fd, prn=o.on_pkt, store=0,
              basecls=USBpcap)
        # , lfilter=lambda p: p.bus==1 and p.device==5)
    except Exception as x:
        q.put(x)
    else:
        q.put(None)
    finally:
        q.close()


def iterate_ftdi_usb_capture(fd: IO[bytes]) -> Iterator[FtdiXfer]:
    q: 'Queue[FtdiXfer|None|Exception]' = Queue()
    p = Process(target=sniffproc, args=(q, fd))
    p.start()
    try:
        while u := q.get():
            if isinstance(u, Exception):
                raise u
            else:
                yield u
    finally:
        p.terminate()
