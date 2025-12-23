#!/usr/bin/env python3
from abc import abstractmethod
import binascii
import struct
import sys
import types
from typing import Callable, Optional, TypeVar, Any
from pyftdi.ftdi import Ftdi
from bitarray import bitarray
from bitarray.util import int2ba


T = TypeVar('T')
W = TypeVar('W')


class Promise[T]:
    class Unresolved:
        pass

    def __init__(self) -> None:
        self.__result: T | Promise.Unresolved = Promise.Unresolved()
        self.__callback: Optional[Callable[[T], None]] = None

    @property
    def value(self) -> T:
        if isinstance(self.__result, Promise.Unresolved):
            raise Exception('Promise not resolved yet')
        return self.__result

    @value.setter
    def value(self, value: T) -> None:
        if not isinstance(self.__result, Promise.Unresolved):
            raise Exception('Promise was already resolved')
        self.__result = value
        if self.__callback is not None:
            self.__callback(self.__result)

    def then(self, cb: Callable[[T], W]) -> 'Promise[W]':
        def on_resolve(t: T) -> None:
            w = cb(t)
            next_promise.value = w

        next_promise = Promise[W]()
        self.__callback = on_resolve
        if not isinstance(self.__result, Promise.Unresolved):
            self.__callback(self.__result)
        return next_promise


def traceback() -> types.TracebackType | None:
    tb = None
    depth = 2
    while True:
        try:
            frame = sys._getframe(depth)
            depth += 1
        except ValueError:
            break
        tb = types.TracebackType(tb, frame, frame.f_lasti, frame.f_lineno)
    return tb


def AssertInt(x: int) -> Callable[[None | int], None]:
    def curry(b: int | None) -> None:
        if b is None or b != x:
            raise AssertionError.with_traceback(AssertionError(
                f"{hex(b) if b is not None else 'None'} != {hex(x)}"), tb)
    tb = traceback()
    return curry


def AssertNone() -> Callable[[Any], None]:
    def curry(b: Any) -> None:
        if b is not None:
            raise AssertionError.with_traceback(AssertionError(), tb)
    tb = traceback()
    return curry


def AssertNotNone() -> Callable[[T | None], T]:
    def curry(b: T | None) -> T:
        if b is None:
            raise AssertionError.with_traceback(AssertionError(), tb)
        return b
    tb = traceback()
    return curry


def AssertBytes(x: str) -> Callable[[bytes], None]:
    def curry(b: bytes) -> None:
        if b != bytes.fromhex(x):
            raise AssertionError.with_traceback(AssertionError(
                f"{b.hex()} != {x}"), tb)
    tb = traceback()
    return curry


def AssertZero() -> Callable[[bytes], None]:
    def curry(x: bytes) -> None:
        if sum(x) != 0:
            raise AssertionError.with_traceback(AssertionError(
                f"{x.hex()} != 0"), tb)
    tb = traceback()
    return curry


def compute_crc6(msg: bitarray) -> int:
    crc = 0x3F
    for i in range(len(msg)):
        bit = (msg[i] ^ crc ^ (crc >> 1)) & 1
        crc = (bit << 5) | (crc >> 1)
    return crc ^ (crc >> 1)


def unpad(ba: bitarray) -> bitarray:
    while len(ba) > 0 and ba[0] == 0:
        ba = ba[1:]  # remove padding 0
    if len(ba) > 0 and ba[0] == 1:
        ba = ba[1:]  # remove leading 1
    return ba


def dap_telegram(cmdid: int, arglen: int = 0,
                 arg: Optional[int] = None) -> bitarray:
    out = bitarray('1')  # packet starts with a 1
    out.extend(int2ba(cmdid, length=5, endian='little'))
    if arg is None:
        out.extend('111111')
    else:
        out.extend(int2ba(arglen, length=6, endian='little'))
        out.extend(int2ba(arg, length=arglen, endian='little'))
    out.extend(int2ba(compute_crc6(out), length=6, endian='little'))
    return out


def dap2_encode(out: bitarray) -> bytes:
    if out[-1] == 1:
        out.append(0)
    out = bitarray('0' * (8 - len(out) % 8), endian='little') + out
    return out.tobytes()


class FtdiCmd:
    def __init__(self, data: bytes = b'', expected: int = 0):
        self.data_out = data
        self.data_in = Promise[bytes]()
        self.expected = expected


class FtdiBatch:
    def __init__(self, ftdi: Ftdi) -> None:
        self.ftdi = ftdi
        self._batch: list[FtdiCmd] = []

    def append(self, cmd: bytes = b'',
               expected: int = 0) -> Promise[bytes]:
        a = FtdiCmd(cmd, expected)
        self._batch.append(a)
        return a.data_in

    def clear(self) -> None:
        self._batch.clear()

    def mpsse_clockout_bytes(self, b: bytes) -> None:
        assert 0 < len(b) <= 0x10000
        self.append(struct.pack("<BH", 0x19, len(b) - 1) + b)

    def mpsse_clockin_bytes(self, b: int) -> Promise[bytes]:
        assert 0 < b <= 0x10000
        return self.append(struct.pack("<BH", 0x28, b - 1), b)

    def mpsse_set_clk_divisor(self, div: int) -> None:
        assert 1 <= div <= 0x10000
        self.append(struct.pack("<BH", 0x86, div-1))

    def mpsse_clockout_bits(self, count: int, value: int) -> None:
        self.append(bytes([0x1b, count-1, value]))

    def read_gpios(self) -> Promise[bytes]:
        return self.append(b'\x81\x83', 2)

    def exec(self) -> list[bytes]:
        try:
            self.append(b'\x87')
            out_data = b''
            in_size = 0
            for c in self._batch:
                out_data += c.data_out
                in_size += c.expected
            self.ftdi.write_data(out_data)
            in_data: bytes = b''
            while len(in_data) != in_size:
                in_data += self.ftdi.read_data(in_size-len(in_data))
            assert len(in_data) == in_size, f"{len(in_data)} != {in_size}"
            out_args: list[bytes] = []
            for c in self._batch:
                if c.expected:
                    b = in_data[:c.expected]
                    c.data_in.value = b
                    out_args.append(b)
                    in_data = in_data[c.expected:]
                else:
                    pass
            assert in_data == b''
            self._batch = []
            return out_args
        finally:
            self.clear()


class DAPInterface(FtdiBatch):
    @abstractmethod
    def dap_output_bytes(self, b: bitarray) -> None:
        raise NotImplementedError()

    @abstractmethod
    def dap_input_bytes(self, b: int) -> Promise[bytes]:
        raise NotImplementedError()

    @abstractmethod
    def test_reset(self) -> None:
        raise NotImplementedError()

    @abstractmethod
    def reset(self) -> None:
        raise NotImplementedError()


class MiniWigglerBatch(DAPInterface):
    # low byte
    # (possible values: 80db, 80da, 004b)
    # 0x0001  ADBUS0 (TCK) <---> DAP0
    # 0x0002  ADBUS1 (TDI) <---> TDI, U304_A
    # 0x0004  ADBUS2 (TDO) <---> U306_A, U304_Y
    # 0x0008  ADBUS3 (TMS) <---> TMS
    # 0x0010  ADBUS4       <---> U303_OE
    # 0x0020  ADBUS5       <--->
    # 0x0040  ADBUS6       <---> USR0
    # 0x0080  ADBUS7       <---> D301

    # high byte
    # (possible values: 12f2, 57f7, 67f7, 55f7)
    # 0x0100  ACBUS0 <--->
    # 0x0200  ACBUS1 <---> RESET
    # 0x0400  ACBUS2 <---> TRST
    # 0x0800  ACBUS3 <---> U307_A
    # 0x1000  ACBUS4 <---> U304_OE
    # 0x2000  ACBUS5 <---> U306_DIR, USR8
    # 0x4000  ACBUS6 --x
    # 0x8000  ACBUS7 <---> U307_DIR

    GPIOH_TRST = b'\x82\x12\xf2'
    GPIOH_RESET = b'\x82\x55\xf7'
    GPIOH_OUTPUT = b'\x82\x67\xf7'
    GPIOH_INPUT = b'\x82\x57\xf7'
    GPIOL_NORMAL = b'\x80\x80\xdb'
    GPIOL_TRST = b'\x80\x00\x4b'  # TCK=0, TDI=0, TMS=0, USR0=0
    GPIOL_OPEN_CLK = b'\x80\x80\xda'

    def __init__(self, ftdi: Ftdi) -> None:
        FtdiBatch.__init__(self, ftdi)

        # The official Infineon software does this, I don't know what it is
        a = self.append(b'\xaa', 2)
        b = self.append(b'\xab', 2)
        self.exec()
        a.then(AssertBytes('faaa'))
        b.then(AssertBytes('faab'))

        # Disable Clk Divide by 5
        # Disable adaptive clocking (return clock signal)
        # Disable 3 Phase Data Clocking (data only valid for 1 edge)
        self.append(b'\x8a\x97\x8d')

        self.test_reset()
        self.read_gpios().then(AssertBytes('a01f'))
        self.append(MiniWigglerBatch.GPIOH_INPUT)
        self.append(MiniWigglerBatch.GPIOL_NORMAL)
        self.exec()

    def dap_output_bytes(self, b: bitarray) -> None:
        self.append(MiniWigglerBatch.GPIOH_OUTPUT)
        self.mpsse_clockout_bytes(dap2_encode(b))
        self.append(MiniWigglerBatch.GPIOH_INPUT)

    def dap_input_bytes(self, b: int) -> Promise[bytes]:
        return self.mpsse_clockin_bytes(b)

    def test_reset(self) -> None:
        self.append(MiniWigglerBatch.GPIOH_TRST)
        self.append(MiniWigglerBatch.GPIOL_TRST)
        self.append(MiniWigglerBatch.GPIOL_NORMAL)

    def reset(self) -> None:
        self.append(MiniWigglerBatch.GPIOH_RESET)
        self.append(MiniWigglerBatch.GPIOL_NORMAL)


class TigardBatch(DAPInterface):
    # low byte
    # 0x0001  BDBUS0 (TCK) ----> DAP0
    # 0x0002  BDBUS1 (TDI) ----> DAP1
    # 0x0004  BDBUS2 (TDO) <---- DAP1
    # 0x0008  BDBUS3 (TMS) ----> TMS
    # 0x0010  BDBUS4       ----> TRST
    # 0x0020  BDBUS5       ----> SRST
    # 0x0040  BDBUS6       <----
    # 0x0080  BDBUS7       <---- SRST

    def __init__(self, ftdi: Ftdi) -> None:
        FtdiBatch.__init__(self, ftdi)
        self.append(b'\x8a\x97\x8d')  # clocking things
        self.append(b'\x80\x30\x3b')
        self.test_reset()
        self.exec()

    def dap_output_bytes(self, b: bitarray) -> None:
        self.mpsse_clockout_bytes(dap2_encode(b))

    def dap_input_bytes(self, b: int) -> Promise[bytes]:
        return self.mpsse_clockin_bytes(b)

    def test_reset(self) -> None:
        self.append(b'\x80\x20\x3b')
        self.append(b'\x80\x30\x3b')

    def reset(self) -> None:
        self.append(b'\x80\x10\x3b')
        self.append(b'\x80\x30\x3b')


class DAPBatch:
    def __init__(self, interface: DAPInterface) -> None:
        self._if = interface
        self.dap_output_bytes = interface.dap_output_bytes
        self.dap_input_bytes = interface.dap_input_bytes
        self.test_reset = interface.test_reset
        self.exec = interface.exec
        self.reset = interface.reset
        self.mpsse_set_clk_divisor = interface.mpsse_set_clk_divisor

    def mpsse_set_clk_freq(self, freq: int, base: int = 30_000_000) -> None:
        # NOTE: base frequency is either 6MHz or 30MHz depending whether
        # commands 0x8a or 0x8b were issued, and whether we are using ft2232H
        # or ft2232D. Here I'm assuming base_freq is 30MHz for now.

        assert freq > 0
        div = round(base / freq)
        if div < 1 or div > 0x10000:
            raise ValueError(f"Selected frequency ({freq}) is out of range")
        error = abs((base / div) - freq) / freq
        if error > 0.05:
            raise ValueError(f"Selected frequency ({freq}) is unreachable")
        return self.mpsse_set_clk_divisor(div)

    def dap_telegram(self, cmdid: int, arglen: int = 0,
                     arg: Optional[int] = None, rsplen: int = 0
                     ) -> Promise[bytes]:
        next_promise = Promise[bytes]()
        t = dap_telegram(cmdid, arglen, arg)
        self.dap_output_bytes(t)

        def on_response(b: bytes) -> None:
            assert 0 < len(b), b
            if 0 < len(b):
                ba = bitarray(b, endian='little')
                ba = unpad(ba)
                b = ba.tobytes()
            next_promise.value = b
        self.dap_input_bytes(rsplen).then(on_response)
        return next_promise

    def dap_write_payload(self, b: bytes) -> None:
        if len(b) != 4:
            raise NotImplementedError()
        ba = bitarray(b, endian='little')
        ba = bitarray(bitarray('01') + ba + bitarray('000000'),
                      endian='little')
        self.dap_output_bytes(ba)

    def dap_readreg(self, reg: int, size: int) -> Promise[int | None]:
        # Looks like a read command, reads DAP registers?
        # Registers seen in captures:
        # 11 (2 bytes) -> some kind of status register?
        # 15 (2 bytes) -> always returns 0x260?
        # 9 (4 bytes) -> reads 1 byte from current selected address
        # 7 (4 bytes) -> reads 2 bytes from current selected address
        # 5 (4 bytes) -> reads 4 bytes from current selected address
        # 3 (4 bytes) -> identical to 5?
        # address for reads is set on telegram 8, low nibble 1
        def on_response(b: bytes) -> int | None:
            ba = bitarray(b, endian='little')
            if len(ba) == 0:
                return None
            b = ba.tobytes()
            if len(b) < size + 1:  # +1 for crc
                raise Exception(f"Response too short: {b.hex()}")
            fmt = {2: "<H", 4: "<I", 8: "<Q"}[size]
            rx, = struct.unpack(fmt, b[:size])
            assert isinstance(rx, int)
            assert sum(b[size+1:]) == 0, b
            crc = compute_crc6(bitarray(b[:size], endian='little'))
            assert b[size] == crc, b
            return rx

        assert 0 <= reg <= 0xf
        if size == 2:
            reg |= 0x40
        elif size == 4:
            reg |= 0x50
        elif size == 8:
            reg |= 0x60
        else:
            raise NotImplementedError(f"Unknown size {size}")
        return self.dap_telegram(26, 7, reg, 9).then(on_response)

    def dap_jtag_swap_dr(self, d: int) -> Promise[int | None]:
        def on_response(b: bytes) -> int | None:
            if sum(b) == 0:
                return None
            else:
                rx, = struct.unpack("<I", b[:4])
                assert isinstance(rx, int)
                assert sum(b[4+1:]) == 0, b
                crc = compute_crc6(bitarray(b[:4], endian='little'))
                assert b[4] == crc, b
                return rx

        return self.dap_telegram(2, 32, d, 7).then(on_response)

    def dap_sync(self) -> Promise[int | None]:
        def on_response(b: bytes) -> int | None:
            if sum(b) == 0:
                return None
            else:
                rx, = struct.unpack("<I", b[:4])
                assert isinstance(rx, int)
                assert sum(b[4+1:]) == 0, b
                crc = compute_crc6(bitarray(b[:4], endian='little'))
                assert b[4] == crc, b
                return rx

        return self.dap_telegram(16, 0, None, 56).then(on_response)

    def dap_dapisc(self, sz: int, data: int) -> Promise[int | None]:
        def on_response(b: bytes) -> int | None:
            if sum(b) == 0:
                return None
            else:
                rx, = struct.unpack("<H", b[:2])
                assert isinstance(rx, int)
                assert sum(b[2+1:]) == 0, b
                crc = compute_crc6(bitarray(b[:2], endian='little'))
                assert b[2] == crc, b
                return rx

        return self.dap_telegram(17, sz, data, 5).then(on_response)

    def dap_jtag_set_ir(self) -> None:
        self.dap_telegram(19, 8, 4, 3).then(AssertBytes('000002'))

    def dap_set_io_client(self, x: int) -> None:
        self.dap_telegram(28, 3, x, 3).then(AssertZero())

    def dap_writereg(self, reg: int, data: int, size: int, rspsize: int = 7
                     ) -> None:
        self.dap_telegram(8, size+4, data << 4 | reg, rspsize
                          ).then(AssertZero())

    def dap_writereg_0(self, x: int) -> None:
        self.dap_writereg(0, x, 12)

    def dap_read_ioinfo(self) -> Promise[int]:
        return self.dap_readreg(0xb, 2).then(AssertNotNone())

    def select_addr(self, addr: int) -> None:
        self.dap_writereg(1, addr, 32)

    def write_comdata(self, x: int) -> None:
        self.dap_writereg(4, x, 32)

    def dap_write_ojconf(self, x: int) -> None:
        self.dap_writereg(0xe, x, 16)

    def dap_writemem(self, addr: int, size: int) -> None:
        assert (size & 0x3fc) == size or size == 0x400
        assert (addr & 0xfffffffc) == addr
        self.dap_telegram(
            9, 40, (addr & 0xfffffffc) << 8 | (size & 0x3fc), 7).then(
                    AssertZero())

    def dap_readmem(self, addr: int, size: int) -> Promise[bytes]:
        def fn(b: bytes) -> bytes:
            out = b''
            ba = bitarray(b, endian='little')
            first = True
            for _ in range((size + 7) // 4):
                # Note: only the first response "payload" was unpadded already
                # but readmem can receive multiple payloads, each is 32 bits
                # so skip applying unpad to the first payload
                if not first:
                    ba = unpad(ba)
                else:
                    first = False
                out += ba.tobytes()[:4]
                ba = ba[32:]
            data = out[:-4]
            crc = binascii.crc32(data) ^ 0xFFFFFFFF
            crc = int('{:032b}'.format(crc)[::-1], 2)
            if len(out) > 4:
                rxcrc, = struct.unpack('<I', out[-4:])
                assert rxcrc == crc
            return data

        assert 0 < size <= 0x400
        assert (size & 3) == 0
        assert (addr & 0xfffffffc) == addr
        RESULT_SIZES = {4: 16, 8: 22, 12: 26, 64: 140, 1024: 1226}
        if size not in RESULT_SIZES:
            raise NotImplementedError()
        return self.dap_telegram(
            10, 40,
            (addr & 0xfffffffc) << 8 | (size & 0x3fc) | 1,
            RESULT_SIZES[size]
            ).then(fn)


class DAPOperations:
    def __init__(self, batch: DAPBatch):
        self._batch = batch

    def read(self, addr: int, size: int) -> bytes:
        # Read a block of bytes, must be aligned to 32-bit
        self._batch.dap_set_io_client(1)
        self._batch.dap_writereg_0(0xc1)
        res = self._batch.dap_readmem(addr, size)
        self._batch.exec()
        return res.value

    def write(self, addr: int, data: bytes) -> bytes:
        # Write a block of bytes, must be aligned to 32-bit
        self._batch.dap_set_io_client(1)
        self._batch.dap_writereg_0(0xc1)
        self._batch.dap_writemem(addr, len(data))
        results: list[Promise[bytes]] = []
        for i in range(0, len(data), 4):
            payload = data[i:i+4]
            self._batch.dap_write_payload(payload)
            last = (i + 4) >= len(data)
            results.append(self._batch.dap_input_bytes(1 + last))
        self._batch.select_addr(addr)
        self._batch.exec()
        return b''.join(v.value for v in results)

    def write8(self, addr: int, data: int) -> None:
        assert 0 <= data <= 255
        self._batch.dap_set_io_client(1)
        self._batch.dap_writereg_0(0xc1)
        self._batch.select_addr(addr)
        self._batch.dap_writereg(8, data, 8)
        self._batch.exec()

    def read8(self, addr: int) -> int:
        self._batch.dap_set_io_client(1)
        self._batch.dap_writereg_0(0xc1)
        self._batch.select_addr(addr)
        res = self._batch.dap_readreg(9, 4)
        self._batch.exec()
        result = res.value
        assert result is not None
        out = result & 0xff
        assert (result & 0xffff) == (result >> 16)
        assert out == (result >> 8 & 0xff)
        return out

    def write16(self, addr: int, data: int) -> None:
        assert 0 <= data <= 0xffff
        self._batch.dap_set_io_client(1)
        self._batch.dap_writereg_0(0xc1)
        self._batch.select_addr(addr)
        self._batch.dap_writereg(6, data, 16)
        self._batch.exec()

    def read16(self, addr: int) -> int:
        self._batch.dap_set_io_client(1)
        self._batch.dap_writereg_0(0xc1)
        self._batch.select_addr(addr)
        res = self._batch.dap_readreg(7, 4)
        self._batch.exec()
        result = res.value
        assert result is not None
        out = result & 0xffff
        assert out == (result >> 16)
        return out

    def write32(self, addr: int, data: int) -> None:
        assert 0 <= data <= 0xffffffff
        self._batch.dap_set_io_client(1)
        self._batch.dap_writereg_0(0xc1)
        self._batch.select_addr(addr)
        self._batch.dap_writereg(4, data, 32)
        self._batch.exec()

    def read32(self, addr: int) -> int:
        self._batch.dap_set_io_client(1)
        self._batch.dap_writereg_0(0xc1)
        self._batch.select_addr(addr)
        res = self._batch.dap_readreg(5, 4)
        self._batch.exec()
        result = res.value
        assert result is not None
        return result
