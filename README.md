# tricore-things

This repo contains some python utilities for working with the DAP OCD protocon found in Aurix Tricore processors.

## Parsers

Miniwiggler USB traffic captured using USBPcap can be parsed with any of the following commands:

```bash
python mpsse_parser.py capture.pcap  # outputs individual MPSSE transfers
python dap_parser.py capture.pcap  # outputs the parsed DAP Telegrams
python ops_parser.py capture.pcap  # outputs high level read/write operations
```

## On-Chip Debug

Some On-Chip Debug operations were reimplemented in python, and can be used either with an origianl Miniwiggler or with a Tigard.

The file "ftdi_dap.py" contains the implementation of the DAP protocol, while "run_demo.py" contains some examples on how to use it.


# DAPBatch

DAPBatch implements low level DAP operations, they can be queued together and run together with the `exec()` method.

Queueing together as many operations as possible is critical to get deterministic timings which are useful when attempting fault-injection.

When queueing a low level DAP operation which has a response, a Promise object is returned, which will contain the response in the `value` field after the `exec()` method is called:

```python
    batch = DAPBatch(MiniWigglerBatch(ftdi))
    dap_status = batch.dap_readreg(0xb, 2)
    batch.exec()

    if dap_status.value == 0x400:
        print("DAP was already unlocked")
```

# DAPOperations

DAPOperations implements higher level DAP operations such as writing to and reading from RAM.
Registers can also be manipulated by writing to the CSFR area of each CPU, refer to the Core Architecture manual for details.
