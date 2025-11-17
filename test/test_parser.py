import pytest
import dap_parser
import ops_parser
import glob
import os


TRACES_DIR = os.path.join(os.path.dirname(__file__), '../traces')


@pytest.fixture(params=glob.glob(os.path.join(TRACES_DIR, '*.pcap*')))
def trace_path(request):
    return request.param


def test_trace_parser(trace_path):
    txt_path = trace_path[:trace_path.rfind(".")] + '.txt'
    with open(txt_path, 'w') as fd:
        ops_parser.parse_and_print(open(trace_path, 'rb'), fd)


def test_compute_crc6():
    assert dap_parser.compute_crc6(0xaaaaaaaa, 32) == 3
    assert dap_parser.compute_crc6(0xf00, 16) == 0x3c
    assert dap_parser.compute_crc6(0x400, 16) == 0x03
