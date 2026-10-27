"""Test Cvdump parser, reading global variables"""

from reccmp.cvdump.parser import (
    CvdumpParser,
    GdataEntry,
)
from reccmp.cvdump.cvinfo import CVInfoTypeEnum

GLOBALS_SAMPLE = """
S_PROCREF: 0x00000000: (   5, 000000D4) WinMain
S_LPROCREF: 0x00000000: (  21, 0000008C) write_char
S_GDATA32: [0003:00018F84], Type:      T_UINT4(0075), _winver
S_UDT:   T_32PRCHAR(0470), va_list
S_LDATA32: [0003:00018FCC], Type:       T_INT4(0074), fSystemSet
"""


def test_globals():
    """Ensure that CvdumpParser tracks symbols for global and link-local
    variables, while ignoring other symbol types found in the GLOBAL section"""
    parser = CvdumpParser()
    parser.read_section("GLOBALS", GLOBALS_SAMPLE)
    assert len(parser.globals) == 2

    assert parser.globals[0] == GdataEntry(
        section=0x0003,
        offset=0x00018F84,
        type=CVInfoTypeEnum.T_UINT4,
        name="_winver",
        is_global=True,
    )
    assert parser.globals[1] == GdataEntry(
        section=0x0003,
        offset=0x00018FCC,
        type=CVInfoTypeEnum.T_INT4,
        name="fSystemSet",
        is_global=False,
    )


SEGMENT_MAP_SAMPLE = """
Sec  flags  ovl   grp   frm sname cname    offset    cbSeg
 01  010d  0000  0000  0001  ffff  ffff  00000000 00235bfa
 02  0109  0000  0000  0002  ffff  ffff  00000000 0008b98a
 03  010b  0000  0000  0003  ffff  ffff  00000000 00033338
 06  0208  0000  0000  0000  ffff  ffff  00000000 ffffffff
"""


def test_segment_map_absolute():
    parser = CvdumpParser()
    parser.read_section("SEGMENT MAP", SEGMENT_MAP_SAMPLE)
    assert parser.absolute_segments == {0x0006}
