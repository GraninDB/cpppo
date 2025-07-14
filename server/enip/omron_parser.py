#
# Cpppo -- Communication Protocol Python Parser and Originator
#
# Copyright (c) 2013, Hard Consulting Corporation.
#
# Cpppo is free software: you can redistribute it and/or modify it under the
# terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.  See the LICENSE file at the top of the source tree.
#
# Cpppo is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
#

from __future__ import absolute_import, print_function, division
try:
    from future_builtins import zip, map  # Use Python 3 "lazy" zip, map
except ImportError:
    pass

__author__ = "Perry Kundert"
__email__ = "perry@hardconsulting.com"
__copyright__ = "Copyright (c) 2013 Hard Consulting Corporation"
__license__ = "Dual License: GPLv3 (or later) and Commercial (see LICENSE)"


"""
enip/parser.py -- The EtherNet/IP CIP protocol parsers

"""

import logging
import struct
import itertools

from ...dotdict import dotdict
from ...automata import (type_str_base, is_listlike, dfa, decide, string_bytes)
#from ...automata import (type_str_base, is_listlike, dfa, decide)

from datetime import datetime, timezone

from .parser import octets_noop, \
                    octets_drop, TYPE, STRUCT, UDINT, SINT, USINT, INT, \
                    UINT, DINT, LINT, ULINT, REAL, LREAL, move_if, \
                    CIP, status, enip_format, enip_machine, enip_encode

from .parser import typed_data as common_typed_data

log = logging.getLogger("enip.srv")


# BOOLEAN C1 OMRON specific 2 bytes
class BOOL(TYPE):
    tag_type = 0x00c1  # 193
    struct_format = '<H'
    struct_calcsize = struct.calcsize(struct_format)

    def terminate(self, exception, machine=None, path=None, data=None):
        super(BOOL, self).terminate(exception=exception, machine=machine, path=path, data=data)

        if exception is not None:
            return
        ours = self.context(path=path)
        if is_listlike(data[ours]):
            data[ours] = list(map(bool, data[ours]))
        else:
            data[ours] = bool(data[ours])

    @classmethod
    def produce(cls, value):
        """Historically, a 0xFF has been used to represent an EtherNet/IP CIP BOOL Truthy value."""
        encoding = super(BOOL, cls).produce(value)
        return encoding if encoding == b'\x00' else b'\xff'


class OMRSTRING(STRUCT):
    """Parses/produces a EtherNet/IP String:
        .OMRSTRING.length            UINT        2
        .OMRSTRING.string            octets[*]    .length+.length%2
    The produce classmethod accepts this structure, or just a plain Python str, and will output the
    equivalent length+string.  If a zero length is provided, no string is parsed, and an empty
    string returned.  Much like SSTRING, except:
    - a 2-byte UINT specifies the length
    - the string is padded to an even number of words with a NUL byte, if necessary
    """
    tag_type = 0x00D0
    struct_calcsize = 80 # Average OMRSTRING size used for estimations
    def __init__(self, name=None, **kwds):
        name = name or kwds.setdefault('context', self.__class__.__name__)
        leng = UINT('length', context='length')
        leng[None] = move_if('empty',  destination='.string', initializer='',
                             predicate=lambda path=None, data=None, **kwds: 0 == data[path].length,
                             state=octets_noop('done',
                                               terminal=True))
        leng[None] = sbdy = string_bytes('string',
                                         limit='..length',
                                         initial='.*',    decode='iso-8859-1')
        sbdy[None] = decide('string_even',
                            predicate=lambda path=None, data=None, **kwds: 0 == data[path].length % 2,
                            state=octets_noop('done',
                                                        terminal=True))
        sbdy[None] = octets_drop('pad', repeat=1,
                                 terminal=True)
        super(OMRSTRING, self).__init__(name=name, initial=leng, **kwds)
    @classmethod
    def produce(cls, value):
        """Truncate or NUL-fill the provided .string to the given .length (if provided and not None).
        Then, emit the (two byte) length+string+pad.  Accepts either a {.length: ..., .string:... }
        dotdict, or a plain string.
        """
        result = b''
        if isinstance(value, type_str_base):
            value = dotdict({'string': value })
        encoded = value.string.encode('iso-8859-1')
        # If .length doesn't exist or is None, set the length to the actual string length
        actual = len(encoded)
        desired = value.setdefault('length', actual)
        if desired is None:
            value.length = actual
        assert value.length < 1<<16, "OMRSTRING must be < 65536 bytes in length; %r" % value
        result += UINT.produce(value.length)
        result += encoded[:value.length]
        if actual < value.length:
            result + b'\x00' * (value.length - actual)
        return result


class OMRDATN(TYPE):     # DATE_AND_TIME_NSEC 0A Vendor Specific
    """An EtherNet/IP DATE_AND_TIME_NSEC, OMRON VENDOR SPECIFIC DATA TYPE, READ/WRITE as ULINT; 8 bytes"""
    tag_type = 0x000a
    struct_format = '<Q'
    struct_calcsize = struct.calcsize(struct_format)

    def terminate(self, exception, machine=None, path=None, data=None):
        super(OMRDATN, self).terminate(exception=exception, machine=machine, path=path, data=data)

        if exception is not None:
            return
        ours = self.context(path=path)
        if is_listlike(data[ours]):
            data[ours] = list(map(datetime.fromtimestamp, map(lambda x: x / 1000000000, data[ours]), itertools.repeat(timezone.utc)))
        else:
            data[ours] = datetime.fromtimestamp(data[ours] / 1000000000, timezone.utc)


class typed_data(common_typed_data):
    """Parses CIP typed data, of the form specified by the datatype (must be a relative path within the
    data artifact, or an integer data type).  Data elements are parsed 'til exhaustion of input, so
    the caller should use limit= to define the limits of the data in the source symbol input stream;
    only complete data items must be parsed, so this must be exact, and match the specified data
    type.

    If no data is provided (or due to a limit=0), no data will be parsed, nor will .data be
    initialized to [].

    The known data types are:

    data type   supported   type value      size

    BOOL        yes = 0x00c1        2 byte (0x0_c1, _=[0-7] indicates relevant bit)
    SINT        yes = 0x00c2        1 byte
    INT         yes = 0x00c3        2 bytes
    DINT        yes = 0x00c4        4 bytes
    REAL        yes = 0x00ca        4 bytes
    LREAL       yes = 0x00cb        8 bytes  (!!! python side - float)
    USINT       yes = 0x00c6        1 byte
    UINT        yes = 0x00c7        2 bytes
    WORD = 0x00d2        2 byte (16-bit boolean array)
    UDINT       yes = 0x00c8        4 bytes
    DWORD = 0x00d3        4 byte (32-bit boolean array)
    LINT        yes = 0x00c5        8 byte
    ULINT       yes = 0x00c9        8 byte
    SSTRING     yes = 0x00da        1 byte length + <length> data
    STRING      yes = 0x00d0        2 byte length + <length> data (rounded up to 2 bytes)
    OMRSTRING   yes = 0x00d0        2 byte length + <length> data
    OMRDATN     yes = 0x000a        8 bytes
    """
    TYPES_SUPPORTED = {
        BOOL.tag_type: BOOL,
        SINT.tag_type: SINT,
        USINT.tag_type: USINT,
        INT.tag_type: INT,
        UINT.tag_type: UINT,
        DINT.tag_type: DINT,
        LINT.tag_type: LINT,
        ULINT.tag_type: ULINT,
        UDINT.tag_type: UDINT,
        REAL.tag_type: REAL,
        LREAL.tag_type: LREAL,
        OMRSTRING.tag_type: OMRSTRING,
        OMRDATN.tag_type: OMRDATN,
    }

    def __init__(self, name=None, tag_type=None, **kwds):
        name = name or kwds.setdefault('context', self.__class__.__name__)
        assert tag_type, "Must specify a numeric (or relative path to) the CIP data type; found: %r" % tag_type

        slct = octets_noop('sel_type')

        i_8d = octets_noop('end_8bit',
                           terminal=True)
        i_8d[True] = i_8p = SINT()
        i_8p[None] = move_if('mov_8bit', source='.SINT',
                             destination='.data', initializer=lambda **kwds: [],
                             state=i_8d)

        u_8d = octets_noop('end_8bitu',
                           terminal=True)
        u_8d[True] = u_8p = USINT()
        u_8p[None] = move_if('mov_8bitu', source='.USINT',
                             destination='.data', initializer=lambda **kwds: [],
                             state=u_8d)

        u_1d = octets_noop('end1bitu',
                           terminal=True)
        u_1d[True] = u_1p = BOOL()
        u_1p[None] = move_if('mov1bitu', source='.BOOL',
                             destination='.data', initializer=lambda **kwds: [],
                             state=u_1d)

        i16d = octets_noop('end16bit',
                           terminal=True)
        i16d[True] = i16p = INT()
        i16p[None] = move_if('mov16bit', source='.INT',
                             destination='.data', initializer=lambda **kwds: [],
                             state=i16d)

        u16d = octets_noop('end16bitu',
                           terminal=True)
        u16d[True] = u16p = UINT()
        u16p[None] = move_if('mov16bitu', source='.UINT',
                             destination='.data', initializer=lambda **kwds: [],
                             state=u16d)

        i32d = octets_noop('end32bit',
                           terminal=True)
        i32d[True] = i32p = DINT()
        i32p[None] = move_if('mov32bit', source='.DINT',
                             destination='.data', initializer=lambda **kwds: [],
                             state=i32d)

        i64d = octets_noop('end64bit',
                           terminal=True)
        i64d[True] = i64p = LINT()
        i64p[None] = move_if('mov64bit', source='.LINT',
                             destination='.data', initializer=lambda **kwds: [],
                             state=i64d)

        u32d = octets_noop('end32bitu',
                           terminal=True)
        u32d[True] = u32p = UDINT()
        u32p[None] = move_if('mov32bitu', source='.UDINT',
                             destination='.data', initializer=lambda **kwds: [],
                             state=u32d)

        fltd = octets_noop('endfloat',
                           terminal=True)
        fltd[True] = fltp = REAL()
        fltp[None] = move_if('movfloat', source='.REAL',
                             destination='.data', initializer=lambda **kwds: [],
                             state=fltd)

        dbld = octets_noop('enddouble',
                           terminal=True)
        dbld[True] = dblp = LREAL()
        dblp[None] = move_if('movdouble', source='.LREAL',
                             destination='.data', initializer=lambda **kwds: [],
                             state=dbld)

        sttd = octets_noop('end_string',
                           terminal=True)
        sttd[True] = sttp = OMRSTRING()
        sttp[None] = move_if('mov_strings', source='.OMRSTRING.string',
                             destination='.OMRSTRING')
        sttp[None] = move_if('mov_string', source='.OMRSTRING',
                             destination='.data', initializer=lambda **kwds: [],
                             state=sttd)

        omrdatnd = octets_noop('endomrdatn',
                               terminal=True)
        omrdatnd[True] = omrdatnp = OMRDATN()
        omrdatnp[None] = move_if('movomrdatn', source='.OMRDATN',
                                 destination='.data', initializer=lambda **kwds: [],
                                 state=omrdatnd)

        slct[None] = decide('BOOL', state=u_1d,
                            predicate=lambda path=None, data=None, **kwds:
                            BOOL.tag_type == (data[path+tag_type] if isinstance(tag_type, type_str_base) else tag_type))
        slct[None] = decide('SINT', state=i_8d,
                            predicate=lambda path=None, data=None, **kwds:
                            SINT.tag_type == (data[path+tag_type] if isinstance(tag_type, type_str_base) else tag_type))
        slct[None] = decide('USINT', state=u_8d,
                            predicate=lambda path=None, data=None, **kwds:
                            USINT.tag_type == (data[path+tag_type] if isinstance(tag_type, type_str_base) else tag_type))
        slct[None] = decide('INT', state=i16d,
                            predicate=lambda path=None, data=None, **kwds:
                            INT.tag_type == (data[path+tag_type] if isinstance(tag_type, type_str_base) else tag_type))
        slct[None] = decide('UINT', state=u16d,
                            predicate=lambda path=None, data=None, **kwds:
                            UINT.tag_type == (data[path+tag_type] if isinstance(tag_type, type_str_base) else tag_type))
        slct[None] = decide('DINT', state=i32d,
                            predicate=lambda path=None, data=None, **kwds:
                            DINT.tag_type == (data[path+tag_type] if isinstance(tag_type, type_str_base) else tag_type))
        slct[None] = decide('LINT', state=i64d,
                            predicate=lambda path=None, data=None, **kwds:
                            LINT.tag_type == (data[path+tag_type] if isinstance(tag_type, type_str_base) else tag_type))
        slct[None] = decide('UDINT', state=u32d,
                            predicate=lambda path=None, data=None, **kwds:
                            UDINT.tag_type == (data[path+tag_type] if isinstance(tag_type, type_str_base) else tag_type))
        slct[None] = decide('REAL', state=fltd,
                            predicate=lambda path=None, data=None, **kwds:
                            REAL.tag_type == (data[path+tag_type] if isinstance(tag_type, type_str_base) else tag_type))
        slct[None] = decide('LREAL', state=dbld,
                            predicate=lambda path=None, data=None, **kwds:
                            LREAL.tag_type == (data[path+tag_type] if isinstance(tag_type, type_str_base) else tag_type))
        slct[None] = decide('OMRSTRING', state=sttd,
                            predicate=lambda path=None, data=None, **kwds:
                            OMRSTRING.tag_type == (data[path+tag_type] if isinstance(tag_type, type_str_base) else tag_type))
        slct[None] = decide('OMRDATN', state=omrdatnd,
                            predicate=lambda path=None, data=None, **kwds:
                            OMRDATN.tag_type == (data[path+tag_type] if isinstance(tag_type, type_str_base) else tag_type))

        super(dfa, self).__init__(name=name, initial=slct, **kwds)
