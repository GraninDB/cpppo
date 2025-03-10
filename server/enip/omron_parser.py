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
    from future_builtins import zip, map # Use Python 3 "lazy" zip, map
except ImportError:
    pass

__author__                      = "Perry Kundert"
__email__                       = "perry@hardconsulting.com"
__copyright__                   = "Copyright (c) 2013 Hard Consulting Corporation"
__license__                     = "Dual License: GPLv3 (or later) and Commercial (see LICENSE)"


"""
enip/parser.py	-- The EtherNet/IP CIP protocol parsers

"""

#import array
#import contextlib
#import json
import logging
import struct
#import sys

#import ipaddress

import cpppo

from .parser import octets_base, octets, octets_encode, octets_struct, octets_noop, \
                    octets_drop, words_base, words, TYPE, STRUCT, UDINT, UDINT_network, SINT, USINT, INT, \
                    UINT, DINT, REAL, LREAL, SSTRING, STRING, INT_network, UINT_network, WORD, IPADDR_network, enip_format, \
                    EPATH, EPATH_padded, move_if, route_path, legacy_CPF_0x0001, connection_ID, unconnected_send, \
                    communications_service, identity_object, send_data, register, unregister, CPF, CIP, status, \
                    enip_machine, enip_encode

from .parser import typed_data as common_typed_data

log				= logging.getLogger( "enip.srv" )

# BOOLEAN C1 OMRON specific 2 bytes
class BOOL( TYPE ):
    tag_type                    = 0x00c1 # 193
    struct_format               = '<H'
    struct_calcsize             = struct.calcsize( struct_format )

# DATE_AND_TIME_NSEC 0A Vendor Specific
class OMRDATN( TYPE ):
     """An EtherNet/IP DATE_AND_TIME_NSEC, OMRON VENDOR SPECIFIC DATA TYPE, READ/WRITE as ULINT; 8 bytes"""
     tag_type			= 0x000a
     struct_format		= '<Q'
     struct_calcsize		= struct.calcsize( struct_format )

class typed_data( common_typed_data ):
    """Parses CIP typed data, of the form specified by the datatype (must be a relative path within the
    data artifact, or an integer data type).  Data elements are parsed 'til exhaustion of input, so
    the caller should use limit= to define the limits of the data in the source symbol input stream;
    only complete data items must be parsed, so this must be exact, and match the specified data
    type.

    If no data is provided (or due to a limit=0), no data will be parsed, nor will .data be
    initialized to [].

    The known data types are:

    data type	supported	type value	  size

    BOOL 			    = 0x00c1	# 2 byte (0x0_c1, _=[0-7] indicates relevant bit)
    SINT	    yes		= 0x00c2	# 1 byte
    INT		    yes		= 0x00c3	# 2 bytes
    DINT	    yes		= 0x00c4	# 4 bytes
    REAL	    yes		= 0x00ca	# 4 bytes
    LREAL       yes		= 0x00cb	# 8 bytes  (!!! python side - float)
    USINT	    yes		= 0x00c6	# 1 byte
    UINT	    yes		= 0x00c7	# 2 bytes
    WORD			    = 0x00d2	# 2 byte (16-bit boolean array)
    UDINT	    yes		= 0x00c8	# 4 bytes
    DWORD			    = 0x00d3	# 4 byte (32-bit boolean array)
    LINT			    = 0x00c5	# 8 byte
    SSTRING	    yes		= 0x00da	# 1 byte length + <length> data
    STRING	    yes		= 0x00d0	# 2 byte length + <length> data (rounded up to 2 bytes)
    OMRDATN     yes		= 0x000a	# 8 bytes
    """
    TYPES_SUPPORTED		= {
        BOOL.tag_type:  	BOOL,
        SINT.tag_type:		SINT,
        USINT.tag_type:		USINT,
        INT.tag_type:		INT,
        UINT.tag_type:		UINT,
        DINT.tag_type:		DINT,
        UDINT.tag_type:		UDINT,
        REAL.tag_type:		REAL,
        LREAL.tag_type:		LREAL,
        SSTRING.tag_type:	SSTRING,
        STRING.tag_type:	STRING,
        OMRDATN.tag_type:	OMRDATN,
    }

    def __init__( self, name=None, tag_type=None, **kwds ):
        name 			= name or kwds.setdefault( 'context', self.__class__.__name__ )
        assert tag_type, "Must specify a numeric (or relative path to) the CIP data type; found: %r" % tag_type

        slct			= octets_noop(	'sel_type' )

        i_8d			= octets_noop(	'end_8bit',
                                                terminal=True )
        i_8d[True]	    = i_8p	= SINT()
        i_8p[None]		= move_if( 	'mov_8bit',	source='.SINT',
                                           destination='.data',	initializer=lambda **kwds: [],
                                                state=i_8d )

        u_8d			= octets_noop(	'end_8bitu',
                                                terminal=True )
        u_8d[True]	    = u_8p	= USINT()
        u_8p[None]		= move_if( 	'mov_8bitu',	source='.USINT',
                                           destination='.data',	initializer=lambda **kwds: [],
                                                state=u_8d )

        u_1d			= octets_noop(	'end1bitu',
                                                terminal=True )
        u_1d[True]	    = u_1p	= BOOL()
        u_1p[None]		= move_if( 	'mov1bitu',	source='.BOOL',
                                           destination='.data',	initializer=lambda **kwds: [],
                                                state=u_1d )

        i16d			= octets_noop(	'end16bit',
                                                terminal=True )
        i16d[True]	    = i16p	= INT()
        i16p[None]		= move_if( 	'mov16bit',	source='.INT',
                                           destination='.data',	initializer=lambda **kwds: [],
                                                state=i16d )

        u16d			= octets_noop(	'end16bitu',
                                                terminal=True )
        u16d[True]	    = u16p	= UINT()
        u16p[None]		= move_if( 	'mov16bitu',	source='.UINT',
                                           destination='.data',	initializer=lambda **kwds: [],
                                                state=u16d )

        i32d			= octets_noop(	'end32bit',
                                                terminal=True )
        i32d[True]	    = i32p	= DINT()
        i32p[None]		= move_if( 	'mov32bit',	source='.DINT',
                                           destination='.data',	initializer=lambda **kwds: [],
                                                state=i32d )

        u32d			= octets_noop(	'end32bitu',
                                                terminal=True )
        u32d[True]	    = u32p	= UDINT()
        u32p[None]		= move_if( 	'mov32bitu',	source='.UDINT',
                                           destination='.data',	initializer=lambda **kwds: [],
                                                state=u32d )

        fltd			= octets_noop(	'endfloat',
                                                terminal=True )
        fltd[True]	    = fltp	= REAL()
        fltp[None]		= move_if( 	'movfloat',	source='.REAL',
                                           destination='.data',	initializer=lambda **kwds: [],
                                                state=fltd )

        dbld			= octets_noop(	'enddouble',
                                                 terminal=True )
        dbld[True]	    = dblp	= LREAL()
        dblp[None]		= move_if( 	'movdouble',	source='.LREAL',
                                            destination='.data',	initializer=lambda **kwds: [],
                                                 state=dbld )

        # Since a parsed "[S]STRING": { "string": "abc", "length": 3 } is multiple layers deep, and we
        # want to completely eliminate the target container in preparation for the next loop, we'll
        # need to move it up one layer, and then into the final target.
        sstd			= octets_noop(	'endsstring',
                                                terminal=True )
        sstd[True]	    = sstp	= SSTRING()
        sstp[None]		= move_if( 	'movsstrings',	source='.SSTRING.string',
                                                destination='.SSTRING' )
        sstp[None]		= move_if( 	'movsstring',	source='.SSTRING',
                                           destination='.data',	initializer=lambda **kwds: [],
                                                state=sstd )

        sttd			= octets_noop(	'end_string',
                                                terminal=True )
        sttd[True]	    = sttp	= STRING()
        sttp[None]		= move_if( 	'mov_strings',	source='.STRING.string',
                                                destination='.STRING' )
        sttp[None]		= move_if( 	'mov_string',	source='.STRING',
                                           destination='.data',	initializer=lambda **kwds: [],
                                                state=sttd )
        omrdatnd		= octets_noop(	'endomrdatn',
                                                 terminal=True )
        omrdatnd[True]	= omrdatnp	= OMRDATN()
        omrdatnp[None]	= move_if( 	'movomrdatn',	source='.OMRDATN',
                                            destination='.data',	initializer=lambda **kwds: [],
                                                 state=omrdatnd )

        slct[None]		= cpppo.decide(	'BOOL',	state=u_1d,
            predicate=lambda path=None, data=None, **kwds: \
                BOOL.tag_type == ( data[path+tag_type] if isinstance( tag_type, cpppo.type_str_base ) else tag_type ))
        slct[None]		= cpppo.decide(	'SINT',	state=i_8d,
            predicate=lambda path=None, data=None, **kwds: \
                SINT.tag_type == ( data[path+tag_type] if isinstance( tag_type, cpppo.type_str_base ) else tag_type ))
        slct[None]		= cpppo.decide(	'USINT',state=u_8d,
            predicate=lambda path=None, data=None, **kwds: \
                USINT.tag_type == ( data[path+tag_type] if isinstance( tag_type, cpppo.type_str_base ) else tag_type ))
        slct[None]		= cpppo.decide(	'INT',	state=i16d,
            predicate=lambda path=None, data=None, **kwds: \
                INT.tag_type == ( data[path+tag_type] if isinstance( tag_type, cpppo.type_str_base ) else tag_type ))
        slct[None]		= cpppo.decide(	'UINT',	state=u16d,
            predicate=lambda path=None, data=None, **kwds: \
                UINT.tag_type == ( data[path+tag_type] if isinstance( tag_type, cpppo.type_str_base ) else tag_type ))
        slct[None]		= cpppo.decide(	'DINT',	state=i32d,
            predicate=lambda path=None, data=None, **kwds: \
                DINT.tag_type == ( data[path+tag_type] if isinstance( tag_type, cpppo.type_str_base ) else tag_type ))
        slct[None]		= cpppo.decide(	'UDINT',state=u32d,
            predicate=lambda path=None, data=None, **kwds: \
                UDINT.tag_type == ( data[path+tag_type] if isinstance( tag_type, cpppo.type_str_base ) else tag_type ))
        slct[None]		= cpppo.decide(	'REAL',	state=fltd,
            predicate=lambda path=None, data=None, **kwds: \
                REAL.tag_type == ( data[path+tag_type] if isinstance( tag_type, cpppo.type_str_base ) else tag_type ))
        slct[None]		= cpppo.decide(	'LREAL',	state=dbld,
             predicate=lambda path=None, data=None, **kwds: \
                LREAL.tag_type == ( data[path+tag_type] if isinstance( tag_type, cpppo.type_str_base ) else tag_type ))
        slct[None]		= cpppo.decide(	'SSTRING', state=sstd,
            predicate=lambda path=None, data=None, **kwds: \
                SSTRING.tag_type == ( data[path+tag_type] if isinstance( tag_type, cpppo.type_str_base ) else tag_type ))
        slct[None]		= cpppo.decide(	'STRING', state=sttd,
            predicate=lambda path=None, data=None, **kwds: \
                STRING.tag_type == ( data[path+tag_type] if isinstance( tag_type, cpppo.type_str_base ) else tag_type ))
        slct[None]		= cpppo.decide(	'OMRDATN', state=omrdatnd,
             predicate=lambda path=None, data=None, **kwds: \
                 OMRDATN.tag_type == ( data[path+tag_type] if isinstance( tag_type, cpppo.type_str_base ) else tag_type ))

        super( cpppo.dfa, self ).__init__( name=name, initial=slct, **kwds )

