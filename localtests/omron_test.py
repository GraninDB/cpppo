"""
Example of using cpppo.server.enip EtherNet/IP CIP client API.

To see the Tag operations succeed, fire up:
    python -m cpppo.server.enip Tag=DINT[10]
"""

import os
import sys
import logging

sys.path.insert(0, '..')
sys.path.insert(0, '../..')

import configparser
from cpppo.server.enip import address, client

try:
    import cpppo
except ImportError:
    # Allow import of 'cpppo' when executing within 'cpppo' package directory
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import cpppo


use_omron = True
dialect = None
if use_omron:
    from cpppo.server.enip.omron import Omron
    dialect = Omron

locatest_ini = configparser.ConfigParser()
locatest_ini.read('localtests\\localtest.ini')

omron_ip = locatest_ini['omron']['ip']

if __name__ == "__main__":
    logging.basicConfig(**cpppo.log_cfg)
#   logging.getLogger().setLevel(logging.DEBUG)
    host = omron_ip     # Controller IP address
    port = address[1]   # default is port 44818
    depth = 1		    # Allow 1 transaction in-flight
    multiple = 0		# Don't use Multiple Service Packet
    fragment = False    # Don't force Read/Write Tag Fragmented
    timeout = 1.0		# Any PLC I/O fails if it takes > 1s
    printing = True		# Print a summary of I/O
    tags = ["Blocks[8,1,1].ID", "Test_input_bool", "Test_input_string"]    # several parameters         34
#    tags = ["Blocks[8,1,1].ID"]                                            # UDINT                      34
#    tags = ["Blocks[2,1,1].ID"]                                            # LINT                       22
#    tags = ["Blocks[8,1,1].Length_Stamp_Start"]                            # LREAL                      34
#    tags = ["Blocks[2,1,1].Length_Stamp_Start"]                            # REAL                       22
#    tags = ["Blocks[2,1,1].Racks_Time"]                                    # DINT                       22
#    tags = ["Blocks[8,1,1].Foam_type"]                                     # STRING
#    tags = ["Blocks[8,1,1].Racks_IN.M_Date"]                               # DATE_AND_TIME__NSEC OMRON
#    tags = ["Test_input_bool"]                                             # BOOL
#    tags = ["Test_output_string"]                                          # STRING
#    tags = ["Test_output_string=(STRING)Test2"]
#    tags = ["Test_output_string"]
#  STRING     - write with odd number of characters does not work
#  03-21 11:21:40.271 MainThread enip.cli WARNING  validate   Client Single Write Tag  Test_output_string returned non-zero status: Status 21
#  Test_output_string              <= ['Test1']: 'Status 21 '


    with client.connector(host=host, port=port, timeout=timeout, dialect=dialect) as connection:
        operations = client.parse_operations(tags)
        failures, transactions = connection.process(
            operations=operations, depth=depth, multiple=multiple,
            fragment=fragment, printing=printing, timeout=timeout)

    print(transactions)

    sys.exit(1 if failures else 0)
