# Packet-Generator

'pktGen' is a packet generation utility that generates and transmits layer 2,
layer 3, layer 4 and user defined packets. The packet header fields can be
specified using CLI or through a file consisting of raw packet data.

The syntax of the command is: (need root permissions)
pktGen <interface> <number of packets> <inter-packet interval> <input file>

<interface>: Output interface from which packets need be transmitted
<number of packets>: Number of packets that need to be transmitted
<inter-packet interval>: Time interval between successive packet transmission
                         (in seconds)
<input file>: File consisting of raw packet data. If the input file argument
              is not specified, then packet header fields are specified using
              CLI.

The utility can be installed using the following command:
./mk_install

The utility can be uninstalled using the following command:
./mk_remove

Make sure to give executable permissions to these commands (chmod +x <file>)

This package consists of source code of linux kernel module that transmits
these packets on the interface (pktGenKernMod), along with source code of user
space command utility (pktGenCmd).
The user space command takes command line inputs, constructs the packet and
passes the packet, interface, number of packets and inter-packet interval to
the kernel module via netlink sockets. The kernel transmits the packets
from the specified interface, with inter-packet time interval between
successive packet transmissions.

