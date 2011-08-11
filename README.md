EOIP tunnels
============
Are handy feature of RouterOS allowing easy setup of high-performance ethernet VPNs.
For documentation and setup guide, see http://wiki.mikrotik.com/wiki/Manual:Interface/EoIP

Protocol spec
-------------

After IP header (which can be fragmented, MTU 1500 is usually used for tunnels)
GRE-like datagram follows. Note that it's nothing like RFC 1701 MikroTik mentioned in their docs:

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |       GRE FLAGS 0x20 0x01     |      Protocol Type  0x6400    | = MAGIC "\x20\x01\x64\x00"
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   Encapsulated frame length   |           Tunnel ID           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Ethernet frame...                                             |

Installation
------------

    # git clone git://github.com/katuma/eoip.git
    # make install

Usage
=====

    # apt-get install uml-utilities
    # tunctl -t tap0
    # eoip
    eoip [-f] <intf> [<local> [<remote>:<tunnelid> <remote:tunnelid...>]]

Example:

    # eoip tap0 1.2.3.4 5.6.7.8:1234
    [admin@5.6.7.8] /interface eoip add name=eoip-test tunnel-id=1234 remote-address=1.2.3.4

This will run the daemon in fixed p2p mode, ie single peer is allowed to establish tunnel via
Tunnel ID 1234.

Modes of operation
------------------

* Fixed, single tunnel:
  `eoip tap0 localip remoteip:1234`
* Fixed, multiple tunnels:
  `eoip tap0 localip remoteip1:1234 remoteip2:1235 ....`
* Open, single tunnel:
  `eoip tap0 localip 0.0.0.0:1234`
* Open, multiple tunnels:
  `eoip tap0 localip`

In "open" mode remote peer is learned via incoming packet (tunnelIDs being used to distinguish between each other).

In "multiple" mode, all tunnels will be bridged together exactly like STP unaware ethernet switch.

Flag '-f' prevents virtual "ports" from talking with each other to prevent packet storms - that means only the tap interface itself will be reachable.

Flag '-r N' sets limits of packet reassembly backlog (per tunnel), 128 by default.

