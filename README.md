EOIP tunnels
============

*BREAKING NEWS* Boian Bonev implemented EOIP kernel module if that's what you're looking for:

https://github.com/bbonev/eoip

EOIP tunnels are handy feature of RouterOS allowing easy setup of high-performance ethernet VPNs.
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
    eoip [-f] [-s /tmp/statusfile] <intf> [<local> [<remote>:<tunnelid> <remote:tunnelid...>]]
    Flags:
            -f      filter switch ports
            -t N    mac address timeout (seconds, 1800 by default)
            -s path store connected status and mac learning reports in here

Example:

    # eoip tap0 1.2.3.4 5.6.7.8:1234
    [admin@5.6.7.8] /interface eoip add name=eoip-test tunnel-id=1234 remote-address=1.2.3.4

This will run the daemon in fixed p2p mode, ie single peer is allowed to establish tunnel via
Tunnel ID 1234.

Tunnel ID with value 'etherip' is special - etherip tunnels will be established instead, fe:

    # eoip tap0 1.2.3.4 5.6.7.8:etherip

Will establish single etherip tunnel between hosts 1.2.3.4 and 5.6.7.8. "open" etherip mode is
achieved via:

    # eoip tap0 1.2.3.4 0.0.0.0:etherip

Modes of operation
------------------

* Fixed, single tunnel:
  `eoip tap0 localip remoteip:1234`
* Fixed, multiple tunnels:
  `eoip tap0 localip remoteip1:1234 remoteip2:1235 ....`
* Open, single tunnel:
  `eoip tap0 localip 0.0.0.0:1234`
* Open, multiple/unlimited tunnels:
  `eoip tap0 localip`
* Open, multiple predefined tunnels:
  `eoip tap0 localip 0.0.0.0:1234 0.0.0.0:1235`

In "open" mode remote peer is learned via incoming packet (tunnelIDs being used to distinguish between each other).

In "multiple" mode, all tunnels will be bridged together exactly like STP unaware ethernet switch.

Flag '-f' prevents virtual "ports" from talking with each other to prevent packet storms - that means only the tap interface itself will be reachable.

