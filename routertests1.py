#!/usr/bin/env python

from switchyard.lib.testing import *
from switchyard.lib.packet import *
from switchyard.lib.address import *
from switchyard.lib.common import *

def mk_ping(hwsrc, hwdst, ipsrc, ipdst, reply=False, ttl=64):
    ether = Ethernet()
    ether.src = hwsrc
    ether.dst = hwdst
    ether.ethertype = EtherType.IP
    ippkt = IPv4()
    ippkt.srcip = ipsrc
    ippkt.dstip = ipdst
    ippkt.ttl = ttl
    ippkt.ipid = 0
    icmppkt = ICMP()
    icmppkt.icmpdata.data = b'\x13' * 13
    icmppkt.icmpdata.sequence = 42
    return ether + ippkt + icmppkt

def test_arp():
    s = Scenario("ARP request")
    s.add_interface('router-eth0', '10:00:00:00:00:01', '192.168.1.1', '255.255.255.0')
    s.add_interface('router-eth1', '10:00:00:00:00:02', '10.10.0.1', '255.255.0.0')
    s.add_interface('router-eth2', '10:00:00:00:00:03', '172.16.42.1', '255.255.255.252')

    # arp for router-eth0 IP addr
    arpreq = create_ip_arp_request("30:00:00:00:00:01", "192.168.1.100", "192.168.1.1")
    arpresp = create_ip_arp_reply("10:00:00:00:00:01", "30:00:00:00:00:01", "192.168.1.1", "192.168.1.100")
    s.expect(PacketInputEvent("router-eth0", arpreq, display=Arp), "ARP request for 192.168.1.1 should arrive on router-eth0")
    s.expect(PacketOutputEvent("router-eth0", arpresp, display=Arp), "Router should send ARP response for 192.168.1.1 on router-eth0")

    # non-arp packet
    icmp_echo = mk_ping("ab:cd:ef:00:00:01", "10:00:00:00:00:01", "192.168.1.242", "10.10.12.34")
    s.expect(PacketInputEvent("router-eth0", icmp_echo, display=IPv4), 
        "An ICMP echo request for 10.10.12.34 should arrive on router-eth0, but it should be dropped (router should only handle ARP requests at this point)")

    return s

scenario = test_arp()
