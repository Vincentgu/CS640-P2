#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time
from switchyard.lib.packet import *
from switchyard.lib.address import *
from switchyard.lib.common import *
import queue

class forwardingTableClass(object):
    def __init__ (self, netDest, netMask, gateWay, intf, prefixlen):
        self.netDest = netDest
        self.netMask = netMask
        self.gateWay = gateWay
        self.intf = intf
        self.prefixlen = prefixlen

forwardingTable = []
matchesList = []
arpTable = {}
q = queue.Queue(10)

class Router(object):
    def __init__(self, net):
        self.net = net
        # other initialization stuff here

    def forwardTableLookUp(self, destIP):
        GotEntry = False
        maxPrefixlen = 0
        for fwdTblObj in forwardingTable:
            prefix = IPv4Address(fwdTblObj.netDest)
            #print (prefix)
            #debugger()
            if ((int(prefix) & int(destIP)) == int(prefix)):
                print ((int(prefix) & int(destIP)) == int(prefix))
                if fwdTblObj.prefixlen > maxPrefixlen:
                    SendFromIntf = fwdTblObj.intf
                    GotEntry = True
                    print (SendFromIntf, maxPrefixlen)
            else:
                continue

        return (GotEntry, SendFromIntf)

    # Function to create an Arp Packet  
    def CreateArpPacket(self, srchw, srcip, targetip):
        ether = Ethernet()
        ether.src = srchw
        ether.dst = 'ff:ff:ff:ff:ff:ff'
        ether.ethertype = EtherType.ARP
        arp = Arp()
        arp.operation = ArpOperation.Request
        arp.senderhwaddr = srchw
        arp.senderprotoaddr = srcip
        arp.targethwaddr = 'ff:ff:ff:ff:ff:ff'
        arp.targetprotoaddr = targetip
        arppacket = ether + arp 
        return arppacket

    def router_main(self, net): 
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''
        my_interfaces = net.interfaces()
        pktDest = False
        my_ips = [intf.ipaddr for intf in my_interfaces]
        #for intf in my_interfaces:
        #    print (intf.name, intf.ipaddr)

        while True:
            gotpkt = True
            try:
                dev,pkt = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                log_debug("No packets available in recv_packet")
                gotpkt = False
            except Shutdown:
                log_debug("Got shutdown signal")
                break

            if gotpkt:
                log_debug("Got a packet: {}".format(str(pkt)))

                #Handling of ARP Packets
                arp = pkt.get_header(Arp)
                if(arp):
                    for intf in my_interfaces:
                        if arp.targetprotoaddr == intf.ipaddr:
                            log_debug("Got ARP packet on interface: {}".format(intf.name))
                            # If this is not ARP Reply
                            print (arp.operation)
                            if arp.operation != ArpOperation.Reply:
                                targethwaddr = arp.senderhwaddr
                                targetprotoaddr = arp.senderprotoaddr
                                myprotoaddr = arp.targetprotoaddr
                                packet = create_ip_arp_reply(intf.ethaddr, targethwaddr, myprotoaddr, targetprotoaddr)
                                log_debug("Send a packet: {}".format(str(packet)))
                                net.send_packet(intf.name, packet)
                            # This is, if we get ARP Reply or Response
                            # Save the Src MAC and Src IP in arpTable
                            else:
                                log_info("ARP Reply on intf {}. Update table, Construct new pkt and Send".format(dev))
                                arpTable[intf.name] = arp.senderhwaddr
                                print (arpTable)
                                # Get the packet from Queue and send 
                                SendPkt = q.get()
                                log_info("sending the packet out on intf {}".format(dev))
                                SendPkt[0].src = intf.ethaddr
                                SendPkt[0].dst = arpTable[dev]
                                SendPkt.get_header(IPv4).ttl = SendPkt.get_header(IPv4).ttl - 1
                                net.send_packet(dev, SendPkt)

                        else:
                            continue

                # Get the IPv4 Packtet Headers and decrement the TTL
                ipv4_header = pkt.get_header(IPv4)
                if (ipv4_header):
                    log_debug("#1 Got a IPv4 Header packet: {}".format(str(ipv4_header)))
                    #newPktTTL = ipv4_header.ttl - 1 
                    #else:
                    #ipv4_header = pkt[1]
                    #log_debug("#2 Got a IPv4 Header packet: {}".format(str(ipv4_header)))

                    # Handling of packets that comes to me. Just Drop It!
                    if ipv4_header.dst in my_ips:
                        log_warn("Pkt for me. Do not do anything for this packet.")
                        continue

                    # Handling of Normal IP Packets
                    GotEntry, SendFromIntf = self.forwardTableLookUp(ipv4_header.dst)
                    log_info("Packet to be set from intf {} GotEntry: {}".format(SendFromIntf, GotEntry))

                    if GotEntry == True:
                        # Check for this destIP or intf entry in ARP Table, if present forward the IP packet.
                        # If not send an Arp Request and put the packet in Queue.
                        # 1. Check in Arp Table for entry

                        # Get the interface Object for this SendFromIntf interface. It is an Optimization.
                        for intf in my_interfaces:
                            if intf.name == SendFromIntf:
                                interfaceObj = intf

                        print (arpTable)
                        if SendFromIntf in arpTable:
                            log_info("Pkt ether dest is present in Arp Table, directly sending the packet out on intf {}".format(SendFromIntf))
                            pkt[0].src = interfaceObj.ethaddr
                            pkt[0].dst = arpTable[dev]
                            pkt.get_header(IPv4).ttl = pkt.get_header(IPv4).ttl - 1
                            net.send_packet(SendFromIntf, pkt)
    
                        # If not in arpTable, send an ARP Request and put pkt in Queue.
                        else:
                            srcHw = interfaceObj.ethaddr
                            srcIp = interfaceObj.ipaddr
                            #   gotInfoFlag = True
                            #else:
                            #    log_warn("Could not find from which interface to send !")
                            # Also Check in ARP Table to get an entry for this Dest. IP
                            # Do an ARP BroadCast and get the peer MAC.
                            log_info("Send an ARP Req from srchw {} srcIP {} destIP {}".format(srcHw, srcIp, ipv4_header.dst))
                            ArpReqPkt = self.CreateArpPacket(srcHw, srcIp, ipv4_header.dst)
                            net.send_packet(SendFromIntf, ArpReqPkt)
                        
                            # Put the packet in Queue and Send when we get arp Reply
                            q.put(pkt)
    
                    if pktDest == False:
                        log_debug("Drop the packet as in do not do anything.")


def switchy_main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    #Build a Forwarding Table
    # 1) Read from forwarding_table.txt and build Routing Table:
    # 2) Through a call to net.interfaces()
    cmd = os.getcwd()
    log_debug("Current cmd: {}".format(cmd))
    my_interfaces = net.interfaces()

    forwardingTableFile = open("/home/vincent/Private/CS640/p2/switchyard-master/forwarding_table.txt",'r')
    for line in forwardingTableFile:
        line = line.replace('\n','')
        NetDest, NetMask, GateWay, Intf = line.split()
        NetConcat = NetDest + '/' + NetMask
        netaddr = IPv4Network(NetConcat)
        AddEntry = forwardingTableClass(NetDest, NetMask, GateWay, Intf, netaddr.prefixlen)
        forwardingTable.append(AddEntry)
        log_info("Added the entry as NetDest {} NetMask {} Gateway {} on Interface {} Prefixlen {}".format(NetDest, NetMask, GateWay, Intf, netaddr.prefixlen))

    # Get the Router Interfaces IP and add in forwarding table.
    for intf in my_interfaces:
        NetDest = intf.ipaddr
        mask = IPv4Address('255.255.255.0')
        NetDest = str(IPv4Address(int(NetDest) & int(mask)))
        NetMask = str(intf.netmask)
        # Putting Gateway as self IP as of now. Use Router Interface to forward packets.
        NetConcat = NetDest + '/' + NetMask
        netaddr = IPv4Network(NetConcat)
        AddEntry = forwardingTableClass(NetDest, NetMask, NetDest, intf.name, netaddr.prefixlen)
        forwardingTable.append(AddEntry)
        log_info("Added the entry as NetDest {} NetMask {} Gateway {} on Interface {} Prefixlen {}".format(NetDest, NetMask, NetDest, intf.name, netaddr.prefixlen))


    r = Router(net)
    r.router_main(net)
    net.shutdown()
