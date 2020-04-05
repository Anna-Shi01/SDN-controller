"""
    EE 555 Project
	Xiaotian Jiang 5456076864
    Ziran Shi  6548299525

	This is a custom router that can support:
	ARP
	Static Routing
	ICMP

"""

from pox.core import core
import pox.openflow.libopenflow_01 as of

from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
import pox.lib.addresses as adr
from pox.lib.packet.icmp import icmp
import pox.lib.packet as pkt
from pox.lib.addresses import IPAddr, EthAddr

import struct

log = core.getLogger()


class Router(object):
    def __init__(self, connection):
        log.debug('router registered')
        self.connection = connection

        # This binds our PacketIn event listener
        connection.addListeners(self)
        # import Ethernet Address
        self.ethernetAddress = ["10.0.1.1", "10.0.2.1", "10.0.3.1"]

        # clear ARP tabl, each cell has IP corresponding to MAC address
        self.arpTable = {}

        # clear routing table, each cell has IP corresponding to port
        self.routingTable = {'10.0.1.0/24': ['10.0.1.100', 's1-eth1', '10.0.1.1', 1],
                             '10.0.2.0/24': ['10.0.2.100', 's1-eth2', '10.0.2.1', 2],
                             '10.0.3.0/24': ['10.0.3.100', 's1-eth3', '10.0.3.1', 3]}

        # clear connection
        self.connections = {}

        # clear ARP waiting line
        self.cache = None

        # store IP to port and IP to MAC
        self.mac_to_port = {}
        self.ip_to_port = {}

        # add my self as listener in openflow
        core.openflow.addListeners(self)

    def send_reply_based_on_arp_response(self, a, packet_in):
        routing = pkt.arp(hwtype=a.hwtype, prototype=a.prototype, hwlen=a.hwlen, protolen=a.protolen,
                          opcode=pkt.arp.REPLY,
                          hwdst=a.hwsrc, protodst=a.protosrc, protosrc=a.protodst,
                          hwsrc=adr.EthAddr('EF:EF:EF:EF:EF:EF'))

        etherneting = ethernet(type=pkt.ethernet.ARP_TYPE, src=adr.EthAddr('EF:EF:EF:EF:EF:EF'), dst=a.hwsrc)
        etherneting.set_payload(routing)
        msg = of.ofp_packet_out()
        msg.data = etherneting.pack()
        action = of.ofp_action_output(port=packet_in.in_port)
        msg.actions.append(action)
        self.connection.send(msg)
        log.debug('Sent an ARP reply based on response')

    def send_arp_request(self, port_num, packet, packet_in):
        routing = arp(hwlen=6, hwdst=ETHER_BROADCAST, protodst=packet.payload.dstip,
                      hwsrc=adr.EthAddr('EF:EF:EF:EF:EF:EF'), protosrc=packet.next.srcip)
        routing.hwtype = routing.HW_TYPE_ETHERNET
        routing.prototype = routing.PROTO_TYPE_IP
        routing.protolen = routing.protolen
        routing.opcode = routing.REQUEST
        etherneting = ethernet(type=ethernet.ARP_TYPE, src=adr.EthAddr('EF:EF:EF:EF:EF:EF'), dst=ETHER_BROADCAST)
        etherneting.set_payload(routing)
        msg = of.ofp_packet_out()
        msg.data = etherneting.pack()
        msg.actions.append(of.ofp_action_output(port=port_num))
        msg.in_port = packet_in.in_port
        self.connection.send(msg)
        log.debug("Send an ARP request based on port number")

    def send_arp(self, packet):
        subnetmask = 0
        for key in self.routingTable.keys():
            if str(packet.payload.dstip) in self.routingTable[key]:
                subnetmask = key
        self.install_flow(packet, subnetmask)
        log.debug('Send arp')

    def icmp_cannot_reach_destination(self, packet, packet_in):
        unreach = pkt.unreach()
        unreach.payload = packet.payload
        reply = pkt.icmp()
        reply.type = pkt.TYPE_DEST_UNREACH
        reply.payload = unreach
        log.debug("The destination cannot be reached by ICMP")
        self.send_icmp(reply, packet, packet_in)

    def icmp_echo_reply(self, icmp_data, packet, packet_in):
        icmp_echo = pkt.echo(seq=icmp_data.payload.seq + 1, id=icmp_data.payload.id)
        icmp_reply = pkt.icmp(type=pkt.TYPE_ECHO_REPLY, payload=icmp_echo)
        log.debug("The router get request as ICMP echo reply")
        self.send_icmp(icmp_reply, packet, packet_in)

    def send_icmp(self, icmp_reply, packet, packet_in):
        packet_payload = packet.payload
        ip_packet = pkt.ipv4(srcip=packet_payload.dstip, dstip=packet_payload.srcip, protocol=pkt.ipv4.ICMP_PROTOCOL,
                             payload=icmp_reply)
        etherneting = pkt.ethernet(type=pkt.ethernet.IP_TYPE, src=packet.dst, dst=packet.src, payload=ip_packet)
        msg = of.ofp_packet_out()
        msg.data = etherneting.pack()
        # Add an action to send to the specified port
        msg.actions.append(of.ofp_action_output(port=packet_in.in_port))
        # Send message to switch
        self.connection.send(msg)
        log.debug("Send ICMP reply")

    def install_flow(self, packet, networkmask):
        msg = of.ofp_packet_out()
        action = of.ofp_action_output(port=self.routingTable[networkmask][3])

        packet.src = adr.EthAddr('EF:EF:EF:EF:EF:EF')
        packet.dst = self.arpTable[packet.payload.dstip]
        msg.data = packet.pack()
        msg.actions.append(action)
        self.connection.send(msg)
        log.debug("Send message through flow")

        msg = of.ofp_flow_mod()
        msg.match.nw_dst = packet.payload.dstip
        msg.match.dl_type = 0x800

        msg.actions.append(of.ofp_action_dl_addr.set_src(packet.src))
        msg.actions.append(of.ofp_action_dl_addr.set_dst(packet.dst))
        msg.actions.append(of.ofp_action_output(port=self.routingTable[networkmask][3]))
        log.debug("Send flow successfully")
        self.connection.send(msg)

    # this function is for handling incoming packets
    def act_like_router(self, packet, packet_in):
        if packet.type == pkt.ethernet.ARP_TYPE:
            log.debug('This is an ARP packet')
            if packet.payload.opcode == arp.REQUEST and packet.payload.protodst in self.ethernetAddress:
                log.debug('This is an ARP request and reply it')
                self.send_reply_based_on_arp_response(packet.payload, packet_in)
            elif packet.payload.opcode == arp.REPLY:
                log.debug('This is an ARP reply and process it')
                self.arpTable[packet.next.protosrc] = packet.src
                log.debug('The arp table is ' + str(self.arpTable))
                self.send_arp(self.cache[0])
                self.cache = None
            else:
                log.debug('This is an error ARP packet and drop it')

        if packet.type == pkt.ethernet.IP_TYPE:
            networkmask = 0
            for key in self.routingTable.keys():
                if packet.payload.dstip.inNetwork(key):
                    networkmask = key
                    break
            if networkmask == 0:
                log.debug('We cannot reach destination network and we can generate ICMP destination unreachable message')
                self.icmp_cannot_reach_destination(packet, packet_in)

            elif packet.payload.protocol == pkt.ipv4.ICMP_PROTOCOL:
                icmp_data = packet.payload.payload

                if icmp_data.type == pkt.TYPE_ECHO_REQUEST and packet.payload.dstip in self.ethernetAddress:
                    log.debug('ICMP received')
                    self.icmp_echo_reply(icmp_data, packet, packet_in)

                elif packet.payload.dstip not in self.arpTable.keys():
                    log.debug('Cache it')
                    self.cache = (packet, packet_in)
                    log.debug('Find port number based on the routing table')
                    port_num = self.routingTable[networkmask][3]
                    log.debug('Send arp request')
                    self.send_arp_request(port_num, packet, packet_in)

                elif packet.payload.dstip in self.arpTable.keys():
                    self.install_flow(packet, networkmask)
            else:
                log.debug("The packet contains IPv4")
                if networkmask != 0:
                    # self.send_ipv4(networkmask, packet)
                    # send_ipv4
                    dst_port_number = self.routingTable[networkmask][3]
                    msg = of.ofp_packet_out()
                    action = of.ofp_action_output(port=dst_port_number)
                    packet.dst = adr.EthAddr('EF:EF:EF:EF:EF:EF')
                    packet.src = adr.EthAddr('EF:EF:EF:EF:EF:EF')

                    msg.data = packet.pack()
                    msg.actions.append(action)
                    self.connection.send(msg)
                    log.debug("Send IPv4 successfully")

                    msg = of.ofp_flow_mod()
                    msg.match.nw_dst = packet.payload.dstip
                    msg.match.dl_type = 0x800
                    msg.actions.append(of.ofp_action_dl_addr.set_src(adr.EthAddr('EF:EF:EF:EF:EF:EF')))
                    msg.actions.append(of.ofp_action_dl_addr.set_dst(adr.EthAddr('EF:EF:EF:EF:EF:EF')))
                    msg.actions.append(of.ofp_action_output(port=dst_port_number))
                    log.debug("Send Flow successfully")
                    self.connection.send(msg)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            log.error("This is an incomplete packet")
            return
        packet_in = event.ofp
        self.act_like_router(packet, packet_in)


def launch():
    def start_switch(event):
        log.debug("Controlling %s" % (event.connection))
        Router(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
