
from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()



class Tutorial (object):
  """
  A Tutorial object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

    # Use this table to keep track of which ethernet address is on
    # which switch port (keys are MACs, values are ports).
    self.mac_to_port = {}
    self.dpid = connection.dpid
    self.flow = {}


  def resend_packet (self, packet_in, out_port):
    """
    Instructs the switch to resend a packet that it had sent to us.
    "packet_in" is the ofp_packet_in object the switch had sent to the
    controller due to a table-miss.
    """
    msg = of.ofp_packet_out()
    msg.data = packet_in

    # Add an action to send to the specified port
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)

    # Send message to switch
    self.connection.send(msg)


  def act_like_hub (self, packet, packet_in):
    """
    Implement hub-like behavior -- send all packets to all ports besides
    the input port.
    """

    # We want to output to all ports -- we do that using the special
    # OFPP_ALL port as the output port.  (We could have also used
    # OFPP_FLOOD.)
    self.resend_packet(packet_in, of.OFPP_ALL)

    # Note that if we didn't get a valid buffer_id, a slightly better
    # implementation would check that we got the full data before
    # sending it (len(packet_in.data) should be == packet_in.total_len)).


  def act_like_switch (self, packet, packet_in):
    if packet.src not in self.mac_to_port:
        self.mac_to_port[packet.src] = packet_in.in_port
        log.debug("The port number is not in the mapping")


    if packet.dst in self.mac_to_port:
        self.resend_packet(self,packet_in, self.mac_to_port[packet.dst])

        log.debug("Switch %d gets port number from %d " % (self.dpid, self.mac_to_port[packet.dst]))

        if packet.dst not in self.flow:
            msg = of.ofp_flow_mod()
            msg.match = of.ofp_match.from_packet(packet)

            action = of.ofp_action_output(port = self.mac_to_port[packet.dst])
            msg.actions.append(action)
            self.connection.send(msg)
            self.flow[packet.dst] = self.mac_to_port[packet.dst]
            log.debug('Switch %d is adding the destination of IP %s and port number %d' % (self.dpid, packet.dst, self.mac_to_port[packet.dst]))
    else:
        log.debug("Let's flood from Switch %d" % (self.dpid))
        self.resend_packet(packet_in,of.OFPP_ALL)


  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.

    # Comment out the following line and uncomment the one after
    # when starting the exercise.
    #self.act_like_hub(packet, packet_in)
    log.debug('Switch %d is trying to send packet from %s to %s' % (self.dpid, packet.src, packet.dst))
    self.act_like_switch(packet, packet_in)



def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Tutorial(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
