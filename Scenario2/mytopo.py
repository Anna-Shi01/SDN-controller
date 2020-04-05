'''
    EE 555 Project
    Xiaotian Jiang 5456076864
    Ziran Shi  6548299525

    Three hosts h1 h2 h3 connect to switch s1.
    Three hosts don't have links with each other but only with the switch.
    Each host is configured with a subnet, IP, gateway and netmask.
'''
from mininet.topo import Topo


class Scenario2_Topo(Topo):

    def __init__(self):
        "Create custom topo."
        # Initialize topology

        Topo.__init__(self)

    # Add hosts and switches

        Host1 = self.addHost('h1', ip="10.0.1.100/24", defaultRoute="via 10.0.1.1")
        Host2 = self.addHost('h2', ip="10.0.2.100/24", defaultRoute="via 10.0.2.1")
        Host3 = self.addHost('h3', ip="10.0.3.100/24", defaultRoute="via 10.0.3.1")

        Switch = self.addSwitch('s1')

    # Add links
        self.addLink(Host1, Switch)
        self.addLink(Host2, Switch)
        self.addLink(Host3, Switch)


topos = {'mytopo': (lambda: Scenario2_Topo())}
