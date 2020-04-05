'''
    EE 555 Project
    Xiaotian Jiang 5456076864
    Ziran Shi  6548299525

    Three hosts h1 h2 h3 connect to switch s1.
    Three hosts don't have links with each other but only with the switch.
    Each host is configured with a subnet, IP, gateway and netmask.
'''
from mininet.topo import Topo


class Scenario4_Topo(Topo):

    def __init__(self):
        "Create custom topo."
        # Initialize topology

        Topo.__init__(self)

    # Add hosts and switches

        Host4 = self.addHost('h4', ip="10.0.1.100/24", defaultRoute="via 10.0.1.1")
        Host5 = self.addHost('h5', ip="10.0.2.100/24", defaultRoute="via 10.0.2.1")
        Host6 = self.addHost('h6', ip="10.0.3.100/24", defaultRoute="via 10.0.3.1")
        Host7 = self.addHost('h7', ip="10.0.4.100/24", defaultRoute="via 10.0.4.1")
        Host8 = self.addHost('h8', ip="10.0.5.100/24", defaultRoute="via 10.0.5.1")
        Host9 = self.addHost('h9', ip="10.0.6.100/24", defaultRoute="via 10.0.6.1")
        Host10 = self.addHost('h10', ip="10.0.7.100/24", defaultRoute="via 10.0.7.1")
        Host11 = self.addHost('h11', ip="10.0.8.100/24", defaultRoute="via 10.0.8.1")
        Host12 = self.addHost('h12', ip="10.0.9.100/24", defaultRoute="via 10.0.9.1")

        Switch1 = self.addSwitch('s1')
        Switch2 = self.addSwitch('s2')
        Switch3 = self.addSwitch('s3')

    # Add links
        self.addLink(Host4, Switch1)
        self.addLink(Host5, Switch1)
        self.addLink(Host6, Switch1)
        self.addLink(Host7, Switch2)
        self.addLink(Host8, Switch2)
        self.addLink(Host9, Switch2)
        self.addLink(Host10, Switch3)
        self.addLink(Host11, Switch3)
        self.addLink(Host12, Switch3)
        self.addLink(Switch1, Switch2)
        self.addLink(Switch2, Switch3)
        self.addLink(Switch1, Switch3)


topos = {'looptopo': (lambda: Scenario4_Topo())}
