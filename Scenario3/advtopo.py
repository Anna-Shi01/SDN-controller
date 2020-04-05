"""Custom topology example

    EE 555 Project
	Xiaotian Jiang 5456076864
    Ziran Shi  6548299525

"""

from mininet.topo import Topo


class Scenario3_AdvanceTopo(Topo):
    "Simple topology example."

    def __init__(self):
        "Create custom topo."

        # Initialize topology
        Topo.__init__(self)

        # Add hosts and switches
        Host3 = self.addHost('h3', ip="10.0.1.2/24", defaultRoute="via 10.0.1.1")
        Host4 = self.addHost('h4', ip="10.0.1.3/24", defaultRoute="via 10.0.1.1")
        Host5 = self.addHost('h5', ip="10.0.2.2/24", defaultRoute="via 10.0.2.1")

        Switch1 = self.addSwitch('s1')
        Switch2 = self.addSwitch('s2')

        # Add links
        self.addLink(Host3, Switch1)
        self.addLink(Host4, Switch1)
        self.addLink(Host5, Switch2)
        self.addLink(Switch1, Switch2)


topos = {'advtopo': (lambda: Scenario3_AdvanceTopo())}
