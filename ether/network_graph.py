#!/usr/bin/env python
# -*- coding: utf-8 -*-
#

##############################################################################
from cether.pckttools import PcapDevice, PacketParser  # , AccessPoint, Station
from time import sleep
from multi_graph import MultiGraph, Center, Node
import logging
##############################################################################


class NetworkGraph(object):
    def __init__(self, iface=None):

        callbacks = dict(
            new_ap_callback=self.ap_callback,
            new_station_callback=self.sta_callback,
            new_keypckt_callback=self.keypckt_callback,
            new_auth_callback=self.auth_callback,
            new_pkt_callback=self.pkt_callback,
            new_stop_parsing_callback=self.stop_callback,
        )

        self.packetParser = PacketParser(
            **callbacks
        )

        self.iface = iface
        self.pcapDevice = PcapDevice()
        self.fStop = False
        self.fStoped = True

        self.mgraph = MultiGraph()

    def getGraphs(self):
        return self.mgraph.graphs

    def open(self, iface=None):
        if iface is None:
            iface = self.iface
        assert(iface is not None)
        self.iface = iface
        self.pcapDevice.open_live(self.iface.open())

    def close(self):
        if self.iface:
            self.stop()
            self.pcapDevice.close()
            self.iface.close()

    def parse(self):
        self.packetParser.parse_pcapdevice(self.pcapDevice)
        self.fStoped = True
        self.fStop = False

    def stop(self):
        self.fStop = True
        sleep(1)

    def ap_callback(self, ap):
        exists = self.mgraph.getGraph(Center(ap))
        if exists is None:
            g = self.mgraph.addGraph(Center(ap))
            self.update_graph_callback(g.key())

    def sta_callback(self, sta):
        ap = self.mgraph.getGraph(Center(sta.ap))
        if ap is None:
            logging.debug('add station for ap: %s; MAC: %s', sta.ap, sta.mac)
            self.ap_callback(sta.ap)
            ap = self.mgraph.getGraph(Center(sta.ap))
            if ap is None:
                for k in self.mgraph.graphs.keys():
                    print '\t', k.key()
        ap.addNode(Node(sta))
        self.update_graph_callback(ap.key())

    def keypckt_callback(self, i):
        sta, idx, pkt = i
        self.mgraph.addEdgeInfoKeypkt(Node(sta), idx, pkt)
        ap = self.mgraph.getGraph(Center(sta.ap))
        assert(ap)
        self.update_graph_callback(ap.key())

    def auth_callback(self, i):
        sta, auth = i
        self.mgraph.addEdgeInfoAuth(Node(sta), auth)
        ap = self.mgraph.getGraph(Center(sta.ap))
        assert(ap)
        self.update_graph_callback(ap.key())

    def pkt_callback(self, i):
        self.mgraph.addEdgeInfoAny(i)

    def stop_callback(self, pkt):
        return self.fStop

    def update_graph_callback(self, name):
        raise NotImplementedError
