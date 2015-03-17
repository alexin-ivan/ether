#!/usr/bin/env python
# -*- coding: utf-8 -*-
#

##############################################################################
from cether.pckttools import PcapDevice, PacketParser  # , AccessPoint, Station
from time import sleep
from multi_graph import MultiGraph
#import logging
##############################################################################


class Callback(object):

    def __init__(self, f):
        self.__subs = [f]

    def subscribe(self, f):
        self.__subs.append(f)

    def unsubscribe(self, f):
        self.__subs.remove(f)

    def __call__(self, x):
        for f in self.__subs:
            yield f(x)


##############################################################################


class NetworkGraph(object):
    def __init__(self, iface=None):

        self.pkt_callback = Callback(self.pkt_callback)
        self.mgraph = MultiGraph()

        args = dict(
            g=self.mgraph,
            new_ap_callback=self.ap_callback,
            new_station_callback=self.sta_callback,
            new_keypckt_callback=self.keypckt_callback,
            new_auth_callback=self.auth_callback,
            new_pkt_callback=self.pkt_callback,
            new_stop_parsing_callback=self.stop_callback,
        )

        self.packetParser = PacketParser(
            **args
        )

        self.iface = iface
        self.pcapDevice = None
        self.fStop = False
        self.fStoped = True

    def getAPs(self):
        return self.mgraph.getAPs()

    def open(self, iface=None):
        if iface is None:
            iface = self.iface
        assert(iface is not None)
        self.iface = iface
        self.pcapDevice = PcapDevice()
        self.pcapDevice.open_live(self.iface.open())

    def close(self):
        if self.iface:
            self.stop()
            self.pcapDevice.close()
            self.pcapDevice = None
            self.iface.close()

    def parse(self):
        assert(self.pcapDevice)
        self.packetParser.parse_pcapdevice(self.pcapDevice)
        self.fStoped = True
        self.fStop = False

    def stop(self):
        self.fStop = True
        sleep(1)

    def _update(self, needUpdate):
        if needUpdate:
            self.update_graph_callback()

    def ap_callback(self, ap):
        self._update(self.mgraph.addAP(ap))

    def sta_callback(self, sta):
        self._update(self.mgraph.addSta(sta))

    def keypckt_callback(self, i):
        sta, idx, pkt = i
        self._update(self.mgraph.addKeypkt(sta, idx, pkt))

    def auth_callback(self, i):
        sta, auth = i
        self._update(self.mgraph.addAuth(sta, auth))

    def pkt_callback(self, i):
        self._update(self.mgraph.addPacket(i))

    def stop_callback(self, pkt):
        return self.fStop

    def update_graph_callback(self, name):
        raise NotImplementedError

    def getNxGraph(self):
        return self.mgraph.getNxGraph()
