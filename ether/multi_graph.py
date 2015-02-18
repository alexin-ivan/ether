#!/usr/bin/env python
# -*- coding: utf-8 -*-
#

##############################################################################
import logging
import netaddr
import scapy.all
##############################################################################

BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff'


# To DS     From DS     Address 1   Address 2   Address 3   Address 4
# 0         0           RcA=DstA    TrA=SrcA    BSSID       N/A
# 0         1           RcA=DstA    TrA=BSSID   SrcA        N/A
# 1         0           RcA=BSSID   TrA=SA      DstA        N/A
# 1         1           RcA         TrA         DstA        SrcA
# A data frame direct from one STA to another STA within the same IBSS,
#       as well as all management and control type frames.
# Data frame exiting the DS.
# Data frame destined for the DS.
# Wireless distribution system (WDS) frame being distributed
#       from one AP to another AP.


def getAddresses(pkt):

    f = pkt.FCfield & 3  # to-DS and from-DS

    #adrs_dict = {
        #0: ('dst', 'src', 'bssid', None),  # from sta to sta
        #1: ('dst', 'bssid', 'src', None),  # out of ds
        #2: ('bssid', 'src', 'dst', None),  # in ds
        #3: ('recv', 'transl', 'dst', 'src')   # between dss
    #}

    if f == 0:
        adrs = ('destination', 'source', 'bssid', None)
    elif f == 1:
        adrs = ('bssid', 'source', 'destination', None)
    elif f == 2:
        adrs = ('destination', 'bssid', 'source', None)
    else:
        adrs = (None, 'bssid', 'destination', 'source')

    pktAddrs = (pkt.addr1, pkt.addr2, pkt.addr3, pkt.addr4)

    class Dummy:
        def __init__(self, *pargs, **kwargs):
            self.__dict__.update(kwargs)

    kw = dict(zip(adrs, pktAddrs))
    del kw[None]

    r = Dummy(**kw)
    r.f = f
    return r


def parseMac(mac):
    try:
        mac_ = netaddr.EUI(mac)
        oui = mac_.oui
        ei = mac_.ei
        result = oui.registration()['org'], ei
    except netaddr.core.NotRegisteredError:
        result = ("Unknown", None)
    return result


class Node(object):

    def __init__(self, sta):
        self.sta = sta

    def key(self):
        return self.sta.mac

    def name(self):
        return self.sta.mac.replace(':', '-')

    def parseMac(self):
        return parseMac(self.sta.mac)

    def addSelfPacket(self, pkt):
        pass


class Edge(object):
    def __init__(self):
        self.pktCount = 0
        self.keypktCount = 0
        self.fAuth = None

    def addPacket(self, pkt):
        self.pktCount += 1

    def addReversePacket(self, pkt):
        self.pktCount += 1

    def addKeyPacket(self, pkt, idx):
        self.keypktCount += 1

    def getInfo(self):
        return (self.pktCount, self.keypktCount, self.fAuth)

    def authStatus(self):
        if self.keypktCount == 4:
            return 'Normal'
        if self.keypktCount == 2:
            return 'Half'


class Essid(object):
    def __init__(self, essid):
        self.s = essid

    def normalize(self):
        try:
            tmp = str(self.s)
            tmp.encode('utf-8')
            tmp.decode('utf-8')
        except UnicodeDecodeError:
            tmp = self.decode('cp1251')

        return tmp


class Center(object):
    def __init__(self, ap):
        self.ap = ap

    def name(self):
        return self.ap.mac.replace(':', '-')

    def hName(self):
        if self.ap.essid:
            s = Essid(self.ap.essid)
            return s.normalize()
        else:
            return "<Unamed>"

    def essid(self):
        return self.ap.essid

    def key(self):
        return self.ap.mac

    def parseMac(self):
        return parseMac(self.ap.mac)


class Graph(object):

    def __init__(self, center):
        self.center = center
        self.stations = []
        self.edges = {}
        self.pCount = 0

    def addNode(self, sta):
        if sta not in self.stations:
            self.stations.append(sta)
            edge = Edge()
            self.edges[sta.key()] = edge

    def addSelfPacket(self, pkt):
        self.pCount += 1

    def addPacket(self, sta, pkt):
        edge = self.edges.get(sta.key())
        assert(edge)
        edge.addPacket(pkt)
        self.pCount += 1

    def key(self):
        return self.center.key()

    def name(self):
        return self.center.name()

    def hName(self):
        return self.center.hName()

    def essid(self):
        return self.center.essid()

    def nodes(self):
        for sta in self.stations:
            edge = self.edges[sta.key()]
            yield (sta, edge)

    def parseMac(self):
        return self.center.parseMac()


class MultiGraph(object):
    def __init__(self):
        self.graphs = {}

    def getGraphs(self):
        return self.graphs.keys()

    def addGraph(self, center):
        graph = Graph(center)
        self.graphs[center.key()] = graph
        return graph

    def getGraph(self, center):
        return self.graphs.get(center.key())

    def getEdge(self, sta_mac):
        for i in self.graphs.iteritems():
            centerID, graph = i
            for n, e in graph.nodes():
                if n.key() == sta_mac:
                    yield (n, e)

    def getEdgeCmp(self, f):
        for i in self.graphs.iteritems():
            centerID, graph = i
            for n, e in graph.nodes():
                res = f(centerID, n, e)
                if res is not None:
                    yield res

    def addEdgeInfoKeypkt(self, sta, idx, pkt):
        for n, e in self.getEdge(sta):
            e.addKeyPacket(pkt, idx)

    def addEdgeInfoAuth(self, sta, auth):
        logging.debug('<<<<<<<<AUTH>>>>>>>>>')
        for n, e in self.getEdge(sta):
            e.fAuth = auth

    def addEdgeInfoAny(self, pkt):
        ra = getAddresses(pkt)
        sta_mac = ra.destination
        if sta_mac == BROADCAST_MAC:
            return

        adrs = [pkt.addr1, pkt.addr2, pkt.addr3, pkt.addr4]

        def fCmp(ap_mac, sta, e):
            sta_mac = sta.key()
            if ap_mac == ra.bssid \
               and ap_mac == ra.bssid \
               and sta_mac == ra.destination:
                return (ap_mac, sta, 0, e)
            elif ap_mac == ra.bssid \
                    and ap_mac == ra.destination \
                    and sta_mac == ra.source:
                return (ap_mac, sta, 1, e)

            if adrs[0] == ap_mac and all([(i is None) for i in adrs[1:]]):
                return (ap_mac, None, 0, None)
            if adrs[0] == sta_mac and all([(i is None) for i in adrs[1:]]):
                return (None, sta, 1, None)

            return None

        r = filter(lambda x: x is not None, list(self.getEdgeCmp(fCmp)))
        for c, n, d, e in r:
            if e:
                if d == 0:
                    e.addPacket(pkt)
                elif d == 1:
                    e.addReversePacket(pkt)
            elif n is None:
                self.graphs[c].addSelfPacket(pkt)
            elif c is None and d == 1:
                n.addSelfPacket(pkt)

        if not r:
            logging.debug("Cant find staions: %s, %s", pkt.summary(), str(ra.__dict__))

    def getGraphByName(self, key):
        return self.graphs.get(key)
