#!/usr/bin/env python
# -*- coding: utf-8 -*-
#

##############################################################################
import logging
import netaddr
import cether.pckttools as pckttools
import networkx
#import scapy.all
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
    """
        0: ('dst', 'src', 'bssid', None),   from sta to sta
        1: ('dst', 'bssid', 'src', None),   out of ds
        2: ('bssid', 'src', 'dst', None),   in ds
        3: ('recv', 'transl', 'dst', 'src')  between dss
    """
    f = pkt.FCfield & 3  # to-DS and from-DS

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


class Station(pckttools.Station):
    pass


class AccessPoint(pckttools.AccessPoint):
    pass


#class Node(object):

    #def __init__(self, g, mac, **kwargs):
        #self.mac = mac
        #self.g = g
        #for k, v in kwargs.iteritems():
            #self.g[k] = v

    #def name(self):
        #return self.mac.replace(':', '-')

    #def parseMac(self):
        #return parseMac(self.mac)

    #def __str__(self):
        #return parseMac(self.mac)

class Node(object):
    def __init__(self, **kwargs):
        self.__dict__.update(**kwargs)


class Edge(object):

    def getPktCount(self):
        return self.g['pktCount']

    def setPckCount(self, v):
        self.g['pktCount'] = v

    pktCount = property(getPktCount, setPckCount)

    def __init__(self, g, **kwargs):
        self.g = g
        self.pktCount = 0
        self.keypktCount = 0
        self.fAuth = None

        for k, v in kwargs.iteritems():
            self.g[k] = v

    def addPacket(self, pkt):
        self.pktCount += 1

    def addReversePacket(self, pkt):
        self.pktCount += 1

    def addKeyPacket(self, pkt, idx):
        self.keypktCount += 1

    def getInfo(self):
        return (self.pktCount, self.keypktCount, self.fAuth)


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


def getNormalName(mac):
    return mac.replace(':', '-')


def getNormalEssid(essid):
    if essid:
        s = Essid(essid)
        return s.normalize()
    else:
        return "Unamed"


class MultiGraph(object):
    def __init__(self):
        self.g = networkx.DiGraph()
        self.logger = logging.getLogger('MultiGraph')

    def addAP(self, ap):
        if ap.mac in self.g:
            return

        nMac = getNormalName(ap.mac)
        nEssid = getNormalEssid(ap.essid)
        vendor = parseMac(ap.mac)
        logging.debug('Found ap: %s', ap.mac)

        self.g.add_node(
            ap.mac,
            mac=ap.mac,
            nEssid=nEssid,
            essid=ap.essid,
            nMac=nMac,
            vendor=vendor,
            label="AP: %s '%s'" % (nMac, nEssid),
            nType='AP'
        )
        return ap.mac

    def addSta(self, sta):
        if sta.mac in self.g:
            return

        nMac = getNormalName(sta.mac)
        vendor = parseMac(sta.mac)
        logging.debug('Found sta: %s', sta.mac)
        self.g.add_node(
            sta.mac,
            mac=sta.mac,
            nMac=nMac,
            vendor=vendor,
            label='STA: %s' % nMac,
            nType='STA'
        )
        if sta.ap:
            u_mac = sta.ap.mac
            v_mac = sta.mac
            if u_mac not in self.g.nodes():
                self.addAP(sta.ap)
            self.g.add_edge(
                u_mac,
                v_mac,
                label='"Unknown"',
                color="red"
            )

        return sta.mac

    def addKeypkt(self, sta, idx, pkt):
        logging.debug('Keypkt: %s', sta.mac)
        #raise NotImplementedError

    def addAuth(self, sta, auth):
        logging.debug('Auth: %s', sta.mac)
        #raise NotImplementedError

    def addPacket(self, pkt):
        ra = getAddresses(pkt)
        sta_mac = ra.destination
        if sta_mac == BROADCAST_MAC:
            return
        #raise NotImplementedError

    def getNxGraph(self):
        return self.g

    def getAPs(self):
        aps = []
        for ix in self.g.nodes():
            n = self.g.node[ix]
            if n.get('nType') == 'AP':
                aps.append(n)

        return sorted(aps, key=lambda x: x['mac'])

#class Graph(object):

    #def __init__(self, center):
        #self.center = center
        #self.stations = {}
        #self.edges = []
        #self.pCount = 0

    #def addNode(self, sta_mac):
        #if sta_mac not in self.stations:
            #station = Station(sta_mac)
            #self.stations[sta_mac] = station
            #edge = Edge(self.center, station)
            #self.edges.append(edge)

    #def addEdge(self, v_mac, u_mac):

        #if v_mac == self.center and u_mac not in self.stations:
            #return self.addNode(u_mac)

        #if v_mac not in self.stations and u_mac == self.center:
            #return self.addNode(v_mac)

        #vStation = Station(v_mac)
        #uStation = Station(u_mac)

        #self.stations[v_mac] = vStation
        #self.stations[u_mac] = uStation

        #edge = Edge(vStation, uStation)

        #self.edges.append(edge)

    #def addSelfPacket(self, pkt):
        #self.pCount += 1

    #def addPacket(self, sta, pkt):
        #edge = self.edges.get(sta.key())
        #assert(edge)
        #edge.addPacket(pkt)
        #self.pCount += 1

    #def key(self):
        #return self.center.key()

    #def name(self):
        #return self.center.name()

    #def hName(self):
        #return self.center.hName()

    #def essid(self):
        #return self.center.essid()

    #def getEdgesForNode(self, node):
        #pass


    #def nodes(self):
        #for sta in self.stations.values():
            #edge = self.getEdgesForNode(sta)
            #yield (sta, edge)

    #def parseMac(self):
        #return self.center.parseMac()


#class MultiGraph(object):
    #def __init__(self):
        #self.graphs = {}

    #def getGraphs(self):
        #return self.graphs.keys()

    #def addGraph(self, center):
        #graph = Graph(center)
        #self.graphs[center.key()] = graph
        #return graph

    #def getGraph(self, center):
        #return self.graphs.get(center.key())

    #def getEdge(self, sta_mac):
        #for i in self.graphs.iteritems():
            #centerID, graph = i
            #for n, e in graph.nodes():
                #if n.key() == sta_mac:
                    #yield (n, e)

    #def getEdgeCmp(self, f):
        #for i in self.graphs.iteritems():
            #centerID, graph = i
            #for n, e in graph.nodes():
                #res = f(centerID, n, e)
                #if res is not None:
                    #yield res

    #def addEdgeInfoKeypkt(self, sta, idx, pkt):
        #for n, e in self.getEdge(sta):
            #e.addKeyPacket(pkt, idx)

    #def addEdgeInfoAuth(self, sta, auth):
        #logging.debug('<<<<<<<<AUTH>>>>>>>>>')
        #for n, e in self.getEdge(sta):
            #e.fAuth = auth

    #def addEdgeInfoAny(self, pkt):
        #ra = getAddresses(pkt)
        #sta_mac = ra.destination
        #if sta_mac == BROADCAST_MAC:
            #return

        #adrs = [pkt.addr1, pkt.addr2, pkt.addr3, pkt.addr4]

        #def fCmp(ap_mac, sta, e):
            #sta_mac = sta.key()
            #if ap_mac == ra.bssid \
               #and ap_mac == ra.bssid \
               #and sta_mac == ra.destination:
                #return (ap_mac, sta, 0, e)
            #elif ap_mac == ra.bssid \
                    #and ap_mac == ra.destination \
                    #and sta_mac == ra.source:
                #return (ap_mac, sta, 1, e)

            #if adrs[0] == ap_mac and all([(i is None) for i in adrs[1:]]):
                #return (ap_mac, None, 0, None)
            #if adrs[0] == sta_mac and all([(i is None) for i in adrs[1:]]):
                #return (None, sta, 1, None)

            #return None

        #r = filter(lambda x: x is not None, list(self.getEdgeCmp(fCmp)))
        #for c, n, d, e in r:
            #if e:
                #if d == 0:
                    #e.addPacket(pkt)
                #elif d == 1:
                    #e.addReversePacket(pkt)
            #elif n is None:
                #self.graphs[c].addSelfPacket(pkt)
            #elif c is None and d == 1:
                #n.addSelfPacket(pkt)

        #if not r:
            #if ra.f == 1L:
                #lan_mac = ra.destination
                #sta_mac = ra.source
                #ap_mac = ra.bssid
                #for imac in self.graphs.keys():
                    #if imac == ap_mac:
                        #g = self.graphs[ap]
                        #g.addOutDsEdge(sta_mac, lan_mac)



            #logging.debug("Cant find staions: %s, %s", pkt.summary(),
            #str(ra.__dict__))

    #def getGraphByName(self, key):
        #return self.graphs.get(key)
