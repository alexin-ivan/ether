#!/usr/bin/env python
# -*- coding: utf-8 -*-
#

##############################################################################
#from packet_parser import PacketParser
#from cpyrit.pckttools import PcapDevice  # , AccessPoint, Station
#from monitor import Monitor
#from time import sleep
#from MultiGraph import MultiGraph
from network_graph import NetworkGraph
from qparser import QParser
from PyQt4.QtCore import QObject, pyqtSignal
##############################################################################


class QNetworkGraph(QObject, NetworkGraph):
    def __init__(self, iface=None, parent=None):
        super(QNetworkGraph, self).__init__(parent)
        NetworkGraph.__init__(self, iface)

        self.parser = None
    updateGraph = pyqtSignal(str)

    def start(self):
        self.parser = QParser(self.parse, self)
        self.parser.start()

    def close(self):
        del self.parser
        self.parser = None
        NetworkGraph.close(self)

    def update_graph_callback(self, apName):
        print 'UPDATE GRAPH'
        self.updateGraph.emit(apName)

    def getGraph(self, apName):
        assert(type(apName) == str)
        return self.mgraph.getGraphByName(apName)

    def isStarted(self):
        return not self.mgraph.fStoped
