#!/usr/bin/env python
# -*- coding: utf-8 -*-
#

##############################################################################
from network_graph import NetworkGraph
from qparser import QParser
from PyQt4.QtCore import QObject, pyqtSignal
##############################################################################
from cether.pckttools import PcapDevice
from scapy.layers.dot11 import RadioTap
import logging


class QNetworkGraph(QObject, NetworkGraph):
    def __init__(self, iface=None, parent=None):
        super(QNetworkGraph, self).__init__(parent)
        NetworkGraph.__init__(self, iface)
        self.parser = None
        self.__logger = logging.getLogger('QNetworkGraph')

    updateGraph = pyqtSignal()
    receivedPacket = pyqtSignal(RadioTap)

    def start(self):
        self.parser = QParser(self.parse, self)
        self.parser.start()

    def close(self):
        NetworkGraph.close(self)
        del self.parser
        self.parser = None

    def pkt_callback(self, pkt):
        NetworkGraph.pkt_callback(self, pkt)
        self.receivedPacket.emit(pkt)

    def update_graph_callback(self):
        self.updateGraph.emit()

    def isStarted(self):
        return not self.mgraph.fStoped

    def suspend(self):
        if self.iface:
            self.stop()
            self.pcapDevice.close()
            self.pcapDevice = None
            self.__logger.debug('Suspended: %s' % str(self.iface))

    def resume(self):
        self.pcapDevice = PcapDevice()
        self.pcapDevice.open_live(self.iface.monitor())
        self.start()
        self.__logger.debug('Resumed: %s' % str(self.iface))
