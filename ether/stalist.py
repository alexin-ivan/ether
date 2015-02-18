#!/usr/bin/env python
# -*- coding: utf-8 -*-
#

##############################################################################
from PyQt4 import QtCore
from PyQt4 import QtGui

from PyQt4.QtGui import (
    QTableWidget, QTableWidgetItem, QVBoxLayout, QMenu, QAction
)
from PyQt4.QtCore import (
    Qt
)
from qnetwork_graph import QNetworkGraph
import logging
import sys
from attacks import AttackManager
##############################################################################


_fromUtf8 = QtCore.QString.fromUtf8


class QStaList(QtGui.QWidget):
    sections = [
        ("MAC", _fromUtf8("MAC-адресс")),
        ("ESSID", _fromUtf8("Название точки доступа")),
        ("Pcount", _fromUtf8("Число полученных пакетов")),
        ("Vendor", _fromUtf8("Производитель устройства"))
    ]

    layout = property(fget=QtGui.QWidget.layout, fset=QtGui.QWidget.setLayout)

    def __init__(self, graph, parent=None):
        super(QStaList, self).__init__(parent)
        self.graph = graph
        self.gw = None
        layout = QVBoxLayout(self)
        self.layout = layout
        graph.updateGraph.connect(self.updateGraph)
        self.attackManager = AttackManager()

    def drawGraph(self, gKey):
        if self.gw is not None:
            self.gw.hide()
            self.layout.removeWidget(self.gw)
            del self.gw

        gw = QTableWidget()
        gw.setRowCount(self._rows())
        gw.setColumnCount(self._columns())
        for row in xrange(self._rows()):
            data = self._getRow(row)
            for column, info in data[1].iteritems():
                item = QTableWidgetItem(info)
                gw.setItem(row, column, item)

            if data[0] == gKey:
                gw.setCurrentCell(row, 0)

        gw.setHorizontalHeaderLabels(
            map(lambda x: x[0], self.sections)
        )
        gw.setContextMenuPolicy(Qt.CustomContextMenu)
        gw.customContextMenuRequested.connect(self.customMenuRequested)
        gw.resizeColumnsToContents()
        self.layout.addWidget(gw)
        gw.show()
        self.gw = gw

    def _rows(self):
        return len(self.graph.getGraphs())

    def _columns(self):
        return len(self.sections)

    def _getRow(self, row):
        graphs = self.graph.getGraphs()
        rowKeys = sorted(graphs.keys())
        g = graphs[rowKeys[row]]

        mac = rowKeys[row]
        essid = g.hName()
        pCount = g.pCount
        oui, _ = g.parseMac()
        if pCount == 0:
            pCount = "N/A"

        info = dict(zip([0, 1, 2, 3], [mac, essid, str(pCount), str(oui)]))

        return (mac, info)

    def updateGraph(self, gKey):
        self.drawGraph(gKey)

    def open(self, iface=None):
        self.graph.open(iface)

    def start(self):
        self.graph.start()

    def close(self):
        self.graph.close()
        super(QStaList, self).close()

    def generateAttackMenu(self, index):
        row = index.row()
        #column = index.column()
        menu = QMenu(self)

        graphs = self.graph.getGraphs()
        rowKeys = sorted(graphs.keys())
        mac = rowKeys[row]
        ifaceMon = self.graph.monitor.ifaceMon
        essid = graphs[mac].essid()
        clients = map(lambda x: x[0].key(), graphs[mac].nodes())

        am = self.attackManager

        def get_callback(name):
            def do(x):
                self.graph.stop()
                am.do(
                    name,
                    mac=mac,
                    ifaceMon=ifaceMon,
                    essid=essid,
                    clients=clients
                )
                self.graph.start()
            return do

        for name in am.names():
            action = QAction(name, self)
            action.triggered.connect(get_callback(name))
            action.setStatusTip(_fromUtf8(u"Вид атаки: %s" % name))
            menu.addAction(action)

        return menu

    def customMenuRequested(self, pos):
        index = self.gw.indexAt(pos)
        if self.gw is not None:
            menu = self.generateAttackMenu(index)
            menu.popup(self.gw.viewport().mapToGlobal(pos))


def main():
    logging.basicConfig(level=logging.DEBUG)

    iface = 'wlan2'

    if len(sys.argv) > 1:
        iface = sys.argv[1]

    app = QtGui.QApplication(sys.argv)

    graph = QNetworkGraph(iface)

    viewer = QStaList(graph)
    viewer.open(iface)
    viewer.resize(400, 400)
    viewer.showMaximized()
    viewer.start()

    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
