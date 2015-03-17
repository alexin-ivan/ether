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

    def drawGraph(self):
        if self.gw is not None:
            self.gw.hide()
            self.layout.removeWidget(self.gw)
            del self.gw

        gw = QTableWidget()
        gw.setRowCount(self._rows())
        gw.setColumnCount(self._columns())
        for row in xrange(self._rows()):
            data = self._getRow(row)
            for column, info in enumerate(data[1]):
                item = QTableWidgetItem(info)
                gw.setItem(row, column, item)

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
        return len(self.graph.getAPs())

    def _columns(self):
        return len(self.sections)

    def _getRow(self, row):
        aps = self.graph.getAPs()
        ap = aps[row]

        mac = ap['mac']
        essid = ap['nEssid']
        pCount = 0  # TODO
        vendor = ap['vendor']
        if vendor[1] is None:
            vendor = "<Unknown>"
        else:
            vendor = vendor[0]
        if pCount == 0:
            pCount = "N/A"

        info = [mac, essid, str(pCount), str(vendor)]

        return (mac, info)

    def updateGraph(self):
        self.drawGraph()

    def open(self, iface=None):
        self.graph.open(iface)

    def start(self):
        self.graph.start()

    def close(self):
        self.graph.close()
        super(QStaList, self).close()

    def generateAttackMenu(self, index):
        row = index.row()
        menu = QMenu(self)

        aps = self.graph.getAPs()
        ap = aps[row]
        iface = self.graph.iface

        am = self.attackManager

        def attack_callback(key):
            def do(x):
                #self.graph.suspend()
                self.graph.suspend()
                am.do(key, graph=self.graph.mgraph, ap=ap, iface=iface)
                self.graph.resume()

            return do

        for key, attack in am.attacks.iteritems():
            name = attack.name()
            action = QAction(name, self)
            action.triggered.connect(attack_callback(key))
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
