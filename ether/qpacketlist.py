#!/usr/bin/env python
# -*- coding: utf-8 -*-
#

##############################################################################
from PyQt4.QtGui import (
    QWidget,
    QListWidget,
    QVBoxLayout,
)

##############################################################################


class QPacketList(QWidget):
    def __init__(self, graph, parent_=None):
        super(QPacketList, self).__init__(parent_)

        self.layoutV = QVBoxLayout(self)
        self.qlist = QListWidget()
        self.layoutV.addWidget(self.qlist)
        #self.sButton = QPushButton("Start")
        #self.eButton = QPushButton("Exit")
        #self.layoutV.addWidget(self.sButton)
        #self.layoutV.addWidget(self.eButton)

        self.graph = graph
        graph.receivedPacket.connect(self.addPacket)

        #self.sButton.clicked.connect(sn.thread.start)
        #self.eButton.clicked.connect(sn.softTerminate)
        #self.eButton.clicked.connect(self.close)

        #sn.receivedPacket.connect(self.appendList)

    def addPacket(self, pkt):
        self.appendList(pkt)

    def appendList(self, s):
        #if s.type == 2L and s.subtype == 0:
        self.qlist.addItem(s.summary())


def main():
    pass


if __name__ == '__main__':
    main()
