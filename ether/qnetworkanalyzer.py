#!/usr/bin/env python
# -*- coding: utf-8 -*-
#

##############################################################################
import sys
import logging
from PyQt4.QtGui import (
    QTabWidget, QMainWindow, QApplication, QVBoxLayout,
    QMessageBox
)
from PyQt4.QtCore import (
    QString
)
from qstalist import QStaList
from iflist import IFlist
from qmultigraph_widget import QNetworkGraphViewer
from qnetwork_graph import QNetworkGraph
from ui.mainwindow_ui import Ui_MainWindow as MainWindowUi
##############################################################################


_fromUtf8 = QString.fromUtf8

try:
    _encoding = QApplication.UnicodeUTF8

    def _translate(context, text, disambig):
        return QApplication.translate(context, text, disambig, _encoding)
except AttributeError:
    def _translate(context, text, disambig):
        return QApplication.translate(context, text, disambig)


class MainWindow(QMainWindow):

    def __init__(self):
        super(MainWindow, self).__init__()

        # setup graph
        self.graph = QNetworkGraph()

        # setup ui
        ui = MainWindowUi()
        ui.setupUi(self)
        ui.actionExit.triggered.connect(self.close)
        ui.actionScan.triggered.connect(self.scanEnable)
        ui.actionForwardClose.triggered.connect(self.forwardClose)

        # add tab
        layout = QVBoxLayout(ui.centralwidget)
        ui.centralwidget.setLayout(layout)

        tab = QTabWidget(self)
        layout.addWidget(tab)
        tab.setObjectName(_fromUtf8("MainTab"))

        tabGraph = self.createGraphWidget()
        tabGraph.setObjectName(_fromUtf8("tabGraph"))
        tab.addTab(tabGraph, _fromUtf8("tabGraph"))

        tabAPs = self.createStaListWidget()
        tabAPs.setObjectName(_fromUtf8("tabAPs"))
        tab.addTab(tabAPs, _fromUtf8("tabAPs"))

        ui.tab = tab
        ui.tabGraph = tabGraph
        ui.tabAPs = tabAPs
        self.retranslateUi(ui)

        self.ui = ui
        self.ifaceList = IFlist()

        self.logger = logging.getLogger('MainWindow')

    def createGraphWidget(self):
        w = QNetworkGraphViewer(self.graph)
        return w

    def createStaListWidget(self):
        w = QStaList(self.graph)
        return w

    def retranslateUi(self, ui):
        ui.tab.setTabText(
            ui.tab.indexOf(ui.tabGraph),
            _translate("MainWindow", "Графы сетей", None)
        )
        ui.tab.setTabText(
            ui.tab.indexOf(ui.tabAPs),
            _translate("MainWindow", "Точки доступа", None)
        )

    def close(self):
        self.graph.close()
        super(MainWindow, self).close()

    def forwardClose(self):
        self.logger.debug('forwardClose()')
        iface = self.ifaceList.get_iface()
        if iface and iface.monitor():
            self.logger.debug('forwardClose(%s)', iface.monitor())
            msgBox = QMessageBox()
            msgBox.setText(_fromUtf8(
                "Вы хотите выключить это устройство?"
            ))
            msgBox.setInformativeText(_fromUtf8(
                "интерфейс <%s>" % iface.monitor()
            ))
            msgBox.setStandardButtons(
                msgBox.StandardButtons(msgBox.Yes | msgBox.No)
            )
            result = msgBox.exec_()
            if result == msgBox.Yes:
                iface.forwardClose()
                self.logger.debug('Forward closed: %s', iface)

    def scanEnable(self, t):
        if t:
            self.logger.debug('Start parsing')
            self.graph.open(self.ifaceList.get_iface())
            self.graph.start()
        else:
            self.graph.close()
            self.logger.debug('Stop parsing')


def main():
    logging.basicConfig(level=logging.DEBUG)
    app = QApplication(sys.argv)
    viewer = MainWindow()
    ether = _fromUtf8("Эфир")
    viewer.setWindowTitle(ether)
    viewer.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
