#!/usr/bin/env python
# -*- coding: utf-8 -*-
#

##############################################################################
import sys
import logging
from PyQt4.QtGui import (
    QTabWidget, QMainWindow, QApplication, QVBoxLayout, QDialog
)
from PyQt4.QtCore import (
    QString
)
from stalist import QStaList
from qmultigraph_widget import QNetworkGraphViewer
from qnetwork_graph import QNetworkGraph
from mainwindow_ui import Ui_MainWindow
from select_iface_dialog_ui import Ui_Dialog as SelectDialogUi
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
        ui = Ui_MainWindow()
        ui.setupUi(self)
        ui.actionExit.triggered.connect(self.close)
        ui.actionIface.triggered.connect(self.selectIfaceDialog)
        ui.actionScan.triggered.connect(self.scanEnable)

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
        self.iface = 'wlan2'

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

    def scanEnable(self, t):
        if t:
            logging.debug('Start parsing')
            self.graph.open(self.iface)
            self.graph.start()
        else:
            self.graph.close()
            logging.debug('Stop parsing')

    def selectIfaceDialog(self):
        self.iface = 'wlan2'
        ui = SelectDialogUi()
        dialog = QDialog()
        ui.setupUi(dialog)
        result = dialog.exec_()
        if result:
            self.iface = str(ui.lineEdit.text())
        logging.debug('Selected %s iface', self.iface)


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
