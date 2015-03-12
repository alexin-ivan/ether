# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'mainwindow.ui'
#
# Created: Wed Mar 11 13:45:04 2015
#      by: PyQt4 UI code generator 4.10.4
#
# WARNING! All changes made in this file will be lost!

from PyQt4 import QtCore, QtGui

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    def _fromUtf8(s):
        return s

try:
    _encoding = QtGui.QApplication.UnicodeUTF8
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig, _encoding)
except AttributeError:
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig)

class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName(_fromUtf8("MainWindow"))
        MainWindow.resize(800, 600)
        self.centralwidget = QtGui.QWidget(MainWindow)
        self.centralwidget.setObjectName(_fromUtf8("centralwidget"))
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtGui.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 800, 21))
        self.menubar.setObjectName(_fromUtf8("menubar"))
        self.menuSettings = QtGui.QMenu(self.menubar)
        self.menuSettings.setObjectName(_fromUtf8("menuSettings"))
        self.menuMode = QtGui.QMenu(self.menubar)
        self.menuMode.setObjectName(_fromUtf8("menuMode"))
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtGui.QStatusBar(MainWindow)
        self.statusbar.setObjectName(_fromUtf8("statusbar"))
        MainWindow.setStatusBar(self.statusbar)
        self.actionIface = QtGui.QAction(MainWindow)
        self.actionIface.setObjectName(_fromUtf8("actionIface"))
        self.actionExit = QtGui.QAction(MainWindow)
        self.actionExit.setObjectName(_fromUtf8("actionExit"))
        self.actionScan = QtGui.QAction(MainWindow)
        self.actionScan.setCheckable(True)
        self.actionScan.setObjectName(_fromUtf8("actionScan"))
        self.actionForwardClose = QtGui.QAction(MainWindow)
        self.actionForwardClose.setObjectName(_fromUtf8("actionForwardClose"))
        self.menuSettings.addAction(self.actionForwardClose)
        self.menuSettings.addAction(self.actionExit)
        self.menuMode.addAction(self.actionScan)
        self.menubar.addAction(self.menuSettings.menuAction())
        self.menubar.addAction(self.menuMode.menuAction())

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        MainWindow.setWindowTitle(_translate("MainWindow", "Эфир", None))
        self.menuSettings.setTitle(_translate("MainWindow", "Настройки", None))
        self.menuMode.setTitle(_translate("MainWindow", "Режим работы", None))
        self.actionIface.setText(_translate("MainWindow", "Установить интерфейс", None))
        self.actionExit.setText(_translate("MainWindow", "Выход", None))
        self.actionExit.setShortcut(_translate("MainWindow", "Alt+X", None))
        self.actionScan.setText(_translate("MainWindow", "Сканирование", None))
        self.actionScan.setShortcut(_translate("MainWindow", "Alt+1", None))
        self.actionForwardClose.setText(_translate("MainWindow", "Принудительно закрыть интерфейс", None))
        self.actionForwardClose.setShortcut(_translate("MainWindow", "Alt+2", None))

