# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'select_iface_dialog.ui'
#
# Created: Thu Feb 19 11:55:19 2015
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

class Ui_Dialog(object):
    def setupUi(self, Dialog):
        Dialog.setObjectName(_fromUtf8("Dialog"))
        Dialog.resize(395, 156)
        self.gridLayoutWidget = QtGui.QWidget(Dialog)
        self.gridLayoutWidget.setGeometry(QtCore.QRect(0, 20, 391, 126))
        self.gridLayoutWidget.setObjectName(_fromUtf8("gridLayoutWidget"))
        self.gridLayout = QtGui.QGridLayout(self.gridLayoutWidget)
        self.gridLayout.setMargin(0)
        self.gridLayout.setObjectName(_fromUtf8("gridLayout"))
        self.lSelect = QtGui.QLabel(self.gridLayoutWidget)
        self.lSelect.setObjectName(_fromUtf8("lSelect"))
        self.gridLayout.addWidget(self.lSelect, 1, 0, 1, 1)
        spacerItem = QtGui.QSpacerItem(20, 40, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Expanding)
        self.gridLayout.addItem(spacerItem, 3, 0, 1, 1)
        self.buttonBox = QtGui.QDialogButtonBox(self.gridLayoutWidget)
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtGui.QDialogButtonBox.Ok)
        self.buttonBox.setCenterButtons(True)
        self.buttonBox.setObjectName(_fromUtf8("buttonBox"))
        self.gridLayout.addWidget(self.buttonBox, 5, 0, 1, 1)
        self.iflist = QtGui.QComboBox(self.gridLayoutWidget)
        self.iflist.setObjectName(_fromUtf8("iflist"))
        self.gridLayout.addWidget(self.iflist, 2, 0, 1, 1)
        self.lTitle = QtGui.QLabel(self.gridLayoutWidget)
        self.lTitle.setObjectName(_fromUtf8("lTitle"))
        self.gridLayout.addWidget(self.lTitle, 0, 0, 1, 1)
        self.cbAnonymize = QtGui.QCheckBox(self.gridLayoutWidget)
        self.cbAnonymize.setChecked(True)
        self.cbAnonymize.setTristate(False)
        self.cbAnonymize.setObjectName(_fromUtf8("cbAnonymize"))
        self.gridLayout.addWidget(self.cbAnonymize, 4, 0, 1, 1)

        self.retranslateUi(Dialog)
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL(_fromUtf8("accepted()")), Dialog.accept)
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL(_fromUtf8("rejected()")), Dialog.reject)
        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog):
        Dialog.setWindowTitle(_translate("Dialog", "Выбор интерфейса", None))
        self.lSelect.setText(_translate("Dialog", "Выберите сетевой интерфейс из списка:", None))
        self.lTitle.setText(_translate("Dialog", "Выбор сетевого интерфейса", None))
        self.cbAnonymize.setText(_translate("Dialog", "Сгенерировать случайный MAC-адрес", None))

