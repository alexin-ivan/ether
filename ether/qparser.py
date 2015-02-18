#!/usr/bin/env python
# -*- coding: utf-8 -*-
#

##############################################################################
from PyQt4 import QtCore
import logging
##############################################################################


class QParser(QtCore.QThread):
    def __init__(self, f, parent=None):
        super(QParser, self).__init__(parent)
        self.f = f

    def run(self):
        logging.debug('QParser: started')
        self.f()
        logging.debug('QParser: stoped')
