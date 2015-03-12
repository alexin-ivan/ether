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
        self.logger = logging.getLogger('QParser')

    def run(self):
        self.logger.debug('started')
        self.f()
        self.logger.debug('stoped')
