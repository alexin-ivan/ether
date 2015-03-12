#!/usr/bin/env python
# -*- coding: utf-8 -*-
#

##############################################################################
from PyQt4 import QtCore
_fromUtf8 = QtCore.QString.fromUtf8
import attack
##############################################################################


class PSpollAttack(attack.Attack):

    def __init__(self, interpreter):
        super(PSpollAttack, self).__init__(interpreter)
        self.logger = attack.logger

    def do(self, **kw):
        self.logger.debug('PSpoll attack begin')
        self.logger.debug('Attack: %s', str(kw))
        self.logger.debug('PSpoll attack end')

    def name(self):
        return _fromUtf8("Эксперимент: Ложные PS-Poll пакеты")

    def key(self):
        return 'pspoll'


Attack = PSpollAttack
