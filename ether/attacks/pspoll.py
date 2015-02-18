#!/usr/bin/env python
# -*- coding: utf-8 -*-
#

##############################################################################
from PyQt4 import QtCore
_fromUtf8 = QtCore.QString.fromUtf8
import logging
import attack
##############################################################################


class PSpollAttack(attack.Attack):

    def do(self, **kw):
        logging.debug('PSpoll attack begin')
        logging.debug('Attack: %s', str(kw))
        logging.debug('PSpoll attack end')

    def name(self):
        return _fromUtf8("Эксперимент: Ложные PS-Poll пакеты")


Attack = PSpollAttack
