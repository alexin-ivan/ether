#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
##############################################################################
import deauth
import pspoll
##############################################################################

_attacks = [
    deauth.Attack,
    pspoll.Attack
]


class AttackManager(object):

    def __init__(self):
        attacks = map(lambda x: x(self), _attacks)
        keys = map(lambda x: x.key(), attacks)
        if len(keys) != len(set(keys)):
            raise Exception(
                'Not unique keys in attacks scripts'
            )
        self.attacks = dict(map(lambda x: (x.key(), x), attacks))

    def attacks(self):
        return self.attacks

    def do(self, key, **kw):
        attack = self.attacks[key]
        attack.do(**kw)
