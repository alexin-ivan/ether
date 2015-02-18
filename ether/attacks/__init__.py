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
        self.attacks = map(lambda x: x(self), _attacks)

    def names(self):
        for i in self.attacks:
            yield i.name()

    def do(self, name, **kw):
        for i in self.attacks:
            if i.name() == name:
                i.do(**kw)
