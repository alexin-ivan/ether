#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
##############################################################################
import abc
##############################################################################


class Attack(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self, cmd):
        self.cmd = cmd

    @abc.abstractmethod
    def do(self, **kw):
        raise NotImplementedError

    @abc.abstractmethod
    def name(self):
        raise NotImplementedError
