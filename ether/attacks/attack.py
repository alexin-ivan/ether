#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
##############################################################################
import abc
import logging
##############################################################################
logger = logging.getLogger('Attack')
##############################################################################


class Attack(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self, interpreter):
        self.interpreter = interpreter
        self.logger = logger

    @abc.abstractmethod
    def do(self, **kw):
        raise NotImplementedError

    @abc.abstractmethod
    def name(self):
        raise NotImplementedError

    @abc.abstractmethod
    def key(self):
        raise NotImplementedError
