#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
##############################################################################
##############################################################################


class WiDevice(object):
    def __init__(self, iface):
        self.__iface = iface

    def open(self):
        # TODO
        pass

    def close(self):
        # TODO
        pass

    def __del__(self):
        self.close()
