#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
##############################################################################
import os
import logging
##############################################################################


def execSystem(cmd):
    logging.debug('Exec: "%s"', cmd)
    r = os.system(cmd)
    if r:
        raise Exception("Can't exec (%x): %s" % (r, cmd))


class Monitor(object):
    def __init__(self, iface=None):
        self.iface = iface
        self.ifaceMon = None
        self.started = False

    def open(self, iface=None):
        if iface is not None:
            self.iface = iface
        self.ifaceMon = '%smon' % iface
        return self._startMonitor()

    def close(self):
        return self._stopMonitor()

    def _startMonitor(self):
        cmd = 'iw dev %s interface add %s type monitor' % \
            (self.iface, self.ifaceMon)
        logging.info('Add monitor device')
        if os.system(cmd):
            logging.warning('Trying delete monitor device')
            self.started = True
            self._stopMonitor()
            self.started = False
            execSystem(cmd)
        cmd = 'ifconfig %s up' % self.ifaceMon
        logging.info("up device")
        execSystem(cmd)
        self.started = True

    def _stopMonitor(self):
        if self.started:
            logging.info("down device")
            cmd = 'ifconfig %s down' % self.ifaceMon
            execSystem(cmd)
            logging.info("Deleting monitor device")
            cmd = 'iw dev %s del' % (self.ifaceMon)
            execSystem(cmd)
            self.started = False

    def __del__(self):
        self.close()
