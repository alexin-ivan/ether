#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
##############################################################################
import logging
##############################################################################
import utils
##############################################################################


class WiDevice(object):
    def __init__(self, iface, inMonitorMode=False):
        self.__iface = iface
        self.__monitorEnabled = inMonitorMode
        self.__defaultMac = None
        self.__randomMac = None
        self.__ifaceMon = None
        if self.__monitorEnabled:
            self.fRandomMac = False
            self.__ifaceMon = self.__iface
        else:
            self.fRandomMac = True

        self.started = False
        self.logger = logging.getLogger('WiDevice')

    def iface(self):
        return self.__iface

    def monitor(self):
        return self.__ifaceMon

    def monitorModeEnabled(self):
        return self.__monitorEnabled

    def __str__(self):
        return 'dev<iface=%s, monitor=%s, frndMac=%s, mac=%s, rndMac=%s>' % (
            str(self.__iface),
            str(self.__monitorEnabled),
            str(self.fRandomMac),
            str(self.__defaultMac),
            str(self.__randomMac),
        )

    def __repr__(self):
        return str(self)

    def _anonymize_mac(self):
        self.__defaultMac, self.__randomMac = utils.mac_anonymize(self.__iface)

    def _mac_change_back(self):
        utils.mac_change_back(self.__iface, self.__defaultMac)

    def _startMonitor(self):
        if self.fRandomMac:
            self._anonymize_mac()

        if self.__ifaceMon is None:
            self.__ifaceMon = "%smon" % self.__iface

        cmd = ['iw', 'dev', self.__iface,
               'interface', 'add', self.__ifaceMon, 'type', 'monitor']
        self.logger.info('Add monitor device: %s', ' '.join(cmd))
        if utils.callProcWithLog(cmd):
            self.logger.warning('Trying delete monitor device')
            self.started = True
            self._stopMonitor()
            self.started = False
            self.logger.info('Add monitor device (again): %s', ' '.join(cmd))
            if utils.callProcWithLog(cmd):
                raise Exception("Can't create monitor for %s" % self.__iface)
        cmd = ['ifconfig', self.__ifaceMon, 'up']
        self.logger.info("up device")
        if utils.callProcWithLog(cmd):
            raise Exception("Can't up device %s" % self.__ifaceMon)
        self.started = True
        return self.__ifaceMon

    def _stopMonitor(self):
        if self.started:
            if self.fRandomMac:
                self._mac_change_back()

            self.logger.info("down device")
            cmd = ['ifconfig', self.__ifaceMon, 'down']
            if utils.callProcWithLog(cmd):
                raise Exception("Can't down device %s" % self.__ifaceMon)
            self.logger.info("Deleting monitor device")
            cmd = ['iw', 'dev', self.__ifaceMon, 'del']
            if utils.callProcWithLog(cmd):
                raise Exception("Can't delete device %s" % self.__ifaceMon)
            self.started = False
            self.__ifaceMon = None

    def open(self):
        if self.__monitorEnabled:
            return self.__ifaceMon
        return self._startMonitor()

    def forwardClose(self):
        self.started = True
        self.close()

    def close(self):
        return self._stopMonitor()

    def __del__(self):
        self.close()
