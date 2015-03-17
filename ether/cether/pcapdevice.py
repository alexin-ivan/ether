#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
##############################################################################
import logging
import scapy
import time
##############################################################################
from pcaplib import PcapDevice as CPcapDevice
##############################################################################


class PcapDevice(CPcapDevice):
    """Read packets from a 'savefile' or a device using libpcap."""

    # Standard filter to always exclude type control, general undirected \
    # and broadcast
    BASE_BPF = "not type ctl " \
               " and not (dir fromds and wlan[4] & 0x01 = 1)" \
               " and not (dir nods and not " \
               "  (subtype beacon or subtype probe-resp or subtype assoc-req))"

    def __init__(self, fname=None, use_bpf=False):
        CPcapDevice.__init__(self)
        self.use_bpf = use_bpf
        self.filtered_aps = set()
        self.filtered_stations = set()
        if fname:
            self.open_offline(fname)
        self.logger = logging.getLogger('PcapDevice')

    def _setup(self):
        try:
            self.datalink_handler = scapy.config.conf.l2types[self.datalink]
        except KeyError:
            raise ValueError(
                "Datalink-type %i not supported by Scapy" % self.datalink
            )
        if self.use_bpf:
            self.set_filter(PcapDevice.BASE_BPF)

    def set_filter(self, filter_string):
        try:
            CPcapDevice.set_filter(self, filter_string)
        except ValueError:
            self.use_bpf = False
            logging.critical(
                "Failed to compile BPF-filter. This may be due to "
                "a bug in Pyrit or because your version of "
                "libpcap is too old. Falling back to unfiltered "
                "processing..."
            )

    def _update_bpf_filter(self):
        """ Update the BPF-filter to exclude certain traffic from stations
            and AccessPoints once they are known.
        """
        if self.use_bpf is False:
            return
        bpf = PcapDevice.BASE_BPF
        if len(self.filtered_aps) > 0:
            # Prune list randomly to prevent filter from getting too large
            while len(self.filtered_aps) > 10:
                self.filtered_aps.pop()
            # Exclude beacons, prope-responses and association-requests
            # once a AP's ESSID is known
            bpf += " and not ((wlan host %s) " \
                "and (subtype beacon " \
                "or subtype probe-resp " \
                " or subtype assoc-req))" \
                % (" or ".join(self.filtered_aps), )
        if len(self.filtered_stations) > 0:
            while len(self.filtered_stations) > 10:
                self.filtered_stations.pop()
            # Exclude encrypted or null-typed data traffic once a station
            # is known
            bpf += " and not (wlan host %s) " \
                " or (wlan[1] & 0x40 = 0 and type data and not subtype null)" \
                % (" or ".join(self.filtered_stations), )
        self.set_filter(bpf)

    def open_live(self, device_name):
        """Open a device for capturing packets"""
        self.logger.debug('open_live()')
        CPcapDevice.open_live(self, device_name)
        self._setup()

    def close(self):
        self.logger.debug('close()')
        super(PcapDevice, self).close()

    def read(self):
        """Read one packet from the capture-source."""
        r = CPcapDevice.read(self)
        if r is not None:
            ts, pckt_string = r
            #tv = time.ctime(ts[0] + ts[0] / 1000000)
            #logging.debug(str(tv))
            pckt = self.datalink_handler(pckt_string)
            return pckt
        else:
            return None

    def __iter__(self):
        return self

    def next(self):
        pckt = self.read()
        if pckt is not None:
            return pckt
        else:
            raise StopIteration

    def __enter__(self):
        if self.type is None:
            raise RuntimeError("No device/file opened yet")
        return self

    def __exit__(self, type, value, traceback):
        self.close()
