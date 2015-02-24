#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
##############################################################################
from cether import pckttools
##############################################################################


class PacketParser(pckttools.PacketParser):
    """
       Parse packets from a capture-source and reconstruct AccessPoints,
       Stations and EAPOLAuthentications from the data.
    """

    def __init__(
        self,
        pcapfile=None,
        new_ap_callback=None,
        new_station_callback=None,
        new_keypckt_callback=None,
        new_auth_callback=None,
        new_pkt_callback=None,
        new_stop_parsing_callback=None,
        use_bpf=True
    ):
        self.pkt_callback = new_pkt_callback
        self.stop_callback = new_stop_parsing_callback
        super(PacketParser, self).__init__(
            pcapfile,
            new_ap_callback,
            new_station_callback,
            new_keypckt_callback,
            new_auth_callback,
            use_bpf
        )

    def parse_pcapdevice(self, reader):
        """Parse all packets from a instance of PcapDevice.

           This method can be very fast as it updates PcapDevice's BPF-filter
           to exclude unwanted packets from Stations once we are aware of
           their presence.
        """

        if not isinstance(reader, pckttools.PcapDevice):
            raise TypeError("Argument must be of type PcapDevice")
        sta_callback = self.new_station_callback
        ap_callback = self.new_ap_callback
        pkt_callback = self.pkt_callback
        # Update the filter only when parsing offline dumps. The kernel can't
        # take complex filters and libpcap starts throwing unmanageable
        # warnings....
        if reader.type == 'offline':
            self.new_station_callback = lambda sta: \
                self._filter_sta(reader, sta_callback, sta)
            self.new_ap_callback = lambda ap: \
                self._filter_ap(reader, ap_callback, ap)

        for pckt in reader:
            self.parse_packet(pckt)
            pkt_callback(pckt)
            if self.stop_callback(pckt):
                break
        self.new_station_callback = sta_callback
        self.new_ap_callback = ap_callback
