#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
##############################################################################
import scapy.config
import scapy.fields
import scapy.layers.dot11
import scapy.packet
import scapy.utils
##############################################################################
from pcapdevice import PcapDevice
##############################################################################
# Suppress useless warnings from scapy...
scapy.config.conf.logLevel = 40
##############################################################################


def str2hex(string):
    """Convert a string to it's hex-decimal representation."""
    return ''.join('%02x' % c for c in map(ord, string))


scapy.config.Conf.l2types.register_num2layer(
    119,
    scapy.layers.dot11.PrismHeader
)


def isFlagSet(self, name, value):
    """Return True if the given field 'includes' the given value.
       Exact behaviour of this function is specific to the field-type.
    """
    field, val = self.getfield_and_val(name)
    if isinstance(field, scapy.fields.EnumField):
        if val not in field.i2s:
            return False
        return field.i2s[val] == value
    else:
        return (1 << field.names.index([value])) & self.__getattr__(name) != 0
scapy.packet.Packet.isFlagSet = isFlagSet
del isFlagSet


def areFlagsSet(self, name, values):
    """Return True if the given field 'includes' all of the given values."""
    return all(self.isFlagSet(name, value) for value in values)
scapy.packet.Packet.areFlagsSet = areFlagsSet
del areFlagsSet


def areFlagsNotSet(self, name, values):
    """Return True if the given field 'includes' none of the given values."""
    return all(not self.isFlagSet(name, value) for value in values)
scapy.packet.Packet.areFlagsNotSet = areFlagsNotSet
del areFlagsNotSet


def iterSubPackets(self, cls):
    """Iterate over all layers of the given type in packet 'self'."""
    try:
        if cls not in self:
            return
        elt = self[cls]
        while elt:
            yield elt
            elt = elt[cls:2]
    except IndexError:
        return
scapy.packet.Packet.iterSubPackets = iterSubPackets
del iterSubPackets


class XStrFixedLenField(scapy.fields.StrFixedLenField):
    """String-Field with nice repr() for hexdecimal strings"""

    def i2repr(self, pkt, x):
        return str2hex(scapy.fields.StrFixedLenField.i2m(self, pkt, x))


class XStrLenField(scapy.fields.StrLenField):
    """String-Field of variable size with nice repr() for hexdecimal strings"""

    def i2repr(self, pkt, x):
        return str2hex(scapy.fields.StrLenField.i2m(self, pkt, x))


class EAPOL_Key(scapy.packet.Packet):
    """EAPOL Key frame"""
    name = "EAPOL Key"
    fields_desc = [scapy.fields.ByteEnumField(
        "DescType", 254, {2: "RSN Key", 254: "WPA Key"}
    )]
scapy.packet.bind_layers(scapy.layers.l2.EAPOL, EAPOL_Key, type=3)


class EAPOL_AbstractEAPOLKey(scapy.packet.Packet):
    """Base-class for EAPOL WPA/RSN-Key frames"""
    fields_desc = [
        scapy.fields.FlagsField(
            "KeyInfo", 0, 16, [
                "HMAC_MD5_RC4", "HMAC_SHA1_AES", "undefined",
                "pairwise", "idx1", "idx2", "install",
                "ack", "mic", "secure", "error", "request", "encrypted"
            ]
        ),
        scapy.fields.ShortField("KeyLength", 0),
        scapy.fields.LongField("ReplayCounter", 0),
        XStrFixedLenField("Nonce", '\x00' * 32, 32),
        XStrFixedLenField("KeyIV", '\x00' * 16, 16),
        XStrFixedLenField("WPAKeyRSC", '\x00' * 8, 8),
        XStrFixedLenField("WPAKeyID", '\x00' * 8, 8),
        XStrFixedLenField("WPAKeyMIC", '\x00' * 16, 16),
        scapy.fields.ShortField("WPAKeyLength", 0),
        scapy.fields.ConditionalField(
            XStrLenField("WPAKey", None,
                         length_from=lambda pkt: pkt.WPAKeyLength),
            lambda pkt: pkt.WPAKeyLength > 0
        )]


class EAPOL_WPAKey(EAPOL_AbstractEAPOLKey):
    name = "EAPOL WPA Key"
    keyscheme = 'HMAC_MD5_RC4'
scapy.packet.bind_layers(EAPOL_Key, EAPOL_WPAKey, DescType=254)


class EAPOL_RSNKey(EAPOL_AbstractEAPOLKey):
    name = "EAPOL RSN Key"
    keyscheme = 'HMAC_SHA1_AES'
scapy.packet.bind_layers(EAPOL_Key, EAPOL_RSNKey, DescType=2)


class AccessPoint(object):

    def __init__(self, mac):
        self.mac = mac
        self.essidframe = None
        self.essid = None
        self.stations = {}

    def __iter__(self):
        return self.stations.values().__iter__()

    def __str__(self):
        return self.mac

    def __contains__(self, mac):
        return mac in self.stations

    def __getitem__(self, mac):
        return self.stations[mac]

    def __setitem__(self, mac, station):
        self.stations[mac] = station

    def __len__(self):
        return len(self.stations)

    def getCompletedAuthentications(self):
        """Return list of completed Authentication."""
        auths = []
        for station in self.stations.itervalues():
            auths.extend(station.getAuthentications())
        return auths

    def isCompleted(self):
        """Returns True if this instance includes at least one valid
           authentication.
        """
        return any(station.isCompleted() for station in self)


class Station(object):

    def __init__(self, mac, ap):
        self.ap = ap
        self.mac = mac
        self.frames = {}

    def __str__(self):
        return self.mac

    def __iter__(self):
        return self.getAuthentications().__iter__()

    def __len__(self):
        return len(self.auths)

    def addAuthenticationFrame(self, idx, pckt_idx, pckt):
        if idx == 0:
            return self.addChallengeFrame(pckt_idx, pckt)
        elif idx == 1:
            return self.addResponseFrame(pckt_idx, pckt)
        elif idx == 2:
            return self.addConfirmationFrame(pckt_idx, pckt)
        else:
            raise IndexError("Invalid authentication-phase.")

    def addChallengeFrame(self, pckt_idx, pckt):
        """Store a packet that contains the EAPOL-challenge"""
        frames = self.frames.setdefault(pckt.ReplayCounter, ({}, {}, {}))
        if pckt.Nonce not in frames[0]:
            frames[0][pckt.Nonce] = (pckt_idx, pckt)
            return self._buildAuthentications(
                {pckt.Nonce: (pckt_idx, pckt)},
                frames[1], frames[2]
            )

    def addResponseFrame(self, pckt_idx, pckt):
        """Store a packet that contains the EAPOL-response"""
        frames = self.frames.setdefault(pckt.ReplayCounter, ({}, {}, {}))

        if EAPOL_WPAKey in pckt:
            keypckt = pckt[EAPOL_WPAKey]
        elif EAPOL_RSNKey in pckt:
            keypckt = pckt[EAPOL_RSNKey]
        else:
            raise TypeError("No key-frame in packet")

        # WPAKeys 'should' set HMAC_MD5_RC4, RSNKeys HMAC_SHA1_AES
        # However we've seen cases where a WPAKey-packet sets
        # HMAC_SHA1_AES in it's KeyInfo-field (see issue #111)
        if keypckt.isFlagSet('KeyInfo', EAPOL_WPAKey.keyscheme):
            version = EAPOL_WPAKey.keyscheme
        elif keypckt.isFlagSet('KeyInfo', EAPOL_RSNKey.keyscheme):
            version = EAPOL_RSNKey.keyscheme
        else:
            # Fallback to packet-types's own default, in case the
            # KeyScheme is never set. Should not happen...
            version = keypckt.keyscheme

        # We need a revirginized version of the EAPOL-frame which produced
        # that MIC.
        keymic_frame = pckt[scapy.layers.dot11.EAPOL].copy()
        keymic_frame.WPAKeyMIC = '\x00' * len(keymic_frame.WPAKeyMIC)
        # Strip padding and cruft from frame
        keymic_frame = str(keymic_frame)[:keymic_frame.len + 4]

        response = (version, keypckt.Nonce, keymic_frame, keypckt.WPAKeyMIC)
        if response not in frames[1]:
            frames[1][response] = (pckt_idx, pckt)
            return self._buildAuthentications(
                frames[0],
                {response: (pckt_idx, pckt)},
                frames[2]
            )

    def addConfirmationFrame(self, pckt_idx, pckt):
        """Store a packet that contains the EAPOL-confirmation"""
        frames = self.frames.setdefault(pckt.ReplayCounter - 1, ({}, {}, {}))
        if pckt.Nonce not in frames[2]:
            frames[2][pckt.Nonce] = (pckt_idx, pckt)
            return self._buildAuthentications(
                frames[0], frames[1], {pckt.Nonce: (pckt_idx, pckt)}
            )

    def _buildAuthentications(self, f1_frames, f2_frames, f3_frames):
        auths = []
        for (version, snonce, keymic_frame, WPAKeyMIC), \
                (f2_idx, f2) in f2_frames.iteritems():
            # Combinations with Frame3 are of higher value as the AP
            # acknowledges that the STA used the correct PMK in Frame2
            for anonce, (f3_idx, f3) in f3_frames.iteritems():
                if anonce in f1_frames:
                    # We have F1+F2+F3. Frame2 is only cornered by the
                    # ReplayCounter. Technically we don't benefit
                    # from this combination any more than just
                    # F2+F3 but this is the best we can get.
                    f1_idx, f1 = f1_frames[anonce]
                    spread = min(abs(f3_idx - f2_idx), abs(f1_idx - f2_idx))
                    auth = EAPOLAuthentication(
                        self, version, snonce, anonce,
                        WPAKeyMIC, keymic_frame, 0, spread, (f1, f2, f3)
                    )
                else:
                    # There are no matching first-frames. That's OK.
                    spread = abs(f3_idx - f2_idx)
                    auth = EAPOLAuthentication(
                        self, version, snonce,
                        anonce, WPAKeyMIC, keymic_frame,
                        1, spread, (None, f2, f3)
                    )
                auths.append(auth)
            for anonce, (f1_idx, f1) in f1_frames.iteritems():
                # No third frame. Combinations with Frame1 are possible but
                # can also be triggered by STAs that use an incorrect PMK.
                spread = abs(f1_idx - f2_idx)
                if anonce not in f3_frames:
                    auth = EAPOLAuthentication(
                        self, version, snonce,
                        anonce, WPAKeyMIC, keymic_frame,
                        2, spread, (f1, f2, None)
                    )
                    auths.append(auth)
        return auths

    def getAuthentications(self):
        """Reconstruct a  list of EAPOLAuthentications from captured
           handshake-packets. Best matches come first.
        """
        auths = []
        for frames in self.frames.itervalues():
            auths.extend(self._buildAuthentications(*frames))
        return sorted(auths)

    def isCompleted(self):
        """Returns True if this instance includes at least one valid
           authentication.
        """
        return len(self.getAuthentications()) > 0


class EAPOLAuthentication(object):

    def __init__(
        self, station, version, snonce, anonce, keymic,
        keymic_frame, quality, spread, frames=None
    ):
        self.station = station
        self.version = version
        self.snonce = snonce
        self.anonce = anonce
        self.keymic = keymic
        self.keymic_frame = keymic_frame
        self.quality = quality
        self.spread = spread
        self.frames = frames

    def getpke(self):
        pke = "Pairwise key expansion\x00" \
            + ''.join(sorted((
                scapy.utils.mac2str(self.station.ap.mac),
                scapy.utils.mac2str(self.station.mac)
            ))) \
            + ''.join(sorted((self.snonce, self.anonce))) \
            + '\x00'
        return pke
    pke = property(getpke)

    def __lt__(self, other):
        if isinstance(other, EAPOLAuthentication):
            return (self.quality, self.spread) < (other.quality, other.spread)
        else:
            return self < other

    def __gt__(self, other):
        return not self < other

    def __str__(self):
        quality = ['good', 'workable', 'bad'][self.quality]
        return "%s, %s, spread %s" % (self.version, quality, self.spread)


class Dot11PacketWriter(object):

    def __init__(self, pcapfile):
        self.writer = scapy.utils.PcapWriter(
            pcapfile, linktype=105, gz=pcapfile.endswith('.gz'), sync=True
        )
        self.pcktcount = 0

    def write(self, pckt):
        if not scapy.layers.dot11.Dot11 in pckt:
            raise RuntimeError("No Dot11-frame in packet.")
        self.writer.write(pckt[scapy.layers.dot11.Dot11])
        self.pcktcount += 1

    def close(self):
        self.writer.close()

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()


class PacketParser(object):
    """Parse packets from a capture-source and reconstruct AccessPoints,
       Stations and EAPOLAuthentications from the data.
    """

    def __init__(
        self,
        g=None,
        new_ap_callback=None,
        new_station_callback=None,
        new_keypckt_callback=None,
        new_auth_callback=None,
        new_stop_parsing_callback=None,
        new_pkt_callback=None,
        use_bpf=True
    ):
        self.air = {}
        self.pcktcount = 0
        self.dot11_pcktcount = 0
        self.new_ap_callback = new_ap_callback
        self.new_station_callback = new_station_callback
        self.new_keypckt_callback = new_keypckt_callback
        self.new_auth_callback = new_auth_callback
        self.stop_callback = new_stop_parsing_callback
        self.pkt_callback = new_pkt_callback
        self.use_bpf = use_bpf
        self.g = g

    def _find_ssid(self, pckt):
        for elt_pckt in pckt.iterSubPackets(scapy.layers.dot11.Dot11Elt):
            if elt_pckt.isFlagSet('ID', 'SSID') and \
               len(elt_pckt.info) == elt_pckt.len and \
               not all(c == '\x00' for c in elt_pckt.info):
                return elt_pckt.info

    def _add_ap(self, ap_mac, pckt):
        ap = self.air.setdefault(ap_mac, AccessPoint(ap_mac))
        if ap.essid is None:
            essid = self._find_ssid(pckt)
            if essid is not None:
                ap.essid = essid
                ap.essidframe = pckt.copy()
                if self.new_ap_callback is not None:
                    self.new_ap_callback(ap)

    def _add_station(self, ap, sta_mac):
        if sta_mac not in ap:
            sta = Station(sta_mac, ap)
            ap[sta_mac] = sta
            if self.new_station_callback is not None:
                self.new_station_callback(sta)

    def _add_keypckt(self, station, idx, pckt):
        new_auths = station.addAuthenticationFrame(idx, self.pcktcount, pckt)
        if self.new_keypckt_callback is not None:
            self.new_keypckt_callback((station, idx, pckt))
        if new_auths is not None and self.new_auth_callback is not None:
            for auth in new_auths:
                self.new_auth_callback((station, auth))

    def parse_pcapdevice(self, reader):
        """Parse all packets from a instance of PcapDevice.

           This method can be very fast as it updates PcapDevice's BPF-filter
           to exclude unwanted packets from Stations once we are aware of
           their presence.
        """

        if not isinstance(reader, PcapDevice):
            raise TypeError("Argument must be of type PcapDevice")
        sta_callback = self.new_station_callback
        ap_callback = self.new_ap_callback

        for pckt in reader:
            self.parse_packet(pckt)
            self.pkt_callback(pckt)
            if self.stop_callback(pckt):
                break
        self.new_station_callback = sta_callback
        self.new_ap_callback = ap_callback

    def parse_packet(self, pckt):
        """Parse one packet"""

        self.pcktcount += 1
        if not scapy.layers.dot11.Dot11 in pckt:
            return
        dot11_pckt = pckt[scapy.layers.dot11.Dot11]
        self.dot11_pcktcount += 1

        if dot11_pckt.isFlagSet('type', 'Control'):
            return

        # Get a AP and a ESSID from a Beacon
        if scapy.layers.dot11.Dot11Beacon in dot11_pckt:
            self._add_ap(dot11_pckt.addr2, dot11_pckt)
            return

        # Get a AP and it's ESSID from a AssociationRequest
        if scapy.layers.dot11.Dot11AssoReq in dot11_pckt:
            self._add_ap(dot11_pckt.addr1, dot11_pckt)

        # Get a AP and it's ESSID from a ProbeResponse
        if scapy.layers.dot11.Dot11ProbeResp in dot11_pckt:
            self._add_ap(dot11_pckt.addr2, dot11_pckt)

        # From now on we are only interested in unicast packets
        if dot11_pckt.isFlagSet('FCfield', 'to-DS') \
           and not int(dot11_pckt.addr2[1], 16) & 1:
            ap_mac = dot11_pckt.addr1
            sta_mac = dot11_pckt.addr2
        elif dot11_pckt.isFlagSet('FCfield', 'from-DS') \
                and not int(dot11_pckt.addr1[1], 16) & 1:
            ap_mac = dot11_pckt.addr2
            sta_mac = dot11_pckt.addr1
        else:
            return

        # May result in 'anonymous' AP
        self._add_ap(ap_mac, dot11_pckt)
        ap = self.air[ap_mac]

        self._add_station(ap, sta_mac)
        sta = ap[sta_mac]

        if EAPOL_WPAKey in dot11_pckt:
            wpakey_pckt = dot11_pckt[EAPOL_WPAKey]
        elif EAPOL_RSNKey in dot11_pckt:
            wpakey_pckt = dot11_pckt[EAPOL_RSNKey]
        else:
            return

        # Frame 1: pairwise set, install unset, ack set, mic unset
        # results in ANonce
        if wpakey_pckt.areFlagsSet('KeyInfo', ('pairwise', 'ack')) \
           and wpakey_pckt.areFlagsNotSet('KeyInfo', ('install', 'mic')):
            self._add_keypckt(sta, 0, pckt)

        # Frame 2: pairwise set, install unset, ack unset, mic set,
        # SNonce != 0. Results in SNonce, MIC and keymic_frame
        elif wpakey_pckt.areFlagsSet('KeyInfo', ('pairwise', 'mic')) \
                and wpakey_pckt.areFlagsNotSet('KeyInfo', ('install', 'ack')) \
                and not all(c == '\x00' for c in wpakey_pckt.Nonce):
            self._add_keypckt(sta, 1, pckt)

        # Frame 3: pairwise set, install set, ack set, mic set
        # Results in ANonce
        elif wpakey_pckt.areFlagsSet(
            'KeyInfo',
            ('pairwise', 'install', 'ack', 'mic')
        ):
            self._add_keypckt(sta, 2, pckt)

    def __iter__(self):
        return [
            ap for essid,
            ap in sorted([(ap.essid, ap) for ap in self.air.itervalues()])
        ].__iter__()

    def __getitem__(self, bssid):
        return self.air[bssid]

    def __contains__(self, bssid):
        return bssid in self.air

    def __len__(self):
        return len(self.air)
