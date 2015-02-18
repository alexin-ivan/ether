
import os
import logging
from subprocess import Popen, call, PIPE
import random
from wirelessdevice import WiDevice


def program_exists(program):
    """
        Uses 'which' (linux command) to check if a program is installed.
    """

    proc = Popen(['which', program], stdout=PIPE, stderr=PIPE)
    txt = proc.communicate()
    if txt[0].strip() == '' and txt[1].strip() == '':
        return False
    if txt[0].strip() != '' and txt[1].strip() == '':
        return True

    r = not (txt[1].strip() == '' or txt[1].find('no %s in' % program) != -1)
    return r

__needs = ['iwconfig']


def get_mac_address(iface, DN):
    """
        Returns MAC address of "iface".
    """
    proc = Popen(['ifconfig', iface], stdout=PIPE, stderr=DN)
    proc.wait()
    mac = ''
    first_line = proc.communicate()[0].split('\n')[0]
    for word in first_line.split(' '):
        if word != '':
            mac = word
    if mac.find('-') != -1:
        mac = mac.replace('-', ':')
    if len(mac) > 17:
        mac = mac[0:17]
    return mac


def mac_anonymize(iface, DN):
    """
        Changes MAC address of 'iface' to a random MAC.
        Only randomizes the last 6 digits of the MAC,
            so the vender says the same.
        Stores old MAC address and the interface in ORIGINAL_IFACE_MAC
    """
    # Store old (current) MAC address
    proc = Popen(['ifconfig', iface], stdout=PIPE, stderr=DN)
    proc.wait()
    for word in proc.communicate()[0].split('\n')[0].split(' '):
        if word != '':
            old_mac = word

    new_mac = generate_random_mac(old_mac)

    call(['ifconfig', iface, 'down'])

    logging.info(
        "Changing %s's MAC from %s to %s." % (iface, old_mac, new_mac)
    )

    proc = Popen(
        ['ifconfig', iface, 'hw', 'ether', new_mac],
        stdout=PIPE,
        stderr=DN
    )
    proc.wait()
    call(['ifconfig', iface, 'up'], stdout=DN, stderr=DN)
    logging.info("Changing %s's MAC is done" % iface)
    return old_mac, new_mac


def generate_random_mac(old_mac):
    """
        Generates a random MAC address.
        Keeps the same vender (first 6 chars) of the old MAC address (old_mac).
        Returns string in format old_mac[0:9] + :XX:XX:XX where X is random hex
    """
    random.seed()
    new_mac = old_mac[:8].lower().replace('-', ':')
    for i in xrange(0, 6):
        if i % 2 == 0: new_mac += ':'
        new_mac += '0123456789abcdef'[random.randint(0, 15)]

    # Prevent generating the same MAC address via recursion.
    if new_mac == old_mac:
        new_mac = generate_random_mac(old_mac)
    return new_mac


class IFlist(object):
    def __init__(self, iface=None):
        self.iface = None
        self.DN = open(os.devnull, 'w')
        self.ERRLOG = open(os.devnull, 'w')
        self.OUTLOG = open(os.devnull, 'w')

    def ask(self, title, select_title, variants):
        pass

    def get_iface(self):
        proc = Popen(['iwconfig'], stdout=PIPE, stderr=self.DN)
        iface = ''
        monitors = []
        adapters = []
        for line in proc.communicate()[0].split('\n'):
            if len(line) == 0:
                continue
            if ord(line[0]) != 32:  # Doesn't start with space
                iface = line[:line.find(' ')]  # is the interface
            if line.find('Mode:Monitor') != -1:
                monitors.append(iface)
            else:
                adapters.append(iface)

        # устройство выбрано пользователем
        if self.iface is not None:
            if monitors.count(self.iface):
                # выбранное пользователем устройство
                # уже находится в режиме мониторинга
                return WiDevice(self.iface, True)
            else:
                if self.iface in adapters:
                    # устройство существует, но его необходимо
                    # переключить в режим мониторинга
                    # valid adapter, enable monitor mode
                    logging.warning(
                        'Could not find'
                        ' wireless interface "%s"'
                        ' in monitor mode' % self.iface
                    )
                    return WiDevice(self.iface)
                else:
                    # устройства нет не в числе adapter, ни в monitors,
                    # следовательно, устройство не существует в системе
                    # couldnt find the requested adapter
                    raise Exception(
                        'Could not find wireless interface "%s"' % self.iface
                    )

        # сюда мы попадаем, если пользователь не задал iface
        if len(monitors) == 1:
            return monitors[0]  # Default to only device in monitor mode
        elif len(monitors) > 1:
            # если "мониторов" несколько, то спрашиваем пользователя:
            return self.ask(
                "Interfaces in monitor mode",
                "Select interface to use for capturing",
                map(lambda x: WiDevice(x), monitors)
            )

        # Сюда мы попадём, если на предыдущих этапах не было найдено
        # устройств в режиме мониторинга.
        # Спрашиваем их список у airmon-ng (Aircrack)
        proc = Popen(['airmon-ng'], stdout=PIPE, stderr=self.DN)
        for line in proc.communicate()[0].split('\n'):
            if len(line) == 0 or line.startswith('Interface'):
                continue
            line = line[:line.find('\t')]
            monitors.append(line)

        # даже airmon ничего не нашёл. Уходим.
        if len(monitors) == 0:
            raise Exception(
                'No wireless interfaces were found.'
                'You need to plug in a wifi device or install drivers.'
            )
        elif self.iface is not None and monitors.count(self.iface) > 0:
            # сюда мы попадём только в том случае, если
            # airmon увидел устройство, а iwconfig - нет.
            # Такая ситуация маловероятная, но всё же...
            for monitor in monitors:
                if monitor.find(self.iface) != -1:
                    return WiDevice(iface)

        elif len(monitors) == 1:
            # одно устройство, и мы его возвращаем.
            return WiDevice(monitor[0])

        # сюда мы попадём только в том случае, если
        # airmon увидел устройство, а iwconfig - нет.
        # Такая ситуация маловероятная, но всё же...
        # Спрашиваем пользователя о том, какое устройство ему нужно
        result = self.ask(
            "Available wireless devices",
            'Select number of device to put into monitor mode',
            map(lambda x: WiDevice(x), monitors)
        )
        return self.enable_monitor_mode(result)

    def setTx(self, tx=None):

        if tx is not None:
            logging.info('Setting Tx power to %s.' % tx)
            call(['iw', 'reg', 'set', 'BO'], stdout=OUTLOG, stderr=ERRLOG)
            call(
                ['iwconfig', iface, 'txpower', str(tx)],
                stdout=OUTLOG,
                stderr=ERRLOG
            )
            stdout, stderr = p.communicate()
            if stdout:
                logger.info(stdout)
            if stderr:
                logger.error(stderr)
            logging.info('Setting is done.')

    def enable_monitor_mode(self, iface):
        """
            First attempts to anonymize the MAC if requested; MACs cannot
            be anonymized if they're already in monitor mode.
            Uses airmon-ng to put a device into Monitor Mode.
            Then uses the get_iface() method to retrieve the new interface's name.
            Sets global variable IFACE_TO_TAKE_DOWN as well.
            Returns the name of the interface in monitor mode.
        """
        mac_anonymize(iface, self.DN)
        logging.info('Enabling monitor mode on %s.' % iface)
        call(['airmon-ng', 'start', iface], stdout=self.DN, stderr=self.DN)
        print 'done'
        self.RUN_CONFIG.WIRELESS_IFACE = ''  # remove this reference as we've started its monitoring counterpart
        self.RUN_CONFIG.IFACE_TO_TAKE_DOWN = self.get_iface()
        return self.RUN_CONFIG.IFACE_TO_TAKE_DOWN
