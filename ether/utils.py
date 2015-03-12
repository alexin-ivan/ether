#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
##############################################################################
import os
import logging
from subprocess import Popen, call, PIPE
import random
##############################################################################
##############################################################################
DN = open(os.devnull, 'wb')
##############################################################################


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


# Программы, необходимые для работы
# '<название>':<обязятельность существования в системе>
progs = {
    'airmon-ng': False,
    'iw': False,
    'iwconfig': True,
    'ifconfig': True
}


# Проверка наличия программ, необходимых для работы программы
def checkDependens():
    for p, req in progs.iteritems():
        exists = program_exists(p)
        if req and not exists:
            raise Exception("Can't find prog %s." % p)
        progs[p] = exists


checkDependens()
del checkDependens


def callProcWithLog(popenargs):
    proc = Popen(
        popenargs,
        stdout=PIPE,
        stderr=PIPE
    )
    stdout, stderr = proc.communicate()
    if stdout:
        logging.info('[%s] %s', popenargs[0], stdout)
    if stderr:
        logging.error('[%s] %s', popenargs[0], stderr)

    return proc.returncode


def callWithoutOutput(popenargs):
    return call(popenargs, stdout=DN, stderr=DN)


def readProcess(popenargs):
    proc = Popen(
        popenargs,
        stdout=PIPE,
        stderr=PIPE
    )
    stdout, stderr = proc.communicate()
    if stderr:
        logging.error('[%s]', popenargs[0], stderr)

    if proc.returncode:
        raise Exception('Call error: %d code' % proc.returncode)

    return str(stdout)


def get_mac_address(iface):
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


def mac_anonymize(iface):
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

    callProcWithLog(['ifconfig', iface, 'down'])

    logging.info(
        "Changing %s's MAC from %s to %s." % (iface, old_mac, new_mac)
    )

    callProcWithLog(['ifconfig', iface, 'hw', 'ether', new_mac])
    callProcWithLog(['ifconfig', iface, 'up'])
    logging.info("Changing %s's MAC is done" % iface)
    return old_mac, new_mac


def mac_change_back(iface, old_mac):
    """
        Changes MAC address back to what it was before attacks began.
    """
    if iface is None or old_mac is None:
        return

    logging.info("Changing %s's mac back to %s" % (iface, old_mac))
    callWithoutOutput(['ifconfig', iface, 'down'])
    callProcWithLog(['ifconfig', iface, 'hw', 'ether', old_mac])
    callWithoutOutput(['ifconfig', iface, 'up'])
    logging.info("done")


def generate_random_mac(old_mac):
    """
        Generates a random MAC address.
        Keeps the same vender (first 6 chars) of the old MAC address (old_mac).
        Returns string in format old_mac[0:9] + :XX:XX:XX where X is random hex
    """
    random.seed()
    new_mac = old_mac[:8].lower().replace('-', ':')
    for i in xrange(0, 6):
        if i % 2 == 0:
            new_mac += ':'
        new_mac += '0123456789abcdef'[random.randint(0, 15)]

    # Prevent generating the same MAC address via recursion.
    if new_mac == old_mac:
        new_mac = generate_random_mac(old_mac)
    return new_mac


def getMonitorsAndAdaptersFromIwconfig():
    proc = Popen(['iwconfig'], stdout=PIPE, stderr=PIPE)
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
    return monitors, adapters


def getDevicesFromAirmon():
    monitors = []
    proc = Popen(['airmon-ng'], stdout=PIPE, stderr=DN)
    for line in proc.communicate()[0].split('\n'):
        if len(line) == 0 or line.startswith('Interface'):
            continue
        line = line[:line.find('\t')]
        monitors.append(line)
    return monitors


def setTx(iface, tx):
    """
    tx - double value of db ##
    """
    logging.info('Setting Tx power to %s.' % str(tx))
    callProcWithLog(['iw', 'reg', 'set', 'BO'])
    callWithoutOutput(['iwconfig', iface, 'txpower', str(tx)])
    logging.info('Setting is done.')


def __enable_monitor_mode(iface):
    """
        First attempts to anonymize the MAC if requested; MACs cannot
        be anonymized if they're already in monitor mode.
        Uses airmon-ng to put a device into Monitor Mode.
        Then uses the get_iface() method to retrieve the
        new interface's name.
        Returns the name of the interface in monitor mode.
    """
    logging.info('Enabling monitor mode on %s.' % iface)
    callWithoutOutput(['airmon-ng', 'start', iface])
    logging.info('done')


def __disable_monitor_mode(iface):
    """
        The program may have enabled monitor mode on a wireless interface.
        We want to disable this before we exit, so we will do that.
    """
    if iface is None:
        return
    logging.info('Disabling monitor mode on %s' % iface)
    callWithoutOutput(['airmon-ng', 'stop', iface])
    logging.info('done')
