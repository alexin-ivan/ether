#!/usr/bin/env python
# -*- coding: utf-8 -*-
#

##############################################################################
import os
import logging
from PyQt4.QtGui import QDialog
from PyQt4.QtCore import QString
##############################################################################
import utils
from ui.select_iface_dialog_ui import Ui_Dialog as SelectDialogUi
from wirelessdevice import WiDevice
##############################################################################
try:
    _fromUtf8 = QString.fromUtf8
except AttributeError:
    def _fromUtf8(s):
        return s

DN = open(os.devnull, 'wb')
##############################################################################


class IFlist(object):
    def __init__(self, iface=None):
        self.iface = None
        self.logger = logging.getLogger('IFlist')

    def ask(self, title, select_title, variants, disableRndMac=False):
        if len(variants) == 1:
            return variants[0]

        ui = SelectDialogUi()
        dialog = QDialog()
        ui.setupUi(dialog)
        ui.lTitle.setText(_fromUtf8(title))
        ui.lSelect.setText(_fromUtf8(select_title))
        ui.iflist.addItems(map(lambda x: x.iface(), variants))
        if disableRndMac:
            ui.cbAnonymize.setChecked(False)
            ui.cbAnonymize.setEnabled(False)
        result = dialog.exec_()
        iface = None
        if result:
            ix = ui.iflist.currentIndex()
            fAnonymize = ui.cbAnonymize.isChecked()
            iface = variants[ix]
            iface.fRandomMac = fAnonymize
        self.logger.debug('Selected %s iface in dialog', self.iface)
        return iface

    def getMonitors(self):
        monitors, _ = utils.getMonitorsAndAdaptersFromIwconfig()
        return monitors

    def get_iface(self):
        monitors, adapters = utils.getMonitorsAndAdaptersFromIwconfig()

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
                    self.logger.warning(
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
        if monitors:
            # если "мониторов" несколько, то спрашиваем пользователя:
            return self.ask(
                "Интерфейсы в режиме мониторинга:",
                "Выберите интерфейс для работы",
                map(lambda x: WiDevice(x, True), monitors),
                True
            )

        # Сюда мы попадём, если на предыдущих этапах не было найдено
        # устройств в режиме мониторинга.
        # Спрашиваем их список у airmon-ng (Aircrack)
        monitors = utils.getDevicesFromAirmon()

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
                    return WiDevice(self.iface)

        # сюда мы попадём только в том случае, если
        # airmon увидел устройство, а iwconfig - нет.
        # Такая ситуация маловероятная, но всё же...
        # Спрашиваем пользователя о том, какое устройство ему нужно
        result = self.ask(
            "Доступные Wi-Fi устройства",
            'Выберите интерфейс для переключения его в режим мониторинга',
            map(lambda x: WiDevice(x), monitors)
        )
        return result


def main():
    from PyQt4.QtGui import QApplication
    import sys
    logging.basicConfig(level=logging.DEBUG)
    app = QApplication(sys.argv)
    iflist = IFlist()
    iface = iflist.get_iface()
    print 'IFACE:', str(iface)
    return
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
