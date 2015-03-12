#!/usr/bin/env python
# -*- coding: utf-8 -*-
#

##############################################################################
from ether import qnetworkanalyzer
import os
##############################################################################


def main():
    if os.getuid() != 0:
        print 'Is not root'
        return
    qnetworkanalyzer.main()


if __name__ == '__main__':
    main()
