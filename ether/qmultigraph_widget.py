#!/usr/bin/env python
# -*- coding: utf-8 -*-
#

##############################################################################
import sys

from PyQt4 import QtCore
from PyQt4 import QtGui
from PyQt4 import QtSvg
from qnetwork_graph import QNetworkGraph
import pydot
import networkx
import logging
import utils
import tempfile
import os
##############################################################################


def coordsGen():
    row = 0
    column = 0
    while True:
        for iRow in xrange(row):
            yield (iRow, column)

        for iColumn in xrange(column):
            yield (row, iColumn)

        yield (row, column)
        row += 1
        column += 1


def svg2scene(svg, parent=None):
    byteArray = QtCore.QByteArray(svg)
    renderer = QtSvg.QSvgRenderer(byteArray)
    svgItem = QtSvg.QGraphicsSvgItem()
    svgItem.setSharedRenderer(renderer)
    scene = QtGui.QGraphicsScene(parent)
    scene.addItem(svgItem)
    return scene


def makeDotSvgGraph(g):
    # build dot graph
    graph = pydot.Dot()
    centerMac = g.center.name()
    centerEssid = g.center.hName()
    center = pydot.Node("%s\n%s" % (centerMac, centerEssid))
    graph.add_node(center)
    for n, e in g.nodes():
        gnode = pydot.Node(n.name())
        gedge = pydot.Edge(src=center.get_name(), dst=gnode.get_name())
        setupEdge(gedge, e)
        graph.add_node(gnode)
        graph.add_edge(gedge)
    ps = graph.create_svg()
    return ps


def create_svg(dot_path):
    return utils.readProcess(['dot', '-Tsvg', dot_path])


def makeNxSvgGraph(g):
    fd, fname = tempfile.mkstemp()
    os.close(fd)
    networkx.write_dot(g, fname)
    result = create_svg(fname)
    return result


def setupEdge(dotEdge, nEdge):
    cPkt, cKey, auth = nEdge.getInfo()
    color = None
    if cKey > 1:
        color = 'red'
    if auth:
        color = 'green'
    if color is None:
        color = 'blue'

    label = "%d|%d" % (cPkt, cKey)
    dotEdge.set_color(color)
    dotEdge.set_label(label)


class QNetworkGraphViewer(QtGui.QWidget):
    def __init__(self, graph, parent=None):
        super(QNetworkGraphViewer, self).__init__(parent)

        self.graph = graph
        graph.updateGraph.connect(self.updateGraph)

        self.setLayout(QtGui.QVBoxLayout())

        self.w = None
        self.logger = logging.getLogger('QNetworkGraphViewer')

    def updateGraph(self):
        self.logger.debug('updateGraph called')
        if self.w is None:
            self.w = self.makeGraphWidget(self.graph.getNxGraph())
            self.layout().addWidget(self.w)
            self.w.show()
        else:
            self.updateGraphWidget()

    def makeScene(self, g):
        svgGraph = makeNxSvgGraph(g)
        return svg2scene(svgGraph)

    def updateGraphWidget(self):
        scene = self.makeScene(self.graph.getNxGraph())
        self.w.setScene(scene)

    def makeGraphWidget(self, g):
        scene = self.makeScene(g)
        view = QtGui.QGraphicsView(scene, self)
        view.setInteractive(True)
        view.setDragMode(QtGui.QGraphicsView.ScrollHandDrag)
        return view


def main():
    logging.basicConfig(level=logging.DEBUG)
    iface = 'wlan2'

    if len(sys.argv) > 1:
        iface = sys.argv[1]

    app = QtGui.QApplication(sys.argv)
    graph = QNetworkGraph(iface)
    graph.open(iface)
    viewer = QNetworkGraphViewer(graph)
    viewer.showMaximized()

    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
