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
import logging
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


def svg2scene(svg):
    byteArray = QtCore.QByteArray(svg)
    renderer = QtSvg.QSvgRenderer(byteArray)
    svgItem = QtSvg.QGraphicsSvgItem()
    svgItem.setSharedRenderer(renderer)
    scene = QtGui.QGraphicsScene()
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


class QParser(QtCore.QThread):
    def __init__(self, f, parent=None):
        super(QParser, self).__init__(parent)
        self.f = f

    def run(self):
        self.f()


class QNetworkGraphViewer(QtGui.QWidget):
    def __init__(self, graph, parent=None):
        super(QNetworkGraphViewer, self).__init__(parent)

        self.graph = graph
        graph.updateGraph.connect(self.updateGraph)

        self.views = {}
        self.setLayout(QtGui.QGridLayout(self))

        def parse():
            self.graph.parse()

        self.parser = QParser(parse)

        self.coordsGen = coordsGen()

    def open(self, iface):
        self.graph.open(iface)

    def addWidgetToGrid(self, w):
        row, column = self.coordsGen.next()
        self.layout().addWidget(w, row, column)

    def updateGraph(self, gname):
        logging.debug('signal updateGraph %s called', gname)
        v = self.views.get(gname)
        if not v:
            g = self.graph.getGraph(str(gname))
            w = self.makeGraphWidget(g)
            self.addWidgetToGrid(w)
            w.show()
            self.views[gname] = (g, w)
        else:
            logging.debug('Update SCENE')
            g, w = v
            self.updateGraphWidget(g, w)

    def start(self):
        self.parser.start()

    def close(self):
        self.graph.close()
        super(QNetworkGraphViewer, self).close()

    def makeScene(self, g):
        svgGraph = makeDotSvgGraph(g)
        return svg2scene(svgGraph)

    def updateGraphWidget(self, g, w):
        scene = self.makeScene(g)
        w.setScene(scene)

    def makeGraphWidget(self, g):
        scene = self.makeScene(g)
        view = QtGui.QGraphicsView(scene, self)
        view.setInteractive(True)
        view.setDragMode(QtGui.QGraphicsView.ScrollHandDrag)
        #view.show()
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
