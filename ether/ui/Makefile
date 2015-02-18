#
###############################################################################
#
###############################################################################

UI_FILES=mainwindow.ui select_iface_dialog.ui
PY_UI_FILES=mainwindow_ui.py select_iface_dialog_ui.py


all: ui

ui:	$(PY_UI_FILES)

clean:
	sudo rm -f *.pyc
	sudo rm -f *.pyo

clean_backup:
	rm *.py~
	rm *.ui~

%_ui.py: %.ui
	pyuic4 -o $@ $<
