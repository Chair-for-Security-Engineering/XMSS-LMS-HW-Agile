VIVADO := /home/$(USER)/vivado/Vivado/2021.2/bin/vivado
TMPDIR := ./.vivado

all: project

export $(TMPDIR)
project: clean
	mkdir .vivado
	$(VIVADO) -mode tcl -source setup_project.tcl -log ./.vivado/vivado.log -journal ./.vivado/vivado.jou

clean:
	rm -rf .vivado
