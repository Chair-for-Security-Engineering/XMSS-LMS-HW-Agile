# Hash-based Signature Schemes
A VHDL implementation of the XMSS and LMS signature schemes.

## Setup
The supplied Makefile creates a .vivado subdirectory, initializes a vivado
project with all vhdl files in `src/`, the constraints in `constraints/`, and
all files in `tb/` as simulation sources. Afterwards it adds the dual-port bram
using the vivado ip generator. 

To use the Makefile, the `VIVADO` parameter must point to a vivado installation.

To initialize the project without make, execute:
```/path/to/vivado -mode tcl -source setup_project.tcl```
