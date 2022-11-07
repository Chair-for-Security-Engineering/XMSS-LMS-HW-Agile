# Hash-based Signature Schemes
A VHDL implementation of the XMSS and LMS signature schemes from the paper `Agile Acceleration of Stateful Hash-Based Signatures in Hardware` [(Link)](https://doi.org/10.1145/3567426).

## Setup
The supplied Makefile creates a .vivado subdirectory, initializes a vivado
project with all vhdl files in `src/`, the constraints in `constraints/`, and
all files in `tb/` as simulation sources. Afterwards it adds the dual-port bram
using the vivado ip generator. 

To use the Makefile, the `VIVADO` parameter must point to a vivado installation.

To initialize the project without make, execute:
```/path/to/vivado -mode tcl -source setup_project.tcl```


This project was supported through:

    the Federal Ministry of Education and Research of Germany QuantumRISC project (16KIS1038)
    the Federal Ministry of Education and Research of Germany PQC4Med project (16KIS1044)
    the Deutsche Forschungsgemeinschaft (DFG, German Research Foundation) under Germany’s Excellence Strategy - EXC 2092 CASA - 390781972
