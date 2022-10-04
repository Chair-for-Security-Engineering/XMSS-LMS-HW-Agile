create_project hss-hdl ./.vivado -part xc7a35tcpg236-3

set vivdir [get_property DIRECTORY [current_project]]
set dir $vivdir/..

set_property target_language VHDL [current_project]
set_property simulator_language VHDL [current_project]
add_files $dir/src/
add_files $dir/config.vhd
add_files -fileset constrs_1 $dir/constraints/
add_files -fileset sim_1 $dir/tb/

set_property top hss_timing_tb [get_filesets sim_1]

# Needed for in place generation of bram
set_property simulator_language Mixed [current_project]

create_ip -name blk_mem_gen -vendor xilinx.com -library ip -version 8.4 -module_name blk_mem_gen_0
set_property -dict [list                                                \
        CONFIG.Memory_Type {True_Dual_Port_RAM}                         \
        CONFIG.Assume_Synchronous_Clk {true}                            \
        CONFIG.Write_Width_A {256}                                      \
        CONFIG.Write_Depth_A {316}                                      \
        CONFIG.Read_Width_A {256}                                       \
        CONFIG.Write_Width_B {256}                                      \
        CONFIG.Read_Width_B {256}                                       \
        CONFIG.Enable_B {Use_ENB_Pin}                                   \
        CONFIG.Register_PortB_Output_of_Memory_Primitives {true}        \
        CONFIG.Port_B_Clock {100}                                       \
        CONFIG.Port_B_Write_Rate {50}                                   \
        CONFIG.Port_B_Enable_Rate {100}                                 \
        CONFIG.Register_PortA_Output_of_Memory_Primitives {false}       \
        CONFIG.Register_PortB_Output_of_Memory_Primitives {false}       \
    ] [get_ips blk_mem_gen_0]

set_property generate_synth_checkpoint false [get_files $vivdir/hss-hdl.srcs/sources_1/ip/blk_mem_gen_0/blk_mem_gen_0.xci]

create_ip -name blk_mem_gen -vendor xilinx.com -library ip -version 8.4 -module_name blk_mem_gen_1
set_property -dict [list                                                \
        CONFIG.Memory_Type {True_Dual_Port_RAM}                         \
        CONFIG.Assume_Synchronous_Clk {true}                            \
        CONFIG.Write_Width_A {256}                                      \
        CONFIG.Write_Depth_A {80}                                       \
        CONFIG.Read_Width_A {256}                                       \
        CONFIG.Write_Width_B {256}                                      \
        CONFIG.Read_Width_B {256}                                       \
        CONFIG.Enable_B {Use_ENB_Pin}                                   \
        CONFIG.Register_PortB_Output_of_Memory_Primitives {true}        \
        CONFIG.Port_B_Clock {100}                                       \
        CONFIG.Port_B_Write_Rate {50}                                   \
        CONFIG.Port_B_Enable_Rate {100}                                 \
        CONFIG.Register_PortA_Output_of_Memory_Primitives {false}       \
        CONFIG.Register_PortB_Output_of_Memory_Primitives {false}       \
    ] [get_ips blk_mem_gen_1]
set_property generate_synth_checkpoint false [get_files $vivdir/hss-hdl.srcs/sources_1/ip/blk_mem_gen_1/blk_mem_gen_1.xci]

exit
