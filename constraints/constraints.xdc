create_clock -period 10 -name clk [get_ports clk]

set_input_delay -clock [get_clocks clk] -min -add_delay 2.000 [get_ports {data_in[*]}]
set_input_delay -clock [get_clocks clk] -max -add_delay 2.000 [get_ports {data_in[*]}]
set_input_delay -clock [get_clocks clk] -min -add_delay 2.000 [get_ports {enable}]
set_input_delay -clock [get_clocks clk] -max -add_delay 2.000 [get_ports {enable}]
set_input_delay -clock [get_clocks clk] -min -add_delay 2.000 [get_ports {next_io}]
set_input_delay -clock [get_clocks clk] -max -add_delay 2.000 [get_ports {next_io}]
set_output_delay -clock [get_clocks clk] -min -add_delay 0.000 [get_ports {done}]
set_output_delay -clock [get_clocks clk] -max -add_delay 2.000 [get_ports {done}]
set_output_delay -clock [get_clocks clk] -min -add_delay 0.000 [get_ports {valid}]
set_output_delay -clock [get_clocks clk] -max -add_delay 2.000 [get_ports {valid}]
set_output_delay -clock [get_clocks clk] -min -add_delay 0.000 [get_ports {needs_keygen}]
set_output_delay -clock [get_clocks clk] -max -add_delay 2.000 [get_ports {needs_keygen}]
set_output_delay -clock [get_clocks clk] -min -add_delay 0.000 [get_ports {current_scheme}]
set_output_delay -clock [get_clocks clk] -max -add_delay 2.000 [get_ports {current_scheme}]
