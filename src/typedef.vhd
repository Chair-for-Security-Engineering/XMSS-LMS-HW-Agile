library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

use work.params.all;

package types is
    type wrapper_input_t is record
        enable : std_logic;

        message : std_logic_vector( 8 * N - 1 downto 0 );
        message_length : unsigned( HASH_BUS_LENGTH_BITS - 1 downto 0 );

        true_random : std_logic_vector( ( 3 * N ) * 8 - 1 downto 0 );

        -- 00 : Key generation
        -- 01 : Sign
        -- 10 : Verify
        mode : std_logic_vector( 1 downto 0 );

        -- If the selected scheme needs a new key, the needs_keygen is high in 
        -- the next clk cycle. The done signal remains low, since the core never 
        -- started any operations.
        -- 0 : LMS
        -- 1 : XMSS
        scheme_select : std_logic;
    end record;

    type wrapper_output_t is record
        done : std_logic;
        valid : std_logic;

        lms_mnext : std_logic; -- unused when configured with xmss
        needs_keygen : std_logic;
    end record;

    type wrapper_io_input_t is record
       enable  : std_logic;
       data_in : std_logic_vector(63 downto 0);
    end record;
    
    type wrapper_io_output_t is record
       done : std_logic;
       valid : std_logic;
	end record;
end package;
