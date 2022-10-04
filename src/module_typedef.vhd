library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

use work.params.all;

package module_types is
    type hash_id is record
        ctr : unsigned( HASH_BUS_ADDRESS_BITS - 1 downto 0 );
        block_ctr : unsigned( 2 downto 0 ); -- Needs to use WOTS_LOG_LEN for XMSS. TODO: generic over hash cores.
    end record;

	type hash_subsystem_input_t is record
	    id : hash_id;
        enable : std_logic;
        len : unsigned( HASH_BUS_LENGTH_BITS - 1 downto 0 );
        input : std_logic_vector( 8 * N - 1 downto 0 );
    end record;

	type hash_subsystem_output_t is record
        done : std_logic;
        done_id : hash_id;
        mnext : std_logic;
        o : std_logic_vector( 8 * N - 1 downto 0);
        busy, idle : std_logic;
        id : hash_id;
	end record;

    constant HASH_INPUT_DONT_CARE : hash_subsystem_input_t := ( enable => '0', id => ( others => ( others => '-' ) ), input => ( others => '-' ), len => ( others => '-' ) );
    constant HASH_OUTPUT_DONT_CARE : hash_subsystem_output_t := ( done => '-', done_id => ( others => ( others => '-' ) ), mnext => '-', o => ( others => '-' ), busy => '-', idle => '-', id => ( others => ( others => '-' ) ) );
	    
    type bram_input_t is record
        enable : std_logic;
        write_enable : std_logic;
        address : std_logic_vector( BRAM_ADDR_SIZE - 1 downto 0 );
        input : std_logic_vector( 8 * BRAM_ROW_SIZE - 1 downto 0 );
    end record;
    
    constant BRAM_INPUT_DONT_CARE : bram_input_t := ( enable => '0', write_enable => '0', address => ( others => '0' ), input => ( others => '0' ) );
    
    type bram_output_t is record
        output : std_logic_vector( 8 * BRAM_ROW_SIZE - 1 downto 0 ); 
    end record;
    
    type dual_port_bram_input_t is record
        a : bram_input_t;
        b : bram_input_t;
    end record;
    
    type dual_port_bram_output_t is record
        a : bram_output_t;
        b : bram_output_t;
    end record;

    type lms_bus_input_t is record
        enable : std_logic;

        -- Random input 
        -- For keygen takes 16 Bytes for I, N Bytes for seed.
        -- For sign takes N Bytes for C in message hash.
        true_random : std_logic_vector( 8 * ( 16 + N ) - 1 downto 0 );

        message_block : std_logic_vector( 8 * N - 1 downto 0 );
        length : unsigned( HASH_BUS_LENGTH_BITS - 1 downto 0 );

        -- "00" => Keygen
        -- "01" => Sign
        -- "10" => Verify
        mode : std_logic_vector( 1 downto 0 );
        
        hash : hash_subsystem_output_t;
        bram : dual_port_bram_output_t;
    end record;

    type lms_bus_output_t is record
        done : std_logic;
        mnext : std_logic;
        valid : std_logic;
        needs_keygen : std_logic;

        hash : hash_subsystem_input_t;
        bram : dual_port_bram_input_t;
    end record;

    type xmss_bus_input_type is record
        enable  : std_logic;

        message : std_logic_vector( 8 * N - 1 downto 0 );
        mlen : integer range 0 to XMSS_MAX_MLEN;

        mode : std_logic_vector( 1 downto 0 );
        true_random : std_logic_vector( ( 3 * n ) * 8 - 1 downto 0 );

        hash : hash_subsystem_output_t;
        bram : dual_port_bram_output_t;
    end record;
    
    type xmss_bus_output_type is record
        done : std_logic;
        valid : std_logic;
        needs_keygen : std_logic;

        hash : hash_subsystem_input_t;
        bram : dual_port_bram_input_t;
	end record;
end package;
