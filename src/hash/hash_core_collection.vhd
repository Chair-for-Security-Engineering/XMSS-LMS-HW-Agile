----------------------------------------------------------------------------------
-- Company: Ruhr-University Bochum / Chair for Security Engineering
-- Engineer: Jan Philipp Thoma, Darius Hartlief
-- 
-- Create Date: 13.08.2020
-- Project Name: Full XMSS Hardware Accelerator
----------------------------------------------------------------------------------


library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

-- use work.params.all;
-- use work.module_types.all;

entity hash_core_collection is
    generic(
        N: integer;
        HASH_CORES: integer;

        HASH_BUS_ADDRESS_WIDTH: integer;
        HASH_BUS_LENGTH_WIDTH: integer
    );
    port( 
        clk: in std_logic;
        reset: in std_logic;

        enable: in std_logic;
        len:    in unsigned( HASH_BUS_LENGTH_WIDTH - 1 downto 0 );
        input:  in std_logic_vector( 8 * N - 1 downto 0 );
        id:       in unsigned(HASH_BUS_ADDRESS_WIDTH - 1 downto 0);
        blockctr: in unsigned(2 downto 0);

        busy, idle:    out std_logic;
        done:          out std_logic;
        done_id:       out unsigned(HASH_BUS_ADDRESS_WIDTH - 1 downto 0);
        done_blockctr: out unsigned(2 downto 0);
        output:        out std_logic_vector( 8 * N - 1 downto 0);

        mnext:         out std_logic;
        next_id:       out unsigned(HASH_BUS_ADDRESS_WIDTH - 1 downto 0);
        next_blockctr: out unsigned(2 downto 0)
    );
end hash_core_collection;

architecture Behavioral of hash_core_collection is
    constant ALL_ONES : std_logic_vector( HASH_CORES - 1 downto 0 ) := ( others => '1' );
    constant ALL_ZEROS : std_logic_vector( HASH_CORES - 1 downto 0 ) := ( others => '0' );
    
    type hash_output_array is array ( HASH_CORES - 1 downto 0 ) of std_logic_vector( n*8-1 downto 0 );
    type hash_id is record
        id: unsigned(HASH_BUS_ADDRESS_WIDTH - 1 downto 0);
        blockctr: unsigned(2 downto 0);
    end record;
    type id_array is array ( HASH_CORES - 1 downto 0 ) of hash_id; -- ID = block_ctr || id
    type reg_type is record 
        done_queue, mnext : std_logic_vector( HASH_CORES - 1 downto 0 );
        ids : id_array;
        busy_indicator, halt_indicator : std_logic_vector( HASH_CORES - 1 downto 0 );
        busy : std_logic;
    end record;
    
    signal hash_outputs : hash_output_array;
    signal i_mnext, i_done, i_enable : std_logic_vector( HASH_CORES - 1 downto 0 );
    
    signal r, r_in : reg_type;
begin
    CoresGenerate: for i in 0 to HASH_CORES - 1 generate
        sha: entity work.absorb_message
        generic map(HASH_BUS_LENGTH_WIDTH => HASH_BUS_LENGTH_WIDTH)
        port map(
            clk => clk,
            reset => reset,
            enable => i_enable(i),
            len => len,
            input => input,
            halt => r_in.halt_indicator(i),
            done => i_done(i),
            mnext => i_mnext(i),
            o => hash_outputs(i) 
        );
    end generate CoresGenerate;
   
    idle <= '1' when r.busy_indicator = ALL_ZEROS else '0';
    busy <= r.busy;

    combinational : process ( r, enable, id, blockctr, i_mnext, i_done, hash_outputs )
        variable v : reg_type;
    begin
        v := r;       
        done <= '0';
        output <= ( others => '-' );
        next_id <= (others => '0');
        next_blockctr <= (others => '0');
        done_id <= (others => '0');
        done_blockctr <= (others => '0');
        mnext <= '0';
        v.busy := '0';
        i_enable <= (others => '0');       
       
        -- If two done signals appear simultaneously, we need to schedule them --> First prepare a queue of
        -- finished cores
        v.done_queue := r.done_queue or i_done;

       
        -- Output the mnext signal for the Core identified in the previous cycle ( Loop above )
        -- Data is expected in THE SAME cycle. Release halt which may be set in the event
        -- that multiple hash cores had mnext simultaniously.
        for k in 0 to HASH_CORES -1 loop
            if r.mnext( k ) = '1' then
                mnext <= '1';
                v.mnext( k ) := '0';
                v.halt_indicator( k ) := '0';
                v.ids( k ).blockctr := r.ids( k ).blockctr + 1;
                next_id <= v.ids(k).id;
                next_blockctr <= v.ids(k).blockctr;
            end if;
        end loop;
       
       
        -- Iterate through all cores until the first mnext signal is found. The hash module
        -- expects the next message block in the next cycle.
        for k in 0 to HASH_CORES -1 loop
            if i_mnext(k) = '1' or r.halt_indicator( k ) = '1' then
                v.busy := '1'; -- next cycle will be mnext data -> Prevent other modules to send anything else ( e.g. enable )
                v.mnext( k ) := '1';
                exit;
            end if;
        end loop;
        
        -- To cover the case where multiple mnext signals occur in the same cycle,
        -- Halt all other Cores that send an mnext signal.
        v.halt_indicator := ( r.halt_indicator or i_mnext ) xor v.mnext;
       
        -- Look for done signals and output the first.
        -- Release busy from the respective hash core.
        for k in 0 to HASH_CORES -1 loop
            if r.done_queue( k ) = '1' then
                done <= '1';
                v.done_queue( k ) := '0';
                v.busy_indicator( k ) := '0';
                done_id <= r.ids( k ).id;
                done_blockctr <= r.ids(k).blockctr;
                output <= hash_outputs( k );
                exit;
            end if;
        end loop;
       
        -- When the enable signal is set, look for the first hash core that is not
        -- busy and forward the signal. Also save the ID for future use.       
        if enable = '1' then
            for k in 0 to HASH_CORES -1 loop
                if r.busy_indicator( k ) = '0' then
                    i_enable( k ) <= '1';
                    v.busy_indicator( k ) := '1';
                    v.ids( k ).id := id;
                    v.ids(k).blockctr := blockctr;
                    exit;
                end if;
            end loop;
        end if;
       
        -- Indicate whether all cores are busy ( if so, no enable must be send )
        if v.busy_indicator = ALL_ONES then
            v.busy := '1';
        end if;
       
        r_in <= v;
    end process;
    
    sequential : process( clk )
   -- variable v : reg_type;
    begin
        if rising_edge( clk ) then
            if reset = '1' then
                -- Zero init queues.
                r.busy_indicator <= ( others => '0' );
                r.done_queue <= ( others => '0' );
                r.mnext <= ( others => '0' );
                r.halt_indicator <= ( others => '0' );
            else
                r <= r_in;
            end if;
        end if;
    end process;
end Behavioral;
