library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

use work.hss_functions.all;
use work.hss_types.all;

entity wots_core_shared is
    generic(
        SCHEME: scheme_t;
        CHAINS: integer;

        N: integer;
        WOTS_W: integer;
        TREE_HEIGHT: integer;

        HASH_BUS_ID_WIDTH: integer;
        HASH_BUS_LEN_WIDTH: integer;
        HASH_BUS_CTR_WIDTH: integer;

        BRAM_ADDR_WIDTH: integer;
        BRAM_WOTS_KEY_ADDR: integer;
        BRAM_IO_ADDR_WIDTH: integer;
        BRAM_IO_WOTS_SIG_ADDR: integer
    );
    port(
        clk:   in std_logic;
        reset: in std_logic;

        enable:        in std_logic;
        scheme_select: in std_logic;
        mode:          in std_logic_vector(1 downto 0);

        message_digest: in std_logic_vector(8 * N - 1 downto 0);
        pub_seed:       in std_logic_vector(8 * N - 1 downto 0); -- pub_seed for XMSS, I for LMS
        leaf_index:     in std_logic_vector(TREE_HEIGHT - 1 downto 0); -- address for XMSS, q for LMS

        done:       out std_logic;

        -- hash bus
        h_enable: out std_logic;
        h_id:     out unsigned(HASH_BUS_ID_WIDTH - 1 downto 0);
        h_block:  out unsigned(HASH_BUS_CTR_WIDTH - 1 downto 0);
        h_len:    out unsigned(HASH_BUS_LEN_WIDTH - 1 downto 0);
        h_input:  out std_logic_vector(N * 8 - 1 downto 0);

        h_done:       in std_logic;
        h_done_id:    in unsigned(HASH_BUS_ID_WIDTH - 1 downto 0);
        h_done_block: in unsigned(HASH_BUS_CTR_WIDTH - 1 downto 0); 
        h_next:       in std_logic;
        h_next_id:    in unsigned(HASH_BUS_ID_WIDTH - 1 downto 0);
        h_next_block: in unsigned(HASH_BUS_CTR_WIDTH - 1 downto 0);
        h_output:     in std_logic_vector(N * 8 - 1 downto 0);
        h_busy:       in std_logic;
        h_idle:       in std_logic;

        -- internal bram
        b_we:      out std_logic;
        b_address: out std_logic_vector(BRAM_ADDR_WIDTH - 1 downto 0);
        b_input:   out std_logic_vector(8 * N - 1 downto 0);
        b_output:  in std_logic_vector(8 * N - 1 downto 0);

        -- io bram
        b_io_we:      out std_logic;
        b_io_address: out std_logic_vector(BRAM_IO_ADDR_WIDTH - 1 downto 0);
        b_io_input:   out std_logic_vector(8 * N - 1 downto 0);
        b_io_output:  in std_logic_vector(8 * N - 1 downto 0)
    );
end entity;

architecture behavioral of wots_core_shared is
    constant WOTS_LOG_W: integer := log2(WOTS_W);
    constant WOTS_LEN1: integer := calculate_len1(N, WOTS_W);
    constant WOTS_LEN2: integer := calculate_len2(N, WOTS_W);
    constant WOTS_LEN: integer := WOTS_LEN1 + WOTS_LEN2;
    constant WOTS_LOG_LEN: integer := log2(WOTS_LEN) + 1; -- Since WOTS_W is a power of 2, this needs to be rounded up.

    type state_t is (S_IDLE, S_READ_SK_1, S_READ_SK_2, S_CHAIN_START, S_DONE_CHECK, S_DONE);
    type bram_state_t is (B_READ_START, B_WRITE_PK, B_WRITE_SIG);

    -- chain addressing types
    type chain_output_array_t is array(0 to CHAINS - 1) of std_logic_vector(N * 8 - 1 downto 0);
    type chain_index_array_t is array(0 to CHAINS - 1) of unsigned(WOTS_LOG_LEN - 1 downto 0);

    type hash_enable_array_t is array(0 to CHAINS - 1) of std_logic;
    type hash_id_array_t is array(0 to CHAINS - 1) of unsigned(HASH_BUS_ID_WIDTH - 1 downto 0);
    type hash_block_array_t is array(0 to CHAINS - 1) of unsigned(HASH_BUS_CTR_WIDTH - 1 downto 0);
    type hash_input_array_t is array(0 to CHAINS - 1) of std_logic_vector(N * 8 - 1 downto 0);
    type hash_len_array_t is array(0 to CHAINS - 1) of unsigned(HASH_BUS_LEN_WIDTH - 1 downto 0);

    -- chain signals
    signal chain_input: std_logic_vector(N * 8 - 1 downto 0);
    signal chains_output: chain_output_array_t;
    signal chains_index: chain_index_array_t;
    signal chain_start, chain_end: unsigned(WOTS_LOG_W - 1 downto 0);
    signal chain_index: unsigned(WOTS_LOG_LEN - 1 downto 0);

    signal chains_h_enable: std_logic_vector(0 to CHAINS - 1);
    signal chains_h_id: hash_id_array_t;
    signal chains_h_block: hash_block_array_t;
    signal chains_h_input: hash_input_array_t;
    signal chains_h_len: hash_len_array_t;
    signal hash_indicator: unsigned(CHAINS - 1 downto 0);

    signal chains_enable, chains_busy, chains_done: std_logic_vector(CHAINS - 1 downto 0);
    constant CHAIN_ZERO: std_logic_vector(CHAINS - 1 downto 0) := (others => '0');
    constant CHAIN_ONE: std_logic_vector(CHAINS - 1 downto 0) := (others => '1');

    -- base_w operation and signals
    type base_w_array_t is array(WOTS_LEN - 1 downto 0) of std_logic_vector(WOTS_LOG_W - 1 downto 0);

    function base_w(input: in std_logic_vector) return base_w_array_t is
        variable sum : unsigned(WOTS_LEN2 * WOTS_LOG_W - 1 downto 0);
        variable result : base_w_array_t;
        variable input_cpy : std_logic_vector(N * 8 - 1 downto 0);
    begin
        sum := to_unsigned(( WOTS_W - 1 ) * WOTS_LEN1, sum'length);
        input_cpy := input;

        for i in 0 to WOTS_LEN1 - 1 loop
            result(i) := input_cpy(N * 8 - 1 downto N * 8 - WOTS_LOG_W);
            input_cpy := std_logic_vector(shift_left(unsigned(input_cpy), WOTS_LOG_W));
        end loop;
        
        for i in 0 to WOTS_LEN1 - 1 loop
            sum := sum - (to_unsigned(0, sum'length - WOTS_LOG_W) & unsigned(result(i)));
        end loop;
        
        for i in WOTS_LEN1 to WOTS_LEN - 1 loop
            result(i) := std_logic_vector(sum(sum'length - 1 downto sum'length - WOTS_LOG_W ));
            sum := shift_left(sum, WOTS_LOG_W);
        end loop;
        
        return result;
    end function;

    signal msg_and_checksum: base_w_array_t;
    signal msg_part: unsigned(WOTS_LOG_W - 1 downto 0);

    -- internal signals
    signal bram_offset: unsigned(WOTS_LOG_LEN - 1 downto 0);
    signal chain: integer range 0 to CHAINS - 1;
    signal bram_state: bram_state_t;
    signal bram_write: std_logic;
    signal hash_select_stable: unsigned(CHAINS - 1 downto 0);

    type register_t is record
        state: state_t;
        chain_index: integer range 0 to WOTS_LEN;
        done_indicator: std_logic_vector(CHAINS - 1 downto 0);
        hash_select: unsigned(CHAINS - 1 downto 0);
    end record;

    constant REG_RESET: register_t := (
        state => S_IDLE, 
        chain_index => 0,
        done_indicator => (others => '0'),
        hash_select => (others => '0')
    );

    signal reg, nreg: register_t;
begin
    hash_chain_collection: for i in 0 to CHAINS - 1 generate
        chain: entity work.wots_chain_shared
        generic map( 
            SCHEME => SCHEME,

            ID => i,

            N => N,
            WOTS_W => WOTS_W,
            TREE_HEIGHT => TREE_HEIGHT,

            HASH_BUS_ID_WIDTH => HASH_BUS_ID_WIDTH,
            HASH_BUS_LEN_WIDTH => HASH_BUS_LEN_WIDTH,
            HASH_BUS_CTR_WIDTH => HASH_BUS_CTR_WIDTH
        )
        port map(
            clk => clk,
            reset => reset,

            enable => chains_enable(i),
            scheme_select => scheme_select,

            input => chain_input,
            pub_seed => pub_seed,
            leaf_index => leaf_index,
            chain_index => chain_index,
            chain_start => chain_start,
            chain_end => chain_end,
            hash_available => hash_indicator(i),

            busy => chains_busy(i),
            done => chains_done(i),
            output => chains_output(i),
            working_index => chains_index(i),

            h_done => h_done,
            h_done_id => h_done_id,
            h_done_block => h_done_block,
            h_next_block => h_next_block,
            h_output => h_output,

            h_enable => chains_h_enable(i),
            h_id => chains_h_id(i),
            h_block => chains_h_block(i),
            h_len => chains_h_len(i),
            h_input => chains_h_input(i)
        );
    end generate;

    msg_and_checksum <= base_w(message_digest);
    msg_part <= unsigned(msg_and_checksum(reg.chain_index)) when reg.chain_index < WOTS_LEN else (others => '0');

    bram_offset <= chains_index(chain);

    b_input <= chains_output(chain);
    b_io_input <= chains_output(chain);

    hash_select_stable <= reg.hash_select when h_next = '0' or reg.state = S_IDLE else shift_left(to_unsigned(1, CHAINS), to_integer(h_next_id));
    hash_indicator <= hash_select_stable when h_busy = '0' else (others => '0');

    chain_index <= to_unsigned(reg.chain_index, WOTS_LOG_LEN);
    chain_input <= b_io_output when mode = "10" else b_output;
    -- Start the chain at for verifying and at 0 for sign and keygen.
    chain_start <= msg_part when mode = "10" else (others => '0');
    -- End the chain at msg for signing and at W for keygen and verify.
    chain_end <= msg_part when mode = "01" else to_unsigned(WOTS_W - 1, WOTS_LOG_W);

    b_we <= '0' when mode = "01" else bram_write;
    b_io_we <= bram_write when mode = "01" else '0';

    hash_mux: process(hash_select_stable, chains_h_enable, chains_h_id, chains_h_block, chains_h_len, chains_h_input)
    begin
        h_enable <= '0';
        h_id <= (others => '-');
        h_block <= (others => '-');
        h_len <= (others => '-');
        h_input <= (others => '-');
        for i in 0 to CHAINS - 1 loop
            if hash_select_stable(i) = '1' then
                h_enable <= chains_h_enable(i);
                h_id <= chains_h_id(i);
                h_block <= chains_h_block(i);
                h_len <= chains_h_len(i);
                h_input <= chains_h_input(i);
            end if;
        end loop;
    end process;

    combinational: process(reg, enable, chains_done, chains_busy, h_next, mode)
        variable done_indicator: std_logic_vector(CHAINS - 1 downto 0);
    begin
        nreg <= reg;

        done <= '0';
        bram_write <= '0';

        chains_enable <= (others => '0');
        chain <= 0;
        bram_state <= B_READ_START;

        done_indicator := reg.done_indicator or chains_done;
        nreg.done_indicator <= done_indicator;

        if h_next = '0' then
            nreg.hash_select <= rotate_left(reg.hash_select, 1);
        end if;
        
        case reg.state is
            when S_IDLE => 
                if enable = '1' then
                    nreg.hash_select <= (0 => '1', others => '0');
                    nreg.chain_index <= 0;
                    nreg.state <= S_READ_SK_1;
                    nreg.done_indicator <= (others => '0');
                end if;

            when S_READ_SK_1 =>
                nreg.state <= S_READ_SK_2;

            when S_READ_SK_2 =>
                nreg.state <= S_CHAIN_START;

            when S_CHAIN_START =>
                for i in 0 to CHAINS - 1 loop
                    -- Only enable chains that are not waiting for their output to be read.
                    if chains_busy(i) = '0' and done_indicator(i) = '0' then
                        chains_enable(i) <= '1';
                        nreg.chain_index <= reg.chain_index + 1;
                        -- Only enable one chain at a time, since the start of the 
                        -- next chain needs to be fetched from BRAM.
                        exit; 
                    end if;
                end loop;
                nreg.state <= S_DONE_CHECK;

            when S_DONE_CHECK =>
                if mode = "01" then
                    bram_state <= B_WRITE_SIG;
                else
                    bram_state <= B_WRITE_PK;
                end if;

                for i in 0 to CHAINS - 1 loop
                    if done_indicator(i) = '1' then
                        chain <= i;
                        nreg.done_indicator(i) <= '0';
                        bram_write <= '1';
                        exit; -- Only one value can be written to the BRAM at a time.
                    end if;
                end loop;

                -- Stays in the done check if all chains are busy, since no
                -- new chain can be enabled.
                if reg.chain_index = WOTS_LEN then
                    if chains_busy = CHAIN_ZERO then
                        nreg.state <= S_DONE; -- done state to reduce critical path
                    end if;
                elsif chains_busy /= CHAIN_ONE then
                    nreg.state <= S_READ_SK_1;
                end if;

            when S_DONE =>
                done <= '1';
                nreg.state <= S_IDLE;
        end case;
    end process;

    bram_mux: process(bram_state, reg.chain_index, mode, bram_offset)
    begin
        b_address <= (others => '0');
        b_io_address <= (others => '0');
        case bram_state is
            when B_READ_START =>
                if mode = "10" then
                    b_io_address <= std_logic_vector(to_unsigned(BRAM_IO_WOTS_SIG_ADDR, BRAM_IO_ADDR_WIDTH) + reg.chain_index);
                else
                    b_address <= std_logic_vector(to_unsigned(BRAM_WOTS_KEY_ADDR, BRAM_ADDR_WIDTH) + reg.chain_index);
                end if;
            when B_WRITE_PK =>
                b_address <= std_logic_vector((to_unsigned(0, BRAM_ADDR_WIDTH - WOTS_LOG_LEN) & bram_offset) + BRAM_WOTS_KEY_ADDR);
            when B_WRITE_SIG =>
                b_io_address <= std_logic_vector((to_unsigned(0, BRAM_IO_ADDR_WIDTH - WOTS_LOG_LEN) & bram_offset) + BRAM_IO_WOTS_SIG_ADDR);
        end case;
    end process;

    sequential: process(clk, reset)
    begin
        if rising_edge(clk) then
            if reset = '1' then
                reg <= REG_RESET;
            else
                reg <= nreg;
            end if;
        end if;
    end process;

end architecture;
