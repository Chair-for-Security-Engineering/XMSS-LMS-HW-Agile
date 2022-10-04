library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

use work.hss_functions.all;
use work.hss_types.all;

entity lmots_compressor is
    generic(
        N: integer;
        WOTS_W: integer;
        TREE_HEIGHT: integer;

        HASH_BUS_ID_WIDTH: integer;
        HASH_BUS_LEN_WIDTH: integer;
        HASH_BUS_CTR_WIDTH: integer;

        BRAM_ADDR_WIDTH: integer;
        BRAM_WOTS_KEY_ADDR: integer
    );
    port(
        clk:   in std_logic;
        reset: in std_logic;

        enable: in std_logic;

        pub_seed:   in std_logic_vector(127 downto 0); -- I
        leaf_index: in std_logic_vector(TREE_HEIGHT - 1 downto 0); -- q

        done:   out std_logic;
        output: out std_logic_vector(8 * N - 1 downto 0);

        -- hash bus
        h_enable: out std_logic;
        h_id:     out unsigned(HASH_BUS_ID_WIDTH - 1 downto 0);
        h_block:  out unsigned(HASH_BUS_CTR_WIDTH - 1 downto 0);
        h_len:    out unsigned(HASH_BUS_LEN_WIDTH - 1 downto 0);
        h_input:  out std_logic_vector(N * 8 - 1 downto 0);

        h_done:       in std_logic;
        h_next:       in std_logic;
        h_output:     in std_logic_vector(N * 8 - 1 downto 0);
        h_idle:       in std_logic;

        -- internal bram
        b_we:      out std_logic;
        b_address: out std_logic_vector(BRAM_ADDR_WIDTH - 1 downto 0);
        b_input:   out std_logic_vector(8 * N - 1 downto 0);

        b_output: in std_logic_vector(8 * N - 1 downto 0)
    );
end entity;

architecture behavioral of lmots_compressor is
    constant WOTS_LOG_W: integer := log2(WOTS_W);
    constant WOTS_LEN: integer := calculate_len1(N, WOTS_W) + calculate_len2(N, WOTS_W);
    constant WOTS_LOG_LEN: integer := log2(WOTS_LEN) + 1;

    constant HASH_TWEAK_SIZE: integer := 128 + 32 + 16; -- Tweak size is the same for compression and leaf generation.
    constant D_PBLC: std_logic_vector(15 downto 0) := x"8080";
    constant D_LEAF: std_logic_vector(15 downto 0) := x"8282";

    type state_t is (S_IDLE, S_READ_PK_1, S_READ_PK_2, S_HASH_COMPRESS, S_LEAF_START, S_HASH_LEAF, S_DONE);

    type register_t is record
        state: state_t;
        chain_index: integer range 0 to WOTS_LEN;
        tmp: std_logic_vector(N * 8 - 1 downto 0);
    end record;

    constant REG_RESET: register_t := (
        state => S_IDLE, 
        chain_index => 0,
        tmp => (others => '0')
    );

    signal hash_select: std_logic_vector(1 downto 0);

    signal comp_h_input: std_logic_vector(8 * N - 1 downto 0);

    signal reg, nreg: register_t;
begin
    output <= reg.tmp;

    b_we <= '0';
    b_input <= h_output;
    b_address <= std_logic_vector(to_unsigned(BRAM_WOTS_KEY_ADDR, BRAM_ADDR_WIDTH) + reg.chain_index);

    h_id <= (others => '0');
    h_block <= (others => '0');

    combinational: process(reg.state, enable, reg.chain_index, b_output, h_output, leaf_index, h_idle, h_next, h_done)
    begin
        nreg <= reg;

        done <= '0';

        h_enable <= '0';
        hash_select <= "11";

        case reg.state is
            when S_IDLE =>
                if enable = '1' then
                    nreg.chain_index <= 0;
                    nreg.state <= S_READ_PK_1;
                end if;

            when S_READ_PK_1 =>
                nreg.state <= S_READ_PK_2;

            when S_READ_PK_2 =>
                nreg.state <= S_HASH_COMPRESS;

            when S_HASH_COMPRESS =>
                -- first iteration: 
                -- (could use reg.chain_index = 0, but would require more bits to check.)
                if h_idle = '1' then
                    h_enable <= '1';
                    nreg.chain_index <= reg.chain_index + 1;
                    nreg.tmp <= b_output;
                    nreg.state <= S_READ_PK_1;
                end if;

                if h_next = '1' then
                    nreg.chain_index <= reg.chain_index + 1;
                    nreg.tmp <= b_output;
                    nreg.state <= S_READ_PK_1;
                end if;

                if h_done = '1' then
                    nreg.tmp <= h_output;
                    nreg.state <= S_LEAF_START;
                end if;

            when S_LEAF_START =>
                h_enable <= '1';
                hash_select <=  "00";
                nreg.state <= S_HASH_LEAF;

            when S_HASH_LEAF =>
                hash_select <= "01";
                if h_done = '1' then
                    nreg.tmp <= h_output;
                    nreg.state <= S_DONE;
                end if;
            
            when S_DONE =>
                done <= '1';
                nreg.state <= S_IDLE;
        end case;
    end process;

    h_len <= to_unsigned(8 * N * WOTS_LEN + HASH_TWEAK_SIZE, HASH_BUS_LEN_WIDTH) when hash_select(1) = '1' else to_unsigned(8 * N + HASH_TWEAK_SIZE, HASH_BUS_LEN_WIDTH);
    with reg.chain_index select comp_h_input <= 
        pub_seed & std_logic_vector(to_unsigned(0, 32 - TREE_HEIGHT)) & leaf_index & D_PBLC & b_output(8 * N - 1 downto HASH_TWEAK_SIZE) when 0,
        reg.tmp(HASH_TWEAK_SIZE - 1 downto 0) & std_logic_vector(to_unsigned(0, 8 * N - HASH_TWEAK_SIZE)) when WOTS_LEN,
        reg.tmp(HASH_TWEAK_SIZE - 1 downto 0) & b_output(8 * N - 1 downto HASH_TWEAK_SIZE) when others;

    with hash_select select h_input <=
        pub_seed & std_logic_vector(to_unsigned(0, 32 - TREE_HEIGHT - 1) & "1" & unsigned(leaf_index)) & D_LEAF & reg.tmp(8 * N - 1 downto HASH_TWEAK_SIZE) when "00",
        reg.tmp(HASH_TWEAK_SIZE - 1 downto 0) & std_logic_vector(to_unsigned(0, 8 * N - HASH_TWEAK_SIZE)) when "01",
        comp_h_input when others;

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
