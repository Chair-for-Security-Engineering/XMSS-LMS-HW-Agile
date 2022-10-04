library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

-- TODO: Better naming
use work.hss_functions.all;
use work.hss_types.all;

entity shared_seed_expander is
    generic(
        SCHEME: scheme_t;
        N: integer;
        TREE_HEIGHT: integer;
        WOTS_LEN: integer;

        BRAM_ADDR_WIDTH: integer;
        BRAM_WOTS_KEY_ADDR: integer;

        HASH_BUS_ID_WIDTH: integer;
        HASH_BUS_LEN_WIDTH: integer;
        HASH_BUS_CTR_WIDTH: integer
    );
    port(
        clk:           in std_logic;
        reset:         in std_logic;
        enable:        in std_logic;
        scheme_select: in std_logic;
        seed:          in std_logic_vector(N * 8 - 1 downto 0);

        pub_seed:    in std_logic_vector(N * 8 - 1 downto 0); -- For LMS this is I, thus only the lower 128 bits are used.
        leaf_index: in std_logic_vector(TREE_HEIGHT - 1 downto 0);

        done: out std_logic;

        -- hash bus
        h_done:       in std_logic;
        h_done_id:    in unsigned(HASH_BUS_ID_WIDTH - 1 downto 0);
--      h_done_block: in unsigned(HASH_BUS_CTR_WIDTH - 1 downto 0); Not needed here
        h_next:       in std_logic;
        h_next_id:    in unsigned(HASH_BUS_ID_WIDTH - 1 downto 0);
        h_next_block: in unsigned(HASH_BUS_CTR_WIDTH - 1 downto 0);
        h_output:     in std_logic_vector(N * 8 - 1 downto 0);
        h_busy:       in std_logic;
        h_idle:       in std_logic;

        h_enable: out std_logic;
        h_id:     out unsigned(HASH_BUS_ID_WIDTH - 1 downto 0);
        h_block:  out unsigned(HASH_BUS_CTR_WIDTH - 1 downto 0);
        h_len:    out unsigned(HASH_BUS_LEN_WIDTH - 1 downto 0);
        h_input:  out std_logic_vector(N * 8 - 1 downto 0);

        -- BRAM
        b_we: out std_logic;
        b_address: out std_logic_vector(BRAM_ADDR_WIDTH - 1 downto 0);
        b_input: out std_logic_vector(N * 8 - 1 downto 0)
    );
end entity;

architecture behavioral of shared_seed_expander is
    type state_t is (S_IDLE, S_EXPAND);
    type register_t is record
        state: state_t;
        index: unsigned(log2(WOTS_LEN) + 1 downto 0);
    end record;

    constant REG_RESET: register_t := (S_IDLE, (others => '0'));

    constant LMS_TWEAK_SIZE: integer := 23 * 8;
    constant LMS_INPUT_SIZE: unsigned(HASH_BUS_LEN_WIDTH - 1 downto 0) := to_unsigned(N * 8 + LMS_TWEAK_SIZE, HASH_BUS_LEN_WIDTH);
    constant XMSS_INPUT_SIZE: unsigned(HASH_BUS_LEN_WIDTH - 1 downto 0) := to_unsigned(N * 8 * 4, HASH_BUS_LEN_WIDTH);

    signal reg, nreg: register_t := REG_RESET;

    signal block_ctr: unsigned(1 downto 0);
    signal last_block: std_logic;
    signal next_block: std_logic;

    signal padded_leaf_index: std_logic_vector(31 downto 0);
begin
    b_we <= h_done;
    b_input <= h_output;
    b_address <= std_logic_vector(resize(h_done_id, BRAM_ADDR_WIDTH) + BRAM_WOTS_KEY_ADDR) when h_done = '1' else (others => '0');

    h_id <= to_unsigned(0, HASH_BUS_ID_WIDTH - log2(WOTS_LEN) - 2) & reg.index;
    h_block <= (others => '0');

    last_block <= '1' when reg.index = WOTS_LEN else '0';
    next_block <= '1' when h_busy = '0' and last_block = '0' else '0';

    block_ctr <= h_next_block(1 downto 0) when next_block = '0' else "00";

    padded_leaf_index <= std_logic_vector(to_unsigned(0, 32 - TREE_HEIGHT)) & leaf_index;

    assert N * 8 >= LMS_TWEAK_SIZE
        report "N must be larger than or equal to the seed expander tweak: 23"
        severity error;

    assert (scheme = XMSS) or (N * 8 >= 128)
        report "N must be large enough accomodate for the LMS public seed"
        severity error;

    combinational: process(reg, enable, next_block, h_idle, last_block)
    begin
        nreg <= reg;

        h_enable <= '0';
        done <= '0';

        case reg.state is
            when S_IDLE =>
                if enable = '1' then
                    nreg.index <= (others => '0');
                    nreg.state <= S_EXPAND;
                end if;

            when S_EXPAND =>
                if next_block = '1' then
                    nreg.index <= reg.index + 1;
                    h_enable <= '1';
                end if;

                if h_idle = '1' and last_block = '1' then
                    done <= '1';
                    nreg.state <= S_IDLE;
                end if;
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

    lms_gen: if SCHEME = LMS generate
        h_len <= LMS_INPUT_SIZE;

        with block_ctr(0) select h_input
            <= pub_seed(127 downto 0) & padded_leaf_index & std_logic_vector(resize(reg.index, 16)) & x"ff" & seed(8 * N - 1 downto LMS_TWEAK_SIZE) when '0',
               seed(LMS_TWEAK_SIZE - 1 downto 0) & std_logic_vector(to_unsigned(0, 8 * N - LMS_TWEAK_SIZE))           when '1',
               (others => '-')                                                                                        when others;
    end generate;

    -- Uses the key generation technique described in the xmss reference implementation
    -- [https://github.com/XMSS/xmss-reference], as the key generation technique
    -- described in the RFC is vulnerable against a multi-target attack.

    -- sk[i] = prf_keygen(sk_seed, pub_seed, adrs)
    -- with adrs = leaf_index || i || 0x0000000000000000
    xmss_gen: if SCHEME = XMSS generate
        h_len <= XMSS_INPUT_SIZE;

        hash_mux: process(block_ctr, seed, h_next_id, h_output, padded_leaf_index, pub_seed)
            variable chain_index: std_logic_vector(31 downto 0);
            constant address_0_to_3: std_logic_vector(4 * 32 - 1 downto 0) := (others => '0');
        begin
            chain_index := std_logic_vector(to_unsigned(0, 32 - HASH_BUS_ID_WIDTH) & h_next_id);

            case block_ctr is
                when "00" =>
                    h_input <= std_logic_vector(to_unsigned(4, 8 * N));
                when "01" =>
                    h_input <= seed;
                when "10" =>
                    h_input <= pub_seed;
                when "11" =>
                    h_input <= address_0_to_3 & padded_leaf_index & chain_index & x"00000000" & x"00000000";
                when others =>
                    h_input <= (others => '-');
            end case;
        end process;
    end generate;

    dual_gen: if SCHEME = DUAL_SHARED_BRAM generate
        hash_mux: process(scheme_select, block_ctr, seed, h_next_id, pub_seed, padded_leaf_index, reg.index)
            variable chain_index: std_logic_vector(31 downto 0);
            constant address_0_to_3: std_logic_vector(4 * 32 - 1 downto 0) := (others => '0');
        begin
            if scheme_select = '0' then
                chain_index := std_logic_vector(to_unsigned(0, 32 - HASH_BUS_ID_WIDTH) & h_next_id);
                h_len <= XMSS_INPUT_SIZE;
                case block_ctr is
                    when "00" =>
                        h_input <= std_logic_vector(to_unsigned(4, 8 * N));
                    when "01" =>
                        h_input <= seed;
                    when "10" =>
                        h_input <= pub_seed;
                    when "11" =>
                        h_input <= address_0_to_3 & padded_leaf_index & chain_index & x"00000000" & x"00000000";
                    when others =>
                        h_input <= (others => '-');
                end case;
            else
                h_len <= LMS_INPUT_SIZE;
                case block_ctr(0) is
                    when '0' =>
                        h_input <= pub_seed(127 downto 0) & padded_leaf_index & std_logic_vector(resize(reg.index, 16)) & x"ff" & seed(8 * N - 1 downto LMS_TWEAK_SIZE);
                    when '1' =>
                        h_input <= seed(LMS_TWEAK_SIZE - 1 downto 0) & std_logic_vector(to_unsigned(0, 8 * N - LMS_TWEAK_SIZE));
                    when others =>
                        h_input <= (others => '-');
                end case;
            end if;
        end process;
    end generate;
end;
