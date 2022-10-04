library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

use work.hss_functions.all;
use work.hss_types.all;

entity wots_chain_shared is
    generic(
        SCHEME: scheme_t;

        ID: integer;

        N: integer;
        WOTS_W: integer;
        TREE_HEIGHT: integer;

        HASH_BUS_ID_WIDTH: integer;
        HASH_BUS_LEN_WIDTH: integer;
        HASH_BUS_CTR_WIDTH: integer
    );
    port(
        clk:   in std_logic;
        reset: in std_logic;

        enable:        in std_logic;
        scheme_select: in std_logic;

        input:         in std_logic_vector(8 * N - 1 downto 0);
        pub_seed:      in std_logic_vector(8 * N - 1 downto 0);
        leaf_index:    in std_logic_vector(TREE_HEIGHT - 1 downto 0); -- address for XMSS, q for LMS
        chain_index:   in unsigned(log2(calculate_len1(N, WOTS_W) + calculate_len2(N, WOTS_W)) downto 0);
        chain_start:   in unsigned(log2(WOTS_W) - 1 downto 0);
        chain_end:     in unsigned(log2(WOTS_W) - 1 downto 0);
        hash_available: in std_logic;

        busy:          out std_logic;
        done:          out std_logic;
        output:        out std_logic_vector(8 * N - 1 downto 0);
        working_index: out unsigned(log2(calculate_len1(N, WOTS_W) + calculate_len2(N, WOTS_W)) downto 0); -- outputs the current index that is worked on

        -- hash bus
        h_done:       in std_logic;
        h_done_id:    in unsigned(HASH_BUS_ID_WIDTH - 1 downto 0);
        h_done_block: in unsigned(HASH_BUS_CTR_WIDTH - 1 downto 0);
        h_next_block: in unsigned(HASH_BUS_CTR_WIDTH - 1 downto 0);
        h_output:     in std_logic_vector(N * 8 - 1 downto 0);

        h_enable: out std_logic;
        h_id:     out unsigned(HASH_BUS_ID_WIDTH - 1 downto 0);
        h_block:  out unsigned(HASH_BUS_CTR_WIDTH - 1 downto 0);
        h_len:    out unsigned(HASH_BUS_LEN_WIDTH - 1 downto 0);
        h_input:  out std_logic_vector(N * 8 - 1 downto 0)
    );
end entity;

architecture behavioral of wots_chain_shared is
    constant WOTS_LOG_W: integer := log2(WOTS_W);
    constant WOTS_LEN: integer := calculate_len1(N, WOTS_W) + calculate_len2(N, WOTS_W);
    constant WOTS_LOG_LEN: integer := log2(WOTS_LEN) + 1; -- Needs to be rounded up, since WOTS_W = 2^w => WOTS_LEN /= 2^k
    constant LMS_TWEAK_SIZE: integer := 128 + 32 + 16 + 8;
    constant LMS_INPUT_SIZE: integer := N * 8 + LMS_TWEAK_SIZE;
    constant XMSS_INPUT_SIZE: integer := 3 * N * 8;

    type state_t is (S_IDLE, S_LOOP, S_XMSS_KEY, S_XMSS_BITMASK, S_XMSS_KEY_AND_MASK, S_XMSS_CORE_HASH_INIT, S_LMS_HASH_INIT, S_HASH);

    type register_t is record
        state: state_t;

        busy: std_logic;

        chain_index: unsigned(WOTS_LOG_LEN - 1 downto 0);
        chain_step: unsigned(WOTS_LOG_W - 1 downto 0);
        chain_step_last: unsigned(WOTS_LOG_W - 1 downto 0);

        tmp: std_logic_vector(N * 8 - 1 downto 0);
        key: std_logic_vector(N * 8 - 1 downto 0);

        key_done, mask_done: std_logic;
    end record;

    constant REG_RESET: register_t := (
        state => S_IDLE, 
        busy => '0',
        chain_index => (others => '0'),
        chain_step => (others => '0'),
        chain_step_last => (others => '0'),
        tmp => (others => '0'),
        key => (others => '0'),
        key_done => '0',
        mask_done => '0'
    );

    signal scheme_select_help: std_logic;
    signal hash_sel: std_logic_vector(2 downto 0);
    signal has_done: std_logic;
    signal reg, nreg: register_t;
begin
    -- state transition XMSS:
    -- IDLE => LOOP => KEY => BITMASK => KEY_AND_MASK => CORE_HASH_INIT => HASH
    --   ^     |  ^                                                           |
    --   |<====<  |<==========================================================<
    --
    -- state transition LMS:
    -- IDLE => LOOP => HASH_INIT => HASH
    --   ^     |  ^                    |
    --   |<====<  |<===================<

    h_id <= to_unsigned(ID, HASH_BUS_ID_WIDTH);
    has_done <= '1' when (h_done = '1') and (to_unsigned(ID, HASH_BUS_ID_WIDTH) = h_done_id) else '0';

    busy <= reg.busy;

    output <= reg.tmp;

    working_index <= reg.chain_index;

    with SCHEME select scheme_select_help <=
        '0' when XMSS,
        '1' when LMS,
        scheme_select when others;

    combinational: process(reg, hash_available, has_done, h_done_block, h_next_block, enable, scheme_select_help, h_output, input, chain_index, chain_start, chain_end)
    begin
        nreg <= reg;

        h_enable <= '0';
        h_block <= (others => '0');

        done <= '0';

        hash_sel <= std_logic_vector(h_next_block(2 downto 0));

        case reg.state is
            when S_IDLE =>
                nreg.busy <= '0';
                if enable = '1' then
                    nreg.tmp <= input;

                    nreg.chain_index <= chain_index;
                    nreg.chain_step <= chain_start;
                    nreg.chain_step_last <= chain_end;

                    nreg.busy <= '1';
                    nreg.state <= S_LOOP;
                end if;

            when S_LOOP =>
                nreg.key_done <= '0';
                nreg.mask_done <= '0';

                if reg.chain_step = reg.chain_step_last then
                    done <= '1';

                    nreg.busy <= '0';
                    nreg.state <= S_IDLE;
                else
                    if scheme_select_help = '0' then
                        nreg.state <= S_XMSS_KEY;
                    else
                        nreg.state <= S_LMS_HASH_INIT;
                    end if;
                end if;

            when S_XMSS_KEY =>
                if hash_available = '1' then
                    h_enable <= '1';
                    h_block <= to_unsigned(0, HASH_BUS_CTR_WIDTH);
                    hash_sel <= "000";
                    nreg.state <= S_XMSS_BITMASK;
                end if;

            when S_XMSS_BITMASK =>
                if has_done = '1' then
                    nreg.key <= h_output;
                    nreg.key_done <= '1';
                end if;

                if hash_available = '1' then
                    h_enable <= '1';
                    h_block <= to_unsigned(0, HASH_BUS_CTR_WIDTH - 3) & "010";
                    hash_sel <= "000";
                    nreg.state <= S_XMSS_KEY_AND_MASK;
                end if;

            when S_XMSS_KEY_AND_MASK =>
                if has_done = '1' then
                    if h_done_block(2) = '0' then
                        nreg.key <= h_output;
                        nreg.key_done <= '1';
                    else
                        nreg.tmp <= reg.tmp xor h_output;
                        nreg.mask_done <= '1';
                    end if;
                end if;

                if reg.key_done = '1' and reg.mask_done = '1' then
                    nreg.state <= S_XMSS_CORE_HASH_INIT;
                end if;

            when S_XMSS_CORE_HASH_INIT =>
                if hash_available = '1' then
                    h_enable <= '1';
                    h_block <= to_unsigned(0, HASH_BUS_CTR_WIDTH - 3) & "101";
                    hash_sel <= "101";
                    nreg.state <= S_HASH;
                end if;

            when S_LMS_HASH_INIT =>
                if hash_available = '1' then
                    h_enable <= '1';
                    h_block <= to_unsigned(0, HASH_BUS_CTR_WIDTH);
                    hash_sel <= "000";
                    nreg.state <= S_HASH;
                end if;

            when S_HASH =>
                if has_done = '1' then 
                    nreg.tmp <= h_output;
                    nreg.chain_step <= reg.chain_step + 1;
                    nreg.state <= S_LOOP;
                end if;
        end case;
    end process;

    lms_hash: if SCHEME = LMS generate
        h_len <= to_unsigned(LMS_INPUT_SIZE, HASH_BUS_LEN_WIDTH);

        hash_mux: process(hash_sel, reg.tmp, leaf_index, reg.chain_step, reg.chain_index)
            variable tweak: std_logic_vector(LMS_TWEAK_SIZE - 1 downto 0);
        begin
            tweak := pub_seed(127 downto 0) & 
                     std_logic_vector(to_unsigned(0, 32 - TREE_HEIGHT)) & leaf_index &
                     std_logic_vector(to_unsigned(0, 16 - WOTS_LOG_LEN)) & std_logic_vector(reg.chain_index) & 
                     std_logic_vector(to_unsigned(0, 8 - WOTS_LOG_W)) & std_logic_vector(reg.chain_step);

            case hash_sel(0) is
                when '0' =>
                    h_input <= tweak & reg.tmp(reg.tmp'length - 1 downto LMS_TWEAK_SIZE);
                when '1' =>
                    h_input <= reg.tmp(LMS_TWEAK_SIZE - 1 downto 0) & std_logic_vector(to_unsigned(0, 8 * N - LMS_TWEAK_SIZE));
                when others =>
                    h_input <= (others => '-');
            end case;
        end process;
    end generate;

    xmss_hash: if SCHEME = XMSS generate
        h_len <= to_unsigned(XMSS_INPUT_SIZE, HASH_BUS_LEN_WIDTH);

        hash_mux: process(hash_sel, pub_seed, leaf_index, reg.chain_index, reg.chain_step, reg.key, reg.tmp)
            variable address: std_logic_vector(N * 8 - 32 - 1 downto 0);
        begin
            -- 000, 001, 010 => KEY = PRF(SEED, ADRS)
            -- 000, 011, 100 => BM = PRF(SEED, ADRS)
            -- 101, 110, 111 => F(KEY, tmp xor BM)

            -- Holds the address WITHOUT KeyAndMask
            address := std_logic_vector(to_unsigned(0, address'length - 96)) & 
                       std_logic_vector(to_unsigned(0, 32 - TREE_HEIGHT)) & leaf_index & 
                       std_logic_vector(to_unsigned(0, 32 - WOTS_LOG_LEN)) & std_logic_vector(reg.chain_index) &
                       std_logic_vector(to_unsigned(0, 32 - WOTS_LOG_W)) & std_logic_vector(reg.chain_step);

            case hash_sel is
                when "000" =>
                    h_input <= std_logic_vector(to_unsigned(3, N * 8));

                when "001" | "011" =>
                    h_input <= pub_seed;

                when "010" =>
                    h_input <= address & x"00000000";
                when "100" =>
                    h_input <= address & x"00000001";

                when "101" =>
                    h_input <= (others => '0');
                when "110" =>
                    h_input <= reg.key;
                when "111" =>
                    h_input <= reg.tmp;

                when others =>
                    h_input <= (others => '-');
            end case;
        end process;
    end generate;

    dual_gen: if SCHEME = DUAL_SHARED_BRAM generate
        hash_mux: process(scheme_select, hash_sel, pub_seed, leaf_index, reg.chain_index, reg.tmp, reg.key)
            variable address: std_logic_vector(N * 8 - 32 - 1 downto 0);
            variable tweak: std_logic_vector(LMS_TWEAK_SIZE - 1 downto 0);
        begin
            if scheme_select = '0' then
                h_len <= to_unsigned(XMSS_INPUT_SIZE, HASH_BUS_LEN_WIDTH);
                -- 000, 001, 010 => KEY = PRF(SEED, ADRS)
                -- 000, 011, 100 => BM = PRF(SEED, ADRS)
                -- 101, 110, 111 => F(KEY, tmp xor BM)

                -- Holds the address WITHOUT KeyAndMask
                address := std_logic_vector(to_unsigned(0, address'length - 96)) & 
                           std_logic_vector(to_unsigned(0, 32 - TREE_HEIGHT)) & leaf_index & 
                           std_logic_vector(to_unsigned(0, 32 - WOTS_LOG_LEN)) & std_logic_vector(reg.chain_index) &
                           std_logic_vector(to_unsigned(0, 32 - WOTS_LOG_W)) & std_logic_vector(reg.chain_step);

                case hash_sel is
                    when "000" =>
                        h_input <= std_logic_vector(to_unsigned(3, N * 8));

                    when "001" | "011" =>
                        h_input <= pub_seed;

                    when "010" =>
                        h_input <= address & x"00000000";
                    when "100" =>
                        h_input <= address & x"00000001";

                    when "101" =>
                        h_input <= (others => '0');
                    when "110" =>
                        h_input <= reg.key;
                    when "111" =>
                        h_input <= reg.tmp;

                    when others =>
                        h_input <= (others => '-');
                end case;
            else
                h_len <= to_unsigned(LMS_INPUT_SIZE, HASH_BUS_LEN_WIDTH);
                tweak := pub_seed(127 downto 0) & 
                         std_logic_vector(to_unsigned(0, 32 - TREE_HEIGHT)) & leaf_index &
                         std_logic_vector(to_unsigned(0, 16 - WOTS_LOG_LEN)) & std_logic_vector(reg.chain_index) & 
                         std_logic_vector(to_unsigned(0, 8 - WOTS_LOG_W)) & std_logic_vector(reg.chain_step);

                case hash_sel(0) is
                    when '0' =>
                        h_input <= tweak & reg.tmp(reg.tmp'length - 1 downto LMS_TWEAK_SIZE);
                    when '1' =>
                        h_input <= reg.tmp(LMS_TWEAK_SIZE - 1 downto 0) & std_logic_vector(to_unsigned(0, 8 * N - LMS_TWEAK_SIZE));
                    when others =>
                        h_input <= (others => '-');
                end case;
            end if;
        end process;
    end generate;

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
