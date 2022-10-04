library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

use work.hss_types.all;

entity thash is
    generic(
        SCHEME: scheme_t;

        N: integer;
        TREE_HEIGHT: integer;
        CORES: integer;

        HASH_BUS_ID_WIDTH: integer;
        HASH_BUS_LEN_WIDTH: integer;
        HASH_BUS_CTR_WIDTH: integer
    );
    port (
        clk:   in std_logic;
        reset: in std_logic;

        enable: in std_logic;
        scheme_select: in std_logic;

        left, right: in std_logic_vector(8 * N - 1 downto 0);
        pub_seed:    in std_logic_vector(8 * N - 1 downto 0);
        addr_type:   in integer range 1 to 2;
        addr_ltree:  in std_logic_vector(TREE_HEIGHT - 1 downto 0);
        addr_height: in integer range 0 to TREE_HEIGHT;
        addr_index:  in std_logic_vector(31 downto 0);

        output: out std_logic_vector(8 * N - 1 downto 0);
        done:   out std_logic;

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
        h_idle:       in std_logic
    );
end entity;

architecture behavioral of thash is
    constant LMS_TWEAK_SIZE: integer := 128 + 32 + 16;
    constant LMS_INPUT_LEN: integer := LMS_TWEAK_SIZE + 2 * 8 * N;
    constant D_INTR: std_logic_vector(15 downto 0) := x"8383";

    type state_t is (S_IDLE, S_KEY, S_BITMASK_2, S_BITMASK_1, S_CORE_HASH_INIT, S_CORE_HASH, S_WAIT_FOR_HASH, S_DONE);
    type register_t is record
        state: state_t;
        mask_input_1, mask_input_2, key: std_logic_vector(8 * N - 1 downto 0);
    end record;

    constant REG_RESET: register_t := (
        state => S_IDLE,
        mask_input_1 => (others => '-'),
        mask_input_2 => (others => '-'),
        key => (others => '0')
    );

    signal hash_enable : std_logic;
    signal lms_block_ctr: unsigned(1 downto 0);
    signal block_ctr : unsigned(2 downto 0);
    signal lms_h_input, xmss_h_input: std_logic_vector(8 * N - 1 downto 0);
    signal xmss_h_len: unsigned(HASH_BUS_LEN_WIDTH - 1 downto 0);
    signal xmss_enable, lms_enable, xmss_h_enable, xmss_done: std_logic;

    signal reg, nreg: register_t;
begin
    -- Static output wiring
    lms_signals: if SCHEME = LMS generate
        h_enable <= enable and h_idle;
        h_block <= (others => '0');
        h_len <= to_unsigned(LMS_INPUT_LEN, HASH_BUS_LEN_WIDTH);
        h_input <= lms_h_input;
        h_id <= (others => '0');

        done <= h_done;
        output <= h_output;
    end generate;

    xmss_signals: if SCHEME = XMSS generate
        xmss_enable <= enable;
        h_enable <= xmss_h_enable;
        h_len <= xmss_h_len;
        h_block <= to_unsigned(0, HASH_BUS_CTR_WIDTH - 3) & block_ctr;
        h_input <= xmss_h_input;

        output <= reg.key;
        done <= xmss_done;
    end generate;

    shared_signals: if SCHEME = DUAL_SHARED_BRAM generate
        lms_enable <= enable and h_idle and scheme_select;
        xmss_enable <= enable and (not scheme_select);

        done <= xmss_done or (scheme_select and h_done);

        h_enable <= lms_enable or xmss_h_enable;
        h_len <= xmss_h_len when scheme_select = '0' else to_unsigned(LMS_INPUT_LEN, HASH_BUS_LEN_WIDTH);
        h_block <= to_unsigned(0, HASH_BUS_CTR_WIDTH - 3) & block_ctr when scheme_select = '0' else (others => '0');
        h_input <= xmss_h_input when scheme_select = '0' else lms_h_input;

        output <= reg.key when scheme_select = '0' else h_output;
    end generate;

    lms_gen: if SCHEME /= XMSS generate
        lms_block_ctr <= (others => '0') when h_idle = '1' else h_next_block(1 downto 0);
        with lms_block_ctr select lms_h_input <=
            pub_seed(127 downto 0) & addr_index & D_INTR & left(8 * N - 1 downto LMS_TWEAK_SIZE)          when "00",
            left(LMS_TWEAK_SIZE - 1 downto 0) & right(8 * N - 1 downto LMS_TWEAK_SIZE)                    when "01",
            right(LMS_TWEAK_SIZE - 1 downto 0) & std_logic_vector(to_unsigned(0, 8 * N - LMS_TWEAK_SIZE)) when "10",
            (others => '-')                                                                               when others;
    end generate;

    xmss_gen: if SCHEME /= LMS generate
        combinational: process(reg, h_next_block, xmss_enable, h_busy, h_done, h_done_id, left, right, h_output)
        begin
            nreg <= reg;

            -- Default assignments
            xmss_h_len <= to_unsigned(768, HASH_BUS_LEN_WIDTH);
            xmss_h_enable <= '0';

            block_ctr <= h_next_block(2 downto 0);
            h_id <= to_unsigned(0, HASH_BUS_ID_WIDTH);

            xmss_done <= '0';

            case reg.state is
                when S_IDLE =>
                    if xmss_enable = '1' then
                        -- Store the inputs
                        nreg.mask_input_1 <= left;
                        nreg.mask_input_2 <= right;
                        nreg.state <= S_KEY;
                    end if;

                when S_KEY =>
                    -- Enable Hash for the key generation
                    xmss_h_enable <= '1';
                    block_ctr <= "000";
                    nreg.state <= S_BITMASK_1;

                when S_BITMASK_1 =>
                    -- Generate the first bitmask
                    if h_busy = '0' then
                        xmss_h_enable <= '1';
                        h_id <= to_unsigned(1, HASH_BUS_ID_WIDTH);
                        block_ctr <= "000";
                        nreg.state <= S_BITMASK_2;
                    end if;
                    -- [Constant check]
                    -- if only one hash core is available, wait until key gen is done
                    -- Otherwise hash.busy =/= 1 in this stage
                    if CORES = 1 then
                        if h_done = '1' then
                            nreg.key <= h_output;
                        end if;
                    end if;

                when S_BITMASK_2 =>
                    -- Generate the 2. Bitmask
                    if h_busy = '0' then
                        xmss_h_enable <= '1';
                        h_id <= to_unsigned(2, HASH_BUS_ID_WIDTH);
                        block_ctr <= "000";
                        nreg.state <= S_WAIT_FOR_HASH;
                    end if;
                    -- [Constant check]
                    -- if less than 3 hash cores are connected, the next hash call
                    -- will not compute in paralell -> wait until hash done
                    if h_done = '1' then
                        if h_done_id = to_unsigned(0, HASH_BUS_ID_WIDTH) then
                            nreg.key <= h_output;
                        else
                            nreg.mask_input_1 <= reg.mask_input_1 xor h_output;
                        end if;
                    end if;

                when S_WAIT_FOR_HASH =>
                    -- wait until key and Bitmask are generated
                    if h_done = '1' then
                        if h_done_id = to_unsigned(0, HASH_BUS_ID_WIDTH) then
                            nreg.key <= h_output;
                        elsif h_done_id = to_unsigned(1, HASH_BUS_ID_WIDTH) then
                            nreg.mask_input_1 <= reg.mask_input_1 xor h_output;
                        else
                            nreg.mask_input_2 <= reg.mask_input_2 xor h_output;
                            nreg.state <= S_CORE_HASH_INIT;
                        end if;
                    end if;

                when S_CORE_HASH_INIT =>
                    -- Hash the inputs with keys and bitmasks
                    xmss_h_enable <= '1';
                    xmss_h_len <= to_unsigned(1024, HASH_BUS_LEN_WIDTH);
                    h_id <= to_unsigned(3, HASH_BUS_ID_WIDTH);
                    block_ctr <= "100";
                    nreg.state <= S_CORE_HASH;

                when S_CORE_HASH =>
                    if h_done = '1' then
                        nreg.key <= h_output;
                        nreg.state <= S_DONE;
                    end if;

                when S_DONE =>
                    xmss_done <= '1';
                    nreg.state <= S_IDLE;

                when others =>
            end case;
        end process;

        -- Multiplex the hash input based on block_ctr signal
        xmss_hash_mux : process(
            block_ctr, reg.mask_input_1, reg.mask_input_2, pub_seed, reg.key, h_next_id, addr_type, addr_ltree, addr_height, addr_index
        )
        begin
            case block_ctr is
                when "000" =>
                    xmss_h_input <= std_logic_vector(to_unsigned(3, n*8));
                when "001" =>
                    xmss_h_input <= pub_seed;
                when "010"=>
                    xmss_h_input <= x"00000000" &
                                    x"0000000000000000" &
                                    std_logic_vector(to_unsigned(addr_type, 32)) &
                                    std_logic_vector(to_unsigned(0, 32 - TREE_HEIGHT)) & addr_ltree &
                                    std_logic_vector(to_unsigned(addr_height, 32)) &
                                    addr_index &
                                    std_logic_vector(resize(h_next_id, 32));
                when "100"  =>
                    xmss_h_input <= std_logic_vector(to_unsigned(1, n*8));
                when "101" =>
                    xmss_h_input <= reg.key;
                when "110" =>
                    xmss_h_input <= reg.mask_input_1;
                when "111" =>
                    xmss_h_input <= reg.mask_input_2;
                when others => -- Dont care in others case
                    xmss_h_input <= (others => '-');
            end case;
        end process;
    end generate xmss_gen;

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
