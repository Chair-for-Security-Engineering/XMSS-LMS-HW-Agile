library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

use work.hss_types.all;
use work.hss_functions.all;

entity wots_chain_shared_tb is
end entity;

architecture default of wots_chain_shared_tb is
    constant t: time := 10 ns;

    constant TREE_HEIGHT: integer := 10;
    constant N: integer := 32;
    constant WOTS_W: integer := 16;
    constant WOTS_LOG_W: integer := log2(WOTS_W);
    constant WOTS_LOG_LEN: integer := log2(calculate_len1(N, WOTS_W) + calculate_len2(N, WOTS_W)) + 1;

    constant HASH_BUS_ID_WIDTH: integer := work.params.HASH_BUS_ADDRESS_BITS;
    constant HASH_BUS_LEN_WIDTH: integer := work.params.HASH_BUS_LENGTH_BITS;
    constant HASH_BUS_CTR_WIDTH: integer := 8;

    constant TARGET: scheme_t := DUAL_SHARED_BRAM;

    type test_case_xmss_t is record
        seed: std_logic_vector(8 * N - 1 downto 0);
        address: std_logic_vector(TREE_HEIGHT - 1 downto 0);
        input: std_logic_vector(8 * N - 1 downto 0);
        index: unsigned(WOTS_LOG_LEN - 1 downto 0); 
        start, final: unsigned(WOTS_LOG_W - 1 downto 0);
        output: std_logic_vector(8 * N - 1 downto 0);
    end record;

    type test_case_lms_t is record
        I: std_logic_vector(127 downto 0);
        q: std_logic_vector(TREE_HEIGHT - 1 downto 0);
        input: std_logic_vector(8 * N - 1 downto 0);
        index: unsigned(WOTS_LOG_LEN - 1 downto 0); 
        start, final: unsigned(WOTS_LOG_W - 1 downto 0);
        output: std_logic_vector(8 * N - 1 downto 0);
    end record;

    signal clk, reset: std_logic;

    signal h_enable, h_done, h_next, h_busy, h_idle: std_logic;
    signal h_id, h_next_id, h_done_id: unsigned(HASH_BUS_ID_WIDTH - 1 downto 0);
    signal h_block, h_next_block, h_done_block: unsigned(HASH_BUS_CTR_WIDTH - 1 downto 0);
    signal h_output, h_input: std_logic_vector(8 * N - 1 downto 0);
    signal h_len: unsigned(HASH_BUS_LEN_WIDTH - 1 downto 0);

    signal uut_input, uut_pub_seed, uut_output: std_logic_vector(8 * N - 1 downto 0);
    signal uut_leaf_index: std_logic_vector(TREE_HEIGHT - 1 downto 0);
    signal uut_chain_index: unsigned(WOTS_LOG_LEN - 1 downto 0);
    signal uut_chain_start, uut_chain_end: unsigned(WOTS_LOG_W - 1 downto 0);
    signal uut_busy, uut_enable, uut_done, uut_hash_available, scheme_select: std_logic;

    signal done: std_logic;

    constant TEST_XMSS: test_case_xmss_t := (
        seed => x"747da1dcd0be23030ad7d72d1e10881e330495a0ad0a2932844bacf00ea112a9",
        input => x"4b1b20c33150dbe8706f0f6e0b998685b618f18442d01076399b1bfebc4b8506",
        address => std_logic_vector(to_unsigned(7, 10)),
        index => to_unsigned(50, WOTS_LOG_LEN),
        start => to_unsigned(0, WOTS_LOG_W),
        final => to_unsigned(WOTS_W - 1, WOTS_LOG_W),
        output => x"31c3672deb00b33ec5a072dadbf7cabb27e47205b3f29f91f50a7e7469430e44"
    );

    constant TEST_LMS: test_case_lms_t := (
        I => x"f3c6c8de5729d908801ae1e0c93dee0f",
        q => std_logic_vector(to_unsigned(851, 10)), -- 0x353
        input => x"05f301a6f74caa57c20487ad4982d6eb6858f0c503215a40b02d179c4d96942b",
        index => to_unsigned(0, WOTS_LOG_LEN),
        start => to_unsigned(0, WOTS_LOG_W),
        final => to_unsigned(WOTS_W - 1, WOTS_LOG_W),
        output => x"35816c8945d62dd236d223396754282e6ac330010666fc24c894c716e1bc2e2d"
    );

begin
    uut: entity work.wots_chain_shared
    generic map(
        SCHEME      => TARGET,

        ID => 0,

        N           => N,
        TREE_HEIGHT => TREE_HEIGHT,
        WOTS_W      => WOTS_W,

        HASH_BUS_ID_WIDTH  => HASH_BUS_ID_WIDTH,
        HASH_BUS_LEN_WIDTH => HASH_BUS_LEN_WIDTH,
        HASH_BUS_CTR_WIDTH => HASH_BUS_CTR_WIDTH
    )
    port map(
        clk => clk,
        reset => reset,

        enable => uut_enable,
        scheme_select => scheme_select,

        input => uut_input,
        pub_seed => uut_pub_seed,
        chain_index => uut_chain_index,
        chain_start => uut_chain_start,
        chain_end => uut_chain_end,
        leaf_index => uut_leaf_index,
        hash_available => uut_hash_available,

        busy => uut_busy,
        done => uut_done,
        output => uut_output,

        h_done => h_done,
        h_done_id => h_done_id,
        h_done_block => h_done_block,
        h_next => h_next,
        h_next_id => h_next_id,
        h_next_block => h_next_block,
        h_output => h_output,
        h_busy => h_busy,
        h_idle => h_idle,

        h_enable => h_enable,
        h_id => h_id,
        h_block => h_block,
        h_len => h_len,
        h_input => h_input
    );

    hash_bus: entity work.hash_core_collection
    port map(
        clk => clk,
        reset => reset,

        hash_alg_select => (others => '0'),

        d.enable => h_enable,
        d.id.ctr => h_id,
        d.id.block_ctr => h_block,
        d.len => h_len,
        d.input => h_input,

        q.done => h_done,
        q.done_id.ctr => h_done_id,
        q.done_id.block_ctr => h_done_block,
        q.mnext => h_next,
        q.id.ctr => h_next_id,
        q.id.block_ctr => h_next_block, 
        q.o => h_output,
        q.busy => h_busy,
        q.idle => h_idle
    );

    clk_gen: process
    begin
        clk <= '0';
        wait for t / 2;
        clk <= '1';
        wait for t / 2;
        if done = '1' then
            wait;
        end if;
    end process;

    uut_hash_available <= not h_busy;

    test: process
    begin
        done <= '0';
        reset <= '1';
        uut_enable <= '0';

        wait for t + t / 2;

        reset <= '0';

        case TARGET is
            when LMS =>
            when others =>
                wait for t;
                uut_pub_seed <= TEST_XMSS.seed;
                uut_input <= TEST_XMSS.input;
                uut_leaf_index <= TEST_XMSS.address;
                uut_chain_index <= TEST_XMSS.index;
                uut_chain_start <= TEST_XMSS.start;
                uut_chain_end <= TEST_XMSS.final;
                scheme_select <= '0';

                uut_enable <= '1';

                wait for t;
                uut_enable <= '0';

                wait for t / 2;

                assert uut_busy = '1' report "XMSS chain not busy!" severity error;

                wait until uut_done = '1';

                assert uut_output = TEST_XMSS.output report "XMSS chain failed!" severity error;

                wait for t;
        end case;

        case TARGET is
            when XMSS =>
            when others =>
                uut_input <= TEST_LMS.input;
                uut_pub_seed(8 * N - 1 downto 128) <= (others => '-');
                uut_pub_seed(127 downto 0) <= TEST_LMS.I;
                uut_leaf_index <= TEST_LMS.q;
                uut_chain_index <= TEST_LMS.index;
                uut_chain_start <= TEST_LMS.start;
                uut_chain_end <= TEST_LMS.final;
                scheme_select <= '1';

                uut_enable <= '1';

                wait for t;
                uut_enable <= '0';

                wait for t / 2;
                assert uut_busy = '1' report "LMS chain not busy!" severity error;

                wait until uut_done = '1';
                assert uut_output = TEST_LMS.output report "LMS chain failed!" severity error;
        end case;
        done <= '1';
        wait;
    end process;

end architecture;
