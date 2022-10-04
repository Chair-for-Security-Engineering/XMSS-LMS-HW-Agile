library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

use work.hss_types.all;
use work.hss_functions.all;

entity thash_tb is
end entity;

architecture default of thash_tb is
    constant t: time := 10 ns;

    constant TARGET: scheme_t := DUAL_SHARED_BRAM;

    constant TREE_HEIGHT: integer := 10;
    constant N: integer := 32;
    constant WOTS_W: integer := 16;
    constant WOTS_LEN: integer := calculate_len1(N, WOTS_W) + calculate_len2(N, WOTS_W);

    constant HASH_BUS_ID_WIDTH: integer := work.params.HASH_BUS_ADDRESS_BITS;
    constant HASH_BUS_LEN_WIDTH: integer := work.params.HASH_BUS_LENGTH_BITS;
    constant HASH_BUS_CTR_WIDTH: integer := 8;

    constant BRAM_ADDR_WIDTH: integer := 15;
    constant BRAM_WOTS_KEY_ADDR: integer := 0;
    constant BRAM_TREE_LEAFS_ADDR: integer := 2 ** TREE_HEIGHT;

    type test_case_t is record
        pub_seed, left, right: std_logic_vector(8 * N - 1 downto 0);
        addr_type: integer range 1 to 2;
        addr_ltree: std_logic_vector(TREE_HEIGHT - 1 downto 0);
        addr_height: integer range 0 to TREE_HEIGHT - 1;
        addr_index: std_logic_vector(TREE_HEIGHT - 1 downto 0);
        output: std_logic_vector(8 * N - 1 downto 0);
    end record;

    signal clk, reset: std_logic;

    signal h_enable, h_done, h_next, h_busy, h_idle: std_logic;
    signal h_id, h_next_id, h_done_id: unsigned(HASH_BUS_ID_WIDTH - 1 downto 0);
    signal h_block, h_next_block, h_done_block: unsigned(HASH_BUS_CTR_WIDTH - 1 downto 0);
    signal h_output, h_input: std_logic_vector(8 * N - 1 downto 0);
    signal h_len: unsigned(HASH_BUS_LEN_WIDTH - 1 downto 0);

    signal uut_pub_seed, uut_left, uut_right: std_logic_vector(8 * N - 1 downto 0);
    signal uut_address_3_to_6: std_logic_vector(4 * 32 - 1 downto 0);
    signal uut_enable, uut_done: std_logic;
    signal uut_output: std_logic_vector(8 * N - 1 downto 0);
    signal uut_addr_type: integer range 1 to 2;
    signal uut_addr_ltree: std_logic_vector(TREE_HEIGHT - 1 downto 0);
    signal uut_addr_height: integer range 0 to TREE_HEIGHT - 1;
    signal uut_addr_index: std_logic_vector(31 downto 0);
    signal scheme_select: std_logic;

    signal done: std_logic;

    signal addr: std_logic_vector(BRAM_ADDR_WIDTH - 1 downto 0);

    constant TEST_LMS: test_case_t := (
        pub_seed => x"00000000000000000000000000000000215f83b7ccb9acbcd08db97b0d04dc2b",
        left => x"e4a220c9d87356f7c762865fd0aea88af77f9e904e25da7636de6046624cc2d8",
        right => x"046c9ebb9be584de00b80b45868109776a8889df97bfce96a07f799461c6569e",
        addr_type => 1, -- unused
        addr_ltree => (others => '-'), -- unused
        addr_height => 0, -- unused
        addr_index => (TREE_HEIGHT - 1 => '1', others => '0'),
        output => x"daa568687b79d12fe77e0d537bd70f025377a78f6538f963140c11a92046d1a5"
    );

    constant TEST_XMSS: test_case_t := (
        pub_seed => x"747da1dcd0be23030ad7d72d1e10881e330495a0ad0a2932844bacf00ea112a9",
        left => x"1e0d8a2a498d0030b3c3ae64ded792c7d54eee666a49237adbfca506d814fded",
        right => x"70edb803dc1a0e5f8ec1f8b6df6947bfe3f63bfc2599c5d2a27146cff050b032",
        addr_type => 2,
        addr_ltree => (others => '0'),
        addr_height => 0,
        addr_index => (1 => '1', others => '0'),
        output => x"a36737a5cca39e9888c0b055374194f5976dea11bc79e03ae0e814d72d9bcc59"
    );

begin
    uut: entity work.thash
    generic map(
        SCHEME      => TARGET,
        N           => N,
        TREE_HEIGHT => TREE_HEIGHT,
        CORES => work.params.HASH_CORES,

        HASH_BUS_ID_WIDTH  => HASH_BUS_ID_WIDTH,
        HASH_BUS_LEN_WIDTH => HASH_BUS_LEN_WIDTH,
        HASH_BUS_CTR_WIDTH => HASH_BUS_CTR_WIDTH
    )
    port map(
        clk => clk,
        reset => reset,

        enable => uut_enable,
        scheme_select => scheme_select,

        pub_seed => uut_pub_seed,
        addr_type => uut_addr_type,
        addr_ltree => uut_addr_ltree,
        addr_height => uut_addr_height,
        addr_index => uut_addr_index,
        left => uut_left,
        right => uut_right,

        done => uut_done,
        output => uut_output,

        h_enable => h_enable,
        h_id => h_id,
        h_block => h_block,
        h_len => h_len,
        h_input => h_input,

        h_done => h_done,
        h_done_id => h_done_id,
        h_done_block => h_done_block,
        h_next => h_next,
        h_next_id => h_next_id,
        h_next_block => h_next_block,
        h_output => h_output,
        h_busy => h_busy,
        h_idle => h_idle
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

    test: process
    begin
        done <= '0';
        reset <= '1';
        uut_enable <= '0';

        wait for t + t / 2;

        reset <= '0';

        if TARGET /= LMS then
            wait for t;

            scheme_select <= '0';

            uut_pub_seed <= TEST_XMSS.pub_seed;
            uut_left <= TEST_XMSS.left;
            uut_right <= TEST_XMSS.right;
            uut_addr_type <= TEST_XMSS.addr_type;
            uut_addr_ltree <= TEST_XMSS.addr_ltree;
            uut_addr_height <= TEST_XMSS.addr_height;
            uut_addr_index <= std_logic_vector(to_unsigned(0, 32 - TREE_HEIGHT)) & TEST_XMSS.addr_index;
            uut_enable <= '1';

            wait for t;

            uut_enable <= '0';

            wait until uut_done = '1';

            assert uut_output = TEST_XMSS.output report "Generated invalid thash value." severity error;
        end if;

        if TARGET /= XMSS then
            wait for t;

            scheme_select <= '1';

            uut_pub_seed <= TEST_LMS.pub_seed;
            uut_left <= TEST_LMS.left;
            uut_right <= TEST_LMS.right;
            uut_addr_index <= std_logic_vector(to_unsigned(0, 32 - TREE_HEIGHT)) & TEST_LMS.addr_index;
            uut_enable <= '1';
            wait for t;
            uut_enable <= '0';

            wait until uut_done = '1';

            assert uut_output = TEST_LMS.output report "Generated invalid lms leaf value." severity error;
        end if;

        done <= '1';

        wait;
    end process;

end architecture;
