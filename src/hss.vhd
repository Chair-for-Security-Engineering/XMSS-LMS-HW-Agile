library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

use work.hss_types.all;
use work.hss_functions.all;

entity hss is
    generic(
        SCHEME: scheme_t;
        CORES: integer;
        CHAINS: integer;
        BDS_K: integer;

        N: integer;
        TREE_HEIGHT: integer;
        WOTS_W: integer
    );
    port(
        clk: in std_logic;
        reset: in std_logic;

        enable: in std_logic;
        mode: in std_logic_vector(1 downto 0);
        scheme_select: in std_logic;
        random: in std_logic_vector(2 * 8 * N - 1 downto 0);

        message_digest: in std_logic_vector(8 * N - 1 downto 0);

        valid: out std_logic;
        needs_keygen: out std_logic;
        current_scheme: out std_logic;
        done: out std_logic;

        io_enable: in std_logic;
        io_write_enable: in std_logic;
        io_address: in std_logic_vector(6 downto 0);
        io_input: in std_logic_vector(8 * N - 1 downto 0);
        io_output: out std_logic_vector(8 * N - 1 downto 0)
    );
end entity;

architecture behavioral of hss is
    constant WOTS_LEN: integer := calculate_len1(N, WOTS_W) + calculate_len2(N, WOTS_W);

    -- elements in bram: 1 + len + 2**BDS_K - BDS_K - 1
    -- len: [34, 265], BDS_K: [0, 2, ..., TREE_HEIGHT]
    -- BDS_K + 1 bits to address internal bram
    -- elements in io bram: 2 + 1 + WOTS_LEN + TREE_HEIGHT
    constant BRAM_ADDR_WIDTH: integer := 9;
    constant BRAM_IO_ADDR_WIDTH: integer := 7;

    constant BRAM_ROOT_ADDR: integer := 0;
    constant BRAM_SEED_ADDR: integer := 1;
    constant BRAM_WOTS_KEY_ADDR: integer := 2;
    constant BRAM_RETAIN_ADDR: integer := BRAM_WOTS_KEY_ADDR + WOTS_LEN;

    constant BRAM_IO_PK_ADDR: integer := 0; -- root node + public seed
    constant BRAM_IO_SIG_ADDR: integer := 2;
    constant BRAM_IO_WOTS_SIG_ADDR: integer := BRAM_IO_SIG_ADDR + 1; -- index (TODO: + message randomizer)
    constant BRAM_IO_PATH_ADDR: integer := BRAM_IO_WOTS_SIG_ADDR + WOTS_LEN;

    constant HASH_BUS_ID_WIDTH: integer := 9; -- max(log2(WOTS_LEN) + 2, log2(CORES) + 1);
    constant HASH_BUS_CTR_WIDTH: integer := 3; -- TODO: This length is fixed, remove generic option for it
    constant HASH_BUS_LEN_WIDTH: integer :=  15; -- max input len LMS: 8 * N * WOTS_LEN + 156, XMSS: 4 * 8 * N,

    type state_t is (S_IDLE, S_CHECK_MODE, S_PATHGEN, S_READ_ROOT_1, S_READ_ROOT_2, S_WRITE_ROOT, S_WRITE_SEED, S_WRITE_INDEX, S_VERIFY, S_DONE);

    type register_t is record
        state: state_t;
        valid: std_logic;
        mode: std_logic_vector(1 downto 0); -- mode should not change throughout operation
        scheme_select: std_logic;
        public_seed: std_logic_vector(8 * N - 1 downto 0);
        secret_seed: std_logic_vector(8 * N - 1 downto 0);
        leaf_index: unsigned(TREE_HEIGHT downto 0);
        message_digest: std_logic_vector(8 * N - 1 downto 0);
    end record;

    constant REG_RESET: register_t := (
        state => S_IDLE,
        mode => "00",
        scheme_select => '0',
        valid => '0',
        leaf_index => (TREE_HEIGHT => '1', others => '0'),
        others => (others => '-')
    );
    signal reg, nreg: register_t := REG_RESET;

    -- hash bus
    signal h_enable, h_done, h_next, h_busy, h_idle: std_logic;
    signal h_id, h_next_id, h_done_id: unsigned(HASH_BUS_ID_WIDTH - 1 downto 0);
    signal h_block, h_next_block, h_done_block: unsigned(HASH_BUS_CTR_WIDTH - 1 downto 0);
    signal h_output, h_input: std_logic_vector(8 * N - 1 downto 0);
    signal h_len: unsigned(HASH_BUS_LEN_WIDTH - 1 downto 0);

    -- thash
    signal th_enable, th_done: std_logic;
    signal th_left, th_right: std_logic_vector(8 * N - 1 downto 0);
    signal th_pub_seed: std_logic_vector(8 * N - 1 downto 0);
    signal th_addr_type: integer range 1 to 2;
    signal th_addr_ltree: std_logic_vector(TREE_HEIGHT - 1 downto 0);
    signal th_addr_height: integer range 0 to TREE_HEIGHT;
    signal th_addr_index: std_logic_vector(31 downto 0);
    signal th_output: std_logic_vector(8 * N - 1 downto 0);
    signal th_h_enable: std_logic;
    signal th_h_len: unsigned(HASH_BUS_LEN_WIDTH - 1 downto 0);
    signal th_h_id: unsigned(HASH_BUS_ID_WIDTH - 1 downto 0);
    signal th_h_block: unsigned(HASH_BUS_CTR_WIDTH - 1 downto 0);
    signal th_h_input: std_logic_vector(8 * N - 1 downto 0);

    -- wots
    signal wots_mode: std_logic_vector(1 downto 0);
    signal wots_pub_seed, wots_seed: std_logic_vector(8 * N - 1 downto 0);
    signal wots_leaf_index: std_logic_vector(TREE_HEIGHT - 1 downto 0);
    signal wots_enable, wots_done: std_logic;
    signal wots_hash_select: std_logic;
    signal wots_leaf: std_logic_vector(8 * N - 1 downto 0);
    signal wots_h_enable: std_logic;
    signal wots_h_len: unsigned(HASH_BUS_LEN_WIDTH - 1 downto 0);
    signal wots_h_id: unsigned(HASH_BUS_ID_WIDTH - 1 downto 0);
    signal wots_h_block: unsigned(HASH_BUS_CTR_WIDTH - 1 downto 0);
    signal wots_h_input: std_logic_vector(8 * N - 1 downto 0);
    signal wots_th_enable: std_logic;
    signal wots_th_left: std_logic_vector(8 * N - 1 downto 0);
    signal wots_th_right: std_logic_vector(8 * N - 1 downto 0);
    signal wots_th_pub_seed: std_logic_vector(8 * N - 1 downto 0);
    signal wots_th_addr_type: integer range 0 to 2;
    signal wots_th_addr_ltree: std_logic_vector(TREE_HEIGHT - 1 downto 0);
    signal wots_th_addr_height: integer range 0 to TREE_HEIGHT;
    signal wots_th_addr_index: std_logic_vector(31 downto 0);
    signal wots_b_a_we: std_logic;
    signal wots_b_a_address: std_logic_vector(BRAM_ADDR_WIDTH - 1 downto 0);
    signal wots_b_a_input: std_logic_vector(8 * N - 1 downto 0);
    signal wots_b_a_output: std_logic_vector(8 * N - 1 downto 0);
    signal wots_b_b_we: std_logic;
    signal wots_b_b_address: std_logic_vector(BRAM_ADDR_WIDTH - 1 downto 0);
    signal wots_b_b_input: std_logic_vector(8 * N - 1 downto 0);
    signal wots_b_io_we: std_logic;
    signal wots_b_io_address: std_logic_vector(BRAM_IO_ADDR_WIDTH - 1 downto 0);
    signal wots_b_io_input: std_logic_vector(8 * N - 1 downto 0);

    -- path generator
    signal path_enable: std_logic;
    signal path_mode: std_logic;
    signal path_hash_select: std_logic; -- 0 => WOTS, 1 => thash
    signal path_bram_select: std_logic; -- 0 => WOTS, 1 => path_generator
    signal path_done: std_logic;
    signal path_wots_enable: std_logic;
    signal path_wots_mode: std_logic_vector(1 downto 0);
    signal path_wots_leaf_index: std_logic_vector(TREE_HEIGHT - 1 downto 0);
    signal path_th_enable: std_logic;
    signal path_th_left: std_logic_vector(8 * N - 1 downto 0);
    signal path_th_right: std_logic_vector(8 * N - 1 downto 0);
    signal path_th_addr_type: integer range 0 to 2;
    signal path_th_addr_ltree: std_logic_vector(TREE_HEIGHT - 1 downto 0);
    signal path_th_addr_height: integer range 0 to TREE_HEIGHT;
    signal path_th_addr_index: std_logic_vector(31 downto 0);
    signal path_b_a_we: std_logic;
    signal path_b_a_address: std_logic_vector(BRAM_ADDR_WIDTH - 1 downto 0);
    signal path_b_a_input: std_logic_vector(8 * N - 1 downto 0);
    signal path_b_b_we: std_logic;
    signal path_b_b_address: std_logic_vector(BRAM_ADDR_WIDTH - 1 downto 0);
    signal path_b_b_input: std_logic_vector(8 * N - 1 downto 0);
    signal path_b_io_we: std_logic;
    signal path_b_io_address: std_logic_vector(BRAM_IO_ADDR_WIDTH - 1 downto 0);
    signal path_b_io_input: std_logic_vector(8 * N - 1 downto 0);

    -- verifier
    signal verify_enable: std_logic;
    signal verify_bram_select: std_logic;
    signal verify_hash_select: std_logic;
    signal verify_valid: std_logic;
    signal verify_done: std_logic;
    signal verify_wots_enable: std_logic;
    signal verify_wots_mode: std_logic_vector(1 downto 0);
    signal verify_wots_pub_seed: std_logic_vector(8 * N - 1 downto 0);
    signal verify_wots_leaf_index: std_logic_vector(TREE_HEIGHT - 1 downto 0);
    signal verify_th_enable: std_logic;
    signal verify_th_left: std_logic_vector(8 * N - 1 downto 0);
    signal verify_th_right: std_logic_vector(8 * N - 1 downto 0);
    signal verify_th_pub_seed: std_logic_vector(8 * N - 1 downto 0);
    signal verify_th_addr_type: integer range 0 to 2;
    signal verify_th_addr_ltree: std_logic_vector(TREE_HEIGHT - 1 downto 0);
    signal verify_th_addr_height: integer range 0 to TREE_HEIGHT;
    signal verify_th_addr_index: std_logic_vector(31 downto 0);
    signal verify_b_io_address: std_logic_vector(BRAM_IO_ADDR_WIDTH - 1 downto 0);

    -- bram
    signal b_a_we: std_logic;
    signal b_a_address: std_logic_vector(BRAM_ADDR_WIDTH - 1 downto 0);
    signal b_a_input: std_logic_vector(8 * N - 1 downto 0);
    signal b_a_output: std_logic_vector(8 * N - 1 downto 0);
    signal b_b_we: std_logic;
    signal b_b_address: std_logic_vector(BRAM_ADDR_WIDTH - 1 downto 0);
    signal b_b_input: std_logic_vector(8 * N - 1 downto 0);
    signal b_b_output: std_logic_vector(8 * N - 1 downto 0);

    signal b_io_e: std_logic;
    signal b_io_we: std_logic;
    signal b_io_address: std_logic_vector(BRAM_IO_ADDR_WIDTH - 1 downto 0);
    signal b_io_input: std_logic_vector(8 * N - 1 downto 0);
    signal b_io_output: std_logic_vector(8 * N - 1 downto 0);

    signal io_e, io_web: std_logic; -- helper for external write enable
    signal io_addrb: std_logic_vector(BRAM_IO_ADDR_WIDTH - 1 downto 0);

    signal self_b_io_we: std_logic;
    signal self_bram_select: std_logic;

    -- internal
    signal internal_scheme_select: std_logic;
begin
    assert BRAM_ADDR_WIDTH >= BDS_K report "Invalid BRAM configuration, internal BRAM needs at least BDS_K bits" severity error;
    assert ((TREE_HEIGHT - BDS_K) mod 2 = 0) report "Invalid BDS_K: TREE_HEIGHT - BDS_K must be even" severity error;

    hash_bus: entity work.hash_core_collection
    generic map(
        HASH_CORES => CORES,
        N => N,

        HASH_BUS_ADDRESS_WIDTH => HASH_BUS_ID_WIDTH,
        HASH_BUS_LENGTH_WIDTH => HASH_BUS_LEN_WIDTH
    )
    port map(
        clk => clk,
        reset => reset,

        enable => h_enable,
        id => h_id,
        blockctr => h_block,
        len => h_len,
        input => h_input,

        done => h_done,
        done_id => h_done_id,
        done_blockctr => h_done_block,
        mnext => h_next,
        next_id => h_next_id,
        next_blockctr => h_next_block,
        output => h_output,
        busy => h_busy,
        idle => h_idle
    );

    th: entity work.thash
    generic map(
        SCHEME      => SCHEME,
        CORES       => CORES,

        N           => N,
        TREE_HEIGHT => TREE_HEIGHT,

        HASH_BUS_ID_WIDTH  => HASH_BUS_ID_WIDTH,
        HASH_BUS_LEN_WIDTH => HASH_BUS_LEN_WIDTH,
        HASH_BUS_CTR_WIDTH => HASH_BUS_CTR_WIDTH
    )
    port map(
        clk => clk,
        reset => reset,

        enable => th_enable,
        scheme_select => internal_scheme_select,

        pub_seed => th_pub_seed,
        addr_type => th_addr_type,
        addr_ltree => th_addr_ltree,
        addr_height => th_addr_height,
        addr_index => th_addr_index,
        left => th_left,
        right => th_right,

        done => th_done,
        output => th_output,

        h_enable => th_h_enable,
        h_id => th_h_id,
        h_block => th_h_block,
        h_len => th_h_len,
        h_input => th_h_input,

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

    wots: entity work.wots_shared
    generic map(
        SCHEME      => SCHEME,
        CHAINS      => CHAINS,

        N           => N,
        TREE_HEIGHT => TREE_HEIGHT,
        WOTS_W      => WOTS_W,

        HASH_BUS_ID_WIDTH  => HASH_BUS_ID_WIDTH,
        HASH_BUS_LEN_WIDTH => HASH_BUS_LEN_WIDTH,
        HASH_BUS_CTR_WIDTH => HASH_BUS_CTR_WIDTH,

        BRAM_ADDR_WIDTH => BRAM_ADDR_WIDTH,
        BRAM_WOTS_KEY_ADDR => BRAM_WOTS_KEY_ADDR,
        BRAM_IO_ADDR_WIDTH => BRAM_IO_ADDR_WIDTH,
        BRAM_IO_WOTS_SIG_ADDR => BRAM_IO_WOTS_SIG_ADDR
    )
    port map(
        clk => clk,
        reset => reset,

        enable => wots_enable,
        scheme_select => internal_scheme_select,

        mode => wots_mode,
        leaf_index => wots_leaf_index,
        message_digest => reg.message_digest,
        pub_seed => wots_pub_seed,
        hash_select => wots_hash_select,
        seed => wots_seed,

        done => wots_done,
        leaf => wots_leaf,

        th_enable => wots_th_enable,
        th_left => wots_th_left,
        th_right => wots_th_right,
        th_pub_seed => wots_th_pub_seed,
        th_addr_type => wots_th_addr_type,
        th_addr_ltree => wots_th_addr_ltree,
        th_addr_height => wots_th_addr_height,
        th_addr_index => wots_th_addr_index,

        th_output => th_output,
        th_done => th_done,

        h_enable => wots_h_enable,
        h_id => wots_h_id,
        h_block => wots_h_block,
        h_len => wots_h_len,
        h_input => wots_h_input,

        h_done => h_done,
        h_done_id => h_done_id,
        h_done_block => h_done_block,
        h_next => h_next,
        h_next_id => h_next_id,
        h_next_block => h_next_block,
        h_output => h_output,
        h_busy => h_busy,
        h_idle => h_idle,

        b_a_we => wots_b_a_we,
        b_a_address => wots_b_a_address,
        b_a_input => wots_b_a_input,
        b_a_output => b_a_output,
        b_b_we => wots_b_b_we,
        b_b_address => wots_b_b_address,
        b_b_input => wots_b_b_input,
        b_b_output => b_b_output,

        b_io_we => wots_b_io_we,
        b_io_address => wots_b_io_address,
        b_io_input => wots_b_io_input,
        b_io_output => b_io_output
    );

    path: entity work.path_generator
    generic map(
        SCHEME => SCHEME,
        BDS_K => BDS_K,

        TREE_HEIGHT => TREE_HEIGHT,
        N => N,

        BRAM_ROOT_ADDR => BRAM_ROOT_ADDR,
        BRAM_RETAIN_ADDR => BRAM_RETAIN_ADDR,
        BRAM_ADDR_WIDTH => BRAM_ADDR_WIDTH,
        BRAM_IO_PATH_ADDR => BRAM_IO_PATH_ADDR,
        BRAM_IO_ADDR_WIDTH => BRAM_IO_ADDR_WIDTH
    )
    port map(
        clk => clk,
        reset => reset,

        enable => path_enable,
        mode => path_mode,
        scheme_select => internal_scheme_select,

        leaf_index => reg.leaf_index(TREE_HEIGHT - 1 downto 0),

        hash_select => path_hash_select,
        bram_select => path_bram_select,
        done => path_done,

        -- wots
        wots_enable => path_wots_enable,
        wots_mode => path_wots_mode,
        wots_leaf_index => path_wots_leaf_index,

        wots_leaf => wots_leaf,
        wots_done => wots_done,

        -- thash
        th_enable => path_th_enable,
        th_left => path_th_left,
        th_right => path_th_right,
        th_addr_type => path_th_addr_type,
        th_addr_ltree => path_th_addr_ltree,
        th_addr_height => path_th_addr_height,
        th_addr_index => path_th_addr_index,

        th_output => th_output,
        th_done => th_done,

        -- internal bram
        b_a_we => path_b_a_we,
        b_a_address => path_b_a_address,
        b_a_input => path_b_a_input,
        b_a_output => b_a_output,

        b_b_we => path_b_b_we,
        b_b_address => path_b_b_address,
        b_b_input => path_b_b_input,

        -- io bram
        b_io_we => path_b_io_we,
        b_io_address => path_b_io_address,
        b_io_input => path_b_io_input
    );

    verifier: entity work.verifier_shared
    generic map(
        SCHEME => SCHEME,

        N => N,
        TREE_HEIGHT => TREE_HEIGHT,

        BRAM_IO_ADDR_WIDTH => BRAM_IO_ADDR_WIDTH,
        BRAM_IO_PK_ADDR => BRAM_IO_PK_ADDR,
        BRAM_IO_SIG_ADDR => BRAM_IO_SIG_ADDR,
        BRAM_IO_PATH_ADDR => BRAM_IO_PATH_ADDR
    )
    port map(
        clk => clk,
        reset => reset,

        enable => verify_enable,
        scheme_select => internal_scheme_select,

        bram_select => verify_bram_select,
        hash_select => verify_hash_select,
        valid => verify_valid,
        done => verify_done,

        wots_enable => verify_wots_enable,
        wots_mode => verify_wots_mode,
        wots_leaf_index => verify_wots_leaf_index,
        wots_pub_seed => verify_wots_pub_seed,

        wots_leaf => wots_leaf,
        wots_done => wots_done,

        -- thash
        th_enable => verify_th_enable,
        th_left => verify_th_left,
        th_right => verify_th_right,
        th_pub_seed => verify_th_pub_seed,
        th_addr_type => verify_th_addr_type,
        th_addr_ltree => verify_th_addr_ltree,
        th_addr_height => verify_th_addr_height,
        th_addr_index => verify_th_addr_index,

        th_output => th_output,
        th_done => th_done,

        -- io bram
        b_io_address => verify_b_io_address,
        b_io_output => b_io_output
    );

    io_bram: entity work.blk_mem_gen_1
    port map(
        clka => clk,
        ena => b_io_e,
        wea(0) => b_io_we,
        addra => b_io_address,
        dina => b_io_input,
        douta => b_io_output,
        clkb => clk,
        enb => io_e,
        web(0) => io_web,
        addrb => io_addrb,
        dinb => io_input,
        doutb => io_output
    );

    block_ram: entity work.blk_mem_gen_0
    port map(
        clka => clk,
        ena => '1',
        wea(0) => b_a_we,
        addra => b_a_address,
        dina => b_a_input,
        douta => b_a_output,
        clkb => clk,
        enb => '1',
        web(0) => b_b_we,
        addrb => b_b_address,
        dinb => b_b_input,
        doutb => b_b_output
    );

    bram_mux: process(
        self_bram_select, path_bram_select, verify_bram_select, reg.state, self_b_io_we, b_a_output, reg.public_seed,
        wots_b_a_we, wots_b_a_address, wots_b_a_input, wots_b_b_we, wots_b_b_address, wots_b_b_input, wots_b_io_we, wots_b_io_address, wots_b_io_input,
        path_b_a_we, path_b_a_address, path_b_a_input, path_b_b_we, path_b_b_address, path_b_b_input, path_b_io_we, path_b_io_address, path_b_io_input,
        verify_b_io_address
    )
    begin
        b_a_we <= wots_b_a_we;
        b_a_address <= wots_b_a_address;
        b_a_input <= wots_b_a_input;
        b_b_we <= wots_b_b_we;
        b_b_address <= wots_b_b_address;
        b_b_input <= wots_b_b_input;
        b_io_we <= wots_b_io_we;
        b_io_address <= wots_b_io_address;
        b_io_input <= wots_b_io_input;
        if path_bram_select = '1' then
            b_a_we <= path_b_a_we;
            b_a_address <= path_b_a_address;
            b_a_input <= path_b_a_input;
            b_b_we <= path_b_b_we;
            b_b_address <= path_b_b_address;
            b_b_input <= path_b_b_input;
            b_io_we <= path_b_io_we;
            b_io_address <= path_b_io_address;
            b_io_input <= path_b_io_input;
        elsif verify_bram_select = '1' then
            b_a_we <= '0';
            b_a_address <= (others => '0');
            b_a_input <= (others => '-');
            b_b_we <= '0';
            b_b_address <= (others => '0');
            b_b_input <= (others => '-');
            b_io_we <= '0';
            b_io_address <= verify_b_io_address;
            b_io_input <= (others => '-');
        elsif self_bram_select = '1' then
            b_a_we <= '0';
            b_a_address <= std_logic_vector(to_unsigned(BRAM_ROOT_ADDR, BRAM_ADDR_WIDTH));
            b_a_input <= (others => '-');
            b_b_we <= '0';
            b_b_address <= (others => '0');
            b_b_input <= (others => '-');

            b_io_we <= self_b_io_we;
            if reg.state = S_WRITE_ROOT then
                b_io_address <= std_logic_vector(to_unsigned(BRAM_IO_PK_ADDR, BRAM_IO_ADDR_WIDTH));
                b_io_input <= b_a_output;
            elsif reg.state = S_WRITE_SEED then
                b_io_address <= std_logic_vector(to_unsigned(BRAM_IO_PK_ADDR + 1, BRAM_IO_ADDR_WIDTH));
                b_io_input <= reg.public_seed;
            elsif reg.state = S_WRITE_INDEX then
                b_io_address <= std_logic_vector(to_unsigned(BRAM_IO_SIG_ADDR, BRAM_IO_ADDR_WIDTH));
                b_io_input <= std_logic_vector(to_unsigned(0, 256 - TREE_HEIGHT) & reg.leaf_index(TREE_HEIGHT - 1 downto 0));
            end if;
        end if;
    end process;

    lms_signals: if SCHEME = LMS generate
        internal_scheme_select <= '1';
    end generate;
    xmss_signals: if SCHEME = XMSS generate
        internal_scheme_select <= '0';
    end generate;
    shared_signals: if SCHEME = DUAL_SHARED_BRAM generate
        internal_scheme_select <= reg.scheme_select;
    end generate;

    -- io bram help
    io_e <= io_enable when reg.state = S_IDLE else '0';
    io_addrb <= io_address;
    io_web <= io_write_enable when reg.state = S_IDLE else '0';

    b_io_e <= '1' when reg.state /= S_IDLE else not io_enable;

    -- hash bus
    -- hash select signals are mutually exclusive
    h_enable <= wots_h_enable when (wots_hash_select or path_hash_select or verify_hash_select) = '0' else th_h_enable;
    h_input  <= wots_h_input  when (wots_hash_select or path_hash_select or verify_hash_select) = '0' else th_h_input;
    h_len    <= wots_h_len    when (wots_hash_select or path_hash_select or verify_hash_select) = '0' else th_h_len;
    h_block  <= wots_h_block  when (wots_hash_select or path_hash_select or verify_hash_select) = '0' else th_h_block;
    h_id     <= wots_h_id     when (wots_hash_select or path_hash_select or verify_hash_select) = '0' else th_h_id;

    -- pathgen
    path_mode <= reg.mode(0);

    -- thash
    thash_mux: process(
        reg.mode(1), wots_hash_select, reg.public_seed,
        wots_th_enable, wots_th_left, wots_th_right, wots_th_addr_type, wots_th_addr_ltree, wots_th_addr_height, wots_th_addr_index,
        path_th_enable, path_th_left, path_th_right, path_th_addr_type, path_th_addr_ltree, path_th_addr_height, path_th_addr_index,
        verify_th_enable, verify_th_left, verify_th_right, verify_th_pub_seed, verify_th_addr_type, verify_th_addr_ltree, verify_th_addr_height, verify_th_addr_index
    )
    begin
        if wots_hash_select = '1' then
            th_enable      <= wots_th_enable;
            th_left        <= wots_th_left;
            th_right       <= wots_th_right;
            th_pub_seed    <= wots_th_pub_seed;
            th_addr_type   <= wots_th_addr_type;
            th_addr_ltree  <= wots_th_addr_ltree;
            th_addr_height <= wots_th_addr_height;
            th_addr_index  <= wots_th_addr_index;
        elsif reg.mode(1) = '0' then
            th_enable      <= path_th_enable;
            th_left        <= path_th_left;
            th_right       <= path_th_right;
            th_pub_seed    <= reg.public_seed;
            th_addr_type   <= path_th_addr_type;
            th_addr_ltree  <= path_th_addr_ltree;
            th_addr_height <= path_th_addr_height;
            th_addr_index  <= path_th_addr_index;
        else
            th_enable      <= verify_th_enable;
            th_left        <= verify_th_left;
            th_right       <= verify_th_right;
            th_pub_seed    <= verify_th_pub_seed;
            th_addr_type   <= verify_th_addr_type;
            th_addr_ltree  <= verify_th_addr_ltree;
            th_addr_height <= verify_th_addr_height;
            th_addr_index  <= verify_th_addr_index;
        end if;
    end process;

    -- wots
    wots_enable     <= path_wots_enable     when reg.mode(1) = '0' else verify_wots_enable;
    wots_mode       <= path_wots_mode       when reg.mode(1) = '0' else verify_wots_mode;
    wots_seed       <= reg.secret_seed; -- The secret seed is only used for keygen and sign
    wots_pub_seed   <= reg.public_seed      when reg.mode(1) = '0' else verify_wots_pub_seed;
    wots_leaf_index <= path_wots_leaf_index when reg.mode(1) = '0' else verify_wots_leaf_index;

    needs_keygen <= reg.leaf_index(TREE_HEIGHT);
    current_scheme <= internal_scheme_select;
    valid <= reg.valid;

    combinational: process(reg, enable, mode, path_done, verify_done, verify_valid, random, message_digest, scheme_select)
    begin
        nreg <= reg;

        nreg.valid <= '0';
        done <= '0';

        self_bram_select <= '0';
        path_enable <= '0';
        verify_enable <= '0';

        self_b_io_we <= '0';

        case reg.state is
            when S_IDLE =>
                if enable = '1' and mode /= "11" then
                    nreg.mode <= mode;
                    nreg.state <= S_CHECK_MODE;

                    if SCHEME = DUAL_SHARED_BRAM then -- constant check
                        if reg.scheme_select /= scheme_select and mode /= "00" then
                            nreg.state <= S_IDLE;
                        else
                            nreg.scheme_select <= scheme_select;
                        end if;
                    end if;
                end if;

            when S_CHECK_MODE =>
                if reg.mode = "00" then
                    nreg.public_seed <= random(2 * 8 * N - 1 downto 8 * N);
                    nreg.secret_seed <= random(8 * N - 1 downto 0);
                    nreg.state <= S_PATHGEN;
                elsif reg.mode = "01" and reg.leaf_index(TREE_HEIGHT) /= '1' then -- All leafs are used when 2^h is reached.
                    nreg.message_digest <= message_digest;
                    nreg.state <= S_PATHGEN;
                elsif reg.mode = "10" then
                    nreg.message_digest <= message_digest;
                    nreg.state <= S_VERIFY;
                else
                    -- TODO: should we signal that the input was invalid?
                    nreg.state <= S_IDLE;
                end if;

            when S_PATHGEN =>
                path_enable <= '1';
                if path_done = '1' then
                    self_bram_select <= '1';
                    nreg.state <= S_READ_ROOT_1;
                end if;

            when S_READ_ROOT_1 =>
                self_bram_select <= '1';
                nreg.state <= S_READ_ROOT_2;

            when S_READ_ROOT_2 =>
                self_bram_select <= '1';
                nreg.state <= S_WRITE_ROOT;

            when S_WRITE_ROOT =>
                self_bram_select <= '1';
                self_b_io_we <= '1';
                nreg.state <= S_WRITE_SEED;

            when S_WRITE_SEED =>
                self_bram_select <= '1';
                self_b_io_we <= '1';
                if reg.mode(0) = '0' then
                    nreg.state <= S_DONE;
                else
                    nreg.state <= S_WRITE_INDEX;
                end if;

            when S_WRITE_INDEX =>
                self_bram_select <= '1';
                self_b_io_we <= '1';
                nreg.state <= S_DONE;

            when S_VERIFY =>
                verify_enable <= '1';
                if verify_done = '1' then
                    nreg.valid <= verify_valid;
                    nreg.state <= S_DONE;
                end if;

            when S_DONE =>
                if reg.mode = "00" then
                    nreg.leaf_index <= (others => '0');
                elsif reg.mode = "01" then
                    nreg.leaf_index <= reg.leaf_index + 1;
                end if;
                done <= '1';
                nreg.state <= S_IDLE;
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
