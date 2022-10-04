library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

use work.hss_types.all;
use work.hss_functions.all;

entity hss_verify is
    generic(
        SCHEME: scheme_t;
        CORES: integer;
        CHAINS: integer;

        N: integer;
        TREE_HEIGHT: integer;
        WOTS_W: integer
    );
    port(
        clk: in std_logic;
        reset: in std_logic;

        enable: in std_logic;
        scheme_select: in std_logic;

        message_digest: in std_logic_vector(8 * N - 1 downto 0);

        valid: out std_logic;
        done: out std_logic;

        io_enable: in std_logic;
        io_write_enable: in std_logic;
        io_address: in std_logic_vector(6 downto 0);
        io_input: in std_logic_vector(8 * N - 1 downto 0)
    );
end entity;

architecture behavioral of hss_verify is
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

    type state_t is (S_IDLE, S_VERIFY);

    type register_t is record
        state: state_t;
        scheme_select: std_logic;
        message_digest: std_logic_vector(8 * N - 1 downto 0);
    end record;

    constant REG_RESET: register_t := (
        state => S_IDLE,
        scheme_select => '0',
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

    -- verifier
    signal verify_enable: std_logic;
    signal verify_bram_select: std_logic;
    signal verify_hash_select: std_logic;
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

    signal io_e_checked, io_web_checked: std_logic; -- helper for external write enable

    signal self_bram_select: std_logic;

    -- internal
    signal internal_scheme_select: std_logic;
begin
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
        VERIFY_ONLY => true,

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
        valid => valid,
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
        enb => io_e_checked,
        web(0) => io_web_checked,
        addrb => io_address,
        dinb => io_input
        -- doutb not needed
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
        verify_bram_select, b_a_output,
        wots_b_a_we, wots_b_a_address, wots_b_a_input, wots_b_b_we, wots_b_b_address, wots_b_b_input, wots_b_io_we, wots_b_io_address, wots_b_io_input,
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
        if verify_bram_select = '1' then
            b_a_we <= '0';
            b_a_address <= (others => '0');
            b_a_input <= (others => '-');
            b_b_we <= '0';
            b_b_address <= (others => '0');
            b_b_input <= (others => '-');
            b_io_we <= '0';
            b_io_address <= verify_b_io_address;
            b_io_input <= (others => '-');
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
    io_e_checked <= io_enable when reg.state = S_IDLE else '0';
    io_web_checked <= io_write_enable when reg.state = S_IDLE else '0';

    b_io_e <= '1' when reg.state /= S_IDLE else '0';

    -- hash bus
    -- hash select signals are mutually exclusive
    h_enable <= wots_h_enable when (wots_hash_select or verify_hash_select) = '0' else th_h_enable;
    h_input  <= wots_h_input  when (wots_hash_select or verify_hash_select) = '0' else th_h_input;
    h_len    <= wots_h_len    when (wots_hash_select or verify_hash_select) = '0' else th_h_len;
    h_block  <= wots_h_block  when (wots_hash_select or verify_hash_select) = '0' else th_h_block;
    h_id     <= wots_h_id     when (wots_hash_select or verify_hash_select) = '0' else th_h_id;

    -- thash
    th_enable      <= wots_th_enable      when wots_hash_select = '1' else verify_th_enable;
    th_left        <= wots_th_left        when wots_hash_select = '1' else verify_th_left;
    th_right       <= wots_th_right       when wots_hash_select = '1' else verify_th_right;
    th_pub_seed    <= wots_th_pub_seed    when wots_hash_select = '1' else verify_th_pub_seed;
    th_addr_type   <= wots_th_addr_type   when wots_hash_select = '1' else verify_th_addr_type;
    th_addr_ltree  <= wots_th_addr_ltree  when wots_hash_select = '1' else verify_th_addr_ltree;
    th_addr_height <= wots_th_addr_height when wots_hash_select = '1' else verify_th_addr_height;
    th_addr_index  <= wots_th_addr_index  when wots_hash_select = '1' else verify_th_addr_index;

    -- wots
    wots_enable     <= verify_wots_enable;
    wots_mode       <= verify_wots_mode;
    wots_seed       <= (others => '-'); -- The secret seed is only used for keygen and sign
    wots_pub_seed   <= verify_wots_pub_seed;
    wots_leaf_index <= verify_wots_leaf_index;

    combinational: process(reg, message_digest, enable, scheme_select, verify_done)
    begin
        nreg <= reg;

        verify_enable <= '0';
        done <= '0';
        case reg.state is
            when S_IDLE =>
                if enable = '1' then
                    nreg.scheme_select <= scheme_select;
                    nreg.message_digest <= message_digest;
                    nreg.state <= S_VERIFY;
                end if;

            when S_VERIFY =>
                verify_enable <= '1';
                if verify_done = '1' then
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
end architecture;
