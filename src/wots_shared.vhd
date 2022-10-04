library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

use work.hss_functions.all;
use work.hss_types.all;

entity wots_shared is
    generic (
        SCHEME: scheme_t;
        CHAINS: integer;
        VERIFY_ONLY: boolean := false;

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
    port (
        clk:   in std_logic;
        reset: in std_logic;

        enable:         in std_logic;
        scheme_select:  in std_logic;
        mode:           in std_logic_vector(1 downto 0);
        pub_seed:       in std_logic_vector(8 * N - 1 downto 0);
        leaf_index:     in std_logic_vector(TREE_HEIGHT - 1 downto 0);
        message_digest: in std_logic_vector(8 * N - 1 downto 0);
        seed:           in std_logic_vector(8 * N - 1 downto 0);

        leaf:        out std_logic_vector(8 * N - 1 downto 0);
        hash_select: out std_logic; -- 0 => wots_shared, 1 => thash
        done:        out std_logic;

        -- thash
        th_enable:         out std_logic;
        th_left:           out std_logic_vector(8 * N - 1 downto 0);
        th_right:          out std_logic_vector(8 * N - 1 downto 0);
        th_pub_seed:       out std_logic_vector(8 * N - 1 downto 0);
        th_addr_type:      out integer range 1 to 2;
        th_addr_ltree:     out std_logic_vector(TREE_HEIGHT - 1 downto 0);
        th_addr_height:    out integer range 0 to TREE_HEIGHT - 1;
        th_addr_index:     out std_logic_vector(31 downto 0);

        th_output: in std_logic_vector(8 * N - 1 downto 0);
        th_done:   in std_logic;
        
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
        b_a_we:      out std_logic;
        b_a_address: out std_logic_vector(BRAM_ADDR_WIDTH - 1 downto 0);
        b_a_input:   out std_logic_vector(8 * N - 1 downto 0);
        b_a_output:  in std_logic_vector(8 * N - 1 downto 0);

        b_b_we:      out std_logic;
        b_b_address: out std_logic_vector(BRAM_ADDR_WIDTH - 1 downto 0);
        b_b_input:   out std_logic_vector(8 * N - 1 downto 0);
        b_b_output:  in std_logic_vector(8 * N - 1 downto 0);

        -- io bram
        b_io_we:      out std_logic;
        b_io_address: out std_logic_vector(BRAM_IO_ADDR_WIDTH - 1 downto 0);
        b_io_input:   out std_logic_vector(8 * N - 1 downto 0);
        b_io_output:  in std_logic_vector(8 * N - 1 downto 0)
    );
end entity wots_shared;

architecture behavioral of wots_shared is
    constant WOTS_LEN: integer := calculate_len1(N, WOTS_W) + calculate_len2(N, WOTS_W);

    type state_t is (S_IDLE, S_SK_GEN, S_CORE, S_COMPRESS);
    type register_t is record
        state: state_t;
    end record;

    signal compressor_enable, compressor_done: std_logic;
    signal seed_enable, core_enable, lms_comp_enable, ltree_enable: std_logic;
    signal seed_done, core_done, lms_comp_done, ltree_done: std_logic;
    signal ltree_output, lms_comp_output: std_logic_vector(8 * N - 1 downto 0);

    signal seed_h_enable, core_h_enable, lms_comp_h_enable: std_logic;
    signal seed_h_id, core_h_id, lms_comp_h_id: unsigned(HASH_BUS_ID_WIDTH - 1 downto 0);
    signal seed_h_block, core_h_block, lms_comp_h_block: unsigned(HASH_BUS_CTR_WIDTH - 1 downto 0);
    signal seed_h_len, core_h_len, lms_comp_h_len: unsigned(HASH_BUS_LEN_WIDTH - 1 downto 0);
    signal seed_h_input, core_h_input, lms_comp_h_input: std_logic_vector(N * 8 - 1 downto 0);

    -- seed, core, comp
    signal seed_b_we, core_b_we, lms_comp_b_we: std_logic;
    signal seed_b_input, core_b_input, lms_comp_b_input: std_logic_vector(8 * N - 1 downto 0);
    signal seed_b_address, core_b_address, lms_comp_b_address: std_logic_vector(BRAM_ADDR_WIDTH - 1 downto 0);
    -- ltree
    signal ltree_b_a_we, ltree_b_b_we: std_logic;
    signal ltree_b_a_input, ltree_b_b_input: std_logic_vector(8 * N - 1 downto 0);
    signal ltree_b_a_address, ltree_b_b_address: std_logic_vector(BRAM_ADDR_WIDTH - 1 downto 0);
    -- internal
    signal internal_b_a_we, internal_b_b_we: std_logic;
    signal internal_b_a_input, internal_b_b_input: std_logic_vector(8 * N - 1 downto 0);
    signal internal_b_a_address, internal_b_b_address: std_logic_vector(BRAM_ADDR_WIDTH - 1 downto 0);

    signal reg, nreg: register_t;

    constant REG_RESET: state_t := S_IDLE;
begin
    full_impl: if not VERIFY_ONLY generate
        sk_gen: entity work.shared_seed_expander
        generic map(
            SCHEME => SCHEME,

            N => N,
            TREE_HEIGHT => TREE_HEIGHT,
            WOTS_LEN => WOTS_LEN,

            HASH_BUS_ID_WIDTH => HASH_BUS_ID_WIDTH,
            HASH_BUS_LEN_WIDTH => HASH_BUS_LEN_WIDTH,
            HASH_BUS_CTR_WIDTH => HASH_BUS_CTR_WIDTH,

            BRAM_ADDR_WIDTH => BRAM_ADDR_WIDTH,
            BRAM_WOTS_KEY_ADDR => BRAM_WOTS_KEY_ADDR
        )
        port map(
            clk => clk,
            reset => reset,

            enable => seed_enable,
            scheme_select => scheme_select,

            pub_seed => pub_seed,
            leaf_index => leaf_index,
            seed => seed,
            done => seed_done,

            h_enable => seed_h_enable,
            h_id => seed_h_id,
            h_block => seed_h_block,
            h_len => seed_h_len,
            h_input => seed_h_input,

            h_done => h_done,
            h_done_id => h_done_id,
            h_next => h_next,
            h_next_id => h_next_id,
            h_next_block => h_next_block,
            h_output => h_output,
            h_busy => h_busy,
            h_idle => h_idle,

            b_we => seed_b_we,
            b_input => seed_b_input,
            b_address => seed_b_address
        );
    end generate;

    core: entity work.wots_core_shared
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

        enable => core_enable,
        scheme_select => scheme_select,

        mode => mode,
        leaf_index => leaf_index,
        message_digest => message_digest,
        pub_seed => pub_seed,

        done => core_done,

        h_enable => core_h_enable,
        h_id => core_h_id,
        h_block => core_h_block,
        h_len => core_h_len,
        h_input => core_h_input,

        h_done => h_done,
        h_done_id => h_done_id,
        h_done_block => h_done_block,
        h_next => h_next,
        h_next_id => h_next_id,
        h_next_block => h_next_block,
        h_output => h_output,
        h_busy => h_busy,
        h_idle => h_idle,

        b_we => core_b_we,
        b_address => core_b_address,
        b_input => core_b_input,
        b_output => b_a_output,

        b_io_we => b_io_we,
        b_io_address => b_io_address,
        b_io_input => b_io_input,
        b_io_output => b_io_output
    );

    gen_xmss: if scheme /= LMS generate
        ltree: entity work.ltree
        generic map(
            N           => N,
            WOTS_W      => WOTS_W,
            TREE_HEIGHT => TREE_HEIGHT,

            BRAM_ADDR_WIDTH => BRAM_ADDR_WIDTH,
            BRAM_WOTS_KEY_ADDR => BRAM_WOTS_KEY_ADDR
        )
        port map(
            clk => clk,
            reset => reset,

            enable => ltree_enable,

            -- pub_seed => pub_seed,
            leaf_index => leaf_index,

            done => ltree_done,
            output => ltree_output,

            th_enable => th_enable,
            th_left => th_left,
            th_right => th_right,
            th_addr_type => th_addr_type,
            th_addr_ltree => th_addr_ltree,
            th_addr_height => th_addr_height,
            th_addr_index => th_addr_index,
            th_done => th_done,
            th_output => th_output,

            b_a_we => ltree_b_a_we,
            b_a_address => ltree_b_a_address,
            b_a_input => ltree_b_a_input,

            b_a_output => b_a_output,

            b_b_we => ltree_b_b_we,
            b_b_address => ltree_b_b_address,
            b_b_input => ltree_b_b_input,

            b_b_output => b_b_output
        );
    end generate;

    gen_lms: if scheme /= XMSS generate
        compressor: entity work.lmots_compressor
        generic map(
            N           => N,
            TREE_HEIGHT => TREE_HEIGHT,
            WOTS_W      => WOTS_W,

            HASH_BUS_ID_WIDTH  => HASH_BUS_ID_WIDTH,
            HASH_BUS_LEN_WIDTH => HASH_BUS_LEN_WIDTH,
            HASH_BUS_CTR_WIDTH => HASH_BUS_CTR_WIDTH,

            BRAM_ADDR_WIDTH => BRAM_ADDR_WIDTH,
            BRAM_WOTS_KEY_ADDR => BRAM_WOTS_KEY_ADDR
        )
        port map(
            clk => clk,
            reset => reset,

            enable => lms_comp_enable,

            pub_seed => pub_seed(127 downto 0),
            leaf_index => leaf_index,

            done => lms_comp_done,
            output => lms_comp_output,

            h_enable => lms_comp_h_enable,
            h_id => lms_comp_h_id,
            h_block => lms_comp_h_block,
            h_len => lms_comp_h_len,
            h_input => lms_comp_h_input,

            h_done => h_done,
            h_next => h_next,
            h_output => h_output,
            h_idle => h_idle,

            b_we => lms_comp_b_we,
            b_address => lms_comp_b_address,
            b_input => lms_comp_b_input,

            b_output => b_a_output
        );
    end generate;

    signal_lms: if SCHEME = LMS generate 
        lms_comp_enable <= compressor_enable;
        ltree_b_a_we <= '0';
        ltree_b_b_we <= '0';
        internal_b_a_we <= lms_comp_b_we;
        internal_b_a_address <= lms_comp_b_address;
        internal_b_a_input <= lms_comp_b_input;
        internal_b_b_we <= '0';
        internal_b_b_address <= (others => '0');
        internal_b_b_input <= (others => '-');
        hash_select <= '0';
        leaf <= lms_comp_output;
    end generate;

    signal_xmss: if SCHEME = XMSS generate
        ltree_enable <= compressor_enable;
        th_pub_seed <= pub_seed;
        lms_comp_h_enable <= '0';
        internal_b_a_we <= ltree_b_a_we;
        internal_b_a_address <= ltree_b_a_address;
        internal_b_a_input <= ltree_b_a_input;
        internal_b_b_we <= ltree_b_b_we;
        internal_b_b_address <= ltree_b_b_address;
        internal_b_b_input <= ltree_b_b_input;
        hash_select <= '1' when reg.state = S_COMPRESS else '0';
        leaf <= ltree_output;
    end generate;

    signal_shared: if SCHEME = DUAL_SHARED_BRAM generate
        hash_select <= '1' when reg.state = S_COMPRESS and scheme_select = '0' else '0';
        th_pub_seed <= pub_seed;
        ltree_enable <= compressor_enable when scheme_select = '0' else '0';
        lms_comp_enable <= compressor_enable when scheme_select = '1' else '0';
        internal_b_a_we <= ltree_b_a_we when scheme_select = '0' else lms_comp_b_we;
        internal_b_a_address <= ltree_b_a_address when scheme_select = '0' else lms_comp_b_address;
        internal_b_a_input <= ltree_b_a_input when scheme_select = '0' else lms_comp_b_input;
        internal_b_b_we <= ltree_b_b_we;
        internal_b_b_address <= ltree_b_b_address;
        internal_b_b_input <= ltree_b_b_input;
        leaf <= ltree_output when scheme_select = '0' else lms_comp_output;
    end generate;

    mux: process(
            reg.state, 
            seed_h_enable, seed_h_id, seed_h_block, seed_h_len, seed_h_input, 
            core_h_enable, core_h_id, core_h_block, core_h_len, core_h_input, 
            lms_comp_h_enable, lms_comp_h_id, lms_comp_h_block, lms_comp_h_len, lms_comp_h_input, 
            seed_b_we, seed_b_address, seed_b_input,
            core_b_we, core_b_address, core_b_input,
            internal_b_a_we, internal_b_a_address, internal_b_a_input, 
            internal_b_b_we, internal_b_b_address, internal_b_b_input
        )
    begin
        h_enable <= '0';
        h_id <= (others => '-');
        h_block <= (others => '-');
        h_len <= (others => '-');
        h_input <= (others => '-');

        b_a_we <= '0';
        b_a_address <= (others => '0');
        b_a_input <= (others => '-');
        b_b_we <= '0';
        b_b_address <= (others => '0');
        b_b_input <= (others => '-');

        case reg.state is
            when S_SK_GEN =>
                h_enable <= seed_h_enable;
                h_id <= seed_h_id;
                h_block <= seed_h_block;
                h_len <= seed_h_len;
                h_input <= seed_h_input;

                b_a_we <= seed_b_we;
                b_a_address <= seed_b_address;
                b_a_input <= seed_b_input;

            when S_CORE =>
                h_enable <= core_h_enable;
                h_id <= core_h_id;
                h_block <= core_h_block;
                h_len <= core_h_len;
                h_input <= core_h_input;

                b_a_we <= core_b_we;
                b_a_address <= core_b_address;
                b_a_input <= core_b_input;

            when S_COMPRESS =>
                h_enable <= lms_comp_h_enable;
                h_id <= lms_comp_h_id;
                h_block <= lms_comp_h_block;
                h_len <= lms_comp_h_len;
                h_input <= lms_comp_h_input;

                b_a_we <= internal_b_a_we;
                b_a_address <= internal_b_a_address;
                b_a_input <= internal_b_a_input;
                b_b_we <= internal_b_b_we;
                b_b_address <= internal_b_b_address;
                b_b_input <= internal_b_b_input;
            when others =>
        end case;
    end process;

    compressor_done <= ltree_done or lms_comp_done;

    combinational: process(reg, enable, seed_done, core_done, compressor_done, mode)
    begin
        nreg <= reg;

        done <= '0';

        seed_enable <= '0';
        core_enable <= '0';
        compressor_enable <= '0';

        case reg.state is
            when S_IDLE =>
                if enable = '1' then
                    if mode = "10" then
                        nreg.state <= S_CORE;
                    else
                        nreg.state <= S_SK_GEN;
                    end if;
                end if;

            when S_SK_GEN =>
                seed_enable <= '1';

                if seed_done = '1' then
                    seed_enable <= '0';
                    nreg.state <= S_CORE;
                end if;

            when S_CORE =>
                core_enable <= '1';

                if core_done = '1' then
                    if mode = "01" then
                        done <= '1';
                        nreg.state <= S_IDLE;
                    else
                        nreg.state <= S_COMPRESS;
                    end if;
                end if;

            when S_COMPRESS =>
                compressor_enable <= '1';

                if compressor_done = '1' then
                    compressor_enable <= '0';
                    done <= '1';
                    nreg.state <= S_IDLE;
                end if;
        end case;
    end process;

    sequential: process(clk, reset)
    begin
        if rising_edge(clk) then
            if reset = '1' then
                reg.state <= REG_RESET;
            else
                reg <= nreg;
            end if;
        end if;
    end process;
end architecture;
