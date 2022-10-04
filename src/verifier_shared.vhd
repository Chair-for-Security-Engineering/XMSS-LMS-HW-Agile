library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

use work.hss_types.all;

entity verifier_shared is
    generic(
        SCHEME: scheme_t;

        N: integer;
        TREE_HEIGHT: integer;
        
        BRAM_IO_ADDR_WIDTH: integer;
        BRAM_IO_PK_ADDR: integer;
        BRAM_IO_SIG_ADDR: integer;
        BRAM_IO_PATH_ADDR: integer
    );
    port(
        clk: in std_logic;
        reset: in std_logic;

        enable: in std_logic;
        scheme_select: in std_logic;

        bram_select: out std_logic; -- 0 => wots, 1 => this module
        hash_select: out std_logic; -- 0 => wots, 1 => thash
        valid: out std_logic;
        done: out std_logic;

        -- wots
        wots_enable:     out std_logic;
        wots_mode:       out std_logic_vector(1 downto 0);
        wots_leaf_index: out std_logic_vector(TREE_HEIGHT - 1 downto 0);
        wots_pub_seed:   out std_logic_vector(8 * N - 1 downto 0);

        wots_leaf: in std_logic_vector(8 * N - 1 downto 0);
        wots_done: in std_logic;

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

        -- io bram
        b_io_address: out std_logic_vector(BRAM_IO_ADDR_WIDTH - 1 downto 0);
        b_io_output:  in std_logic_vector(8 * N - 1 downto 0)
    );
end entity;

architecture behavioral of verifier_shared is
    type state_t is (S_IDLE, S_READ_PK_1, S_READ_PK_2, S_READ_PK, S_READ_SEED_1, S_READ_SEED, S_READ_SIG_1, S_READ_SIG, S_WOTS_VRFY, S_READ_PATH_1, S_VRFY_LOOP, S_VRFY_START, S_DONE);

    type register_t is record
        state: state_t;
        public_key, public_seed: std_logic_vector(8 * N - 1 downto 0);
        leaf_index: unsigned(TREE_HEIGHT - 1 downto 0);
        current_height: integer range 0 to TREE_HEIGHT;
        node: std_logic_vector(8 * N - 1 downto 0);
    end record;

    constant REG_RESET: register_t := (state => S_IDLE, current_height => 0, leaf_index => (others => '-'), others => (others => '-'));

    signal leaf_index_padded: unsigned(TREE_HEIGHT downto 0);
    signal node_index_shifted: unsigned(TREE_HEIGHT downto 0);
    signal reg, nreg: register_t := REG_RESET;
begin
    node_index_shifted <= shift_right(("" & scheme_select) & reg.leaf_index, reg.current_height + 1);

    leaf_index_padded <= "0" & reg.leaf_index;
    th_pub_seed <= reg.public_seed;
    th_left <= reg.node     when leaf_index_padded(reg.current_height) = '0' else b_io_output;
    th_right <= b_io_output when leaf_index_padded(reg.current_height) = '0' else reg.node;
    th_addr_type <= 2;
    th_addr_index(31 downto TREE_HEIGHT + 1) <= (others => '0');
    th_addr_index(TREE_HEIGHT downto 0) <= std_logic_vector(node_index_shifted);
    xmss_signals: if SCHEME /= LMS generate
        th_addr_ltree <= (others => '0');
        th_addr_height <= reg.current_height;
    end generate;

    wots_mode <= "10";
    wots_leaf_index <= std_logic_vector(reg.leaf_index);
    wots_pub_seed <= reg.public_seed;

    bram_hash_mux: process(reg.state)
    begin
        bram_select <= '1';
        hash_select <= '0';
        case reg.state is
            when S_READ_PK_1 | S_READ_PK_2 =>
                b_io_address <= std_logic_vector(to_unsigned(BRAM_IO_PK_ADDR, BRAM_IO_ADDR_WIDTH));
            when S_READ_PK | S_READ_SEED_1 =>
                b_io_address <= std_logic_vector(to_unsigned(BRAM_IO_PK_ADDR + 1, BRAM_IO_ADDR_WIDTH));
            when S_READ_SEED | S_READ_SIG_1 =>
                b_io_address <= std_logic_vector(to_unsigned(BRAM_IO_SIG_ADDR, BRAM_IO_ADDR_WIDTH));
            when S_READ_SIG | S_READ_PATH_1 | S_VRFY_LOOP | S_VRFY_START =>
                hash_select <= '1';
                b_io_address <= std_logic_vector(to_unsigned(BRAM_IO_PATH_ADDR, BRAM_IO_ADDR_WIDTH) + reg.current_height);
            when others =>
                bram_select <= '0';
                b_io_address <= (others => '-');
        end case;
    end process;

    combinational: process(reg, enable, wots_done, wots_leaf, th_done, th_output, b_io_output)
    begin
        nreg <= reg;

        wots_enable <= '0';
        th_enable <= '0';

        valid <= '0';
        done <= '0';

        case reg.state is
            when S_IDLE =>
                if enable = '1' then
                    nreg.current_height <= 0;
                    nreg.state <= S_READ_PK_1;
                end if;

            when S_READ_PK_1 =>
                nreg.state <= S_READ_PK_2;

            when S_READ_PK_2 =>
                nreg.state <= S_READ_PK;

            when S_READ_PK =>
                nreg.public_key <= b_io_output;
                nreg.state <= S_READ_SEED_1;

            when S_READ_SEED_1 =>
                nreg.state <= S_READ_SEED;

            when S_READ_SEED =>
                nreg.public_seed <= b_io_output;
                nreg.state <= S_READ_SIG_1;

            when S_READ_SIG_1 =>
                nreg.state <= S_READ_SIG;

            when S_READ_SIG =>
                nreg.leaf_index <= unsigned(b_io_output(TREE_HEIGHT - 1 downto 0));
                nreg.state <= S_WOTS_VRFY;

            when S_WOTS_VRFY =>
                wots_enable <= '1';
                if wots_done = '1' then
                    nreg.node <= wots_leaf;
                    nreg.state <= S_READ_PATH_1;
                end if;

            when S_READ_PATH_1 =>
                nreg.state <= S_VRFY_LOOP;

            when S_VRFY_LOOP =>
                if reg.current_height = TREE_HEIGHT then
                    nreg.state <= S_DONE;
                else
                    nreg.state <= S_VRFY_START;
                end if;

            when S_VRFY_START =>
                th_enable <= '1';
                if th_done = '1' then
                    nreg.state <= S_READ_PATH_1;
                    nreg.node <= th_output;
                    nreg.current_height <= reg.current_height + 1;
                end if;

            when S_DONE =>
                done <= '1';
                if reg.node = reg.public_key then
                    valid <= '1';
                end if;
                nreg.state <= S_IDLE;
        end case;
    end process;

    sequential: process(clk)
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
