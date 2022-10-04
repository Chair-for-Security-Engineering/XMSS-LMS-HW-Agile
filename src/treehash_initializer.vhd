library IEEE;
use IEEE.std_logic_1164.ALL;
use IEEE.numeric_std.ALL;

use work.hss_types.all;

entity treehash_initializer is
    generic(
        SCHEME: scheme_t;

        N: integer;
        TREE_HEIGHT: integer;
        BDS_K: integer
    );
    port(
        clk: in std_logic;
        reset: in std_logic;

        enable: in std_logic;
        scheme_select: in std_logic;

        hash_select: out std_logic; -- 0 => wots hash_select, 1 => thash

        retain, auth: out std_logic;
        current_height: out integer range 0 to TREE_HEIGHT;
        current_node: out std_logic_vector(8 * N - 1 downto 0);
        retain_index: out unsigned(BDS_K - 1 downto 0);

        done: out std_logic;

        -- treehash stack
        stack_push, stack_pop:  out std_logic;
        stack_input: out std_logic_vector(8 * N - 1 downto 0);
        stack_input_height: out integer range 0 to TREE_HEIGHT;
        stack_output: in std_logic_vector(8 * N - 1 downto 0);
        stack_output_height: in integer range -1 to TREE_HEIGHT;
        
        -- treehasher
        treehash_load_start: out std_logic;
        treehash_height:     out integer range 0 to TREE_HEIGHT - BDS_K;
        treehash_start_node: out std_logic_vector(8 * N - 1 downto 0);

        -- wots
        wots_enable:     out std_logic;
        wots_leaf_index: out std_logic_vector(TREE_HEIGHT - 1 downto 0);

        wots_leaf: in std_logic_vector(8 * N - 1 downto 0);
        wots_done: in std_logic;

        -- thash
        th_enable:         out std_logic;
        th_left:           out std_logic_vector(8 * N - 1 downto 0);
        th_right:          out std_logic_vector(8 * N - 1 downto 0);
        th_addr_height:    out integer range 0 to TREE_HEIGHT - 1;
        th_addr_index:     out std_logic_vector(31 downto 0);

        th_output: in std_logic_vector(8 * N - 1 downto 0);
        th_done:   in std_logic
    );
end entity;

architecture behavioral of treehash_initializer is
    type state_t is (S_IDLE, S_OUTER_LOOP, S_WOTS, S_STORE_LEAF, S_INNER_LOOP, S_OUTPUT_SIGNALS, S_GEN_NODE, S_DONE);

    type register_t is record
        state: state_t;
        j: unsigned(TREE_HEIGHT downto 0); -- needs 1 bit more for finished check
        current_height: integer range 0 to TREE_HEIGHT;
        node: std_logic_vector(8 * N - 1 downto 0);
    end record;
    constant REG_RESET: register_t := (state => S_IDLE, j => (others => '0'), current_height => 0, node => (others => '-'));

    signal shift_j_height: unsigned(TREE_HEIGHT - 1 downto 0);
    signal retain_help, auth_help, treehash_load_start_help: std_logic;

    signal index: unsigned(TREE_HEIGHT - 1 downto 0);

    signal reg, nreg: register_t;
begin
    shift_j_height <= shift_right(reg.j(TREE_HEIGHT - 1 downto 0), reg.current_height);
    auth_help <= '1' when shift_j_height = 1 else '0';
    -- TODO: this propably can not be done within a single clock cycle. Ensure that retain is only high after enough time has passed for retain_index to stabilize.

    ex_retain: if TREE_HEIGHT - BDS_K <= TREE_HEIGHT - 2 generate
        retain_index <= shift_left(to_unsigned(1, BDS_K), TREE_HEIGHT - 1 - reg.current_height) + reg.current_height - TREE_HEIGHT + resize(shift_right(shift_j_height - 3, 1), BDS_K);
        retain_help <= '1' when reg.current_height >= TREE_HEIGHT - BDS_K else '0';
    end generate;

    no_retain: if TREE_HEIGHT - BDS_K > TREE_HEIGHT - 2 generate
        retain_index <= (others => '0');
        retain_help <= '0';
    end generate;

    treehash_load_start_help <= '1' when (reg.current_height < TREE_HEIGHT - BDS_K) and (shift_j_height = 3) else '0';

    -- index for LMS / XMSS depending on scheme_select
    index <= shift_right(("" & scheme_select) & reg.j(TREE_HEIGHT - 1 downto 1), reg.current_height); -- shift by height + 1

    th_left <= stack_output;
    th_right <= reg.node;
    th_addr_index <= std_logic_vector(to_unsigned(0, 32 - TREE_HEIGHT) & index);
    xmss_signals: if SCHEME /= LMS generate
        th_addr_height <= reg.current_height;
    end generate;

    wots_leaf_index <= std_logic_vector(reg.j(TREE_HEIGHT - 1 downto 0));

    current_height <= reg.current_height;
    current_node <= reg.node;

    stack_input <= reg.node;
    stack_input_height <= reg.current_height;

    treehash_height <= reg.current_height;
    treehash_start_node <= reg.node;

    combinational: process(reg, enable, wots_leaf, wots_done, retain_help, auth_help, treehash_load_start_help, stack_output, stack_output_height, th_output, th_done)
    begin
        nreg <= reg;

        retain <= '0';
        auth <= '0';
        treehash_load_start <= '0';

        wots_enable <= '0';
        th_enable <= '0';

        stack_push <= '0';
        stack_pop <= '0';

        hash_select <= '0';
        done <= '0';

        case reg.state is
            when S_IDLE =>
                if enable = '1' then
                    nreg.j <= (others => '0');
                    nreg.state <= S_OUTER_LOOP;
                end if;
            
            when S_OUTER_LOOP =>
                if reg.j = 2**TREE_HEIGHT then
                    nreg.node <= stack_output;
                    stack_pop <= '1';
                    nreg.state <= S_DONE;
                else
                    nreg.current_height <= 0;
                    wots_enable <= '1';
                    nreg.state <= S_WOTS;
                end if;

            when S_WOTS =>
                if wots_done = '1' then
                    nreg.node <= wots_leaf;
                    nreg.state <= S_INNER_LOOP;
                    if TREE_HEIGHT - BDS_K > 0 and reg.j = 3 then
                        nreg.state <= S_STORE_LEAF;
                    end if;
                end if;

            when S_STORE_LEAF =>
                treehash_load_start <= '1';
                nreg.state <= S_INNER_LOOP;

            when S_INNER_LOOP =>
                if reg.current_height = stack_output_height then
                    nreg.state <= S_OUTPUT_SIGNALS; -- Allow retain index to stabilize
                else
                    nreg.j <= reg.j + 1;
                    stack_push <= '1';
                    nreg.state <= S_OUTER_LOOP;
                end if;

            when S_OUTPUT_SIGNALS =>
                auth <= auth_help;
                treehash_load_start <= treehash_load_start_help;
                -- threehash_load_start and retain are guaranteed to be mutually exclusive, 
                -- but auth and retain are not necessarily. Thus we need to only write 
                -- back if the node is not part of auth.
                retain <= retain_help and (not auth_help);

                hash_select <= '1';
                th_enable <= '1';
                nreg.state <= S_GEN_NODE;

            
            when S_GEN_NODE =>
                hash_select <= '1';
                if th_done = '1' then
                    stack_pop <= '1';
                    nreg.node <= th_output;
                    nreg.current_height <= reg.current_height + 1;
                    nreg.state <= S_INNER_LOOP;
                end if;

            when S_DONE =>
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
