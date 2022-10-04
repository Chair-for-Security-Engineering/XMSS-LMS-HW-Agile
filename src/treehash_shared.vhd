library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

use work.hss_functions.all;
use work.hss_types.all;

entity treehash_shared is
    generic(
        SCHEME: scheme_t;

        N: integer;
        TREE_HEIGHT: integer;

        BDS_K: integer
    );
    port(
        clk:   in std_logic;
        reset: in std_logic;

        enable: in std_logic;
        scheme_select: in std_logic;

        load_start: in std_logic;
        start_node: in std_logic_vector(8 * N - 1 downto 0);

        height: in integer range 0 to TREE_HEIGHT - BDS_K - 1;
        initialize: in std_logic;
        next_index: in unsigned(TREE_HEIGHT - 1 downto 0);

        done: out std_logic;

        node: out std_logic_vector(8 * N - 1 downto 0);
        height_on_stack: out integer range 0 to TREE_HEIGHT;

        -- hash_select: 0 => hash controlled by WOTS hash select
        --              1 => hash controlled by thash
        hash_select: out std_logic;

        -- trehash stack
        stack_check_index: out integer range 0 to TREE_HEIGHT;
        stack_check_height: in integer range 0 to TREE_HEIGHT - 1;
        stack_push, stack_pop:  out std_logic;
        stack_input: out std_logic_vector(8 * N - 1 downto 0);
        stack_input_height: out integer range 0 to TREE_HEIGHT;
        stack_output: in std_logic_vector(8 * N - 1 downto 0);
        stack_output_height: in integer range -1 to TREE_HEIGHT; -- -1 for no element

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

architecture behavioral of treehash_shared is
    constant LMS_TWEAK_SIZE: integer := 128 + 32 + 16;
    constant LMS_INPUT_LEN: integer := LMS_TWEAK_SIZE + 2 * 8 * N;
    constant D_INTR: std_logic_vector(15 downto 0) := x"8383";

    -- treehash[i].completed is not needed, since we are keeping track of the treehashHeight() output.
    type instance_t is record
        node: std_logic_vector(8 * N - 1 downto 0);
        next_index: unsigned(TREE_HEIGHT - 1 downto 0);
        height: integer range 0 to TREE_HEIGHT;
        stackusage: integer range 0 to TREE_HEIGHT + 1;
    end record;

    constant INSTANCE_RESET: instance_t := (
        node => (others => '-'), 
        next_index => (others => '0'),
        height => 0,
        stackusage => 0
    );

    type instance_array_t is array(0 to TREE_HEIGHT - BDS_K - 1) of instance_t;
    
    type state_t is (S_IDLE, S_GEN_LEAF, S_LOOP, S_NODE, S_UPDATE_HEIGHT, S_COMPLETED_CHECK, S_DONE);

    type register_t is record
        state: state_t;
        instances: instance_array_t;
        height: integer range 0 to TREE_HEIGHT - 1;
        stack_index: integer range 0 to TREE_HEIGHT;
    end record;

    constant REG_RESET: register_t := (
        state => S_IDLE,
        instances => (others => INSTANCE_RESET),
        stack_index => 0,
        height => 0
    );

    signal index: unsigned(TREE_HEIGHT downto 0);
    signal height_valid: integer range 0 to TREE_HEIGHT - BDS_K - 1;
    signal reg, nreg: register_t;
begin
    assert (TREE_HEIGHT >= BDS_K) and ((TREE_HEIGHT - BDS_K) mod 2 = 0) report "Invalid BDS parameter" severity error;

    height_valid <= height when height < TREE_HEIGHT - BDS_K else 0;
    -- height_on_stack is either TREE_HEIGHT when no elements are on the stack, the treehash height,
    -- if the treehash instance is done, or the smallest height on the stack.
    height_on_stack <= reg.instances(height_valid).height;
    node <= reg.instances(height_valid).node;

    wots_leaf_index <= std_logic_vector(reg.instances(height_valid).next_index);


    stack_input <= reg.instances(height_valid).node;
    stack_input_height <= reg.height;
    stack_check_index <= reg.stack_index;
    -- stack_element_index <= reg.stack_index - 1 when reg.stack_index > 0 else 0;

    th_left <= stack_output; -- reg.stack(stack_element_index).node;
    th_right <= reg.instances(height_valid).node;
    th_addr_index <= std_logic_vector(to_unsigned(0, 32 - TREE_HEIGHT - 1) & index);

    xmss_signals_th: if SCHEME /= LMS generate
        th_addr_height <= reg.height;
    end generate;

    assert (height < TREE_HEIGHT - BDS_K) or (load_start = '0' and initialize = '0' and enable = '0') report "Started treehash with invalid height" severity error;

    index <= shift_right(("" & scheme_select) & reg.instances(height_valid).next_index, reg.height + 1); -- + 2^height for LMS
    combinational: process(reg.state, load_start, initialize, enable, start_node, height_valid, next_index, wots_done, wots_leaf, th_done, th_output, stack_output_height, stack_check_height)
    begin
        nreg <= reg;

        wots_enable <= '0';
        th_enable <= '0';

        stack_push <= '0';
        stack_pop <= '0';

        done <= '0';

        hash_select <= '0';

        case reg.state is
            when S_IDLE =>
                if load_start = '1' then
                    nreg.instances(height_valid).node <= start_node;
                    nreg.instances(height_valid).height <= TREE_HEIGHT;
                elsif initialize = '1' then
                    nreg.instances(height_valid).next_index <= next_index;
                    nreg.instances(height_valid).height <= height_valid;
                elsif enable = '1' then
                    nreg.height <= 0;
                    nreg.stack_index <= 0;
                    nreg.state <= S_GEN_LEAF;
                end if;

            when S_GEN_LEAF =>
                wots_enable <= '1';
                if wots_done = '1' then
                    nreg.instances(height_valid).node <= wots_leaf;
                    nreg.state <= S_LOOP;
                end if;

            when S_LOOP =>
                hash_select <= '1';
                if stack_output_height = reg.height and reg.instances(height_valid).stackusage > 0 then
                    th_enable <= '1';
                    nreg.state <= S_NODE;
                else
                    nreg.stack_index <= reg.stack_index + 1;
                    nreg.state <= S_UPDATE_HEIGHT;
                end if;

            when S_NODE =>
                hash_select <= '1';
                if th_done = '1' then
                    stack_pop <= '1';
                    nreg.instances(height_valid).node <= th_output;
                    nreg.instances(height_valid).stackusage <= reg.instances(height_valid).stackusage - 1;

                    nreg.height <= reg.height + 1;

                    if reg.instances(height_valid).stackusage = 1 then
                        nreg.instances(height_valid).height <= TREE_HEIGHT;
                    end if;

                    nreg.state <= S_LOOP;
                end if;

            -- After elements have been purged from the stack, we need to find
            -- the new lowest height on the stack for the treehash instance.
            when S_UPDATE_HEIGHT =>
                nreg.stack_index <= reg.stack_index + 1;
                if reg.stack_index - 1 = reg.instances(height_valid).stackusage then
                    nreg.state <= S_COMPLETED_CHECK;
                elsif stack_check_height < reg.instances(height_valid).height then
                    nreg.instances(height_valid).height <= stack_check_height;
                end if;

            when S_COMPLETED_CHECK =>
                if reg.height = height_valid then
                    nreg.instances(height_valid).height <= TREE_HEIGHT;
                else
                    -- TODO: might need two states, if timing cannot be met
                    if reg.height < reg.instances(height_valid).height then
                        nreg.instances(height_valid).height <= reg.height;
                    end if;
                    stack_push <= '1'; -- nreg.stack_index <= reg.stack_index + 1;
                    -- nreg.stack(reg.stack_index) <= (reg.instances(height).node, reg.height);
                    nreg.instances(height_valid).stackusage <= reg.instances(height_valid).stackusage + 1;
                    nreg.instances(height_valid).next_index <= reg.instances(height_valid).next_index + 1;
                end if;
                nreg.state <= S_DONE;

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
