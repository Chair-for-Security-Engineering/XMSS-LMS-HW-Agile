library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity treehash_stack is
    generic(
        N: integer;
        TREE_HEIGHT: integer
    );
    port(
        clk: in std_logic;
        reset: in std_logic;

        push, pop: in std_logic;
        input: in std_logic_vector(8 * N - 1 downto 0);
        input_height: in integer range 0 to TREE_HEIGHT;
        output: out std_logic_vector(8 * N - 1 downto 0);
        output_height: out integer range -1 to TREE_HEIGHT;

        check_index: in integer range 0 to TREE_HEIGHT;
        check_height: out integer range 0 to TREE_HEIGHT
    );
end entity;

architecture behavioral of treehash_stack is
    type stack_node_t is array(0 to TREE_HEIGHT) of std_logic_vector(8 * N - 1 downto 0); -- height + 1 elements
    type stack_height_t is array(0 to TREE_HEIGHT) of integer range 0 to TREE_HEIGHT - 1;

    constant STACK_NODE_RESET: stack_node_t := (others => (others => '0'));
    constant STACK_HEIGHT_RESET: stack_height_t := (others => 0);

    signal stacknode_next, stacknode: stack_node_t;
    signal stackheight_next, stackheight: stack_height_t;
    signal index_next, index: integer range 0 to TREE_HEIGHT;
    signal index_current: integer range 0 to TREE_HEIGHT;
    signal cindex: integer range 0 to TREE_HEIGHT;
begin
    index_current <= index - 1 when index > 0 else 0;

    output <= stacknode(index_current);
    output_height <= stackheight(index_current) when index > 0 else -1;

    check_height <= stackheight(index_current - cindex) when cindex <= index_current else TREE_HEIGHT;

    combinational: process(stacknode, stackheight, index, push, pop, input, input_height, index_current)
    begin
        stacknode_next <= stacknode;
        stackheight_next <= stackheight;
        index_next <= index;

        if push = '1' and index <= TREE_HEIGHT then
            stacknode_next(index) <= input;
            stackheight_next(index) <= input_height;
            index_next <= index + 1;
        elsif pop = '1' then
            index_next <= index_current;
        end if;
    end process;

    sequential: process(clk, reset)
    begin
        if rising_edge(clk) then
            if reset = '1' then
                stacknode <= STACK_NODE_RESET;
                stackheight <= STACK_HEIGHT_RESET;
                index <= 0;
            else
                stacknode <= stacknode_next;
                stackheight <= stackheight_next;
                index <= index_next;
                cindex <= check_index;
            end if;
        end if;
    end process;
end architecture;
