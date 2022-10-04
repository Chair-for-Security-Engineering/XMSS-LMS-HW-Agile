library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

use work.hss_types.all;

entity path_generator is
    generic(
        SCHEME: scheme_t;
        BDS_K: integer;

        TREE_HEIGHT: integer;
        N: integer;

        BRAM_RETAIN_ADDR: integer;
        BRAM_ROOT_ADDR: integer;
        BRAM_ADDR_WIDTH: integer;
        BRAM_IO_PATH_ADDR: integer;
        BRAM_IO_ADDR_WIDTH: integer
    );
    port(
        clk:   in std_logic;
        reset: in std_logic;

        enable: in std_logic;
        mode: in std_logic; -- 0 => keygen, 1 => path generation
        scheme_select: in std_logic;

        leaf_index: in unsigned(TREE_HEIGHT - 1 downto 0);
        
        hash_select: out std_logic; -- 0 => WOTS, 1 => thash NOTE: (can be ORed with the wots hash select)
        bram_select: out std_logic; -- 0 => WOTS, 1 => path_generator
        done: out std_logic;

        -- wots
        wots_enable:     out std_logic;
        wots_mode:       out std_logic_vector(1 downto 0);
        wots_leaf_index: out std_logic_vector(TREE_HEIGHT - 1 downto 0);

        wots_leaf: in std_logic_vector(8 * N - 1 downto 0);
        wots_done: in std_logic;

        -- thash
        th_enable:         out std_logic;
        th_left:           out std_logic_vector(8 * N - 1 downto 0);
        th_right:          out std_logic_vector(8 * N - 1 downto 0);
        th_addr_type:      out integer range 1 to 2;
        th_addr_ltree:     out std_logic_vector(TREE_HEIGHT - 1 downto 0);
        th_addr_height:    out integer range 0 to TREE_HEIGHT - 1;
        th_addr_index:     out std_logic_vector(31 downto 0);

        th_output: in std_logic_vector(8 * N - 1 downto 0);
        th_done:   in std_logic;

        -- internal bram
        b_a_we:      out std_logic;
        b_a_address: out std_logic_vector(BRAM_ADDR_WIDTH - 1 downto 0);
        b_a_input:   out std_logic_vector(8 * N - 1 downto 0);
        b_a_output:  in std_logic_vector(8 * N - 1 downto 0);

        b_b_we:      out std_logic;
        b_b_address: out std_logic_vector(BRAM_ADDR_WIDTH - 1 downto 0);
        b_b_input:   out std_logic_vector(8 * N - 1 downto 0);
        -- b_b_output:  in std_logic_vector(8 * N - 1 downto 0);

        -- io bram
        b_io_we:      out std_logic;
        b_io_address: out std_logic_vector(BRAM_IO_ADDR_WIDTH - 1 downto 0);
        b_io_input:   out std_logic_vector(8 * N - 1 downto 0)
        -- b_io_output:  in std_logic_vector(8 * N - 1 downto 0)
    );
end entity;

-- mode = 0, Initializes the algorithm, generates the first path and the root node.
-- mode = 1, Generates the wots signature, writes the current path to IO bram
-- and generates the next path
architecture behavioral of path_generator is
    type state_t is (S_IDLE, S_INITIALIZE, S_STORE_ROOT, S_WOTS_SIG, S_STORE_AUTH, S_CHECK_TAU, S_GEN_NODE, S_GEN_LEAF, S_AUTH_LOOP, S_GET_TREEHASH, S_READ_RETAIN_1, S_READ_RETAIN_2, S_TREEHASH_INIT_LOOP, S_TREEHASH_INIT, S_TREEHASH_LOOP, S_FIND_HEIGHT, S_TREEHASH_START, S_TREEHASH, S_DONE);

    type path_t is array(0 to TREE_HEIGHT - 1) of std_logic_vector(8 * N - 1 downto 0);
    type keep_t is array(0 to TREE_HEIGHT - 2) of std_logic_vector(8 * N - 1 downto 0);

    type register_t is record
        state: state_t;
        next_auth: path_t;
        keep: keep_t;
        index: integer range 0 to TREE_HEIGHT - 1;
        h: integer range 0 to TREE_HEIGHT - BDS_K - 1;
        min_height: integer range 0 to TREE_HEIGHT;
        k: integer range 0 to TREE_HEIGHT;
    end record;

    constant REG_RESET: register_t := (
        state => S_IDLE,
        index => 0,
        h => 0,
        min_height => 0,
        k => 0,
        keep => (others => (others => '-')),
        next_auth => (others => (others => '-'))
    );
    
    signal reg, nreg: register_t;

    function min(a: in integer; b: in integer) return integer is
    begin
        if a < b then
            return a;
        else
            return b;
        end if;
    end function;

    function lowest_bit_not_set(a: in unsigned) return integer is
    begin
        for i in 0 to a'length - 1 loop
            if a(i) = '0' then
                return i;
            end if;
        end loop;
        return a'length - 1;
    end function;

    -- initializer
    signal thinit_enable, thinit_hash_select, thinit_retain, thinit_auth, thinit_stack_push, thinit_stack_pop, thinit_done: std_logic;
    signal thinit_current_height: integer range 0 to TREE_HEIGHT;
    signal thinit_current_node: std_logic_vector(8 * N - 1 downto 0);
    signal thinit_retain_index: unsigned(BDS_K - 1 downto 0);
    signal thinit_stack_input: std_logic_vector(8 * N - 1 downto 0);
    signal thinit_stack_input_height: integer range 0 to TREE_HEIGHT;
    signal thinit_wots_enable: std_logic;
    signal thinit_wots_leaf_index: std_logic_vector(TREE_HEIGHT - 1 downto 0);
    signal thinit_th_enable: std_logic;
    signal thinit_th_left: std_logic_vector(8 * N - 1 downto 0);
    signal thinit_th_right: std_logic_vector(8 * N - 1 downto 0);
    signal thinit_th_addr_height: integer range 0 to TREE_HEIGHT - 1;
    signal thinit_th_addr_index: std_logic_vector(31 downto 0);
    signal thinit_treehash_height: integer range 0 to TREE_HEIGHT - BDS_K - 1;

    -- treehash
    signal treehash_enable, treehash_done: std_logic;
    signal treehash_load_start: std_logic;
    signal treehash_start_node: std_logic_vector(8 * N - 1 downto 0);
    signal treehash_height: integer range 0 to TREE_HEIGHT - BDS_K - 1;
    signal treehash_initialize: std_logic;
    signal treehash_next_index: unsigned(TREE_HEIGHT - 1 downto 0);
    signal treehash_node: std_logic_vector(8 * N - 1 downto 0);
    signal treehash_height_on_stack: integer range 0 to TREE_HEIGHT;
    signal treehash_hash_select: std_logic;
    signal treehash_stack_push: std_logic;
    signal treehash_stack_pop: std_logic;
    signal treehash_stack_input: std_logic_vector(8 * N - 1 downto 0);
    signal treehash_stack_input_height: integer range 0 to TREE_HEIGHT;
    signal treehash_wots_enable: std_logic;
    signal treehash_wots_leaf_index: std_logic_vector(TREE_HEIGHT - 1 downto 0);
    signal treehash_th_enable: std_logic;
    signal treehash_th_left: std_logic_vector(8 * N - 1 downto 0);
    signal treehash_th_right: std_logic_vector(8 * N - 1 downto 0);
    signal treehash_th_addr_height: integer range 0 to TREE_HEIGHT - 1;
    signal treehash_th_addr_index: std_logic_vector(31 downto 0);

    -- th_stack
    signal stack_push, stack_pop: std_logic;
    signal stack_input, stack_output: std_logic_vector(8 * N - 1 downto 0);
    signal stack_input_height, stack_output_height: integer range -1 to TREE_HEIGHT;
    signal stack_check_height: integer range 0 to TREE_HEIGHT;
    signal stack_check_index: integer range 0 to TREE_HEIGHT;

    -- internal bram helper
    signal offset, rowidx: unsigned(BDS_K - 1 downto 0);

    -- internal th / wots helper
    signal self_wots_enable, self_th_enable: std_logic;
    
    signal treehash_next_index_full: unsigned(TREE_HEIGHT + 2 downto 0);
    signal padded_leaf_index: unsigned(TREE_HEIGHT downto 0);
    signal tau: integer range 0 to TREE_HEIGHT - 1;
begin
    initializer: entity work.treehash_initializer
    generic map(
        SCHEME => SCHEME,

        N => N,
        TREE_HEIGHT => TREE_HEIGHT,
        BDS_K => BDS_K
    )
    port map(
        clk => clk,
        reset => reset,

        enable => thinit_enable,
        scheme_select => scheme_select,

        hash_select => thinit_hash_select, -- 0 => wots hash_select, 1 => thash (controlled by this module)

        retain => thinit_retain,
        auth => thinit_auth,
        current_height => thinit_current_height,
        current_node => thinit_current_node,
        retain_index => thinit_retain_index,

        done => thinit_done,

        -- treehash stack
        stack_push => thinit_stack_push,
        stack_pop => thinit_stack_pop,
        stack_input => thinit_stack_input,
        stack_input_height => thinit_stack_input_height,
        stack_output => stack_output,
        stack_output_height => stack_output_height,
        
        -- treehasher
        treehash_load_start => treehash_load_start,
        treehash_height => thinit_treehash_height,
        treehash_start_node => treehash_start_node,

        -- wots
        wots_enable => thinit_wots_enable,
        wots_leaf_index => thinit_wots_leaf_index,

        wots_leaf => wots_leaf,
        wots_done => wots_done,

        -- thash
        th_enable => thinit_th_enable,
        th_left => thinit_th_left,
        th_right => thinit_th_right,
        th_addr_index => thinit_th_addr_index,
        th_addr_height => thinit_th_addr_height,

        th_output => th_output,
        th_done => th_done
    );

    treehasher: entity work.treehash_shared
    generic map(
        SCHEME => SCHEME,

        N => N,
        TREE_HEIGHT => TREE_HEIGHT,

        BDS_K => BDS_K
    )
    port map(
        clk => clk,
        reset => reset,

        enable => treehash_enable,
        scheme_select => scheme_select,

        load_start => treehash_load_start,
        start_node => treehash_start_node,

        height => treehash_height,
        initialize => treehash_initialize,
        next_index => treehash_next_index,

        done => treehash_done,

        node => treehash_node,
        height_on_stack => treehash_height_on_stack,

        hash_select => treehash_hash_select,

        stack_push => treehash_stack_push,
        stack_pop => treehash_stack_pop,
        stack_input => treehash_stack_input,
        stack_input_height => treehash_stack_input_height,
        stack_output => stack_output,
        stack_output_height => stack_output_height,
        stack_check_index => stack_check_index,
        stack_check_height => stack_check_height,

        -- wots
        wots_enable => treehash_wots_enable,
        wots_leaf_index => treehash_wots_leaf_index,

        wots_leaf => wots_leaf,
        wots_done => wots_done,

        -- thash
        th_enable => treehash_th_enable,
        th_left => treehash_th_left,
        th_right => treehash_th_right,
        th_addr_height => treehash_th_addr_height,
        th_addr_index => treehash_th_addr_index,

        th_output => th_output,
        th_done => th_done
    );

    th_stack: entity work.treehash_stack
    generic map(
        N => N,
        TREE_HEIGHT => TREE_HEIGHT
    )
    port map(
        clk => clk,
        reset => reset,

        push => stack_push,
        pop => stack_pop,
        input => stack_input,
        input_height => stack_input_height,
        output => stack_output,
        output_height => stack_output_height,
        check_index => stack_check_index,
        check_height => stack_check_height
    );

    -- stack
    stack_push <= thinit_stack_push when reg.state = S_INITIALIZE else treehash_stack_push;
    stack_pop <= thinit_stack_pop when reg.state = S_INITIALIZE else treehash_stack_pop;
    stack_input <= thinit_stack_input when reg.state = S_INITIALIZE else treehash_stack_input;
    stack_input_height <= thinit_stack_input_height when reg.state = S_INITIALIZE else treehash_stack_input_height;

    with reg.state select th_enable <=
        thinit_th_enable   when S_INITIALIZE,
        treehash_th_enable when S_TREEHASH,
        self_th_enable     when S_GEN_NODE,
        '0'                when others;
    with reg.state select th_left <=
        thinit_th_left         when S_INITIALIZE,
        treehash_th_left       when S_TREEHASH,
        reg.next_auth(tau - 1) when S_GEN_NODE,
        (others => '-')        when others;
    with reg.state select th_right <=
        thinit_th_right   when S_INITIALIZE,
        treehash_th_right when S_TREEHASH,
        reg.keep(tau - 1) when S_GEN_NODE,
        (others => '-')   when others;
    with reg.state select th_addr_index <=
        thinit_th_addr_index                                     when S_INITIALIZE,
        treehash_th_addr_index                                   when S_TREEHASH,
        std_logic_vector(to_unsigned(0, 32 - TREE_HEIGHT - 1) & 
            shift_right(("" & scheme_select) & leaf_index, tau)) when S_GEN_NODE,
        (others => '-')                                          when others;
    with reg.state select th_addr_height <=
        thinit_th_addr_height   when S_INITIALIZE,
        treehash_th_addr_height when S_TREEHASH,
        tau - 1                 when S_GEN_NODE,
        0                       when others;

    with reg.state select wots_enable <=
        thinit_wots_enable   when S_INITIALIZE,
        treehash_wots_enable when S_TREEHASH,
        self_wots_enable     when S_GEN_LEAF | S_WOTS_SIG,
        '0'                  when others;
    with reg.state select wots_leaf_index <=
        thinit_wots_leaf_index       when S_INITIALIZE,
        treehash_wots_leaf_index     when S_TREEHASH,
        std_logic_vector(leaf_index) when S_GEN_LEAF | S_WOTS_SIG,
        (others => '-')              when others;


    -- treehash
    treehash_height <= thinit_treehash_height when reg.state = S_INITIALIZE else reg.h;
    treehash_next_index_full <= shift_left(to_unsigned(3, TREE_HEIGHT + 3), reg.h) + 1 + leaf_index; -- leaf_index + 1 + 3 * (2 ** h)
    treehash_next_index <= treehash_next_index_full(TREE_HEIGHT - 1 downto 0);

    -- bram
    b_a_we <= thinit_retain;
    b_a_input <= thinit_current_node;

    ex_retain: if TREE_HEIGHT - BDS_K <= TREE_HEIGHT - 2 generate
        offset <= resize(shift_left(to_unsigned(1, BDS_K), TREE_HEIGHT - 1 - reg.h) + reg.h - TREE_HEIGHT, BDS_K);
        rowidx <= resize(shift_right(shift_right(leaf_index, reg.h) - 1, 1), BDS_K);
    end generate;
    no_retain: if TREE_HEIGHT - BDS_K > TREE_HEIGHT - 2 generate
        offset <= (others => '0');
        rowidx <= (others => '0');
    end generate;

    b_a_address <= std_logic_vector(to_unsigned(BRAM_RETAIN_ADDR, BRAM_ADDR_WIDTH) + thinit_retain_index) when reg.state = S_INITIALIZE 
                   else std_logic_vector(to_unsigned(BRAM_RETAIN_ADDR, BRAM_ADDR_WIDTH) + offset + rowidx);

    b_b_address <= std_logic_vector(to_unsigned(BRAM_ROOT_ADDR, BRAM_ADDR_WIDTH));
    b_b_input <= thinit_current_node;

    b_io_input <= reg.next_auth(reg.index) when reg.index < TREE_HEIGHT else (others => '-');
    b_io_address <= std_logic_vector(to_unsigned(BRAM_IO_PATH_ADDR, BRAM_IO_ADDR_WIDTH) + reg.index) when reg.index < TREE_HEIGHT else (others => '-');
    
    xmss_signals: if SCHEME /= LMS generate
        th_addr_type <= 2;
        th_addr_ltree <= (others => '0');
    end generate;

    -- internal
    tau <= lowest_bit_not_set(leaf_index);
    padded_leaf_index <= "0" & leaf_index;

    combinational: process(reg, mode, enable, tau, leaf_index, padded_leaf_index, thinit_retain, thinit_auth, thinit_done, thinit_current_node, wots_done, wots_leaf, th_done, th_output, treehash_node, treehash_done, treehash_next_index_full, treehash_height_on_stack, treehash_hash_select, thinit_hash_select, b_a_output)
    begin
        nreg <= reg;

        hash_select <= treehash_hash_select or thinit_hash_select;
        bram_select <= '0';

        b_b_we <= '0';
        b_io_we <= '0';
        thinit_enable <= '0';

        treehash_enable <= '0';
        treehash_initialize <= '0';

        wots_mode <= "00";
        self_wots_enable <= '0';

        self_th_enable <= '0';

        done <= '0';

        case reg.state is
            when S_IDLE =>
                if enable = '1' then
                    nreg.index <= 0;
                    if mode = '0' then
                        thinit_enable <= '1';
                        nreg.state <= S_INITIALIZE;
                    else
                        nreg.state <= S_WOTS_SIG;
                    end if;
                end if;

            when S_INITIALIZE =>
                bram_select <= thinit_retain;
                if thinit_auth = '1' and reg.index < TREE_HEIGHT then
                    nreg.next_auth(reg.index) <= thinit_current_node;
                    nreg.index <= reg.index + 1;
                end if;

                if thinit_done = '1' then
                    nreg.state <= S_STORE_ROOT;
                end if;

            when S_STORE_ROOT =>
                bram_select <= '1';
                b_b_we <= '1';
                nreg.state <= S_DONE;

            when S_WOTS_SIG =>
                wots_mode <= "01";
                self_wots_enable <= '1';
                if wots_done = '1' then
                    nreg.state <= S_STORE_AUTH;
                end if;

            when S_STORE_AUTH =>
                bram_select <= '1';
                -- TODO: This might be a timing issue.
                b_io_we <= '1';
                nreg.index <= reg.index + 1;
                if reg.index = TREE_HEIGHT - 1 then
                    nreg.state <= S_CHECK_TAU;
                    if leaf_index = 2**TREE_HEIGHT - 1 then -- do not try to generate a path that does not exist
                        nreg.state <= S_DONE;
                    end if;
                end if;

            when S_CHECK_TAU =>
                if padded_leaf_index(tau + 1) = '0' and tau < TREE_HEIGHT - 1 then -- (leaf_index >> tau) & 1 == 0
                    nreg.keep(tau) <= reg.next_auth(tau);
                end if;
                if tau = 0 then
                    nreg.state <= S_GEN_LEAF;
                else
                    nreg.state <= S_GEN_NODE;
                end if;

            when S_GEN_LEAF =>
                self_wots_enable <= '1';
                if wots_done = '1' then
                    nreg.next_auth(0) <= wots_leaf;
                    nreg.index <= 0;
                    nreg.state <= S_TREEHASH_LOOP;
                end if;

            when S_GEN_NODE =>
                hash_select <= '1';
                self_th_enable <= '1';
                if th_done = '1' then
                    nreg.next_auth(tau) <= th_output;
                    nreg.h <= 0;
                    nreg.state <= S_AUTH_LOOP;
                end if;

            when S_AUTH_LOOP =>
                if reg.h = tau then
                    nreg.h <= 0;
                    nreg.state <= S_TREEHASH_INIT_LOOP;
                else
                    if reg.h < TREE_HEIGHT - BDS_K then
                        nreg.state <= S_GET_TREEHASH;
                    else
                        bram_select <= '1';
                        nreg.state <= S_READ_RETAIN_1;
                    end if;
                end if;

            when S_GET_TREEHASH =>
                nreg.next_auth(reg.h) <= treehash_node;
                nreg.h <= reg.h + 1;
                nreg.state <= S_AUTH_LOOP;

            when S_READ_RETAIN_1 =>
                bram_select <= '1';
                nreg.state <= S_READ_RETAIN_2;

            when S_READ_RETAIN_2 =>
                bram_select <= '1';
                nreg.next_auth(reg.h) <= b_a_output;
                nreg.h <= reg.h + 1;
                nreg.state <= S_AUTH_LOOP;

            when S_TREEHASH_INIT_LOOP =>
                nreg.state <= S_TREEHASH_INIT;
                if reg.h = min(tau, TREE_HEIGHT - BDS_K) then
                    nreg.index <= 0;
                    nreg.state <= S_TREEHASH_LOOP;
                end if;

            when S_TREEHASH_INIT =>
                if treehash_next_index_full < 2**TREE_HEIGHT then
                    treehash_initialize <= '1';
                end if;
                nreg.h <= reg.h + 1;
                nreg.state <= S_TREEHASH_INIT_LOOP;

            when S_TREEHASH_LOOP =>
                nreg.state <= S_FIND_HEIGHT;
                nreg.k <= TREE_HEIGHT - BDS_K;
                nreg.min_height <= TREE_HEIGHT;
                nreg.h <= 0;
                if reg.index = (TREE_HEIGHT - BDS_K) / 2 then
                    nreg.state <= S_DONE;
                end if;

            when S_FIND_HEIGHT =>
                -- TODO: might be a timing issue
                nreg.h <= reg.h + 1;
                if treehash_height_on_stack < reg.min_height then
                    nreg.min_height <= treehash_height_on_stack;
                    nreg.k <= reg.h;
                end if;
                if reg.h = TREE_HEIGHT - BDS_K - 1 then
                    nreg.state <= S_TREEHASH_START;
                end if;

            when S_TREEHASH_START =>
                if reg.k = TREE_HEIGHT - BDS_K then
                    nreg.state <= S_DONE;
                else
                    nreg.h <= reg.k;
                    nreg.state <= S_TREEHASH;
                end if;

            when S_TREEHASH =>
                treehash_enable <= '1';
                if treehash_done = '1' then
                    nreg.index <= reg.index + 1;
                    nreg.state <= S_TREEHASH_LOOP;
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
