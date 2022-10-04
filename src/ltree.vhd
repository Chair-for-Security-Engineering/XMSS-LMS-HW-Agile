library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

use work.hss_functions.all;

entity ltree is
    generic(
        N: integer;
        WOTS_W: integer;
        TREE_HEIGHT: integer;

        BRAM_ADDR_WIDTH: integer;
        BRAM_WOTS_KEY_ADDR: integer
    );
    port (
        clk:   in std_logic;
        reset: in std_logic;

        enable: in std_logic;

        -- pub_seed:   in std_logic_vector(8 * N - 1 downto 0);
        leaf_index: in std_logic_vector(TREE_HEIGHT - 1 downto 0);

        output: out std_logic_vector(8 * N - 1 downto 0);

        done: out std_logic;

        -- thash
        th_enable:         out std_logic;
        th_left, th_right: out std_logic_vector(8 * N - 1 downto 0);
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

        b_a_output: in std_logic_vector(8 * N - 1 downto 0);

        b_b_we:      out std_logic;
        b_b_address: out std_logic_vector(BRAM_ADDR_WIDTH - 1 downto 0);
        b_b_input:   out std_logic_vector(8 * N - 1 downto 0);

        b_b_output: in std_logic_vector(8 * N - 1 downto 0)
    );
end entity;

architecture behavioral of ltree is
    constant WOTS_LOG_W: integer := log2(WOTS_W);
    constant WOTS_LEN: integer := calculate_len1(N, WOTS_W) + calculate_len2(N, WOTS_W);
    constant WOTS_LOG_LEN: integer := log2(WOTS_LEN) + 1;

    type state_t is (S_IDLE, S_LOOP, S_INNER_LOOP, S_THASH, S_BRAM_WAIT_1, S_BRAM_WAIT_2 , S_SWITCH_READ, S_SWITCH_WRITE, S_BRAM_WAIT);

    type register_t is record
        state: state_t;
        l: unsigned(WOTS_LOG_LEN - 1 downto 0);
        height: integer range 0 to WOTS_LOG_LEN;
        parent_node: unsigned(WOTS_LOG_LEN - 1 downto 0);
        chain_index: integer range 0 to WOTS_LEN;
    end record;

    constant REG_RESET: register_t := (
        state => S_IDLE,
        l => (others => '0'),
        height => 0,
        parent_node => (others => '0'),
        chain_index => 0
    );

    signal bram_select : unsigned(1 downto 0);

    signal reg, nreg: register_t;
begin
    b_b_we <= '0';
    b_b_input <= (others => '-');

    -- Ensures that the bram is not read/written at the same clock cycle. 
    -- -> Silences read/write warnings.
    b_b_address <= (others => '-') when bram_select = "10" else std_logic_vector(to_unsigned(BRAM_WOTS_KEY_ADDR + 2 * reg.chain_index, BRAM_ADDR_WIDTH));

    b_a_input <= th_output when bram_select = "10" else b_b_output;

    th_left <= b_b_output;
    th_right <= b_a_output;

    th_addr_type <= 1;
    th_addr_ltree <= leaf_index;
    th_addr_height <= reg.height;
    th_addr_index <= std_logic_vector(to_unsigned(reg.chain_index, 32));

    -- The ltree module does not need a output register, since the thash module
    -- already stores its result in registers.
    output <= th_output;

    combinational: process(reg, th_done, enable)
    begin
        nreg <= reg;

        th_enable <= '0';
        b_a_we <= '0';

        done <= '0';

        bram_select <= (others => '0');

        case reg.state is
            when S_IDLE =>
                if enable = '1' then
                    -- Initialize variables
                    nreg.l <= to_unsigned(WOTS_LEN, WOTS_LOG_LEN);
                    nreg.height <= 0;
                    nreg.chain_index <= 0;
                    nreg.state <= S_BRAM_WAIT;
                end if;

            when S_LOOP =>
                -- l couts the remaning n-bit hashes to be compressed
                if reg.l > 1 then
                    nreg.parent_node <= shift_right(reg.l, 1);
                    nreg.state <= S_INNER_LOOP;
                else
                    done <= '1';
                    nreg.state <= S_IDLE;
                end if;

            when S_INNER_LOOP =>
                if reg.chain_index < reg.parent_node then
                    -- Use thash to compress the next two n-bit values
                    -- Inputs from BRAM
                    th_enable <= '1';
                    nreg.state <= S_THASH;
                else
                    -- If the remaining number of nodes is even, start next loop iteration
                    -- otherwise copy the remaining "odd" value on top of the reduced stack
                    nreg.height <= reg.height + 1;
                    if reg.l(0) = '1' then
                        bram_select <= "01"; -- read the reminaing 2n+1-th value
                        nreg.l <= shift_right(reg.l, 1) + 1;
                        nreg.state <= S_SWITCH_READ;
                    else
                        nreg.l <= shift_right(reg.l, 1);
                        nreg.state <= S_BRAM_WAIT;
                        nreg.chain_index <= 0;
                    end if;
                end if;

            when S_SWITCH_READ =>
                -- Read takes two cycles --> wait
                bram_select <= "01";
                nreg.state <= S_SWITCH_WRITE;

            when S_SWITCH_WRITE =>
                -- write the read value to the new position and reset the counter
                bram_select <= "01";
                b_a_we <= '1';
                nreg.chain_index <= 0;
                nreg.state <= S_BRAM_WAIT;

            when S_BRAM_WAIT =>
                -- make sure, BRAM reads are finished in time
                nreg.state <= S_LOOP;

            when S_THASH =>
                -- wait until thash algorithm is done and increase counter
                if th_done = '1' then
                    bram_select <= "10";
                    b_a_we <= '1'; -- write new value...
                    nreg.chain_index <= reg.chain_index + 1;
                    nreg.state <= S_BRAM_WAIT_1;
                end if;

            when S_BRAM_WAIT_1 =>
                -- Make sure BRAM reads are ready when entering inner Loop...
                nreg.state <= S_BRAM_WAIT_2;

            when  S_BRAM_WAIT_2 =>
                nreg.state <= S_INNER_LOOP;

        end case;
    end process;


    bram_mux : process(bram_select, reg.chain_index)
    begin
        case bram_select is
            when "01" =>
                b_a_address <= std_logic_vector(to_unsigned(BRAM_WOTS_KEY_ADDR + reg.chain_index, BRAM_ADDR_WIDTH));
            when "10" =>
                b_a_address <= std_logic_vector(to_unsigned(BRAM_WOTS_KEY_ADDR + reg.chain_index, BRAM_ADDR_WIDTH));
            when "00" =>
                b_a_address <= std_logic_vector(to_unsigned(BRAM_WOTS_KEY_ADDR + 2 * reg.chain_index + 1, BRAM_ADDR_WIDTH));
            when others =>
                b_a_address <= (others => '-');
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
