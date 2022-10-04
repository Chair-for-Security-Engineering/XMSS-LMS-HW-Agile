library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

use work.config.all;

entity io_wrapper is
    port(
        clk: in std_logic;

        enable: in std_logic;
        next_io: in std_logic;
        data_in: in std_logic_vector(63 downto 0);

        done: out std_logic;
        valid: out std_logic;
        needs_keygen: out std_logic;
        current_scheme: out std_logic
    );
end entity;

architecture behavioral of io_wrapper is
    type state_t is (S_IDLE, S_RAND, S_WRITE_IO, S_EN, S_DONE);

    constant BRAM_IO_ADDR_WIDTH: integer := 7;

    type register_t is record 
        state: state_t;
        reset: std_logic;
        ctr: integer;
        valid: std_logic;
        random: std_logic_vector(2 * 8 * N - 1 downto 0);
        mdigest: std_logic_vector(8 * N - 1 downto 0);

        io_addr: std_logic_vector(BRAM_IO_ADDR_WIDTH - 1 downto 0);
        io_input: std_logic_vector(8 * N - 1 downto 0);
    end record;

    signal reg, nreg: register_t;

    signal hss_enable: std_logic;
    signal hss_mode: std_logic_vector(1 downto 0);
    signal hss_scheme_select: std_logic;
    signal hss_random: std_logic_vector(2 * 8 * N - 1 downto 0);
    signal hss_mdigest: std_logic_vector(8 * N - 1 downto 0);
    signal hss_valid: std_logic;
    signal hss_needs_keygen: std_logic;
    signal hss_current_scheme: std_logic;
    signal hss_done: std_logic;
    signal hss_io_en: std_logic;
    signal hss_io_wen: std_logic;
    signal hss_io_addr: std_logic_vector(6 downto 0);
    signal hss_io_input, hss_io_output: std_logic_vector(8 * N - 1 downto 0);
begin
    hss: entity work.hss
    generic map(
        SCHEME => SCHEME,
        CORES => HASH_CORES,
        CHAINS => HASH_CHAINS,
        BDS_K => BDS_K,
        N => N,
        TREE_HEIGHT => TREE_HEIGHT,
        WOTS_W => WOTS_W
    )
    port map(
        clk => clk,
        reset => reg.reset,
        enable => hss_enable,
        mode => hss_mode,
        scheme_select => hss_scheme_select,
        random => hss_random,
        message_digest => hss_mdigest,
        done => hss_done,
        valid => hss_valid,
        needs_keygen => hss_needs_keygen,
        current_scheme => hss_current_scheme,
        io_enable => hss_io_en,
        io_write_enable => hss_io_wen,
        io_address => hss_io_addr,
        io_input => hss_io_input,
        io_output => hss_io_output
    );

    hss_random <= reg.random;
    hss_mdigest <= reg.mdigest;
    hss_io_addr <= reg.io_addr;
    hss_io_input <= reg.io_input;

    needs_keygen <= hss_needs_keygen;
    current_scheme <= hss_current_scheme;
    valid <= reg.valid;

    
    combinational : process(reg.state, enable, data_in, hss_done, hss_valid, next_io)
    begin
        nreg <= reg;
    
        hss_enable <= '0';
        hss_io_wen <= '0';
        hss_io_en <= '0';
        hss_scheme_select <= '0';
        done <= '0';
        nreg.reset <= '0';
        nreg.valid <= '0';
        hss_mode <= "00";

        case reg.state is
            when S_IDLE =>
                if enable = '1' then
                    nreg.reset <= '1';
                    nreg.state <= S_RAND;
                    nreg.ctr <= 0;
                end if;

            when S_RAND =>
                if reg.ctr < 4 then
                    nreg.mdigest(reg.ctr * 64 + 63 downto reg.ctr * 64) <= data_in;
                else
                    nreg.random((reg.ctr - 4) * 64 + 63 downto (reg.ctr - 4) * 64 ) <= data_in;
                end if;

                nreg.ctr <= reg.ctr + 1;

                if reg.ctr = (( 3 * N ) / 4) then
                    nreg.ctr <= 0;
                    nreg.state <= S_WRITE_IO;
                end if;

            when S_WRITE_IO =>
                case reg.ctr is
                    when 0 =>
                        if next_io = '1' then
                            nreg.ctr <= reg.ctr + 1;
                        else
                            hss_mode <= data_in(1 downto 0);
                            hss_scheme_select <= data_in(2);
                            hss_enable <= '1';
                            nreg.state <= S_EN;
                        end if;
                    when 1 =>
                        nreg.io_addr <= data_in(BRAM_IO_ADDR_WIDTH - 1 downto 0);
                        nreg.ctr <= reg.ctr + 1;
                    when 6 =>
                        hss_io_en <= '1';
                        hss_io_wen <= '1';
                        nreg.ctr <= 0;
                    when others => 
                        nreg.ctr <= reg.ctr + 1;
                        nreg.io_input((reg.ctr - 2) * 64 + 63 downto (reg.ctr - 2) * 64) <= data_in;

                end case;

            when S_EN =>
                if hss_done = '1' then
                    nreg.valid <= hss_valid;
                    nreg.state <= S_DONE;
                end if;
                
            when S_DONE =>
                done <= '1';
                nreg.state <= S_IDLE;
        end case;
    end process;

    sequential : process(clk)
	begin
	   if rising_edge(clk) then
	       reg <= nreg;
	   end if;
    end process;
end behavioral;
