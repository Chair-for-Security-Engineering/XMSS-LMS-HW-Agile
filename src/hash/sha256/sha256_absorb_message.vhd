----------------------------------------------------------------------------------
-- Company: Ruhr-University Bochum / Chair for Security Engineering
-- Engineer: Jan Philipp Thoma
-- 
-- Create Date: 13.08.2020
-- Project Name: Full XMSS Hardware Accelerator
----------------------------------------------------------------------------------


library IEEE;
use IEEE.STD_LOGIC_1164.ALL;
use ieee.numeric_std.all;

use work.sha_comp.ALL;
use work.sha_functions.ALL;

entity absorb_message is
    generic(
        HASH_BUS_LENGTH_WIDTH: integer
    );
    port(
        clk: in std_logic;
        reset: in std_logic;
	    halt  : in std_logic;
        enable: in std_logic;
        len   : in unsigned( HASH_BUS_LENGTH_WIDTH - 1 downto 0 );
        input : in std_logic_vector( 255 downto 0);

        done : out std_logic;
        mnext: out std_logic;
        o    : out std_logic_vector( 255 downto 0)
   );
end absorb_message;

-- This Module is responsible for feeding the message in 32 Bit Chunks to 
-- the underlying SHA Module and creating the padding
    
architecture Behavioral of absorb_message is
    type state_type is (S_IDLE, S_MSG_ABSORB_1, S_MSG_ABSORB_2, S_MNEXT_1, S_MNEXT_2);
    type reg_type is record 
        state : state_type;
	    is_padded, last : std_logic;
        message : unsigned(255 downto 0); -- 256 bit message block to be absorbed
        input_len, remaining_len : unsigned( HASH_BUS_LENGTH_WIDTH - 1 downto 0 );

        hash_enable : std_logic;
    end record;
    type out_signals is record
        sha : sha_output_type;
    end record;
    
    signal modules : out_signals;
    signal r, r_in : reg_type;
begin

    --------- Wire up the hash module:
	sha_256 : entity work.sha_256
	port map(
		clk     => clk,
		reset   => reset,
		d.enable  => r.hash_enable,
		d.halt => halt,
		d.last    => r.last,      
		d.message => r.message(255 downto 224), 
		q         => modules.sha
    );

    -- The output is equal to the underlying SHA Module
    o <= modules.sha.hash;
    done <= modules.sha.done;

    combinational : process (r, enable, input, len, modules)
	   variable v : reg_type;
	begin
	   v := r;
	   v.hash_enable := '0';
       mnext <= '0';
       
	   case r.state is
	       when S_IDLE =>
	           if enable = '1' then
                   -- get the first message block and start hashing
	               v.message := unsigned(input);
	               v.hash_enable := '1';
	               v.input_len := len;
	               
	               -- Padding indicator for very short messages
	               -- This doesn't really happen in XMSS except if very short
	               -- messages should be signed.
	               if len < 256 then
	                   v.remaining_len := ( others => '0' );
	                   v.message(to_integer(255 - len(7 downto 0))) := '1';

	                   v.is_padded := '1';
	                   v.last := '1';
	               else 
	                   v.is_padded := '0';
	                   v.remaining_len := len - 256;
	                   v.last := '0';
	               end if;
	               
	               v.state := S_MSG_ABSORB_1;
               end if;
               
               
           when S_MSG_ABSORB_1 =>
              v.message := SHIFT_LEFT(r.message, 32);
              
              if modules.sha.mnext = '1' then
                    v.state := S_MNEXT_1;
                    if r.remaining_len /= 0 then
                        mnext <= '1';
                    end if;
              end if;

           when S_MNEXT_1 => 
              if r.remaining_len >= 256 then
                   v.message := unsigned(input); 
	               v.remaining_len := r.remaining_len - 256;
	          else
	               v.message := (others => '0');
	               if r.remaining_len = 0 then -- there is no more message left
	                   if  r.is_padded = '0' then  -- padding 1 not in place
	                       v.message(255) := '1';
	                   end if;
	               else
	                   v.message := unsigned(input); 
	                   v.message(to_integer(255 - r.remaining_len(7 downto 0))) := '1';
	                   v.remaining_len := (others => '0');
	               end if;
	               v.is_padded := '1';
              end if;
              
	          if r.remaining_len < 192 then
	               v.message := v.message or gen_padding_sha256(r.input_len);
	               v.last := '1';
	          end if;

	          v.state := S_MSG_ABSORB_2;

	      when S_MSG_ABSORB_2 =>
	          v.message := SHIFT_LEFT(r.message, 32);

              if modules.sha.mnext = '1' then
                    v.state := S_MNEXT_2;
                    if r.remaining_len /= 0 then
                        mnext <= '1';
                    end if;
              end if;
              
              if modules.sha.done = '1' then
                    v.state := S_IDLE;
              end if;
	      when S_MNEXT_2 =>
              if r.remaining_len >= 256 then
                   v.message := unsigned(input); 
	               v.remaining_len := r.remaining_len - 256;
	          else
	               if r.remaining_len = 0 then -- there is no more message left
	                   -- message is implicitly 0 due to SHIFT
	                   if  r.is_padded = '0' then  -- padding 1 not in place
	                       v.message(255) := '1';
	                   end if;
	               else
	                   v.message := unsigned(input); 
	                   v.message(to_integer(255 - r.remaining_len(7 downto 0))) := '1';
	                   v.remaining_len := (others => '0');
	               end if;
	               v.is_padded := '1';
              end if;
	          v.state := S_MSG_ABSORB_1;

	   end case;
	   
       r_in <= v;
	end process;
	
	
    sequential : process(clk, halt)
   -- variable v : reg_type;
	begin
	   if rising_edge(clk) then
	    if reset = '1' then
	       r.state <= S_IDLE;
	    elsif halt = '0' then
		   r <= r_in;
        end if;
        
       end if;
	end process;
end Behavioral;
