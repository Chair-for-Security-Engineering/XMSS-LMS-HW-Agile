library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

package hss_functions is 
    function log2( n : in integer ) return integer;
    function calculate_len1( n: in integer; w : in integer ) return integer;
    function calculate_len2( n: in integer; w : in integer ) return integer;
end package;

package body hss_functions is
    function log2(n : in integer) return integer is
        variable n_bit : unsigned(31 downto 0);
    begin
        if n <= 0 then
            return 0;
        end if;

        n_bit := to_unsigned(n, 32);

        for i in 31 downto 0 loop
            if n_bit(i) = '1' then
                return i;
            end if;
        end loop;

        -- should be unreachable
        return 1;
    end function;

    function calculate_len1( n: in integer; w : in integer ) return integer is
        variable log_w: integer;
    begin
        log_w := log2(w);
        return (8 * n + log_w - 1) / log_w;
    end function;
    
    function calculate_len2( n: in integer; w : in integer ) return integer is
        variable log_w: integer;
    begin
        log_w := log2(w);
        return (log2((w - 1) * calculate_len1(n, w)) + 1 + log_w - 1) / log_w;
    end function;
end package body;
