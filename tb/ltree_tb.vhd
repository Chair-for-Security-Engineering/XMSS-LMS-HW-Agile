library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

use work.hss_types.all;
use work.hss_functions.all;

entity ltree_tb is
end entity;

architecture default of ltree_tb is
    constant t: time := 10 ns;

    constant TREE_HEIGHT: integer := 10;
    constant N: integer := 32;
    constant WOTS_W: integer := 16;
    constant WOTS_LEN: integer := calculate_len1(N, WOTS_W) + calculate_len2(N, WOTS_W);

    constant HASH_BUS_ID_WIDTH: integer := work.params.HASH_BUS_ADDRESS_BITS;
    constant HASH_BUS_LEN_WIDTH: integer := work.params.HASH_BUS_LENGTH_BITS;
    constant HASH_BUS_CTR_WIDTH: integer := 8;

    constant BRAM_ADDR_WIDTH: integer := work.params.BRAM_ADDR_SIZE;
    constant BRAM_WOTS_KEY_ADDR: integer := 0;

    type hash_array_t is array(0 to WOTS_LEN - 1) of std_logic_vector(8 * N - 1 downto 0);

    type test_case_t is record
        pub_seed: std_logic_vector(8 * N - 1 downto 0);
        leaf_index: std_logic_vector(TREE_HEIGHT - 1 downto 0);
        public_key: hash_array_t;
        leaf_value: std_logic_vector(8 * N - 1 downto 0);
    end record;

    signal clk, reset: std_logic;

    signal h_enable, h_done, h_next, h_busy, h_idle: std_logic;
    signal h_id, h_next_id, h_done_id: unsigned(HASH_BUS_ID_WIDTH - 1 downto 0);
    signal h_block, h_next_block, h_done_block: unsigned(HASH_BUS_CTR_WIDTH - 1 downto 0);
    signal h_output, h_input: std_logic_vector(8 * N - 1 downto 0);
    signal h_len: unsigned(HASH_BUS_LEN_WIDTH - 1 downto 0);

    signal uut_pub_seed: std_logic_vector(8 * N - 1 downto 0);
    signal uut_leaf_index: std_logic_vector(TREE_HEIGHT - 1 downto 0);
    signal uut_enable, uut_done: std_logic;
    signal uut_output: std_logic_vector(8 * N - 1 downto 0);

    signal th_enable, th_done: std_logic;
    signal th_pub_seed, th_left, th_right, th_output: std_logic_vector(8 * N - 1 downto 0);
    signal th_address_3_to_6: std_logic_vector(4 * 32 - 1 downto 0);

    signal b_a_we: std_logic;
    signal b_a_address: std_logic_vector(BRAM_ADDR_WIDTH - 1 downto 0); 
    signal b_a_input: std_logic_vector(8 * N - 1 downto 0);
    signal b_a_output: std_logic_vector(8 * N - 1 downto 0);

    signal uut_b_a_we: std_logic;
    signal uut_b_a_address: std_logic_vector(BRAM_ADDR_WIDTH - 1 downto 0); 
    signal uut_b_a_input: std_logic_vector(8 * N - 1 downto 0);
    signal h_b_a_we: std_logic;
    signal h_b_a_address: std_logic_vector(BRAM_ADDR_WIDTH - 1 downto 0); 
    signal h_b_a_input: std_logic_vector(8 * N - 1 downto 0);

    signal b_b_en, b_b_we: std_logic;
    signal b_b_address: std_logic_vector(BRAM_ADDR_WIDTH - 1 downto 0); 
    signal b_b_input: std_logic_vector(8 * N - 1 downto 0);
    signal b_b_output: std_logic_vector(8 * N - 1 downto 0);

    signal done: std_logic;

    signal setup: std_logic;

    constant TEST_XMSS: test_case_t := (
        pub_seed => x"747da1dcd0be23030ad7d72d1e10881e330495a0ad0a2932844bacf00ea112a9",
        leaf_index => std_logic_vector(to_unsigned(2, TREE_HEIGHT)),
        leaf_value => x"28856680bb87fdfc66341aa0fd8855a08c5cdaf3637e0d2974571fc6267ac85a",
        public_key => (
            x"c733cdf806a6fed4edf88f588d5fad5e6a6e3d774fcd0a7e51d4a224124caf9e",
            x"ba0a5a5c6cd33025fbeba56bfb052afb6fba1bccd5414dd37143061c2dcffbd2",
            x"7d8421075c4d19452d5f90dc07aa570aefd509faf3955db05b2fe413f08b573f",
            x"bd023731d440fd382631da6f73e31ffcb5c9949a085457609e16dde2c4a82a6e",
            x"0765a08ae52b5fdda0b567611825a1d2fe8c2a8ea76bdfbd881e6eaf43b3fae1",
            x"b4ea8b54ae95d3470cbcba7067527cecd690e216e75b79c22d6407678fa63c80",
            x"8f3f647d7ae61181131a5b280a182cf59c1c3e949830c8e44388ead8e3ab8e61",
            x"fadfc3d285b6e21b19ae1091ddc4f9c256b9684a6355e0117b0c6600fcc1e4b2",
            x"5eec180132eee0be7b08ea59fc361ed2136e1d21c3297e7811514e0c638f7eae",
            x"951366a1664ed9641187b2bae06edeb81bcfb3022cdc28b355b195f8b0c940bb",
            x"0eb709fdf253a204633a4eff791c037114aa16c8d1a521f0270f56308f4ab315",
            x"72383792b143d5362ce15a1ac707e485baad510cb4521d48eab98cd15173e532",
            x"a2f4430687711ab7b244af6eb111924771a3471c638a103015805019d9b18791",
            x"b776185bf05d0bbda1f6e8708a11cfe1862435106dd0ab6d4166e758a2c18f48",
            x"b332b27b31a5c4d24c895b23b61fbc4421bb10f98aef98c79474eef9562f6896",
            x"bc5a172cc1821bf9e46906c96c6fe6e11ba9fd2b7764c9457c621d1522c22d1d",
            x"9234a5d1a13ebab07836df9a119c134d4e1586be80f8bca3ea905bc1712b98e1",
            x"0f7715ba67728e8dd6e9918d19319ff0fe60a0eee19fe592d6825dec5807e960",
            x"0e2a4dcd1b0eb1c88c4254aac5e5b5200fa9c15d77eb6a6f21b330d1eb7a196b",
            x"111b698855b437d6b4c99f667e26632276f15731874a38f4f844dd3abe9aca3f",
            x"80d957265728736a7e9a531b53ab3eb18084ed8d79409694859f1943028395fe",
            x"c39cbc641ffde8fc5582f6f7916a7714e25784bf3d5a278d83997ee2bba9af5f",
            x"2cc6f6be747dafb3d7aa43d9af499726982bbb0537537127ab144cf9f53eec25",
            x"4c344d98f8a4434a0461b9aafb8c81b4cf983192fa498083416de2389851c78c",
            x"91eed601e344bd9642adb4de51947ed30b0c1c33a34f5dd67f3b5eecacd0d01a",
            x"734faf66ae01c6a01f4f7aabdbddc2b2686fb17c69921852a70ab07f0f3e7a14",
            x"4766df2d10dc34ab2d5ecc41eabb45fd84379236ced9ee41ae61f89699d99adc",
            x"58f46ba2e024b1212da610b4915bbb5f315720c4be0bcc913ed901fd7f30def9",
            x"dba6c351ee2ce2751babe3e5f187105350284d104916d6b95bce3b0a9cb7ea1d",
            x"1ca0501d19c8420e34f0afbf05ff38b911d663e543eb014eefd404f4d64be175",
            x"ff9c8d5bb62462a341188662b2126d30179e21964326b965603d7b62edcde146",
            x"db4de4e891f6a0cacba153d8cf6b62743a9b6dcb538c4b34988e7fa6f7688a08",
            x"4fec35f39d12314c3e57dd1496e792fe5784eb3d24e96541cad027a001ee5a1d",
            x"3c4da5e2fc5e16883057180e8e15ef6cde8bea7f4cb872d0ef2d69aba37a61cb",
            x"0e5dc45e2740fac101d7e47b58d5f3d6d1cc76d4a7da3778a30fc2bea68e05fe",
            x"a30de4f87215849fb29637085dccc47f9f63921a30983a8879ee1bd320efc476",
            x"537a1e246380ccf73daddbfd9d1fcad894e7ddc18e46a5f1a175ff4dfe1b7993",
            x"7ed1a23eae696a00653c7a7723304a9826590e7e1589a64011011cf9de3e9c1c",
            x"31dbf471693ea0fa385f7a399f0314b94e52f62dbb9ca92d9ccfcf8fdb9caaed",
            x"c6c11f149cb856bf634cf70af4b0f3cdbcd9564f1212b72a5e0a87d1813425d7",
            x"658d32d8cad10bcd64475eee82c4c060d3454f8ade4e08850f87af09e8e06c4f",
            x"607b1c0bee22aee3c87b2c8f5acdd36c41dccdf440515c417314264031b27280",
            x"b96ecec0d0f379bee371c0fab772260543e4a59c4990a7497c53400401dc6f8a",
            x"1ba6d460cac40154f9d3b346509de96144c409ea30ace540bc455c169b416740",
            x"74c4ab870522ccc4d1545a1f7b8ea19302e1f8883594424e26ba7f984cb20137",
            x"1f7369d0b60737279effeca61800ecb82c243189aee7877e54aeb96460a323fa",
            x"399bc131757a076a99755100ce9d542b6edaf730f732dae0620e96cbca3531a6",
            x"8416dcfd28af6b334ce5aa14f37d5a2943d5dc13b68f443a70bc2ce22409dd99",
            x"1ce72ae9a289afb85b1b2c33d0f2f115343af15caa472791f9b99eb66fc6679d",
            x"5f2b8058e7ca872fe408c4a05a946783f3ae125eb8d712459693de5f13dd5fb2",
            x"81d579515eb46ad1468908ff1364b323382501098332b0e11d53b20390407a6c",
            x"7e0ca4fb1281f4128faabddc8e8fa2fa71452bcb7b62f9f0abe0af997e3a3bd1",
            x"813cdfa18fbc103ae2b30d87a01d376b76868b750ac9e950b6b3bc1b89e043f9",
            x"5f4416e5be28b5ad8667844ce342e6ffec3fa028b6cb8fc7816df01f15d5c03c",
            x"fcb3dc6b63a4fc35138f8be81e4293a813b7a11b1a40e1c3ec441f7706c45ac7",
            x"70d04417190cc0552795c3f7db492f831b3fcb1eab61a6e293404dae770f3620",
            x"1d78ba55c2a64f1a769c8d5c2fe1608c07b01219becacce5a954bb528cc64fe3",
            x"1d20567ea1fdbd8846ef481d66ab65283c684cbfdab40c66eaa5383fa3b3ac70",
            x"e95b68589b681f93192ea0c7f9d999d09d814f80f0f0f1f8f57f419f153a8f33",
            x"1e6d260768d07f462cdf31a58ee09713c4c402fd5059421f3434ac6be2784f5c",
            x"8c53a747c187042a845e116539d68b934eb5afca896fc29f6b86cb96523bbc05",
            x"05dccb0bc59031b29e168ae39fc343fbb2b9beccc1d23840d586993141c9c821",
            x"31f5bb4935d745c50dbc7d965a320b7b5823a005c48735bc354f927528c37aa4",
            x"7ed54a6c1986d8c906dc48569abeb43cad8d2c7c99c80351e24fb1cecc730afa",
            x"f5dd875ffbe51613933e0b2324e9c6197e654a9c63959fe1e6b17ae7afb8ae6e",
            x"1996781c93941dc5859514493b38fe80f621957e085f6c43dcebc2514144bc21",
            x"1b7c86a1d77232c1f027ed35e851936dc37b9829a83ac34d9adfccd975ec0c53"
        )
    );

begin
    uut: entity work.ltree
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

        enable => uut_enable,

        pub_seed => uut_pub_seed,
        leaf_index => uut_leaf_index,

        done => uut_done,
        output => uut_output,

        th_enable => th_enable,
        th_left => th_left,
        th_right => th_right,
        th_address_3_to_6 => th_address_3_to_6,
        th_done => th_done,
        th_output => th_output,

        b_a_we => uut_b_a_we,
        b_a_address => uut_b_a_address,
        b_a_input => uut_b_a_input,

        b_a_output => b_a_output,

        b_b_we => b_b_we,
        b_b_address => b_b_address,
        b_b_input => b_b_input,

        b_b_output => b_b_output
    );

    thash: entity work.thash
    generic map(
        N           => N,
        TREE_HEIGHT => TREE_HEIGHT,
        CORES => work.params.HASH_CORES,

        HASH_BUS_ID_WIDTH  => HASH_BUS_ID_WIDTH,
        HASH_BUS_LEN_WIDTH => HASH_BUS_LEN_WIDTH,
        HASH_BUS_CTR_WIDTH => HASH_BUS_CTR_WIDTH
    )
    port map(
        clk => clk,
        reset => reset,

        enable => th_enable,

        pub_seed => th_pub_seed,
        address_3_to_6 => th_address_3_to_6,
        left => th_left,
        right => th_right,

        done => th_done,
        output => th_output,

        h_enable => h_enable,
        h_id => h_id,
        h_block => h_block,
        h_len => h_len,
        h_input => h_input,

        h_done => h_done,
        h_done_id => h_done_id,
        h_done_block => h_done_block,
        h_next => h_next,
        h_next_id => h_next_id,
        h_next_block => h_next_block,
        h_output => h_output,
        h_busy => h_busy,
        h_idle => h_idle
    );

    hash_bus: entity work.hash_core_collection
    port map(
        clk => clk,
        reset => reset,

        hash_alg_select => (others => '0'),

        d.enable => h_enable,
        d.id.ctr => h_id,
        d.id.block_ctr => h_block,
        d.len => h_len,
        d.input => h_input,

        q.done => h_done,
        q.done_id.ctr => h_done_id,
        q.done_id.block_ctr => h_done_block,
        q.mnext => h_next,
        q.id.ctr => h_next_id,
        q.id.block_ctr => h_next_block, 
        q.o => h_output,
        q.busy => h_busy,
        q.idle => h_idle
    );

    clk_gen: process
    begin
        clk <= '0';
        wait for t / 2;
        clk <= '1';
        wait for t / 2;
        if done = '1' then
            wait;
        end if;
    end process;

    block_ram: entity work.blk_mem_gen_0
    port map(
        clka => clk,
        ena => '1',
        wea(0) => b_a_we,
        addra => b_a_address,
        dina => b_a_input,
        douta => b_a_output,
        clkb => clk,
        enb => b_b_en,
        web(0) => b_b_we,
        addrb => b_b_address,
        dinb => b_b_input,
        doutb => b_b_output
    );

    b_a_we <= uut_b_a_we when setup = '1' else h_b_a_we;
    b_a_input <= uut_b_a_input when setup = '1' else h_b_a_input;
    b_a_address <= uut_b_a_address when setup = '1' else h_b_a_address;

    test: process
    begin
        done <= '0';
        reset <= '1';
        uut_enable <= '0';
        b_b_en <= '0';

        wait for t + t / 2;

        reset <= '0';
        setup <= '0';

        for i in 0 to WOTS_LEN - 1 loop
            h_b_a_address <= std_logic_vector(to_unsigned(BRAM_WOTS_KEY_ADDR + i, BRAM_ADDR_WIDTH));
            h_b_a_we <= '1';
            h_b_a_input <= TEST_XMSS.public_key(i);
            wait for t;
        end loop;
        setup <= '1';
        h_b_a_we <= '0';
        b_b_en <= '1';

        th_pub_seed <= TEST_XMSS.pub_seed;
        uut_pub_seed <= TEST_XMSS.pub_seed;
        uut_leaf_index <= TEST_XMSS.leaf_index;
        uut_enable <= '1';

        wait for t;

        uut_enable <= '0';

        wait until uut_done = '1';

        assert uut_output = TEST_XMSS.leaf_value report "Generated invalid leaf value." severity error;

        done <= '1';

        wait;
    end process;

end architecture;
