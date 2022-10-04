library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

use work.hss_types.all;
use work.hss_functions.all;

entity lmots_compressor_tb is
end entity;

architecture default of lmots_compressor_tb is
    constant t: time := 10 ns;

    constant TREE_HEIGHT: integer := 10;
    constant N: integer := 32;
    constant WOTS_W: integer := 16;
    constant WOTS_LEN: integer := calculate_len1(N, WOTS_W) + calculate_len2(N, WOTS_W);

    constant HASH_BUS_ID_WIDTH: integer := work.params.HASH_BUS_ADDRESS_BITS;
    constant HASH_BUS_LEN_WIDTH: integer := work.params.HASH_BUS_LENGTH_BITS;
    constant HASH_BUS_CTR_WIDTH: integer := 8;

    constant BRAM_ADDR_WIDTH: integer := 15;
    constant BRAM_WOTS_KEY_ADDR: integer := 0;
    constant BRAM_TREE_LEAFS_ADDR: integer := 2 ** TREE_HEIGHT;

    type hash_array_t is array(0 to WOTS_LEN - 1) of std_logic_vector(8 * N - 1 downto 0);

    type test_case_lms_t is record
        I: std_logic_vector(127 downto 0);
        q: std_logic_vector(TREE_HEIGHT - 1 downto 0);
        public_key: hash_array_t;
        leaf_value: std_logic_vector(8 * N - 1 downto 0);
    end record;

    signal clk, reset: std_logic;

    signal h_enable, h_done, h_next, h_busy, h_idle: std_logic;
    signal h_id, h_next_id, h_done_id: unsigned(HASH_BUS_ID_WIDTH - 1 downto 0);
    signal h_block, h_next_block, h_done_block: unsigned(HASH_BUS_CTR_WIDTH - 1 downto 0);
    signal h_output, h_input: std_logic_vector(8 * N - 1 downto 0);
    signal h_len: unsigned(HASH_BUS_LEN_WIDTH - 1 downto 0);

    signal uut_pub_seed: std_logic_vector(127 downto 0);
    signal uut_leaf_index: std_logic_vector(TREE_HEIGHT - 1 downto 0);
    signal uut_enable, uut_done: std_logic;
    signal uut_output: std_logic_vector(8 * N - 1 downto 0);

    signal b_we: std_logic;
    signal b_address: std_logic_vector(BRAM_ADDR_WIDTH - 1 downto 0); 
    signal b_input: std_logic_vector(8 * N - 1 downto 0);
    signal b_output: std_logic_vector(8 * N - 1 downto 0);

    signal done: std_logic;

    signal addr: std_logic_vector(BRAM_ADDR_WIDTH - 1 downto 0);

    constant TEST_LMS: test_case_lms_t := (
        I => x"215f83b7ccb9acbcd08db97b0d04dc2b",
        q => std_logic_vector(to_unsigned(4, TREE_HEIGHT)),
        -- pk compressed => x"0b5659e376286d37161339b96d91a261b85cd9c858b528c46b10cdf39128fa26",
        leaf_value => x"10343254c0f9cc00203393051f96d863957f80f26e5d73ad44e41b70f3c9e170",
        public_key => (
            x"f7e98665af554acc21c20142dc3358a9bd92e267b1b6ad0c26fc7381b72ff9b8",
            x"a5121d75db52969b1f0e16907003535fabe2c0530cb9d912ff4059f4e8ff207c",
            x"15c0005d6143f4f1de1168cdddd56f8ce9f54f80e8cd2f1955410f45a58e70ea",
            x"8ad450598a34a78c75ab5205169269c5949f18c3cdc59079c5cfb1dc072f524a",
            x"2a4115bcc20d67a867d6d87ca6a57282d89dfb57a453102ee9c3f51b4bc79d13",
            x"b3f528d7c31f5a382ee4bee1a795075a9709e6cbd64c04dbf2b18ee5f7b62727",
            x"9822d756f44b4704547460fe800bdce1b2087852d4e5322b2f32f0bad2cf5cb2",
            x"2cbfa6ac360de587d0f2cde972683c8b3f26a950c39e4a7159cc639c68b0270a",
            x"fd5ac8e87ed7b0918d2fb68e49f16523648fd9945d9e98cb7a57e313a6f2da98",
            x"c2946739035c82125ce42ac30e4b7551a0f4287fbf150c3c070336fc837d26e7",
            x"1d0a4139c5da6726e922fa4568c5744deb4bdfb378b49ebfdce7a46259876ead",
            x"bd1c5d1c3f72dcaccd276ee6fe0941a44edd6033beb064f09e4ad4ba293d09df",
            x"947991413365e24f8c0a5ef5c78da4d8bafd0983a5c3d1d224e3c78ba1b307be",
            x"a953fa2f05e8c23d3e6fd4d4546e151263f2720c588808552d52b7cf865575a4",
            x"414e1c6d3897c5db9495d1d2c97b1f782009783e85d584991d0fb9c3b679f794",
            x"18fc3ea3ea67c37f4b6fcc23cfafd97cdc18f0fdd79e4fec2d7051b08ccd256c",
            x"c0cf17dcb6cc3c48d9f938b122c9c0ad3c6777b1327d75da64c7db48b48164d3",
            x"931a02090cc107938dddef6da648afb0125994124f85d058c6f11df02e2c8941",
            x"81334390d1a5cf3a6ce0376839a77f2bf56c950cb013b8bb14b000bd50d91b74",
            x"8b6c71d0c5c2a53afc07344e3b7aaae517672b457b22563ef1685f1760b0d90b",
            x"e1d09d39576841b4c057cf3ec08328e395c8d6e09355fc376250319b484051f1",
            x"f53032a4558351fe2ea432d31eabe5f53f927387473fdfa4f6ddc91ea3431a62",
            x"56981bdf1bc6174a2eaa163f8360589f448c3291e6a66e3c9d9955e73380a2af",
            x"3ffc01389cd18077a12a563f46bd26ab44353ea034c32bbc3fa38572301711d2",
            x"2fc5e678bf07f19bf9f948d40e03c536485fc41f2ec95a82f2ba84b26ffc74d3",
            x"9511296bb90283e390c2793f1bd30422d456d6f691e5bdd6d52306a8c455a6a3",
            x"53ac72cebd33babd81c58f25f5c90d2bf49c1a0cbe7419529a60c6b3478ea5b4",
            x"e330aaf4b9237b9e8bfbc1b918b88584306e8c60b56f103105f003d4aca25dbb",
            x"6073d2e10ff3450fd1c2d1e0ddff711368b43a8ea1d0b9a545b2c7f494108807",
            x"3fdd1a3cf4fe593e620bd993458454f52d69280752f4a3bd4659f1dab3cc66fb",
            x"e708db1c87fb551903ae9e23da1acee08a824cc0b98d25c01e8af154cc7d00f0",
            x"0a0d535135ed3ba6daf74c2ef13e5c8d325c82c112e6704e697e94fd902e8f49",
            x"982fb2e370c078edb042c84db34ce36b46ccb76460a690cc86c302457dd1cde1",
            x"e9f338b78734260cecc848f69379b96dc7a56e747ec03df5a955725afb8f3444",
            x"a3f4d8f859587a0ad5bcf5b4be29d11d20ba4efef991b281d1e147fbd74af6dd",
            x"21bc1b1074d04534ba0ae5b486902029022b485dd5bf387b5e3e2c0fdc8c2efe",
            x"c40626ed05ae573818c398a335476b7b2e7906999b070fc80f91d2b51a95bd47",
            x"be51ea621cf5383f968ba82e71c60713e4b4d0a41690e308cfcb56232f37556d",
            x"769f1fb7877b043385be195e092fb3676f1ff02f02b2afc375b83c6b8dd92ffc",
            x"bf9384df602e2983fc36e64efcaaebf9cef876f60a2d97a8de2818c5deafa320",
            x"a96f50ea39e385f8a38daca60440bbb774d5d6b523617be82e78df5dd2eaa8d4",
            x"45e80c5d8a2c9d48f31907c5cfdd7467705babc53174b018cb402a2070973221",
            x"29809e2fb875c8da8a4355422a13359f7bc61d811cc1e981c510151d608e6188",
            x"5aa4bb4a6d734d21827f8507bfb83585749984a9ef8c0318f27d4c6409e0afc2",
            x"4a0c660de7c896d9ee32ad8f76d0f55f0a8bd46fbe1ee901b5dca83af3c6a3ba",
            x"905d0f073d020e3dd5554d5c3c66866be5c1846b7833d92f4ff54c7070770274",
            x"5c320dc3283a85c712f9155755986965030d471ef0a464a2e62bd43d42728be2",
            x"9f8d717a61c119da524db7b5fb939a2d574a9237276ac6d1af7e7ec72c62e20a",
            x"f9e334db654633f85dc93baa852f16fc00d89492ac2a7ef1b318fe78af5e78df",
            x"9ce179509011ae774272588e7b9110a6028e4d949c7813abd778825edf3e8d21",
            x"4465e92c24e1688260a62f5b394c099cd87f95fd752789b64e6a3951fbba1d2b",
            x"47ec177d7c6b7f76c067aad33670db900fb439d2d865ed70f1eb707a1321a925",
            x"324722395cfab101fb2deb9ef3158dfc01dc6f78b8830a801c60b6fdb44eb1ed",
            x"dc8edb8322d0ddcf66be41766b9500c6badd4a8ee964ab3b1a20e65ff9f552f1",
            x"7a44bdd4cdf1cb57c72f93e0c917872668c4a3fc7a807f015bbfc682a0f5651a",
            x"fcda9e0aa04e6cbccedb0a86677ff848f4bfe6c58923e4e7b929d3643cd984c7",
            x"4daeb0053ae1c35b10e12d9a7f024e5a47c787b64e7a1c6032847d79de1e3644",
            x"5231b459be25a19930d9bcc550032e00b75acf6a07c49c88b262bc9a9623a16b",
            x"a5e5a9b27b8c7c711adabeffe420b1f5a21a3d35e541f33339584dc9bb3492b7",
            x"008efcfa6d5556ec9b75e1cb8676174f2e046c07f3b8e96a870ffad9e27fb3dc",
            x"95bef67d9ead351a1030639ce84a4f368b8a6bee806962972d741e1315398ceb",
            x"f4eabb8ef5ab8c0949be63ec5e1722ac54c93126a9915a620b1faa8a5fee3961",
            x"8376ef0d7bb9c875c10f502bedee6c3f2cc77a6e4363d7011dd190427d112a42",
            x"7cb40d00e7c57b0e4911987e97c37555c7d62605f0630781089606efadd0f8c9",
            x"7bc6bb11ab7db61bdfdd99dd1e31f0fd1c720758e676e9ff0c1a5ba189eae681",
            x"17d1825320821dc2b11eebd9f50f0eaeb791f0f0eb1ad7eff85fc1a0607c05ce",
            x"a34f5cc6a41d20929c5844d74c88f84f39de894a5e9107a605cc1dbd1361aac9"
        )
    );

begin
    uut: entity work.lmots_compressor
    generic map(
        N           => N,
        TREE_HEIGHT => TREE_HEIGHT,
        WOTS_W      => WOTS_W,

        HASH_BUS_ID_WIDTH  => HASH_BUS_ID_WIDTH,
        HASH_BUS_LEN_WIDTH => HASH_BUS_LEN_WIDTH,
        HASH_BUS_CTR_WIDTH => HASH_BUS_CTR_WIDTH,

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
        h_idle => h_idle,

        b_we => b_we,
        b_address => b_address,
        b_input => b_input,

        b_output => b_output
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

    addr <= b_address when to_integer(unsigned(b_address)) - BRAM_WOTS_KEY_ADDR < TEST_LMS.public_key'length else std_logic_vector(to_unsigned(BRAM_WOTS_KEY_ADDR, BRAM_ADDR_WIDTH));
    b_output <= TEST_LMS.public_key(to_integer(unsigned(addr)) - BRAM_WOTS_KEY_ADDR);

    test: process
    begin
        done <= '0';
        reset <= '1';
        uut_enable <= '0';

        wait for t + t / 2;

        reset <= '0';

        uut_pub_seed <= TEST_LMS.I;
        uut_leaf_index <= TEST_LMS.q;
        uut_enable <= '1';

        wait for t;

        uut_enable <= '0';

        wait until uut_done = '1';

        assert uut_output = TEST_LMS.leaf_value report "Generated invalid leaf value." severity error;

        done <= '1';

        wait;
    end process;

end architecture;
