library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

use work.hss_types.all;
use work.hss_functions.all;

entity wots_core_shared_tb is
end entity;

architecture default of wots_core_shared_tb is
    constant t: time := 10 ns;

    constant TREE_HEIGHT: integer := 10;
    constant N: integer := 32;
    constant CHAINS: integer := 8;
    constant CORES: integer := 8;
    constant WOTS_W: integer := 16;
    constant WOTS_LEN: integer := calculate_len1(N, WOTS_W) + calculate_len2(N, WOTS_W);

    constant HASH_BUS_ID_WIDTH: integer := work.config.HASH_BUS_ADDRESS_BITS;
    constant HASH_BUS_LEN_WIDTH: integer := work.config.HASH_BUS_LENGTH_BITS;
    constant HASH_BUS_CTR_WIDTH: integer := 3;

    constant BRAM_ADDR_WIDTH: integer := 10;
    constant BRAM_IO_ADDR_WIDTH: integer := 10;
    constant BRAM_WOTS_KEY_ADDR: integer := 0;
    constant BRAM_IO_WOTS_SIG_ADDR: integer := 0;

    constant TARGET: scheme_t := XMSS;

    type hash_array_t is array(0 to WOTS_LEN - 1) of std_logic_vector(8 * N - 1 downto 0);

    type test_case_xmss_t is record
        seed: std_logic_vector(8 * N - 1 downto 0);
        leaf_index: std_logic_vector(TREE_HEIGHT - 1 downto 0);
        message_digest: std_logic_vector(8 * N - 1 downto 0);
        secret_key, signature, public_key: hash_array_t;
    end record;

    type test_case_lms_t is record
        I: std_logic_vector(127 downto 0);
        q: std_logic_vector(TREE_HEIGHT - 1 downto 0);
        message_digest: std_logic_vector(8 * N - 1 downto 0);
        secret_key: hash_array_t;
        signature: hash_array_t;
        public_key: hash_array_t;
    end record;

    signal clk, reset: std_logic;

    signal h_enable, h_done, h_next, h_busy, h_idle: std_logic;
    signal h_id, h_next_id, h_done_id: unsigned(HASH_BUS_ID_WIDTH - 1 downto 0);
    signal h_block, h_next_block, h_done_block: unsigned(HASH_BUS_CTR_WIDTH - 1 downto 0);
    signal h_output, h_input: std_logic_vector(8 * N - 1 downto 0);
    signal h_len: unsigned(HASH_BUS_LEN_WIDTH - 1 downto 0);

    signal mode: std_logic_vector(1 downto 0);
    signal uut_pub_seed, uut_message_digest: std_logic_vector(8 * N - 1 downto 0);
    signal uut_leaf_index: std_logic_vector(TREE_HEIGHT - 1 downto 0);
    signal uut_enable, uut_done, scheme_select: std_logic;

    signal b_we, b_io_we: std_logic;
    signal b_address: std_logic_vector(BRAM_ADDR_WIDTH - 1 downto 0); 
    signal b_io_address: std_logic_vector(BRAM_IO_ADDR_WIDTH - 1 downto 0);
    signal b_input, b_io_input: std_logic_vector(8 * N - 1 downto 0);
    signal b_output, b_io_output: std_logic_vector(8 * N - 1 downto 0);

    signal done: std_logic;

    signal addr: std_logic_vector(BRAM_ADDR_WIDTH - 1 downto 0);
    signal io_addr: std_logic_vector(BRAM_IO_ADDR_WIDTH - 1 downto 0);

    signal generated: std_logic_vector(WOTS_LEN - 1 downto 0);

    constant TEST_XMSS: test_case_xmss_t := (
        seed => x"747da1dcd0be23030ad7d72d1e10881e330495a0ad0a2932844bacf00ea112a9",
        leaf_index => std_logic_vector(to_unsigned(1, TREE_HEIGHT)),
        message_digest => x"9c92a51368cb468aeaa97d15a0b0850c331f602e3214172224f23874009521e9",
        secret_key => (
            x"f75c82b9c6ffeb43544dc7918fa98086f6007795a9e74bce7594261d357f9101",
            x"26cb033a4a8a7d1de755eabee382090c1e43b68f64b72a6a5647c4d1db028496",
            x"3874bc481b6e5537f4889ec3d61d0fe7def6a8f86381cc95d46622efcfb5a58f",
            x"8b18eb70ebc4444393f26dbb99e14499f15b89d1daa0296dab66dc809b2e54c7",
            x"339b807a6749a637254fbf516a2bd1e948e765c7a6116eda69ce9ce668d54eb8",
            x"dc6e5ed9f90f0dd813dc24a27a3c6fd7f893aa2f6a3c0161c104b3087f7da5c8",
            x"50a0b2cdb8555829d6aee9c78df19e0ec216deb1ad9f56cec2ec673913edabc3",
            x"fbe9c16a9f5eb77015b930fa5350d389fb40e770eef256f51761811af8898a23",
            x"2aba1e205b049a95d0a17c7632530716f33b1a13066e4554c9221d14c215d2d1",
            x"cb4b19f0df7a456344e5b900532d260b53419963440532925582238b233a39e4",
            x"e2b6eba1ba0d052f91154ae74aa8b68d98e198b6bba6b6da8cd46e3b2b3476b1",
            x"08f69062d26ab452fb32a7864a37b9462c73572f948f89f6933a2328a63afe77",
            x"30a0cf25696ce9311a94ee77067a23e31585b88fd84bee1c11434a608cdba1d9",
            x"7cbd68ef6823dd71b41926bd7623810cb606ae4cb9f81ef889516022e004a30c",
            x"60af4273fa4c0251c84dd16ab76bf16a90ac75a1b5970fdf667c9dbec2231fdf",
            x"53e169ef59008aa60a1fbd684bae6dfce214ba7b6b4d36969ae336f682aaddef",
            x"7baf8ffade8aae7e36a059a8da71ed7944a96d647f7a0b713bf2e305495b85bd",
            x"ee7d4e80f17820c069d7196222395aebf7f2848e4e48444c21f503127c7ff142",
            x"4bad929659492a8df1678e487318887b7075970e4e32a1a061a219a598a2e32f",
            x"0c3db82fcd82f138587f2fc6826a44fafbaca49f7031a173d26e62cd651d9fbe",
            x"5d5b8c65a14022cb933737cfc4fb3ee43bc694c844cbb0c6ddbecaeb627afd15",
            x"2228d46de503599a1e3be8df479518210295f57c5310e79dd1bbc1628c9cef4a",
            x"172698657467d5a13069d9156ecf7005a61daee372d39c08ee6bdce075ae2a18",
            x"501413fbad58a974959c7c390609f3ef8b7cef383d749e88e3e76070f18245be",
            x"f73dbaad48d916e274aa74ea397448b0db96c8d87fcd8f2ca2dc670114ce4f09",
            x"7b8511a01b593cc1fe9dae4f02e3b538024d6430e6cc6950c5c757474ea82cf6",
            x"9e76aa8bead7cdce5dd6a1ea1b4da819e27b07e25f3118a3bef555a0bdbca7e4",
            x"1b5f3f64f249dd3b4738572d3ebf143a05068e5d3d303f4a38314c4307b41366",
            x"60caf5100038eba5c37ad220ba525e8dc493c0e264ddac8bed61bfd3f80a1e78",
            x"1e812eff48c073160dbc5e6d67ccd92a69c176b923b1609f8d2334550d12f2a1",
            x"b50e8e169382b776bff6e2bc6dcba5c41f1d9294bddc45902e873df9a1c33590",
            x"7562105ab480c34e573f640195e0af7084dd2ded4fd2145211baf7636271df1f",
            x"a897b68c7a64f024f2cf02a36252940702839cdc1dcef823c1678346da4aab89",
            x"79b45b542a524145354e9285d2ade885c2dba9a3dcf0df8a663cac0acdce9d50",
            x"3ec94ecbd18898dcb1163e7606a25bdb92aad983bc6026b8f5c6da4efc80dce5",
            x"5836e89cca61704bc643a8b645026681ad0938ad8f1f349df918e70960d5d729",
            x"543ab1b070bccfff2815c26839650feabbad769c4ab6870a6ff620e5551b037f",
            x"aedfb76e6b1949ab8d04abb85b0eee159480f39e4ededb6d27ec82199dcf3f17",
            x"1011e70a8cd39bae34756d5323601287968cd6439f32ae45ccef9b0f0567c075",
            x"ef3271d06b07159c457472e1bcc0d06bf1e614358eb59eac57174a1de38db9d3",
            x"31881493bfe4267359ff270e6a17b6bcb18c1e5d00e31194173e287b4f1fb1e9",
            x"1baab89d020dde66a15046721be9104771f25f5a05ae35ad4e2781e8132e767f",
            x"ed3cc7faf4bfe6c7913847616e4b4118dd846c2671060f0ce569d515ade72df0",
            x"3e1b022c21a7fb456255009e540c7e5529b7ed46f9e7a84ec895fd7e1857fc8f",
            x"8cc866518d64c9624a9260522af2f5d423ae211d0aa31ce7aa9173e0c9bde75c",
            x"06a40e3e4530e27091c7957fc591420b79886fd4279de4c1c3d15b133e6c950c",
            x"f56b4c7f2e3c16d092d252213ac5ba625c3a824e335a508118dc7f815116e503",
            x"35f24f97b1b0ff883ef9e171608b37b6f9a75c7f5e278237f44ffdc2c6266a6c",
            x"0e7588e2b5ef036b769fd4c6bd67be5609094a1ce37072a8f678b18e1d0d61a2",
            x"f9ab536bf836dac4e1354a7ef1ac3629669da432b70659180adb6ee52ee56611",
            x"8d69a3976d879726841b3549464bb330b6adb60c3d4687a9a0b934df0696c7f9",
            x"494408fa7cd2b20431f16d6750080ebc7b3e9508766179273bd747855957aa04",
            x"d81700536b4a33b52eb4d7c1e5c5c6c0e11e7c57ca391e86090d2824aac00703",
            x"df83d83a42ddfa581cbba2ad14c47708d4aa8367e71cc15cc49941e239bd59df",
            x"e41681357310d793d7ef3f1a2d2ce7e37adaf4db3c7501f53b6bc39ee7bd2f0b",
            x"715b9d56848f2c3661332c7f301de814fe5888f4263decf3da7b5e01623c7eb7",
            x"fc541eaf3548dab9f0110ac18f64a2c6a39b7d473cae32c4c4b29143222fa413",
            x"2fd368b6edb06fa53e8b893499a2cbbbe9e9977f3717472839f04f5a046fb4ef",
            x"6ee5501df4339ae6cdfe87c6096b75b199c24b5221ba93e57af3455fd18c7d1f",
            x"aeb19412e5440309db01b571613befe38f8200f08247df37eaaae934e206479f",
            x"0c5d6168dd6debbb9d6d4ebcee55f9e89d85eb58e363f28d2612d3af2050fcba",
            x"20f9b1844f80c42ffcb87a610d3334c1aa1e1dbf22be21acb1777876fa44b574",
            x"669450eab0f75860b70e862739e04ab889f0cd656f6051a6e9f96c9b69e7184d",
            x"ae11bc46d446e5e9cf2fc3d647d0622c66cf0e642bff079cd22b41cac95ca89f",
            x"2853e1af26c2f76ed163086a4e171945567203feada731383e40ca1744f68569",
            x"df441a225ccd71862c57004098e21897618d7439552b355e76674efc44c3a6f3",
            x"4a6d4cd8300ddc1aeae4f4331abd408c66242c6fcd11185f4a94fdba11b94401"
        ),
        signature => (
            x"5b30fcfcb09b46b9ba4cb8a076c47c549b72cb9f12139e0ea76a576084d4c88f",
            x"b49cd6f7749eac12ebdb8bc6623f194c6a87ef3b11aaf675095a7c6f0e680c83",
            x"3ebf4ed559be9b925734d130759ac7ea211ea94454a867bc5832b80131001eb0",
            x"4897d47eeaa25f4009b03190ae9e556e1f646041986e13def7d0e4e2c2b0e963",
            x"0bd6ca1026e2c4fe0483f92730cb666166c471a028e8f1dedefafa2cde47d8a9",
            x"dcbfe0e6400adb0bfb1f34671259c82d9e9f2b94a10606539b6042a3506cd968",
            x"7aace058e4f9093e93bae37a8de330915886ef7d8d0152295a87c33a3cdf977d",
            x"c1d1053a75dd2225c58ea07c8c42ec9692365947d3356ab41b574a365b1a4618",
            x"479b951d87d24a05b13bc600e29a54eb2559a258099254bc55b3c6d669f472d3",
            x"4ccb6faa68375dbefb002d41fd79da1cafc8c197dd90f51446f58f92fa53b465",
            x"e343f0729e5a2863f68d714bfffbacae77510ca177ebff73dceed8464939e73e",
            x"ea9bc293199abe9ef4e20e0fd85baafef8b539da61ba080eedcf6a651e2c99bc",
            x"7689e29ee419287d01489f9eda12ea61e41814c52919c41a4df7e735d57e523a",
            x"cecad93ed11a1c43b6b32fbe835015f9a3be5e42dfa7b3f039cec62a8f371479",
            x"b8e0d774c507475fd035fdd4091e927dcd5ec03204055789d01de8df6103108f",
            x"80fbd33c09a4f2ac35596fa2490b68db05297eab8e2dbaccfde3d63188458c24",
            x"005fb05ce94ddc31371cc3ca30408d8168a90426cdefba47cb3d15b404fa0522",
            x"c90575ceceb982dbeacda1983e54c1836ae4aeba632c55de674bc329efaeaec6",
            x"5e85c3eeea4dbd4f05a704d97229b6d2beae45e505ce7856789f5c3aabbad1cb",
            x"e8d5871e333f3f9d25297d90299679a3de24f4a3349beee9489ad96f198a847a",
            x"62b4125185c855a66d7a4edbd6667924b224ae3437e9a706acb23690b2833ace",
            x"e287af9db016611099d3ff3fb576612b04ab7a57e59fec5853a9a5fb145440c6",
            x"f95f8fce7425e605084a7de8ce2f55851e601ff9b8f403a8a1457633d37392bf",
            x"44882da3cdddcd29cbc2bcf1ca0e3690ccdd8ec91532c88491812606d6dca367",
            x"20fdd9a9f643dfb913738224bc9aba4870a90a2a1a9637fc1a8fb42dc374cab6",
            x"7b8511a01b593cc1fe9dae4f02e3b538024d6430e6cc6950c5c757474ea82cf6",
            x"79dc88097e2b6e622f1874f9edb5717f560d723709349e49ae2849bdb058fd94",
            x"1b5f3f64f249dd3b4738572d3ebf143a05068e5d3d303f4a38314c4307b41366",
            x"d4559d2f0f8eba7946f6202fb4b3291484c8b08957b5a22040748b86701e7fed",
            x"185469044d54193df9bd689237f7e5e186938409c8d68cf2172df31c13bfc0c7",
            x"b50e8e169382b776bff6e2bc6dcba5c41f1d9294bddc45902e873df9a1c33590",
            x"e64f43e810dd41c660e71f4ceb8f10acf711a963385e03824358dd93316a07bc",
            x"1f2dca018108a2b138af53347ccc4fdee3fa928efd7ee46879872d6c8505b091",
            x"19689408f768496c7b9438159a0fa55ce7ee7cf28f44989baaf6cc32561aba9f",
            x"72814b5f50cb531c6e0a3cb10b7f76008cf9a902cc5b612595f19b7c84fa5a2c",
            x"124e62d85d719be2f71156262965ce72bb6e16cb8aad0bb8a0b83e5b6acea69b",
            x"bdc9832e9ab0dd54cd78148a4e59172dc570d1c87a32d887c2ca586c407a745a",
            x"aedfb76e6b1949ab8d04abb85b0eee159480f39e4ededb6d27ec82199dcf3f17",
            x"03b45d42191324ed9202d597d9e0c5d0a89b21445b382e341ed2f6bf81304cb4",
            x"cbf43c9af131fb2eb01f0f496a674a1d9b83ff0f70627810ce4bc2c20cdc316b",
            x"c78806b474b81833f92b24b081297004a0d0b2c41d43ad23bf155cc60b66591c",
            x"9e723526d8d32c27a74816cb77e0eba1dc270c5ab91b7b5d0fe8a5f3a44fd82a",
            x"cb668c1cc0f1899706f2b5a69a2bff41741835a34e101d2deb648086ca2d66d2",
            x"208c831f52b2116f27f9d1fc5134c6123461588da4164aa115d47a0082e306a5",
            x"86c334b0c8801c86d24acd58ca832a14659cea16d6a57ff2d6d9a14da42445e8",
            x"62f5ac2e382d9617c867782c6d7960738b5d7a21645426dd7dd9b8161dac93f9",
            x"0c53cfe7a387db1cf4228cbbf96a81194e60d4fd51f405a40484564eb6b66742",
            x"f62e7fbecfdeb00aae19a11efde1f417054fd2ec90e07cb5f6283b3394450396",
            x"9e0867fad1540de0643d815825f5bca1d27fd173e685a0de8546e45dc49d8adc",
            x"2e21b691bf235b34cbb797b8b760f08edf85bd3ce7800dfc74c654f8128fa27f",
            x"f121e3ef0e21aceaf2672be96d2aad6224643d6cce8fd5f5cf5ee8b3ce90eaab",
            x"c4eac5043b9ada6e9b92292012e98b67bdccb557960aef834ab5c131f12fc495",
            x"a6c5de19d84fd24e45cb43e28c0bde43a70b6a06af3507058346d3f29b6cd184",
            x"26933fa4d67b3d47ef73d2728402b101e16b8540ca4d4a0f243e10324a9bce42",
            x"eedac3629630d054e080e7478f26944ee7f2e4ddc87f573dc255a9c4c2dcb291",
            x"befd8c04b07167509cc33de0fa7a3e0408f4d7792da8a8b3003568c477cbade2",
            x"fc541eaf3548dab9f0110ac18f64a2c6a39b7d473cae32c4c4b29143222fa413",
            x"2fd368b6edb06fa53e8b893499a2cbbbe9e9977f3717472839f04f5a046fb4ef",
            x"b2b24e62a5a189133cf1070dfccfb17102cfca2b9830d8cefafdb24690b5687c",
            x"8907eda7ee100dcbb1ae7a6a48030f636c8db6b2e6481ccde769fc62da592cd8",
            x"18c97ee53bf40d464c26749cffa5aec701d7c4ea3005869e140e254d63873d65",
            x"036b1b5a333f545e45410b92c3e060f208c9b2a0d5bf96e6543efd0385481a8f",
            x"b5254fd6dbf265a940e577c7d88652ff314069c7652ab925b18045a2f9f52b20",
            x"690fb80460a333192a371d974ddb91e822ade696ce1fbbea497fdbdec99be03b",
            x"7b19e0e69293789e719eb9ab364f27bb48eb80e6a6d68f221949510e9544990c",
            x"b3ca2c3e971df9fefd44144970b0b1a04a474bb2b89773317c7724580b8beb82",
            x"6d5956c8d34d33c725a177018a5faf8f58af9394c5ec0656d71fa61e8978a107"
        ),
        public_key => (
            x"22bb675c23b714e123bf0f3c078ab33b15ff2ae35d1cda640c7ba446205babcf",
            x"364593a361cacb7ce9399282b9395a5fbda3c280ce5e411fe11e0beb3ed51cd5",
            x"7bcaf5159b7e17067fff0990d4d22e413ac0cf0e2fc8f746c619d04b5507de8a",
            x"376188f051ef081d881a547c8e74e61c737324ffb56110f720769364e1acfffc",
            x"c960d1c74ed938915b033d427fa8d487ab521eaf79775d2667d48a986b836a4a",
            x"cd8f27980aacfa9212ba1db042ab65b5d24a003414df3bdecfebb6f70440e987",
            x"939e34fc78e40db79b6096a542423689db733075d08d2d77246a38b055960a1e",
            x"c70531d6c6fbc5db23e426b60b8676c59791a4fbaa1a5451991c42ad41c06d69",
            x"eea18d8d70130efd44114c8564003057bb3ebe50dd9bde764a96e06957f6bdfb",
            x"31228f56bc22befa871a12670954a69c15f82c14314790eaf48d77a2c408a92d",
            x"c061c26b0c04030cc0c1552042da43964345fc1fbbfb1ae56af2c0b51a49b88f",
            x"39bc5dc1cee65ecc27803e64b4c95b9e416d03e9660462ca8a0b28403da038aa",
            x"f4b807b71bb7b26fa851ea46c7656ae543afbe66957a28150db7bfdfffd92c18",
            x"1d65df6df6dfec3209f88722d8cefe8540cd2fc4e085f45672c6cdc24eef8ebd",
            x"99f92f2c1f440888349536c2d8336c761858276dabd8198b48573fa061e4ba28",
            x"d75261430d07d01e9b756df7ba53bb3b3b95f43be936ce851f36019df42f205c",
            x"7d6ccd71460f3a4e590b91d8956b475e153e6fe210874e2eed1b63eafd8c599b",
            x"640beb709ae16eac678e1d3dc9aea6ceab1813258c9d94c1804c02f727eaf5df",
            x"9c6f252bb324914cabaf5280eb086affe9846271e058d8b0730fd7d3f2cebd44",
            x"d81a40a103614f13e367edbd345b65f5f27cb7716055d640a96571a9e52fe3da",
            x"27843629fd9c7ded57b19e38fc89eeabc714e2586e313ff3ba72487fad2b6274",
            x"65d3e88f0c2a3186cb1ca88041f6b760fdd33246be207f76cb52ff85fca15311",
            x"c446397b473e381bf50341f895e7f0d57a694a71a6b6ed20022f5c0f509aa490",
            x"74707c6da87b0afa85a53d01d6b441ebf21367a2c9eee063d1f67f4ca6f64e3b",
            x"c2b15f3b7a09d20ed40c14719aa028e7aa758007e0bb0ab7d676166eaaf4a9a0",
            x"046e1f166eaf03f3c1f26ce75b2f9d3547209a2d023314672c2ee025dbff195c",
            x"a084f2d6a495d9908df9d4aa6686b99cf775241f654ab27f18c2ea534bdbfa7d",
            x"a6913abbe2a920162242a0f2177d35d8a20004ce9191e77e69916dc64ca026fe",
            x"30345b43c4b34c6fed60ab42d9f6fcb42382b642723ce89fac2e11b48aff2209",
            x"2b218939be3602be16ce429b96a70d2c175829890e1dc8a0f40d89635ef1d2e0",
            x"d1ff205d85da42edb8ba2ac92459495124663f4e2f7a022e20e57ae75ee0b3b5",
            x"cce24ce25d97effe7ba16efaaf97c1f689520f79a487d62213404a24f05e8a2c",
            x"f6a97fd3a4f82d7b79ca119d3fcaee9850b646da46875659587aa762ab73b423",
            x"779be27e138c2160645e56577c17390ba8c3892261ad0cf7f38d5426d6fc8d48",
            x"32a7a878a45518acb840c8eb11f0e7a024bced4f49445830f4cf57bbc4f57553",
            x"124e62d85d719be2f71156262965ce72bb6e16cb8aad0bb8a0b83e5b6acea69b",
            x"ac53f5aa509b67a64f5329c3949ccfaa4c3a7d86862718d1dfdd219b59119232",
            x"55fcc3ac898a898febddb5eb23d583eef055eefdf23c80b0fbd292314072482c",
            x"142ac3200ae8bc7c939eecaed5fd40caab3dfb5abc9cc939940eab0cf5859913",
            x"1c52d1cdcfc5f7b2f1314de93f71aa936bc3c38a07344712a12f7b5fb58c8d29",
            x"3e28b3cdb819be5679bb1fb2b3f802999f0e6c7857c87a064384cfb4ef135a34",
            x"0383412cff8e5aa45c916cd2aa297f60be1cfca075d8977763a6768a0ae8d6e4",
            x"bffb654ace7b6c9f89420e0419626b65f19fa2e078e625b3c83536d78d49be3c",
            x"0237ce58872cfd8cbe123b6921fd8d7e22dba0f07b71a38a020b8bceaaf202cc",
            x"4bf46a4319fd935b3b7e1a4d96941d684f656759bf23007f6b0165ce62e656dd",
            x"87486ff182f9f21f038e7d27da800283ab0acb9d14dd5fbeef246ea42f88058a",
            x"f23adb5fa54d72510ab14652d94f92f9fa4a9f2e4f5a723c286d89d89c9f6184",
            x"2fa620e0e7b3485150cf5f074d214a54a3f6a3b08afc16efb52c3b281ddf6583",
            x"fb5d23512a1cc910d1b61de8469239b2eb90c4f8c1d87c77328b19c9a65a6529",
            x"3700a9811dd655f198c8784c067577de0f841f402f3f6210bd9224962e0c26ec",
            x"f121e3ef0e21aceaf2672be96d2aad6224643d6cce8fd5f5cf5ee8b3ce90eaab",
            x"55fcf81ef2abb74df3c051489154ca910e3601a99760872bacfb9a06bdbb037c",
            x"6f8211b5a6e43c07e5d8f89890e4b54b0186eec483abe42717ec1bca8679c87f",
            x"c5663d857d2ed391291782d76a1d3a26f6339c634f15edc9af32174b0da18a85",
            x"5c5b7f3739d5550bc6658bfb6833f197edbb520a0a86ac900f6d4c0e3ab098ad",
            x"037423131fcc4e98cd6a8af9378b116060fde6bb3dde4b920ee185f9ad877523",
            x"72dfc2d36b432d5feb0ee4281db8bf46f014ae7bb4adc9a367bea08a2b3da6ac",
            x"fa08a93ecc3d0c2f47e13d30034a2428fb0cc2015acaf421e629b7489a9eb2a7",
            x"1492f72525ffe06a90801211b3722114e0595e66b1a54fe0c25306ade8896f97",
            x"a6d908470fcb42f61a1e69a8359a7b6d7a89663feb51c0e2b58f780c2991d864",
            x"5c56802269f145e9a24bdb262877f9a037856b54339d06676c9b714f56729ab6",
            x"6f74d5be893d02742c748057d5925a39e692001b0b35f3cb8eaaaa3c5b17aa0c",
            x"ce981c964753d4ff432b6e1ac48cadd0222750ad6dcfa04a6efe0bab95b3c322",
            x"b6b40ad8e93588371b837690643fac9ddccf008bdc9cb0d5d088eb7cbf4b70e7",
            x"9286c8db587c8508f04f10dae9428a5a63fd980117745edfbe752bc2a25d49ba",
            x"d395d30bb7cc0931377c43fdfd38a307bb42f90d7c9bc0f76d8528b4eb8ee48a",
            x"28f3622b79db71efaca24ef3831f7e2902911227cf2418771d38a2ce43b578af"
        )
    );

    constant TEST_LMS: test_case_lms_t := (
        I => x"215f83b7ccb9acbcd08db97b0d04dc2b",
        q => std_logic_vector(to_unsigned(4, TREE_HEIGHT)),
        message_digest => x"2ab2665c8ce066e72717fdecab2c95476687bb353bc5f8b47615f36075e106e3",
        secret_key => (
            x"39872536c71454852258da5805153b9af300bc9f11aeed9526620cfdb0f92a60",
            x"96e0bd3eabb414b80fe9b12ab00d830562c830a88a6613b091a8cea68fd1a575",
            x"f41ecad8ea0777bd10323d0be630b35f0e81220e972f61ecb330f703f1a3cc54",
            x"10d0fe000597ecfe2e487209c93d7a733766f59d2fdc2464e7a0473cd5eaec56",
            x"1b92cd3766b21de48483185f04f50a75eda891ef5d332a20991eb660db3626a2",
            x"6494e8d45973cec41b40f4b50a62bd97cb32e0372ebf86beb5e8cd72f0330ba2",
            x"b6ec7ba35df1c0c9bd68b9e8ace429aaff66993d3a4235dcb12f33343cbd7a6f",
            x"1177a87bc28b9bf4eb8922dc6a43563ea844d3249f4fd84459a9d9c18daf0448",
            x"2d3874741ed45ef5d2434b5b1d9900748a2b55d28d437b257f0b37dbd052becc",
            x"8ea6d565d89a32ce867eeeafa63e6735c00c7d21f3fb5e68fde0e1082c69c91e",
            x"0eb8b4370d2f441b870a86e4c8d3135a6f9a985539ab0786b376f476c8082367",
            x"3cdbee8d42125b020fbe9d551bdc2b45e1766bd48853f4d1e4f12869512a41a7",
            x"465f8585b72d8ec7e965388de288e672c49a10346d72b02d5ebe3abddfb57bc9",
            x"6b1e07c05c4fa5bf307e91f5994539badc6181fd36e7496d78369c439248fe91",
            x"2e9e6d079e6360b6c4b3265420dd407fa2d1da9c70bf8c0d7d69e6531bbc7358",
            x"990282f6f97c440f442cfcb75c7979f1e7ca7360a9d9089e8d41419cdba6afc4",
            x"982bf07405108fe029b2772296513e1d772171667a70205835a13d275f8fd990",
            x"151ee417606b2b5c77e3e55889661e0461b29d48ecf5c3711e5b97a4d62eeb52",
            x"ac0bc97927b6e54e159b9d9106bd1e24a1b80ea738ff056f6d03117c4b913a19",
            x"1309c3534be04eb4f74c31d08e9ed233f04fa4e94903e14a52975fc726ce9253",
            x"e30dcd68efe2fda52af6c861aa98c8867e696067abc0a94d5493f2c06bd6323a",
            x"951c2a71c9aeb2a593f211c1168d603a3c45df593849bb39f00f5d3917276597",
            x"1043b4c5804ca375b71ffe4d0a8fdba5080740618a2952c716078af2bc39059e",
            x"6fc0dbd52cb497b83c131d7ddadca13cd6e0c7c1ad063f97655267b28c3c4a92",
            x"f899a30f4ae2394a54064c269103355d1bcb7e6a7e0d438749171ddec09e5abb",
            x"0395a8650bedc4b72d5c2273cbd62e2fe4ec0f9f7b85ddbe5a0718595c449a88",
            x"2d5f10db7df275a1b9034770f8a99527396a9624b39ab0771f02e49140c780a0",
            x"88af71bde2dcc66ea90cb1512fbb07b21bb4653bd81142b0a5f6040a8be59101",
            x"3cb19807a6ccdf62efd45548d376da927292699137323b09c570a2e824e9aced",
            x"009cf623097fe1bc25129ac640b7e71df158268659e0e34dbe85af6a8719eec2",
            x"459971264788682e67862703accb14e52e9317eaa08021abdffc1e754f36e934",
            x"2606c32d05354b2eec824590e7c4a661ff34a446c1008b111da1cb3b5c994832",
            x"90bd8f1841e96de3b0f94a0bbe1eed7d1be482546664425da1620a102bf77113",
            x"9f839d767685a2781b1aae94c0315c91b82968c681f9fff15fbc3a5db20ab395",
            x"e58a814a6b88bdc6086cb2a4b8bddfaac26b378b64d06e3a2a79929ed6cd4980",
            x"36cdacd435c184041c0deff5ea827263781c48fd7a5fc432ce775c89ceaed374",
            x"1a7428c2af2805ca5622ccb7c898007e8c4148056a9b541eae98aa44cd0f5022",
            x"4d3e39ccd21935d351a9b3b1a69f2e9ea9eb2c5505c6dc998899587befb4e0a7",
            x"cd98de3b1929ef9294cf0100e8b1f02167af39484fbc05edc4a1e3ee3dbc140c",
            x"2f9e21e7f31ab66241dbc5187261a9087b2cd82f4bfcefb1882f54aeda1f3aef",
            x"7831ee5babb4b0a905b2be3bf5ada82ee5e51281e72accaf4d5a3f7451615b2d",
            x"feb5459b1d42afaca0e2dbcf5000a326be1a8603136c14ad3a945065fc5f0718",
            x"7e121216887e45c4dc96ed06f4be3a96ca937b494047c737f9e66ab59e7af693",
            x"233b3f38e33a2daccd4afd02d70587f5d20a3db5a75e46290c8b2c58ac7985cd",
            x"0e5cb0939a9dbd5e921a5f7a69f74e96be9e539cd2fa2a26b45a980fef7337e9",
            x"45ec444c413b73209e48b2966fe01562fea4f84ef251f767c070c3707ced9157",
            x"b81eb21c47a19053217ed4d379a582a9f303e4ecdfc141ade438f1f3c53d5796",
            x"e260ee41992fec3190e561e85f817fb16d00b630db8f3c7b31043a2c59b80996",
            x"7c6f3446e7acd443396b386c75986ee636c5a83c5e78ba988d34dece8e809f23",
            x"77c0ffd3c125fe6151a804387ab2ec736ec41f0c0a8f7f9abb0b8c11ad22f6c0",
            x"e0438c52436257b03d04d16cfc46d38c1ceebfe558f381bd9c4864ad0498fe53",
            x"c1b8b138c2731efe9c98647ed79ece343646695a1abdb95256b04cf9f10a553f",
            x"36491170204e86883b99598b09a2bc05c7946e74e976f530f8c71f7df459b99e",
            x"197a2ad37b8fd9fc58b6a9efd22cf4e6e11e30468bdd8bf9941c8d617ddab227",
            x"f1041b7b2896d4eeb834363dc213b067c4c4b648339aa98524ac47aecddc1b24",
            x"d21043d91946758b8e9d5b0eb84c486e26ad02d0339b48a7da3b093992e38d3b",
            x"e3fa343d4ff49e3ce43fac46743354c548938905fa6290f43f4bbab4ff199c3d",
            x"372c8f5b705ced02b50916a5a1c206b07ac49864557f09969258ce13139a5d5b",
            x"1b467a31d2eb354f6e9d1df145a5a075b8deb822b434e6d2869e46a385efac19",
            x"6a3e3557901296ec9901eb2244b36c9fa8c6d244946aa4548cb780a3c62ce87f",
            x"aceb167a16982a49dce3d4b18390ee57417364bab0f945f0a5eed8a0fd6fd231",
            x"fdc4a04ec1d175a707a8824d3414c576a1a6f77fcdfff4e5b7a953320ccadc45",
            x"3e73a3bf33e93cd60b780622b93a3e122cbde2d919f039a1aea8e0e7c575970b",
            x"babb823f708b9532222e4da107ac69877161ef7c1815b5e5bbc9768cd1f47ae7",
            x"44c17801c89eb5dcf473712db644b52c965e4ec652aacaca57562282251d5e4f",
            x"56c575d6408337092b12d4a1c793a6c74fce85e6db42909f0d9c1eec3278bf2d",
            x"c7975475df0ca802c325b355577472353bc282872ec5acb9318d2a1d350af08d"
        ),
        signature => (
            x"93d8b3bf4e0061d8e0bf7250834c89be345e5b287103b31a453e7c07ac5f7ddb",
            x"f1d94f50b468c94e2205c7975d49501e064933332f792dbbaae779b735495c84",
            x"92dc20fd4371367276895081fad4475ff8c9d05fd8000231250dcee57d22fe8a",
            x"716c7fcb2b9b9f662d1fde23336ebae3c001dafebc905922c909683e7b7abd5d",
            x"18815062e335a0a79a6a646016eb4e57e17c1a50be6697f879dc1d458b54af79",
            x"cf6839d33918c73a9c72904827709d10beaec6a8fb23d6e417e9cdbd0a87a14d",
            x"7657590d42202bbb9ae2db55f938e7264bf4a92d319d95cf63b2151b22b56762",
            x"41c12bba4f9c4bba2f57c1faadf0618e23ff9aae1e2e87108ade51fb81c6e9fa",
            x"0fa4aae4f873906b516a26f4efc8d35e809885b393d3f3e628feb9850e7f77b6",
            x"2d6b9b3a8b4905969da7542f0660a264253ab258f68b1f38f1984ccf190e6e5d",
            x"a75b8638f94a07a7806f2f8b1b55036948d936c30a5e3a9782a91a2b8a01b03c",
            x"3cdbee8d42125b020fbe9d551bdc2b45e1766bd48853f4d1e4f12869512a41a7",
            x"877c8d2acb2def2cb1062677e9dc63dbf4ea4643b25f681f1898f0ac8c6a61c6",
            x"6fa9f762de7aae8d199fcd4cce460800fcfa3355dab90be1ed6c94b5eaf2eb06",
            x"067be5a42c21e2ae952f36e5ca5c174f111d68c1f2979680f28d181f3bbb6226",
            x"9ee861815accdb8bba0b134fd1611212574b24b5e91af915e86828daf4cde848",
            x"41ce3d642e57bb9df94aef1f5d43fbc86b6dd4281d7f81c2e7f7cd448f2b4f26",
            x"4f6182c9964b10b489dc21bd6028c2086d977e429e43f73375735ffec2942902",
            x"5e3a1d54c6a4ec5830f8e5d935527e6e84a5f8fb78a6ed80775cca1d608b3df7",
            x"3a5552aa2690291e201b9683f99e7ae96b984e92c3398c195a91b2bc6be03666",
            x"e1d09d39576841b4c057cf3ec08328e395c8d6e09355fc376250319b484051f1",
            x"99d0124b7794c91af8625df0b505cbae80b19af4b8e2bc1c8481877ac9b0e4fe",
            x"1d7210d09908a5916e74a868511a70383f034d237fa1e064a2a3cda8968ab69d",
            x"84a6eed9ecb2dd9b0d11e34f269845681422e2f5cfd23f3b3b03878e93766f48",
            x"0477e7952c6c8d2f9937eda9640fa9f5fe2b4b5805d2c2556b93b6141724b6d7",
            x"12805958f5cfb100347256608d4283a298e1d5829fa9b1be079ff0c096206ff8",
            x"863cc728bfdc3741e369e1ff001d0bb80590d5ff08852046ede814250e55ab4d",
            x"6661d158c1dd10fed9f1735eadbe918f73da40aaa45b52837f34151f0e7af547",
            x"ce1986f04b2114a87787a5c78add4a791c6f881248f32c4fb653f51bcd5a1125",
            x"5f8f8e3b12989423b371f34bfa7d10bd2cb763952b89309b14a4e7cff00a0fa7",
            x"2aae70da046c8a5190c6d51609b80e152c503ff79c128ce54ccaf4eedb29298b",
            x"a9448a2b85b908f931265b6c107efa27fe7406bb9f5eeea3efa095e9efd205a7",
            x"9ee21eb377d2efcc7d3a59ecf944af71a3e999687304c07d7816d0dcf15f952c",
            x"3386e637923039016cc7fc43e225837dbc3689353c19113626c1c119e13f344a",
            x"345d09b8d44a328538b145c097a602e7fd14a653bca4272e09eeaec52e875c02",
            x"f4674adb0f2cafcb80e1f4f615474d55077c8b280463669b3e64cef28858210b",
            x"80d04173a2f1f5cb3e185bcfcdbd50d7f011be60e0e8344eb735735dd8771343",
            x"0d94b133bab590b977bd3d30fd9aa55fbd379229dafca57f2d50bbc3d98af8f5",
            x"a30fad6c3b33f0d736f0c94a4de4907f55634646b87152548da6f96ec5e0c8cf",
            x"cdf28c52d989c5281591d429add39b5a5edb4cb66014fe5a4273c888e96c7e1a",
            x"bb149fbb4407958a88f74f055fc79b652ee6701fd4d7c8dba427ce87074c14c7",
            x"6af543dd4c1ac1d6ea3fac757d8b09c94e71c038a9388b125a2f2000318f3f62",
            x"73222ac6fa411d816053aff94316c7fc5f9065be2a4174d09f07a83909ff7d89",
            x"2a932ca976a8c334e960e4c43a2f690b2457fd903af31fddfb0a2743a32b242f",
            x"4a0c660de7c896d9ee32ad8f76d0f55f0a8bd46fbe1ee901b5dca83af3c6a3ba",
            x"8f405460d85a94570adbd4adc4e660efdf98ebdc8fc716b1a9a082196ebe4f09",
            x"51efb82cf3f46bb5f4f77c97fa1945cadc77fa72e2de4b3ff1c953e364a6544e",
            x"8464c6adba9b31a674982d7e0a27e4cc8ceab6f9ce66c17fb1d43470ab884df0",
            x"fc65ee5c1fa77f24a2b77500d5c4a18b9402c432d4de59a927234c25ac043fd2",
            x"84c4b7a45df2d0ea67f1f1872b0fc66c382783df7231c7e9bb7213010e50de10",
            x"6410a5fb5ad27590ba38bd3aa4c7f2561f9faab9995736ccc89a3053af101ae9",
            x"96d0c62e3f003e3addea3914f481f96d0ad63aba6fa92c7b800f8bad08b8c2e4",
            x"324722395cfab101fb2deb9ef3158dfc01dc6f78b8830a801c60b6fdb44eb1ed",
            x"317d2e2471a1c1ff6d1c2b91a63debd1d3cb526fe25050deaee73b1e1e1c8490",
            x"80805adfe5249aa28f9aced375d54c3576c1e3a22a71208e722c3f5b5f042aec",
            x"d21043d91946758b8e9d5b0eb84c486e26ad02d0339b48a7da3b093992e38d3b",
            x"5b409433da0d38b68a0078cd38e66af6d8c449633a2a02cc3a8a9b26678048e2",
            x"3976a76549d26323733b2bf93fa5c138f75fbe371468fb17093d060fc060ba87",
            x"69b7fbb332a70eeb637f39173538c32dffc05c39de8a1e222d05aee5f8744f2e",
            x"ce4ef3485f37bfc509f12f985dc47767e9204b92001e14f7849976b735084a7a",
            x"aceb167a16982a49dce3d4b18390ee57417364bab0f945f0a5eed8a0fd6fd231",
            x"4c4a71391e5c6965c57483630b47f0985a53b35287e7deb92cc659c035f99610",
            x"fd469ac0c89c2530e4d2c5fb48cc9dbc99e299cf98ec2c49d33bd49bbc8fd007",
            x"8536a705caac5d3c31812f22b2d39d3343a71121b04b3468bfd2f795f08c2625",
            x"d2125e02c02971c3803a235f39b0d2bc0ea24f105380eb737b3def90143a8866",
            x"88adaa5c7d2824e35cc4b0f0e3bd4646b7b43785a72af39a8c33528851bb61ed",
            x"8c42e24f906814cda3d529315e62e6bc99607801332e9d8d5dc7f504ac428142"
        ),
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
    uut: entity work.wots_core_shared
    generic map(
        SCHEME      => TARGET,
        CHAINS      => CHAINS,

        N           => N,
        TREE_HEIGHT => TREE_HEIGHT,
        WOTS_W      => WOTS_W,

        HASH_BUS_ID_WIDTH  => HASH_BUS_ID_WIDTH,
        HASH_BUS_LEN_WIDTH => HASH_BUS_LEN_WIDTH,
        HASH_BUS_CTR_WIDTH => HASH_BUS_CTR_WIDTH,

        BRAM_ADDR_WIDTH => BRAM_ADDR_WIDTH,
        BRAM_WOTS_KEY_ADDR => BRAM_WOTS_KEY_ADDR,
        BRAM_IO_ADDR_WIDTH => BRAM_IO_ADDR_WIDTH,
        BRAM_IO_WOTS_SIG_ADDR => BRAM_IO_WOTS_SIG_ADDR
    )
    port map(
        clk => clk,
        reset => reset,

        enable => uut_enable,
        scheme_select => scheme_select,

        mode => mode,
        leaf_index => uut_leaf_index,
        message_digest => uut_message_digest,
        pub_seed => uut_pub_seed,

        done => uut_done,

        h_done => h_done,
        h_done_id => h_done_id,
        h_done_block => h_done_block,
        h_next => h_next,
        h_next_id => h_next_id,
        h_next_block => h_next_block,
        h_output => h_output,
        h_busy => h_busy,
        h_idle => h_idle,

        h_enable => h_enable,
        h_id => h_id,
        h_block => h_block,
        h_len => h_len,
        h_input => h_input,

        b_we => b_we,
        b_address => b_address,
        b_input => b_input,
        b_output => b_output,

        b_io_we => b_io_we,
        b_io_address => b_io_address,
        b_io_input => b_io_input,
        b_io_output => b_io_output
    );

    hash_bus: entity work.hash_core_collection
    generic map(
        N => N,
        HASH_CORES => CORES,
        
        HASH_BUS_ADDRESS_WIDTH => HASH_BUS_ID_WIDTH,
        HASH_BUS_LENGTH_WIDTH => HASH_BUS_LEN_WIDTH 
    )
    port map(
        clk => clk,
        reset => reset,

        enable => h_enable,
        id => h_id,
        blockctr => h_block,
        len => h_len,
        input => h_input,

        done => h_done,
        done_id => h_done_id,
        done_blockctr => h_done_block,
        mnext => h_next,
        next_id => h_next_id,
        next_blockctr => h_next_block, 
        output => h_output,
        busy => h_busy,
        idle => h_idle
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

    addr <= b_address when to_integer(unsigned(b_address)) - BRAM_WOTS_KEY_ADDR < TEST_LMS.secret_key'length else std_logic_vector(to_unsigned(BRAM_WOTS_KEY_ADDR, BRAM_ADDR_WIDTH));
    io_addr <= b_io_address when to_integer(unsigned(b_io_address)) - BRAM_IO_WOTS_SIG_ADDR < TEST_LMS.signature'length else std_logic_vector(to_unsigned(BRAM_IO_WOTS_SIG_ADDR, BRAM_IO_ADDR_WIDTH));

    with scheme_select & mode select b_output
    <= TEST_LMS.secret_key(to_integer(unsigned(addr)) - BRAM_WOTS_KEY_ADDR) when "100",
       TEST_LMS.secret_key(to_integer(unsigned(addr)) - BRAM_WOTS_KEY_ADDR) when "101",
       TEST_XMSS.secret_key(to_integer(unsigned(addr)) - BRAM_WOTS_KEY_ADDR) when "000",
       TEST_XMSS.secret_key(to_integer(unsigned(addr)) - BRAM_WOTS_KEY_ADDR) when "001",
       (others => '0') when others;

    with scheme_select & mode select b_io_output
    <= TEST_LMS.signature(to_integer(unsigned(io_addr)) - BRAM_IO_WOTS_SIG_ADDR) when "110",
       TEST_XMSS.signature(to_integer(unsigned(io_addr)) - BRAM_IO_WOTS_SIG_ADDR) when "010",
       (others => '0') when others;

    test: process
    begin
        done <= '0';
        reset <= '1';
        uut_enable <= '0';

        wait for t + t / 2;

        reset <= '0';

        case TARGET is
            when LMS =>
            when others =>
                uut_pub_seed <= TEST_XMSS.seed;
                uut_message_digest <= TEST_XMSS.message_digest;
                uut_leaf_index <= TEST_XMSS.leaf_index;
                mode <= "00";
                scheme_select <= '0';
                uut_enable <= '1';

                wait for t;
                uut_enable <= '0';
                generated <= (others => '0');

                for i in 0 to WOTS_LEN - 1 loop
                    wait for t / 2;
                    if b_we = '0' then
                        wait until b_we = '1';
                        wait for t / 2;
                    end if;
                    generated(to_integer(unsigned(b_address)) - BRAM_WOTS_KEY_ADDR) <= '1';
                    assert b_input = TEST_XMSS.public_key(to_integer(unsigned(b_address)) - BRAM_WOTS_KEY_ADDR) 
                        report "Error generating WOTS+ public key at position: " & integer'image(to_integer(unsigned(b_address)) - BRAM_WOTS_KEY_ADDR) 
                        severity error;
                    wait for t / 2;
                end loop;

                wait until uut_done = '1';

                assert generated = std_logic_vector(to_unsigned(0, WOTS_LEN) - 1)
                    report "Not all WOTS+ public key values were generated." severity error;

                wait for t;

                mode <= "01";
                uut_enable <= '1';

                wait for t;
                uut_enable <= '0';
                generated <= (others => '0');

                for i in 0 to WOTS_LEN - 1 loop
                    wait for t / 2;
                    if b_io_we = '0' then
                        wait until b_io_we = '1';
                        wait for t / 2;
                    end if;
                    generated(to_integer(unsigned(b_io_address)) - BRAM_IO_WOTS_SIG_ADDR) <= '1';
                    assert b_input = TEST_XMSS.signature(to_integer(unsigned(b_io_address)) - BRAM_IO_WOTS_SIG_ADDR) 
                        report "Error generating WOTS+ signature at position: " & integer'image(to_integer(unsigned(b_io_address)) - BRAM_IO_WOTS_SIG_ADDR) 
                        severity error;
                    wait for t / 2;
                end loop;

                wait until uut_done = '1';

                assert generated = std_logic_vector(to_unsigned(0, WOTS_LEN) - 1)
                    report "Not all WOTS+ signature values were generated." severity error;

                wait for t;

                mode <= "10";
                uut_enable <= '1';

                wait for t;
                uut_enable <= '0';
                generated <= (others => '0');

                for i in 0 to WOTS_LEN - 1 loop
                    wait for t / 2;
                    if b_we = '0' then
                        wait until b_we = '1';
                        wait for t / 2;
                    end if;
                    generated(to_integer(unsigned(b_address)) - BRAM_WOTS_KEY_ADDR) <= '1';
                    assert b_input = TEST_XMSS.public_key(to_integer(unsigned(b_address)) - BRAM_WOTS_KEY_ADDR) 
                        report "Error generating WOTS+ public key candidate at position: " & integer'image(to_integer(unsigned(b_address)) - BRAM_WOTS_KEY_ADDR) 
                        severity error;
                    wait for t / 2;
                end loop;

                wait until uut_done = '1';
                wait for t;

                assert generated = std_logic_vector(to_unsigned(0, WOTS_LEN) - 1)
                    report "Not all WOTS+ public key candidate values were generated." severity error;
        end case;

        case TARGET is
            when XMSS =>
            when others =>
                uut_pub_seed(8 * N - 1 downto 128) <= (others => '-');
                uut_pub_seed(127 downto 0) <= TEST_LMS.I;
                uut_message_digest <= TEST_LMS.message_digest;
                uut_leaf_index <= TEST_LMS.q;
                mode <= "00";
                scheme_select <= '1';
                uut_enable <= '1';

                wait for t;
                uut_enable <= '0';
                generated <= (others => '0');

                for i in 0 to WOTS_LEN - 1 loop
                    wait for t / 2;
                    if b_we = '0' then
                        wait until b_we = '1';
                        wait for t / 2;
                    end if;
                    generated(to_integer(unsigned(b_address)) - BRAM_WOTS_KEY_ADDR) <= '1';
                    assert b_input = TEST_LMS.public_key(to_integer(unsigned(b_address)) - BRAM_WOTS_KEY_ADDR) 
                        report "Error generating LMOTS public key at position: " & integer'image(to_integer(unsigned(b_address)) - BRAM_WOTS_KEY_ADDR) 
                        severity error;
                    wait for t / 2;
                end loop;

                wait until uut_done = '1';

                assert generated = std_logic_vector(to_unsigned(0, WOTS_LEN) - 1)
                    report "Not all LMOTS public key values were generated." severity error;

                wait for t;

                mode <= "01";
                uut_enable <= '1';

                wait for t;
                uut_enable <= '0';
                generated <= (others => '0');

                for i in 0 to WOTS_LEN - 1 loop
                    wait for t / 2;
                    if b_io_we = '0' then
                        wait until b_io_we = '1';
                        wait for t / 2;
                    end if;
                    generated(to_integer(unsigned(b_io_address)) - BRAM_IO_WOTS_SIG_ADDR) <= '1';
                    assert b_input = TEST_LMS.signature(to_integer(unsigned(b_io_address)) - BRAM_IO_WOTS_SIG_ADDR) 
                        report "Error generating LMOTS signature at position: " & integer'image(to_integer(unsigned(b_io_address)) - BRAM_IO_WOTS_SIG_ADDR) 
                        severity error;
                    wait for t / 2;
                end loop;

                wait until uut_done = '1';

                assert generated = std_logic_vector(to_unsigned(0, WOTS_LEN) - 1)
                    report "Not all LMOTS signature values were generated." severity error;

                wait for t;

                mode <= "10";
                uut_enable <= '1';

                wait for t;
                uut_enable <= '0';
                generated <= (others => '0');

                for i in 0 to WOTS_LEN - 1 loop
                    wait for t / 2;
                    if b_we = '0' then
                        wait until b_we = '1';
                        wait for t / 2;
                    end if;
                    generated(to_integer(unsigned(b_address)) - BRAM_WOTS_KEY_ADDR) <= '1';
                    assert b_input = TEST_LMS.public_key(to_integer(unsigned(b_address)) - BRAM_WOTS_KEY_ADDR) 
                        report "Error generating LMOTS public key candidate at position: " & integer'image(to_integer(unsigned(b_address)) - BRAM_WOTS_KEY_ADDR) 
                        severity error;
                    wait for t / 2;
                end loop;

                wait until uut_done = '1';
                wait for t;

                assert generated = std_logic_vector(to_unsigned(0, WOTS_LEN) - 1)
                    report "Not all LMOTS public key candidate values were generated." severity error;
        end case;
        done <= '1';
        wait;
    end process;

end architecture;
