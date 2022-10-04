library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

use work.hss_types.all;

entity shared_seed_expander_tb is
end entity;

architecture default of shared_seed_expander_tb is
    constant t: time := 10 ns;

    constant TREE_HEIGHT: integer := 10;
    constant N: integer := 32;
    constant WOTS_LEN: integer := 67;

    constant HASH_BUS_ID_WIDTH: integer := work.params.HASH_BUS_ADDRESS_BITS;
    constant HASH_BUS_LEN_WIDTH: integer := work.params.HASH_BUS_LENGTH_BITS;
    constant HASH_BUS_CTR_WIDTH: integer := 8;

    constant TARGET: scheme_t := DUAL_SHARED_BRAM;

    type output_array_t is array(0 to WOTS_LEN - 1) of std_logic_vector(255 downto 0);

    type test_case_xmss_t is record
        seed: std_logic_vector(8 * N - 1 downto 0);
        pub_seed: std_logic_vector(8 * N - 1 downto 0);
        leaf_index: std_logic_vector(TREE_HEIGHT - 1 downto 0);
        output: output_array_t;
    end record;

    type test_case_lms_t is record
        seed: std_logic_vector(8 * N - 1 downto 0);
        I: std_logic_vector(127 downto 0);
        q: std_logic_vector(TREE_HEIGHT - 1 downto 0);
        output: output_array_t;
    end record;

    signal clk, reset: std_logic;

    signal b_we: std_logic;
    signal b_addr: std_logic_vector(31 downto 0);
    signal b_input: std_logic_vector(8 * N - 1 downto 0);

    signal h_enable, h_done, h_next, h_busy, h_idle: std_logic;
    signal h_id, h_next_id, h_done_id: unsigned(HASH_BUS_ID_WIDTH - 1 downto 0);
    signal h_block, h_next_block, h_done_block: unsigned(HASH_BUS_CTR_WIDTH - 1 downto 0);
    signal h_output, h_input: std_logic_vector(8 * N - 1 downto 0);
    signal h_len: unsigned(HASH_BUS_LEN_WIDTH - 1 downto 0);

    signal uut_pub_seed: std_logic_vector(8 * N - 1 downto 0);
    signal uut_leaf_index: std_logic_vector(TREE_HEIGHT - 1 downto 0);
    signal uut_seed: std_logic_vector(8 * N - 1 downto 0);
    signal uut_enable, uut_done, scheme_select: std_logic;

    signal done: std_logic;

    constant TEST_XMSS: test_case_xmss_t := (
        seed => x"7781de0544c42dca964108451a40804f7939401122173c83425787d4facb49bb", 
        pub_seed => x"747da1dcd0be23030ad7d72d1e10881e330495a0ad0a2932844bacf00ea112a9", 
        leaf_index => std_logic_vector(to_unsigned(1, TREE_HEIGHT)),
        output => (
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
        )
    );
    constant TEST_LMS: test_case_lms_t := (
        seed => x"44fde64a62bc407348cfda10116bec2d6cd7880790a3deb885649839ead4129a",
        I => x"1c6e5c0d68a3e62bb6b6c274375e5645",
        q => "1101011000", -- 0x358
        output => (
            x"58f37731922a3cc36afa770e6385ed14ca1efd3190078721b0ca8a405899aa90",
            x"a383b3f74ef1c31691671277fbafd0fbad4e9047a0abfd857b855dd7a061d4b7",
            x"0a7da56bf56ab44c3ce842b93edd31eedde93ab35095a63c2b348d6927a72232",
            x"b5412271edfb6f48b0dd12d262fdd2071ee746cb2bc56446079b5f8400d29697",
            x"d13c7d7371b6e3913317c6e86062fd6a13aa3c0d037ecc1f087aa4389ad54058",
            x"df772aca4a83a44b74398ee14e58f2cd56cc768003ed570a72839f2ad56b833b",
            x"da15ce506d802b16d91d09f96219c4b5b0f0a04e91e7b06b8062dceecfac05c5",
            x"9baccf0caf2b794ad697495b775c44d33329b61901c05a49fc8c69e067f8e3e0",
            x"440819c36d54d915f58ba815d1ab38b284fd95ed3131645f4b8a16d4ec693b93",
            x"5074d3c91de48c00c6faa64986e9fe88e398a9a9753c8a50e60d8f3570637673",
            x"8e3ea2df574ae4bb626ecfe9410a953463e879dea2a354b81d78bf24e37c5e89",
            x"9133d1c702929b9f9d12a15b0a827419933d19bd3ed18a3e7f303f6c5cbbbf9d",
            x"ba076457a3214118e5b93ec91aa4bbb52f032af323a95e97f80877d3d3c659f9",
            x"e3b3dbf9dc935862027f33952b6f4e14b719f1bb9b4686c263a55e4150251f0c",
            x"928937442d2552e3323b02640a0076a25bbeaffa29681d0b14131a3a74547904",
            x"546854456135bdaa77ef8c682a0ed474da74c22b6775b4be17564ad10a872fef",
            x"6d8b0a4e638a9cb74a9dfba10dc3b30eebf51f14324493bf21184f188d68a58c",
            x"6c2d98feb42b7eea2693e90ec8a49b76330f6170aca27d3f49328a603c07369e",
            x"1fbaae6edafdad2d8d38a444a9d863601d6e2e3c5113e1138e20fea934ffcb96",
            x"4e3e5e7d2fb1b1e3c94989aee9bb755927985dd845f3529c29a299dc91b87de9",
            x"6b05d6e1bae0c5e04f807460b36da2b12f079e370103a1c401517ebc942fcd46",
            x"fe791e72b62096da34e1636f430a2270826e46be9425849a44c6bcf1d10f383b",
            x"331e80cccfc50de30c3548149021d268697d12e336b7f1b9c64020ae8fa0fe24",
            x"0958233be24bf2dcbe680451c734f1b298db46553ad1125db2659fa05d7ba871",
            x"8638a5715c7f5db5dc31f9c639dcca40966eae3873fc7a911c4879930e427fc9",
            x"0c7e0ede4a86bbf576c34d92abd2e788a1f9070702bf36229ae915e48d5155cc",
            x"0837a92c80c4555098ce8cc8e68b2af7b6f47aac23e135d7ad013a1dfa5ee22f",
            x"7aa92078235acaec21a8c2f443cb72146c1a4dec7d1cd142c024eecc87e2dead",
            x"c0261cdc46320be46ff13d53c4ceb6827215d082f13725928774021f1bd97d28",
            x"6c9de5d118c13365280fbe18a8016417c094d1ea69ca5908c38a77de20f374c9",
            x"f7d51669c7ba2b60dfb58ab2dfe25400b36fda7771c1b3f7e24325466900d192",
            x"eb254da784bf4d46229d2b20074645504b7925402c809bec9d432bf0e29bbbb5",
            x"e1edd09f4fe30cb21139eb77f6cc05b4f9924770f6ccdd98f3a940e8b16949c0",
            x"aaadae8836edd07e730840dde09cb9284396e2c173304bbe9b7753b228d73122",
            x"71870fe57715fa001a0019abbc6b43e9111290ee45509ffb2e24c6ffd6f42958",
            x"e56306b9f178c6f6a9ef5d5e720790c034097a4365c8f7c7a21914f515a0719f",
            x"88b03bc8ce796a36c1e39ecbb48851a810bf7a2a4a254eb28db1015ad0dec74a",
            x"903990d71236ce2e5427d020c8ee9b839997459c64bf0d8a65cd7dae53b4d969",
            x"5ed84cef88a1ea3f8f759daaa5cb70a854a4b08321b656c3e8c86b7cb5f6c081",
            x"8f03fc72fdae1ed5e2196236314826d238bb40d4b1793e80d7f860979acddd34",
            x"3d9b1ba5051724b283df4b67298eeb9c63e77b0d7ab7e6ac7366ad2b4b9bda28",
            x"4671fe1e4546099ff37402475a2c42f006a83ff4ce3ca3bca22e092cc5766d29",
            x"0576cf0d06a9b5a44830b57b83ce15c4f19bc7b98d4d211aeb39aa7c41d888ad",
            x"0c735c41909fd8807a4d39e64afd719ab91d20ef01271c0d3242374ee0983b9f",
            x"af7ffb46e402b98770700644b499cbd88a1a33e25b7c4048db3abb9a72863cd4",
            x"7692de00050aaaf43d9aab058b9cf596f1ea7cc80404d8158c3cfe0539a891b6",
            x"954fda57c7c05236fc5cfa8368b57575eb68db84154ec2e9bea2d576c8679b94",
            x"96ea3ff96ade2e606c9167013443d8f501531b6a2bc8ca6c112455982b694e78",
            x"1f1c23e2b1e4517fdbaa58951f0b0923ecd7ef00ab6ce8e69a3004c5cc81d041",
            x"d8c4f5d11fa7740870305ba995c67395864147502766ed83908f0fe5a5d90b5c",
            x"a4d6d24ac461da9fa282831417c1e5ad476e603119f92ecb38090fdffc713a3b",
            x"fb4de14bc36f8b0ec699807c5ebdbd016bb5350f9d49714ed59401255a84551e",
            x"a6b76358ed86b2c389a1574d1509d6b5b76683089a3e0981490df795adcc4768",
            x"9717e1572311f1f1e3d925ce684496a38ad53511b8e672870ddf1f425a7a5ea0",
            x"ae2ed433ced24be7363be3338b59e0dfd5e613a33196e1457b1491a0689ddf49",
            x"74971ac4058f2891986f5fee2e1f6a9cb54d59ffcf6ac2e8ec3a4a11ca92af25",
            x"ae8797345d7934187cda775d7a850bf3f486fad2426c8b88c7ee1a5c38b757b6",
            x"fd3db245a0465beebac183c45709f0002873e778c5ceac9b185ade4b17eabc1f",
            x"b3b6d88912ec3e555f816b3ee58f6624290bb2e09a73de4f1c38eeffc99c83dd",
            x"d7d84b2e01c885e26d1ed5fc00ef26ac2b6e902b6fedd17334f3969965319fe9",
            x"e917a14525a57403fe57944925fad1b834cf1dc6b115942487c59ca3622e64aa",
            x"9397e67d2896a7688ab6a91842d49d3c6fdd6e9113480990f3078268aa4d1d23",
            x"ba5ee3803b86fbae865ebdb954866aec78527e098ce1ee601dcf34d92c9db274",
            x"1ff261c366649c9cd301424acfc0fade4e4f03dace4613bc4684304d00960565",
            x"aefa911842dc77225f197acf0d196094059c72c16e566de654c0c6a61138ec90",
            x"53e74b5e942c77002639aefa6d5627e36422c82f64f5284a04e4e02175568cb8",
            x"b59793b038cddbbe003e6e24dc8203f6356a61cb85d1cc32926e29a6b8f8b1ca"
        )
    );

begin
    uut: entity work.shared_seed_expander
    generic map(
        SCHEME      => TARGET,
        N           => N,
        TREE_HEIGHT => TREE_HEIGHT,
        WOTS_LEN    => WOTS_LEN,

        BRAM_ADDR_WIDTH    => 32,
        BRAM_WOTS_KEY_ADDR => 0, -- Start at address 0.

        HASH_BUS_ID_WIDTH  => HASH_BUS_ID_WIDTH,
        HASH_BUS_LEN_WIDTH => HASH_BUS_LEN_WIDTH,
        HASH_BUS_CTR_WIDTH => HASH_BUS_CTR_WIDTH
    )
    port map(
        clk => clk,
        reset => reset,

        enable => uut_enable,
        scheme_select => scheme_select,

        pub_seed => uut_pub_seed,
        leaf_index => uut_leaf_index,

        seed => uut_seed,

        done => uut_done,

        h_done => h_done,
        h_done_id => h_done_id,
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
        b_address => b_addr,
        b_input => b_input
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

    test: process
    begin
        done <= '0';
        reset <= '1';
        uut_enable <= '0';
        wait for t + t / 2;

        reset <= '0';

        if TARGET /= LMS then
            uut_enable <= '1';
            uut_seed <= TEST_XMSS.seed;
            uut_pub_seed <= TEST_XMSS.pub_seed;
            uut_leaf_index <= TEST_XMSS.leaf_index;
            scheme_select <= '0';
            wait for t;
            uut_enable <= '0';

            for j in 0 to WOTS_LEN - 1 loop
                wait for t;
                if b_we = '0' then
                    wait until b_we = '1';
                    wait for t / 2;
                end if;
                assert b_input = TEST_XMSS.output(to_integer(unsigned(b_addr))) report "XMSS Output wrong at " & integer'image(to_integer(unsigned(b_addr))) severity error;
            end loop;
            wait until uut_done = '1';
            wait for t;
        end if;

        if TARGET /= XMSS then
            uut_seed <= TEST_LMS.seed;
            uut_pub_seed(8 * N - 1 downto 128) <= (others => '-');
            uut_pub_seed(127 downto 0) <= TEST_LMS.I;
            uut_leaf_index <= TEST_LMS.q;
            uut_enable <= '1';
            scheme_select <= '1';
            wait for t;
            uut_enable <= '0';

            for j in 0 to WOTS_LEN - 1 loop
                if b_we = '0' then
                    wait until b_we = '1';
                end if;
                assert TEST_LMS.output(to_integer(unsigned(b_addr))) = b_input report "LMS Output wrong at" & integer'image(to_integer(unsigned(b_addr))) severity error;
                wait for t;
            end loop;
            wait until uut_done = '1';
        end if;
        done <= '1';
        wait;
    end process;

end architecture;
