library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

use work.hss_types.all;
use work.hss_functions.all;

entity hss_verify_tb is
end entity;

architecture default of hss_verify_tb is
    constant t: time := 5 ns;

    constant TARGET: scheme_t := DUAL_SHARED_BRAM;
    constant CORES: integer := 8;
    constant CHAINS: integer := 8;
    constant BDS_K: integer := 3;

    constant N: integer := 32;
    constant TREE_HEIGHT: integer := 5;
    constant WOTS_W: integer := 16;

    constant WOTS_LEN: integer := calculate_len1(N, WOTS_W) + calculate_len2(N, WOTS_W);
    constant BRAM_IO_PK_ADDR: integer := 0; -- root node + public seed
    constant BRAM_IO_SIG_ADDR: integer := 2;
    constant BRAM_IO_WOTS_SIG_ADDR: integer := BRAM_IO_SIG_ADDR + 1; -- index (TODO: + message randomizer)
    constant BRAM_IO_PATH_ADDR: integer := BRAM_IO_WOTS_SIG_ADDR + WOTS_LEN;
    constant BRAM_IO_ADDR_WIDTH: integer := 7;

    signal clk, reset: std_logic;

    signal hss_enable: std_logic;
    signal hss_scheme_select: std_logic;
    signal hss_mdigest: std_logic_vector(8 * N - 1 downto 0);
    signal hss_done, hss_valid: std_logic;
    signal hss_io_en: std_logic;
    signal hss_io_wen: std_logic;
    signal hss_io_addr: std_logic_vector(6 downto 0);
    signal hss_io_input: std_logic_vector(8 * N - 1 downto 0);

    type keygen_test_t is record
        seed, public_seed, root: std_logic_vector(8 * N - 1 downto 0);
    end record;

    type wots_sig_t is array(0 to WOTS_LEN - 1) of std_logic_vector(8 * N - 1 downto 0);
    type path_t is array(0 to TREE_HEIGHT - 1) of std_logic_vector(8 * N - 1 downto 0);

    type vrfy_test_t is record
        public_key: std_logic_vector(8 * N - 1 downto 0);
        public_seed: std_logic_vector(8 * N - 1 downto 0);
        mdigest: std_logic_vector(8 * N - 1 downto 0);
        leaf_index: integer range 0 to 2**TREE_HEIGHT - 1;
        wots_sig: wots_sig_t;
        path: path_t;
    end record;

    constant XMSS_VRFY: vrfy_test_t := (
        public_key =>  x"77d091e1238ba26b1bd9014d658d8a40ebcdd327ecb803e9491defdfb06b7f4c",
        public_seed => x"747da1dcd0be23030ad7d72d1e10881e330495a0ad0a2932844bacf00ea112a9",
        mdigest =>     x"91489fa66971f875d2a945f2b28ca5fc082a9549144f552789829cee6d13a869",
        leaf_index => 2 ** TREE_HEIGHT - 1,
        wots_sig => (
            x"efafdca7886b5ff0db3885c37606e78492dfe1693a15d23acd42d84a59093da8",
            x"b017f35109b2e722a599b38a994de4b0a984a554fc36c9d5cef3e5928212c69a",
            x"4ab7266ff7de84d9c2cc40dfcbbe77df2549cac04df7f3bc40d181dc638a7a26",
            x"aae87eb791c903a43228dfcb618b6b6a97a9418fc47ac9e25beaaf8229bb062c",
            x"548fde9fe3c70ff3ed2c6a0c09656d6ca2710efa64f12aa1935f32a50c05b5ad",
            x"35a2e03f6459e4e84f01bcc09bec24bf93604ec6d5898020ac2652195eef7d7c",
            x"0f51cc91e8848dde4036db9741175f95992c44319934f3600ff1164c994a407a",
            x"f07c412567cf2b8819517a28711d27a28eccf4e66ee793ec685c08a72d5b0421",
            x"93e35ccf61bc82c5faf1d88acaf34c3e7d128b6575f55dea222a905c7c160816",
            x"4b568ced1cda312ab9c44e7435d32cdc2446356466c6f624a8507141b62651b3",
            x"39e1025a00f81b212544e6c8ad0a656faafd060525b438005e9b82e65dbdc5cb",
            x"bb994f7a5eac59c03d86878646c52191466dd6bee7296a744c04a8c021e54c7f",
            x"9d0e02cd3197af5bc7cbc7d8823bc4b73ea35b2fb27d5d0030e840f4407fc408",
            x"bebbdbeffaec401609b280a9ca9c9f41401e9e74fff8f01ce9db456167d99cae",
            x"fc2c4dcaa5a5f5c3763f1e6c50dcd7b47cc4f852316eb3488e7bc7b49edfb3a8",
            x"a1d777ccbd6c664c5889f58c3346f9e191609ffaaeb94994de83c7012944297e",
            x"b6171f324fc1034d5ad6baf1c70a32bb9fe52c5c08ee97d4ebd4b55d3de313a8",
            x"a2a5ee4b4e115911cdb4f75cf327a3dc6548ef96f43a95f08ecec6e370f77a94",
            x"9d5c42ec314c663e8366d38a985ec99262f04e6772b42513d2225720dca88e71",
            x"7e974ae8ca7e086780787f1cf96cc655e6d70a5c2ab86b82ae95cde484dbe768",
            x"978c7fd30dbb3a1cc8f0479e8c3fba6b29cb33c64ce6ccf9c969ba6d96e7f4a1",
            x"7c30c326f75371e799583f2a117bc1d2a5679fc23dcd0728a270305cd32a417b",
            x"e09e0a6487ec022c537d7d7a0c2f060e9f0971743933e5bd54a7cb43cd8edf9e",
            x"1f7b3f447aaf31d120e297966d2dcb525b07f9c3ac58b512efc262b2a00b0bb7",
            x"aeff880d10c1b8b321defaf3adc180fa288256c6d3df5acc7032a299c5e1d9c4",
            x"03efb70f13b8f1ca064e621d17953473c1fdff5cf72c548f614dcedda213278a",
            x"61a1ac5555ee3736d7826ccb6c7446d8b19ca806228bf031ce4307043b6eea0f",
            x"03aeba46870101255dd8c15b5d0d3d46ae0d85fea2c5cdc505928543818b1a5b",
            x"c14132f2dba96e0334cd275e21048b7052786f8b36edd2c784b0c6431d158837",
            x"b65d3e18e25efba3b8b3c3a9a674cbc0c65749e4f69306a10532f1f792cda301",
            x"ec9136b7eafc1542e0f194455877e1bf34be6af70756c0cf0781ee1149d59c5e",
            x"e380c2f523c0a23e9f9846f4de55b315cfdad087988a4dac7f3e1f5e56154c55",
            x"563da4651dbed447de2a7abc712185fd3ef0dd0e7d040385ffb214dc3d8a3c7c",
            x"5ea85102ba4b51b820c8653f37910051f22c77f02d428a0073e383c03b76a910",
            x"89e02b61443ac9a31b0995327ac548c91cb47c09f6881fd735772f5321aff3d7",
            x"a33c8da2ab9f3e6880ade8d37a8445439149a887cddd549fdea14518d41e68b2",
            x"6590a0a830a38e50d381a6c35f6b751d9558771b06bba19f41084283dff0333a",
            x"f27484351ff3c7ec0911714a35675b358153552fd3c5ffefaf48f5345a7e43eb",
            x"a4d4bdb7a0487a6c45488fc6b1ac6682aa716ca57cd6c2e670db0806d51a7f01",
            x"9ffc5eedf9775bbaf3a68e9428d8b4163a177eb14e4f48348b189ac6865ee2d5",
            x"87f1922462884e97436027079676b4c57af53ee9d5ef86465719ef4e01a34cfa",
            x"5536dd1cb679b27e1d34e659aec21e90d1f472c8a511452fa60f32a40e4e5d6d",
            x"9d1a5935a5f475917f1b0f946335288ce04d3d7b6eedff2326081cb1316154c7",
            x"80578cc2bd44a0ee655a1746e1625b6c108020926067cb6bba4920cfa9f0bb8b",
            x"63edaaed5b0f15c3eb5e304981d24a9c3bff9148cf33adb638bf56cfec94b23f",
            x"73e47546687e4809a9bb674d93dd9bf43a5f5f554288d8a51cc638770a92fade",
            x"e98889b982ba7f77bf8dabc3e748c641b6c17b7a33f57e063c9a1eb43082fe32",
            x"95c7935a4063b389523a474558a475625ada9c7d4fa86b54d8446cbd9336a5d8",
            x"9a5eb50e3aa28bdaa9acd8767cae04c4c8b55656f13b1cbafe748f3af53d4e3e",
            x"abd9cef271c22256aa6bc33309545b4e30503dca183e1971bc5bc880f2c113d5",
            x"ba2a8fec452bdb4996f744510ff3bd20eedb1bfd4e89324a76b831bd1b72b31a",
            x"6a930774171caad3909b9ef99d678ec010d902c0f8ee0c1f59d95fd898c70f9d",
            x"7bd4fe556d2275de968f06afa482ef02f099e2eb6f60a261642ed4ad1887cb34",
            x"6656464a478696ff2b4a07a063ef44869e048fb1bd082966e2614ef24c0cd1ad",
            x"b6c3734f7f613c466ba4f6824840847bdaedc4ea6b7d5f1dd2348bce5a9a36ac",
            x"ede36efb3569b763dda45ff37b91a5bc4422cb6af34c56c12165fcef79cc5bf5",
            x"cb6a1cd592f6e7e3552a4fa62bd160a893d8081cd547a8d0ea425e6cfb2914a6",
            x"b6340993dde5ddda8796873f3ea5d6b6e939cbe96d2ebc2d20bf15a0d8c84661",
            x"a33da57e9c9131110dcb236a104cb8a344b704328aed1ef2f643cfce885c91e7",
            x"8817c430a5133b1e9a9d59746b30e40f9f2294254f2aa34731069738fc1a5064",
            x"f00fcc5772891faa0180a72e19f3c6963b1081bf40d2548a811682834b967331",
            x"77c41d6453b9c83ba73d677c7beecbf10fae2c6f0d3e5e1846cfbffe89ea7ea2",
            x"004866feca16df1e7954186a570b3048b93d210d53e6d81ff5886bec9d8da785",
            x"d45041246108d7c5aa9896e41a68b7e00240c1a6a1c91d9d5875128f503280b9",
            x"165b14408cb4ad493ddc05ae90109b191976f2a29bf89a36bd75a523da640547",
            x"87383a38d9e8850ff12657c45d0d474c50d9ee22a10fc6fb5a83377042fc81b5",
            x"ba438b6501ceb98f404334fb7dc96774bac09ada89ae5d7ed2cde5293187cabf"
        ),
        path => (
            x"8a155928e87fb77555388d1aaa2de528a1f84547cb32319609513ea89d501483",
            x"56f7b5b269ad71d9db3a7bafb13e9d7defb8a1f59caa1889790a3fdddef2972d",
            x"bfa8baee8d34a3a4ec3864cdc76526f98c7cae88d985cd1d390b674f88201167",
            x"f35897f155d2287409086ea891ba6fe2ddac2f9ecfeb8d1860e7c8bd3d2106ec",
            x"f66b4721121c425e9cafff8a56768ddc0600b91df162ee10035dfb436bf0dc08"
        )
    );

    constant LMS_VRFY: vrfy_test_t := (
        public_key => x"f6018c38c40529463a4d50fc716f9ae3ee4a6b6fb083b624e67ce7111dd316f2",
        public_seed => x"00000000000000000000000000000000215f83b7ccb9acbcd08db97b0d04dc2b",
        mdigest =>    x"0eb1ed54a2460d512388cad533138d240534e97b1e82d33bd927d201dfc24ebb",
        leaf_index => 2 ** TREE_HEIGHT - 1,
        wots_sig => (
            x"a6a4d957aade099c8183f875915d44b442a7ea20773a6aad870c5d1dbb7665f3",
            x"1515f4315dd8a8d2a4daa32c835b5b60331409378b005f763a4f2a867386db98",
            x"9744de8c9dd5d5f1cc1d3e35202701a97da618c23bb93f1706318c201b560928",
            x"0fda6e3a4606d0c377d87d81854def98689c4237111fc51a76edd5be78a2c497",
            x"34a3945f539300f67e5fbfd1337a6c1e389cdad48ea7d86b74204c4d4ef3f08c",
            x"b808fac69826475683dd1dddd552fb0e7e9aa5d2cf850ad763ff0fa252950c5f",
            x"086f5f3f0efb1f264e784f5757933549cb11053748269bbdc2c297b1bc5ee0f5",
            x"804fa4480b47b1d5e850388d11f84dd3af377ff8c66245d558826b059ed5f5ab",
            x"dd539d6ab5f2e57789d8da163e2613251584389f5bec07497b659ac3f351683d",
            x"06f79f9f12b2deea7b9d144a6332260fc474d76ce871a841fcad8784e2b04a48",
            x"98dfbc5eabaaa71605974f013185c807e5e8d1c550617f132f8e35d77458eb1e",
            x"8928b1686bf69de7241daadf2a7c34eedc09cc145299b12f8aae4e1bf9ef1570",
            x"9b2aa1a99e936dd4ed511a1ae58894c459bd62f47a0bfc5354d27a931e3aac94",
            x"2acadd46e75840f35476c90ba1a9a834a9727f5e4554f3ebe6324dadbc07592c",
            x"f99203767f3cc09742011f0e7b56669c96da57626d6e7807bcd14ad5717770d6",
            x"d477db21775c0ace3113d8a4a49a97b5830e47068e56bf2ef3dcb9a89f716193",
            x"053834bbf1918c2ce6aeefd4b031baa54594bf36e713be5ca39c1536e5a470bc",
            x"3d83d6fbf257383d7b9a65d0f95fdb1d3a1848961c489e13c7b2978d2d81a7b5",
            x"6d1ccf30c892f0341d8e9dcd83f1da13cbec17dd815d754dbd7778d5277667f8",
            x"2b8f9d52de55fb3e9e5135928d5045ba31c22fd15c6891a88d9c250368050abd",
            x"272d0504040657d934c3382f9b974cb0a5af1519b409d8156512fa52b23ec572",
            x"b3a4e8ecd852c959eee63a8378e20e325dc2ac04e59f83fb0e172f7640afa64b",
            x"6b16df373ac66d5691c2c24e12776a21a310900bef9913c9b461cf7b34c28639",
            x"41ee9cab0e78b0c833d8d46e20a1f1956ca4f5e28020f5e28fe3da126bc4ff42",
            x"db24641a047d37e1e98d7378e93dabf22af1f8d00405d60ef29f5a54559caecb",
            x"17307c37263a420a1cedf704f1fe4b4b543b8fd8b5e26550b138f53ad1cf272b",
            x"e7768fa4f27ae93fb726ba7c56043f79b80dd26f56deb1a1bc4028bfc78d04fe",
            x"08f9377c120f512f35beab370937dc11637005b6d47ba50b42e11a341e2e5d6d",
            x"9cba6e5b5f4fbbcac98b5c2035b15fb551b096ce33b17b97fcc35f72f34282d8",
            x"991c1597602a8ac7fac87a77cb9894aa3184e687869b2ba8a4a8b7834f5d7d87",
            x"44438af55617a7e3be187063283a01a9b082382e7c992060ef07f02919784d13",
            x"8101cd8f59ffbed40f6dd6e212a1dab635834732538e7dbd6a9acf3541cb6606",
            x"4443004a61b4f1b66cf02f4c1eea13c9624a0e96aecc637102d1c1d418b7b768",
            x"3f86061f5b3d38b91861531d23d04da3c01ca15f23e31040e51a0b1669d93acf",
            x"76219fedc687e9d649cadb7fca88b4575784abaa23d3fa5b28569cd3aa380bb7",
            x"f6668ddf88b0c2e27927d8e7f4d2bcd4404b7130b24a4698e572a7e825bbf7f1",
            x"ac566f72a32daf71bf74af455cb1745ac14d696c8557c91160e970a67691080d",
            x"4363a25a3e905c0bb144bc09164e926156503b2eca1c67fdc75bfee9bd3d14c6",
            x"35a0ab4866d38f2f5a13cf66bd39d0d259dc941be783ec22b2569790169197ea",
            x"504df1ddd63d2840740362bb68351a5e2a3eeec91890b1a4e29c06ce99498825",
            x"7672ced58cfcd2a7cf7384fe5a116a78689f25869b41d1f6f115eec8a0ca2202",
            x"b1184886111aa73c2dd5d2b90bebce0b346e47bca5cd1d78e3c0a3a25ee75036",
            x"28ea2e8eb52fa339bfb435f135d24a6de6dffdf194a49831531f51e2fe1512a2",
            x"f3f3ba2de690f0f469613da4322fc51db2f5fabe859089070a6188e98758afd6",
            x"e22faf9dd6d2d4f3e40bedfb5c79f732290b78c3a5673fccdf8f016d2f950526",
            x"8e3bf0a6979655a82da28a0081f177aec8f18ecb0df99c08d0541f7802ed6487",
            x"4d2149cfe2e5155d54d0c424405b82c2973190c4d467c8fcab4eefd738200b1f",
            x"2fb27413ab549e4fed8cbebaac851b983ea61d1d431ee30ad0f92a6486fdb295",
            x"c04a22c8e00231bcc51aebfeea0c58e973caf1318392254da3fa572cf33b7616",
            x"5499125d1aded59989a9d29489b64604feb089a22207bf7b63733f12114e1c1b",
            x"9f56d3a608bd9155732ed01279e38b9d267fbe184eca86231af938a1e247ebe2",
            x"9a93a34bd4177dc99a9064834429be4a14d2032c30d6d1c7e7939a70d71b74db",
            x"1c2c16e819f31665e5eafd8c3a4d59822315af4bdfa6208a5f40d73938d1aa8b",
            x"d5e9a994cdb0d3d375a34c2ec39e7fd0474f6d8c2f6e9a710bc5c4ad9f8d7a5b",
            x"6295375a0a97bbfbe0cce80cd0b7615fe5b54eae781a998c668534ed17008c5f",
            x"5faa24b00c24b2a24850649cbec0bdaedefa8809ea20a45d66dc833f23add437",
            x"9a2623497d57a31d28849ba3a3211b4243f41afd7547bc2e35301131e8a671cb",
            x"4410340b827f5058445ce50ec20edecc3613a70efe39664c6fb0c46c1dedc99f",
            x"85abb1fa9babe26a0fbdcd0e4f85ce5422566b953d61d5fd690748479bff0a3a",
            x"e30813c200d13b104d9736e0fb15cad0423bf9597251d6af57c4caeed001fc56",
            x"5bd6f51a29836b822b640f2b830f59c106fe123982172cb4523062e91070c4c8",
            x"4f43043ad98c017b0357de2934e03f5f4fda80d0779edcc9a53b70226d8bec31",
            x"2989b0e6e4658013bd14b856e81889bf7fce41bcdafa7b3f0fb9a5bb9dcbfe65",
            x"c7ca80bea77fa40a5ba41809d4e0d6886d7e7a8de431bdd37f8dcf48a2fa1244",
            x"9c189701cb31ffcf82ebad7202586d3e1b901418be396713bca43d48cab8ab22",
            x"31b530797b1c04715add86b0d63a19e7216e43107de399f00c6a5ed40a97343c",
            x"6826c59236199ca14e48373928a74c7b23bc6c263138d5f6be69b68f0e563c2f"
        ),
        path => (
            x"4c690f2a973d8f15894450889a74ed617e94c5f9072b86c0e0a2b47f192362a8",
            x"d13edf237824bd063432b68ac1d99e7c3b0fb3feeb3bbdeddc0905611731d803",
            x"7b21040279ebefbbb0928cc4cb4af22ee3c753e0e40071fadf387bb0a2c5e036",
            x"9b03d71cc3404ba5c7409e23f71cb6bb0b7428b745368d4b550e328867ed414e",
            x"028455f2cca8cd18f36bcbe318a092f5e6613de054039d07f2e29707ab329db9"
        )
    );

    signal done: std_logic;
begin
    uut: entity work.hss_verify
    generic map(
        SCHEME => TARGET,
        CORES => CORES,
        CHAINS => CHAINS,
        N => N,
        TREE_HEIGHT => TREE_HEIGHT,
        WOTS_W => WOTS_W
    )
    port map(
        clk => clk,
        reset => reset,
        enable => hss_enable,
        scheme_select => hss_scheme_select,
        message_digest => hss_mdigest,
        done => hss_done,
        valid => hss_valid,
        io_enable => hss_io_en,
        io_write_enable => hss_io_wen,
        io_address => hss_io_addr,
        io_input => hss_io_input
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
        variable correct: boolean := true;
    begin
        hss_enable <= '0';
        hss_io_en <= '0';
        hss_io_wen <= '0';
        hss_io_addr <= (others => '0');
        hss_io_input <= (others => '0');
        hss_scheme_select <= '0';

        done <= '0';
        reset <= '0';
        wait for t / 2;
        reset <= '1';
        wait for t;
        reset <= '0';

        if TARGET /= XMSS then
            -- setup bram
            hss_io_en <= '1';
            hss_io_wen <= '1';
            hss_io_addr <= std_logic_vector(to_unsigned(BRAM_IO_PK_ADDR + 0, BRAM_IO_ADDR_WIDTH));
            hss_io_input <= LMS_VRFY.public_key;
            wait for 2 * t;
            hss_io_addr <= std_logic_vector(to_unsigned(BRAM_IO_PK_ADDR + 1, BRAM_IO_ADDR_WIDTH));
            hss_io_input <= LMS_VRFY.public_seed;
            wait for t;
            hss_io_addr <= std_logic_vector(to_unsigned(BRAM_IO_SIG_ADDR, BRAM_IO_ADDR_WIDTH));
            hss_io_input <= std_logic_vector(to_unsigned(LMS_VRFY.leaf_index, 8 * N));
            wait for t;
            for i in LMS_VRFY.wots_sig'range loop
                hss_io_addr <= std_logic_vector(to_unsigned(BRAM_IO_WOTS_SIG_ADDR + i, BRAM_IO_ADDR_WIDTH));
                hss_io_input <= LMS_VRFY.wots_sig(i);
                wait for t;
            end loop;
            for i in XMSS_VRFY.path'range loop
                hss_io_addr <= std_logic_vector(to_unsigned(BRAM_IO_PATH_ADDR + i, BRAM_IO_ADDR_WIDTH));
                hss_io_input <= LMS_VRFY.path(i);
                wait for t;
            end loop;
            hss_io_en <= '0';
            hss_io_wen <= '0';

            hss_mdigest <= LMS_VRFY.mdigest;
            hss_scheme_select <= '1';
            hss_enable <= '1';
            report "LMS: Starting signature validation @ " & integer'image(now/1 ns) & " ns";
            wait for t;
            hss_enable <= '0';
            wait until hss_done = '1';
            report "LMS: Finished signature validation @ " & integer'image(now/1 ns) & " ns";
            if hss_valid = '1' then
                report "LMS: Validated generated signature";
            else
                report "LMS: Falsely reported signature invalid" severity error;
            end if;
            wait for t;
        end if;

        if TARGET /= LMS then
            -- setup bram
            hss_io_en <= '1';
            hss_io_wen <= '1';
            hss_io_addr <= std_logic_vector(to_unsigned(BRAM_IO_PK_ADDR + 0, BRAM_IO_ADDR_WIDTH));
            hss_io_input <= XMSS_VRFY.public_key;
            wait for 2 * t;
            hss_io_addr <= std_logic_vector(to_unsigned(BRAM_IO_PK_ADDR + 1, BRAM_IO_ADDR_WIDTH));
            hss_io_input <= XMSS_VRFY.public_seed;
            wait for t;
            hss_io_addr <= std_logic_vector(to_unsigned(BRAM_IO_SIG_ADDR, BRAM_IO_ADDR_WIDTH));
            hss_io_input <= std_logic_vector(to_unsigned(XMSS_VRFY.leaf_index, 8 * N));
            wait for t;
            for i in XMSS_VRFY.wots_sig'range loop
                hss_io_addr <= std_logic_vector(to_unsigned(BRAM_IO_WOTS_SIG_ADDR + i, BRAM_IO_ADDR_WIDTH));
                hss_io_input <= XMSS_VRFY.wots_sig(i);
                wait for t;
            end loop;
            for i in XMSS_VRFY.path'range loop
                hss_io_addr <= std_logic_vector(to_unsigned(BRAM_IO_PATH_ADDR + i, BRAM_IO_ADDR_WIDTH));
                hss_io_input <= XMSS_VRFY.path(i);
                wait for t;
            end loop;
            hss_io_en <= '0';
            hss_io_wen <= '0';

            hss_scheme_select <= '0';
            hss_mdigest <= XMSS_VRFY.mdigest;
            hss_enable <= '1';
            report "XMSS: Starting signature validation @ " & integer'image(now/1 ns) & " ns";
            wait for t;
            hss_enable <= '0';
            wait until hss_done = '1';
            report "XMSS: Finished signature validation @ " & integer'image(now/1 ns) & " ns";
            if hss_valid = '1' then
                report "XMSS: Validated generated signature";
            else
                report "XMSS: Falsely reported signature invalid" severity error;
            end if;
            wait for t;
        end if;

        done <= '1';
        wait;

    end process;
end architecture;
