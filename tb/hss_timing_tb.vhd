library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

use work.hss_types.all;
use work.hss_functions.all;

entity hss_timing_tb is
end entity;

architecture default of hss_timing_tb is
    constant t: time := 5 ns;

    constant TARGET: scheme_t := work.config.SCHEME;
    constant CORES: integer := work.config.HASH_CORES;
    constant CHAINS: integer := work.config.HASH_CHAINS;
    constant BDS_K: integer := work.config.BDS_K;

    constant N: integer := work.config.N;
    constant TREE_HEIGHT: integer := work.config.TREE_HEIGHT;
    constant WOTS_W: integer := work.config.WOTS_W;

    constant WOTS_LEN: integer := calculate_len1(N, WOTS_W) + calculate_len2(N, WOTS_W);
    constant BRAM_IO_PK_ADDR: integer := 0; -- root node + public seed
    constant BRAM_IO_SIG_ADDR: integer := 2;
    constant BRAM_IO_WOTS_SIG_ADDR: integer := BRAM_IO_SIG_ADDR + 1; -- index (TODO: + message randomizer)
    constant BRAM_IO_PATH_ADDR: integer := BRAM_IO_WOTS_SIG_ADDR + WOTS_LEN;
    constant BRAM_IO_ADDR_WIDTH: integer := 7;

    signal clk, reset: std_logic;

    signal hss_enable: std_logic;
    signal hss_mode: std_logic_vector(1 downto 0);
    signal hss_scheme_select: std_logic;
    signal hss_random: std_logic_vector(2 * 8 * N - 1 downto 0);
    signal hss_mdigest: std_logic_vector(8 * N - 1 downto 0);
    signal hss_done, hss_valid, hss_current_scheme, hss_needs_keygen: std_logic;
    signal hss_io_en: std_logic;
    signal hss_io_wen: std_logic;
    signal hss_io_addr: std_logic_vector(6 downto 0);
    signal hss_io_input, hss_io_output: std_logic_vector(8 * N - 1 downto 0);

    type keygen_test_t is record
        seed, public_seed, root: std_logic_vector(8 * N - 1 downto 0);
    end record;

    type wots_sig_t is array(0 to WOTS_LEN - 1) of std_logic_vector(8 * N - 1 downto 0);
    type path_t is array(0 to TREE_HEIGHT - 1) of std_logic_vector(8 * N - 1 downto 0);

    type sign_test_t is record
        mdigest: std_logic_vector(8 * N - 1 downto 0);
        leaf_index: integer range 0 to 2**TREE_HEIGHT - 1;
        wots_sig: wots_sig_t;
        path: path_t;
    end record;

    constant XMSS_KEYGEN: keygen_test_t := (
        seed => x"7781de0544c42dca964108451a40804f7939401122173c83425787d4facb49bb",
        public_seed => x"747da1dcd0be23030ad7d72d1e10881e330495a0ad0a2932844bacf00ea112a9",
        root => x"84552873c4aad5dc92265288267c5ddaf45f3ced1165e5ab594a9b1dca9506e4"
    );

    constant XMSS_SIGN: sign_test_t := (
        mdigest => x"ace2130e94d35c4b1b3fdfdc722f451c969479644af8184f965b51c3d6592c84",
        leaf_index => 1,
        wots_sig => (
            x"75641db501777c62b6c2b0669f17d09549d1425a6ff6b71048191ce3626ca942",
            x"b49cd6f7749eac12ebdb8bc6623f194c6a87ef3b11aaf675095a7c6f0e680c83",
            x"9c27e6cc4983d0b76d0af4f65173e405dde9551ae9811010e84c2a4c55e515d1",
            x"4897d47eeaa25f4009b03190ae9e556e1f646041986e13def7d0e4e2c2b0e963",
            x"5d50ee0b4d238313d032b072f5363b4a7b2aa35636219d2f6c46a69db04a7823",
            x"ae48df9971d94e7cbd0ef4e0098d7ad0a44d8d5371cc55ba3569290c6a605584",
            x"50a0b2cdb8555829d6aee9c78df19e0ec216deb1ad9f56cec2ec673913edabc3",
            x"bceffdbe4a588a9dc7bdebe8b8e35885287c6d22bbc2328f84b73526d8d5c7e4",
            x"02153a72edc82ddad036818e1d635fee1d72155fa1ec0813320344681984456f",
            x"24c69eca7af72f4a9442d7bbb116dbeff8159655604846150c79b993c7c26dcb",
            x"72b6ffcad0004f90e86af469694eed6098cc954119517c52097f9e4419797a9d",
            x"fc34a859035a8a637866dd6bf9efc8f12a4ac73ed8f5ed97779a2a0f9d2ef591",
            x"dffe3a3be6ee37c80a0c66eb74da05961942a41db09c73ce1dd88d69c0379851",
            x"b9415b36656ae1ff3306ef5407d46053c22476c61b1fae0fb7225f548a19a72d",
            x"2fabe3f66d7e802aaf724fed1e35631d517b718cfd680041c3e9e42070d6a9ec",
            x"2c8734d742b3226146875139037679b8a2b6e56c1aafc0d77a10b5abd01f0e3c",
            x"557c1951baa37dacc78f13398f4a3b6fb434417babb87e0a74b4a7e35a46d9b9",
            x"8fbf8c1380ca17d127c834b9bab7a7ae8b63cd3ebac83aebdf9a2e5fad20b9af",
            x"aba45093b58d3c394f7636e6af0824560dda89f498782174f08f8f139a5f94c5",
            x"d81a40a103614f13e367edbd345b65f5f27cb7716055d640a96571a9e52fe3da",
            x"21fe71e374f52b384fe3e038bfa69fa92995b98048593b9d89fc9c143c4e5cb7",
            x"65d3e88f0c2a3186cb1ca88041f6b760fdd33246be207f76cb52ff85fca15311",
            x"90d71708b16be56dfc9380a9476bd0687e28b3085e72724c505d58349b1c3b61",
            x"7635eb646532cd5db0cffd498fef50e6f79f5227353348aaaf9b8490c2a79564",
            x"5d70f9248ac34d0b65a7b2f5882633f0ef8042ef95f6399fcc0c7104a6938649",
            x"deacfd033dd48493e8fe3a9bd75b07a7e3c01574c8d39ee76c20f471ae115141",
            x"30f4f94a6ef12eed0d8f73c801321fed350ad26261e9e8b7b4bb8e5316bb54a0",
            x"a6913abbe2a920162242a0f2177d35d8a20004ce9191e77e69916dc64ca026fe",
            x"3472d2f1ad60ee5279d55adf11eea7a99b931a787c1819dc59c528a4b34be681",
            x"185469044d54193df9bd689237f7e5e186938409c8d68cf2172df31c13bfc0c7",
            x"efd3b44cf23e28406f6cbaf914b84e9422c6d6862c0c7963c77231b0c91498f6",
            x"e64f43e810dd41c660e71f4ceb8f10acf711a963385e03824358dd93316a07bc",
            x"a3102e8f42508913428059e4aeb872ba032b2f5b885d4b1a25fa709809edfb10",
            x"3d4c1c50d0e31b4aac96042a4dbb428e8b4ef99136a914ad21bfa6c5f31a4aa3",
            x"cd50eb42105f344e3154e3e2014bbd703ad1683a28fb1a86eb3285aa8cb831dd",
            x"4189ea81a5c7cbb70acc1c26864ffa6ecb6479e9019cd33ece9461eeb5fa3322",
            x"b7ce8e831a01ae35454afc1ad1de1804e3954f6a4b233cecfcd67f94b30cc672",
            x"29146d29643eba57829397498b15a8d55cc48b39a1fb210ddb84622c76e9d28e",
            x"7bc57ae66058f4a7a695f7d4af93099c5ced0d342255cbeee9850ea7eabe3112",
            x"488d5b10ad4b5863d7dde06030391d8734481227233e24c14c08ddf73111c542",
            x"251f48e7034983eac6314b30bc595eb81d2b6d0ab0221832facc2226b8e12f6a",
            x"4cd29871288ae1a3a61dbd3931fe8937d9b682eec90333a2da327b6a0c5e6914",
            x"bffb654ace7b6c9f89420e0419626b65f19fa2e078e625b3c83536d78d49be3c",
            x"94d56170316f4cf1ed278c721c3dcfc5d04f3864489422ae6100a523ca9d3f36",
            x"86c334b0c8801c86d24acd58ca832a14659cea16d6a57ff2d6d9a14da42445e8",
            x"f876b6c65bb7bb84b2f563be1d5220eb9cada08590c9573cd9a1326500f1dd4c",
            x"1391b28aa9d2c5a239dc644223cd5103d175526eb342ef7f404ddfeb0522151c",
            x"2fa620e0e7b3485150cf5f074d214a54a3f6a3b08afc16efb52c3b281ddf6583",
            x"4e7a972fc9f666ff106831fa754bf8565b568ecaf0349a7c4edd3b6c75891d18",
            x"f1d9fa6ad2c03249dfb42d16abded990a757dd027a5b3627c9e4d517bca57dff",
            x"4dcc44dee84051d79f9625276abc73e05af26a9caaffb1ebabe2a75f5077d228",
            x"ea318164cda2c2fdcd83f1c0117529d4ad13181aabb4e4f72a4d62334c0e8a58",
            x"75c5f5fb010108ab1142da646326e207524aaaa71cea161a8b4eecd2c3641be9",
            x"67fb0c377db8121a340db9acef3d9bacb1b166d8e231ed499cad39c3d24d26f3",
            x"14358cc7f3431983ac41a8feb6a456e501c793e1684c86e3ed2866d9aeb1e0b1",
            x"85e7c78601f7aed49c2fe320adfb22d046c411343467cdd024f5d47a8f47e884",
            x"a898639c9c5100cfc330c72ad113b7589e989d2898900bfa974cbcae9e610d5f",
            x"706f5e3a6afd8eda86123449f66e896e09b8bd4962ae0a63c559a3033896dd29",
            x"c478f1645548057a8b79a0519b636fe00bcca68778fc10cc2d96e799d41f54cf",
            x"02956868a4e445a5f06b2a87f1bb2dec6482318e2c10306ad8699b1a47677a80",
            x"18c97ee53bf40d464c26749cffa5aec701d7c4ea3005869e140e254d63873d65",
            x"bb57156908a489bd08af6ad209f340e7f1149c26727ca534841e01350996d498",
            x"a5266d0b76f7fb7b2c8bc18a9da5879ce6d9e2c179a7acb042ca2410242a58ea",
            x"3e1e072d2bbed538d1adb57eef345d67d38aa1c8972434e5a7501f92740429f0",
            x"454075aeff6aac16f1e416ed765d9ef1203f94dd71d14e806a56a340e2df94a2",
            x"6a409216d49351ef86cdb548a1b24caefbad0ecb1478218503fbb0242da27213",
            x"6d5956c8d34d33c725a177018a5faf8f58af9394c5ec0656d71fa61e8978a107"
        ),
        path => (
            x"d6b3f974b538700c6b212a959b411d1d57f5f29a501059ad0af28f3229cf8681",
            x"6365534e33b2a94f384b994b12bac72db3b3503435586de5d2de6f4ac24241f9",
            x"428ef2cc2ed6c72bbeb1f0eedd447b4116a7c2413d0f874ea7fee48afeea245d",
            x"68e8a50aff12762481f2030fab0a9ab47815378b84ff1d1336c7588de948a47c",
            x"687fe054f350114f953ff3fac1c0261e396c285c254dd350f4b6e8cf68c3964d",
            x"be65c9df149c31e2c129fc5dee150ae0c52d4ef5c07437b9e6799775c568c23b",
            x"7b7a940e303ffb8b0f3faae4faf83b59268ee3c138bc3d31cdd441bae86c4c74",
            x"4c0997b6d0afd6aa7da0c74427006b3107b9f0edf269014544f99032d24e717c",
            x"14344fedfdcf74e8dd0192a4810ed90975ce039e9ab1781f86ba3c8cf72c420e",
            x"e639f98d695645350f009157a628ed29aefccd3fd493f899a4bb07bd4c2b7952"
        )
    );

    constant LMS_KEYGEN: keygen_test_t := (
        seed => x"a1c4696e2608035a886100d05cd99945eb3370731884a8235e2fb3d4d71f2547",
        public_seed => std_logic_vector(to_unsigned(0, 8 * N - 128)) & x"215f83b7ccb9acbcd08db97b0d04dc2b",
        root => x"b6fd483859a8fdda88451d50c3d685d846ed7bc9a0d08524fd7bb128185fa198"
    );

    constant LMS_SIGN: sign_test_t := (
        mdigest => x"b84a3617deaefb260ac54f7e63936f77916df174e155c1f2f13c6b2b69dfcd30",
        leaf_index => 4,
        wots_sig => (
            x"fa64e2622da24a8b2364dc25e9bc218f97d95e97fb022c4feff3791203376ade",
            x"65d8cc5555650ae0f86b9dd1b3d257dd81106aa20ad1fdb048b52c429a11cb46",
            x"3a023d89282458864bfdd81bfc2979d831f6eec52bf3b69ec023e86060ec549b",
            x"1e8ed87eecc467c0ec6f8f36b7cb405732779908d6e70be9b0e5a6cd14659764",
            x"97d3dba926a346cf60a5a157e79012a30bab6cef6f5d0f605b6bbb9594cfa38f",
            x"a05b44dbd6ea9c2aff843a876b7b5d6dec8a94fbd801715b00c673abeef7b36c",
            x"92840536fdfcc1a67efac6fb35ae3b5ba86bbb03427bc983a5cd42aa354a9097",
            x"e80bb8ca2f4ea2a3e5c4a7792d688f4dbff9afdc7aad23ca9b08188db45f4060",
            x"5a233ca229f3d9cc67e9fc3e5af86d2f1cb9f7234d7662f8a5830767cc9e3588",
            x"62ef9b1ab83b9cfcb6eb7818a7197f8496e5a2f8d90458264401b82daf5a7b3c",
            x"a322e0641088de04b0b1c3fa4da60dd26f8aa01d26a0cb91c723fb3e5431bd1b",
            x"9d7925b84f3d0a04d5df8a3471147c45db9abeea39b42d3f8db2a39d0890fa95",
            x"ef3d22905b4cc94829b821723f6ba1a94499dd542dbae3235a1a5eed5387a7a3",
            x"bb2d65ea4ace71ec565d8d1ddae0f8110908cfd17221522a091e43b244be88d4",
            x"1c5344b7e0879e93f57cd535e05316951d29fbeeed7ebb687745dd77f3a5787f",
            x"03cf205fd1551725cb6249b7bd85640cc2168ebaf9a400a31e9ce59c3cefdc9d",
            x"fcd3e5ccbf490af2a7f4bf0e63693052ca9f32291cfc961afc97134bed299b17",
            x"7f23eb47b6c24de995456778c5b46993499d0d07ca8f4275bfd21d5ae6cbc9ad",
            x"29bbda65a2ddbcc7ab0fbc1dc25724749b5d9844ec4e0ce12ace5f71f9e4b4e5",
            x"a76e77fa34108d758e57b31ea9967eb187192f2f4cc67a09899bce04b3552a34",
            x"f3ad656dbabeb6cd9d06fdec7f0631ebb1309d0da2b52dcddbe0908669b765af",
            x"3fed566748d5e95c34191fc58fe214f6fa1633a64600c67d34b856c9068bb09d",
            x"3e8f86fbcb99416024e89791a2412b85c1e298d90c538ab5ba57735ee65ff079",
            x"e2cdb984a438cbdc90c70285df0a09ce9b02cd809482b463003902370c3fc618",
            x"babcfd26d27471e6205b674f0a4dabb8c19db6e8fc41c7ea89a1157b6f7f5113",
            x"db15eac021c788f1fef0f1be54a9421962c21c4690e97af8b162678d24285fec",
            x"32f28847bf167078fbd31606ca5213f00ec17defa4e412bf345ce0d96fbd31fa",
            x"674acb4bc05199398219f45ce61552384dcee3ff9989eded86099f4f09204044",
            x"1938d437d24235843269b8e7fa5c8ffcba10fddbdb5d22ad613c5b3aa3263815",
            x"54b41d3430bda5a524edb3cc4c5523add95e258e1beb4adda232caedf9f04e50",
            x"dbe1856555f34a1fecd00c74da3c54f909d1cf3cfd6bc29c1afa03473e8579f0",
            x"7d30d8846650d01130932fc462456033093bdc46fa83dc895d56435d8b6f187a",
            x"8500ae951f654bf39e46a01d8f5e9f86922e80ac4bdef8470a04e2509f8e491d",
            x"4218f2cb8a3831811536e8685a2ae836bbc125e04f3c29341e4c6432815c4db9",
            x"011bf790e41be1de1abc7bc03e0b090e8a0cb32ad33c21d425eee504de94a23d",
            x"1d5b675245e9016299d261ab360df7fd636809130bc801a9ba841c017c6881fe",
            x"b27d118088498294643f558e7c007a9726782d522de3091a8e636273e2e41082",
            x"82cadb243c09c27eb03c64a5fc0d565c9a03340390eedf88fe5e6a707019fd5d",
            x"8f9d689df91454ec3d03c9606a85c6adec53eeb9045475ebd71c878b8103b9b2",
            x"9dbed1f8da9fa15514d5e45ef68c5ff23666f814a143fee59d46868b8e4b04eb",
            x"33faf7fe61071defdb5bce0d4e06c78c2de33a8b21925fe56f31a600845ebac8",
            x"fdbae9693511ee09bb917bbf6fe79f625dc7722f0d6ed6200c5ebefaa674ef91",
            x"6c2900eaf55e063b87e15b05a587870c7bef740e17ccf79d146b72c37d7ed24a",
            x"dfd8c1ba2ca5613e66f5f58f3b89fa9a83743bba7759153acf6593fdb6ead3b7",
            x"950c49aae6fb9093aa8c76597eea233caaef16ca87e7bd2cc025480201d6a767",
            x"afa977f807a6e8abc6ac3cc3dd304b8a9aef21ddf9704beeffb4963a0708ab0b",
            x"77f406b73cd7015bf5553e2b68b82a890b155d0531cd2396ad27d86aa6d7dcd9",
            x"235bf13e80dffa37f5d23d8a46ee045efa9a718effa6091b9ab7808991400e19",
            x"ad4a212f70206161c1f3ddb7a708ff66616ec5ddcab1d2fe0a26f843207e3dee",
            x"82d937845234b2534cfcd1709745f7957b6ba4a203524bc7c44b26898d64c63e",
            x"0af93bed2e969eadb1330b513b4764cdb6874988a7e56a0f3e65fae27b00b0ed",
            x"0f7a563a20084ec4d42ffcb7603d413d3c57713f2b7cac1a5d3ed0af32a6aff1",
            x"6878c1b2dfb86bf3e5f17d5ee4a043ac84e5c3b9695aa8235551519a1a9e4e18",
            x"73337cba56f20722bd75f7de6287677b55b9c2c58ba99e4cadb26c8f6161e73c",
            x"115307540881683b43e279bfb60f812113053c3ec3e7de2eca127a2377a544cc",
            x"d7e38ebf831ee3107997b65d92e396109eb45d517dbc85e53bcb502b8853412d",
            x"52434092cb5bc417611fcd356709efef7421dd0dbcf5889706d14871d64a830c",
            x"9749a0a2660b6dd36d04246e541300fcbf3b0e726ec36af2de62adc1a741af1e",
            x"5e444a681407e5527f62daf2c080ff7445513ea9884fc34e1f2dc57fc2f97a00",
            x"09005fb54060c49a749bca2262eff2985bf331e28f9d57dbfbd061b155704137",
            x"2843ebfe840a360d913143c3c3e71740bbcc65394750698033e9c529dd28864d",
            x"a5e76dcaa50ad2636ca874db45c3237ebb12d21ebefd7fc5cbde7e7deaa952df",
            x"f73c1d2f6138232150cf71eed13f6603a70951b0dff96a8246cfb2ddabbeb6ed",
            x"504033d5ed226f6109447d5262f62c98ba109824356fb47a48b2ea8d5384bc01",
            x"9a381fcad6767ce29fc6bd53202d856efda59b75826b2562921f4b376e380fbc",
            x"ad7936d41b51b13fe15112b0401b27a19d80eb8a5fb655eaf985818753748bb3",
            x"1afba80a60df742bd7f9d7f32479d3c5587cc83b1d6fedcfe15d80de01f892bc"
        ),
        path => (
            x"e4a220c9d87356f7c762865fd0aea88af77f9e904e25da7636de6046624cc2d8",
            x"81eb38cf900cac83b8fd27f0827c5e96e5046538b2f47665170e819dc0ee81d9",
            x"59617e53a8d81d065918b21ee69e660d050385b213864d7009bcef768d77facd",
            x"67867dda4fdf90c2a804f198fe32185f20c22399a4fe703ab6042c7c4c78d8af",
            x"049edd64e90fed8ae8c489c5f40461d1f4c893460feab595d968de6513620c60",
            x"7bac0c8549991035986d744175f6cb23c539f9318b284e0d590321d961e1b06d",
            x"84525ab838d2fdf12f2a3def7a979d5b845546aa2a2f354000ed39706e831ad1",
            x"d699f00809999fe31a7b586a7fcafec6a9a90f6f60f66778924ee014327241d6",
            x"acf46df99cdd87ce2136f390b29b7a0f9804747f50b018893b0c9ab5838e841b",
            x"7732ba2d01b71887cb64a05bcdfbb2976b0180e7c39227c429acb89f55d7be9d"
        )
    );

    signal done: std_logic;
begin
    uut: entity work.hss
    generic map(
        SCHEME => TARGET,
        CORES => CORES,
        CHAINS => CHAINS,
        BDS_K => BDS_K,
        N => N,
        TREE_HEIGHT => TREE_HEIGHT,
        WOTS_W => WOTS_W
    )
    port map(
        clk => clk,
        reset => reset,
        enable => hss_enable,
        mode => hss_mode,
        scheme_select => hss_scheme_select,
        random => hss_random,
        message_digest => hss_mdigest,
        done => hss_done,
        needs_keygen => hss_needs_keygen,
        valid => hss_valid,
        current_scheme => hss_current_scheme,
        io_enable => hss_io_en,
        io_write_enable => hss_io_wen,
        io_address => hss_io_addr,
        io_input => hss_io_input,
        io_output => hss_io_output
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

        done <= '0';
        reset <= '0';
        wait for t / 2;
        reset <= '1';
        wait for t;
        reset <= '0';

        if TARGET /= XMSS then 
            hss_mode <= "00";
            hss_scheme_select <= '1';
            hss_random <= LMS_KEYGEN.public_seed & LMS_KEYGEN.seed;
            wait for t;
            report "LMS: Generating public key @ " & integer'image(now / 1ns) & " ns";
            hss_enable <= '1';
            wait for t;
            hss_enable <= '0';
            wait until hss_done = '1';
            report "LMS: Finished public key generation @ " & integer'image(now / 1ns) & " ns";
            wait for t;

            hss_io_en <= '1';
            hss_io_addr <= std_logic_vector(to_unsigned(BRAM_IO_PK_ADDR, BRAM_IO_ADDR_WIDTH));
            wait for 2 * t;
            if hss_io_output = LMS_KEYGEN.root then
                report "LMS: Valid root value generated";
            else
                report "LMS: Invalid root value generated" severity error;
            end if;

            hss_io_addr <= std_logic_vector(to_unsigned(BRAM_IO_PK_ADDR + 1, BRAM_IO_ADDR_WIDTH));
            wait for 2 * t;
            if hss_io_output = LMS_KEYGEN.public_seed then
                report "LMS: Correct public seed in BRAM";
            else
                report "LMS: Invalid public seed in BRAM" severity error;
            end if;

            -- Overwriting root / seed
            hss_io_addr <= std_logic_vector(to_unsigned(BRAM_IO_PK_ADDR, BRAM_IO_ADDR_WIDTH));
            hss_io_input <= (others => '0');
            hss_io_wen <= '1';
            wait for t;
            hss_io_addr <= std_logic_vector(to_unsigned(BRAM_IO_PK_ADDR + 1, BRAM_IO_ADDR_WIDTH));
            wait for t;
            hss_io_wen <= '0';

            hss_io_en <= '0';
            hss_mdigest <= LMS_SIGN.mdigest;
            hss_mode <= "01";
            report "LMS: Looping through signatures to reach leaf index " & integer'image(LMS_SIGN.leaf_index);
            for i in 0 to LMS_SIGN.leaf_index - 1 loop
                report "LMS: Starting signature " & integer'image(i) & " @ " & integer'image(now/1 ns) & " ns";
                hss_enable <= '1';
                wait for t;
                hss_enable <= '0';
                wait until hss_done = '1';
                report "LMS: Finished signature @ " & integer'image(now/1 ns) & " ns";
                wait for t;
            end loop;

            report "LMS: Generating test case signature @ " & integer'image(now/1 ns) & " ns";
            hss_enable <= '1';
            wait for t;
            hss_enable <= '0';
            wait until hss_done = '1';
            report "LMS: Finished signature generation @ " & integer'image(now/1 ns) & " ns";
            wait for t;

            hss_io_en <= '1';
            hss_io_addr <= std_logic_vector(to_unsigned(BRAM_IO_PK_ADDR, BRAM_IO_ADDR_WIDTH));

            wait for 2 * t;
            if hss_io_output = LMS_KEYGEN.root then
                report "LMS: Correct root value in BRAM";
            else
                report "LMS: Invalid root value in BRAM" severity error;
            end if;
            hss_io_addr <= std_logic_vector(to_unsigned(BRAM_IO_PK_ADDR + 1, BRAM_IO_ADDR_WIDTH));
            wait for 2 * t;
            if hss_io_output = LMS_KEYGEN.public_seed then
                report "LMS: Correct public seed in BRAM";
            else
                report "LMS: Invalid public seed in BRAM" severity error;
            end if;
            hss_io_addr <= std_logic_vector(to_unsigned(BRAM_IO_SIG_ADDR, BRAM_IO_ADDR_WIDTH));
            wait for 2 * t;
            if unsigned(hss_io_output(TREE_HEIGHT - 1 downto 0)) = LMS_SIGN.leaf_index then
                report "LMS: Correct leaf index in BRAM";
            else
                report "LMS: Invalid leaf index in BRAM" severity error;
            end if;
            for i in 0 to WOTS_LEN - 1 loop
                hss_io_addr <= std_logic_vector(to_unsigned(BRAM_IO_WOTS_SIG_ADDR + i, BRAM_IO_ADDR_WIDTH));
                wait for 2 * t;
                if hss_io_output /= LMS_SIGN.wots_sig(i) then
                    report "Invalid wots sig at " & integer'image(i) severity error;
                    correct := false;
                end if;
            end loop;
            if correct then
                report "LMS: Correct WOTS signature generated";
            end if;

            correct := true;

            for i in 0 to TREE_HEIGHT - 1 loop
                hss_io_addr <= std_logic_vector(to_unsigned(BRAM_IO_PATH_ADDR + i, BRAM_IO_ADDR_WIDTH));
                wait for 2 * t;
                if hss_io_output /= LMS_SIGN.path(i) then
                    report "LMS: Invalid path at " & integer'image(i) severity error;
                    correct := false;
                end if;
            end loop;
            if correct then
                report "LMS: Correct path generated";
            end if;
            hss_io_en <= '0';

            wait for t;
            hss_mode <= "10";
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

            hss_io_en <= '1';
            hss_io_addr <= std_logic_vector(to_unsigned(3, BRAM_IO_ADDR_WIDTH));
            wait for 2 * t;
            hss_io_input <= hss_io_output xor std_logic_vector(to_unsigned(1, N * 8));
            hss_io_wen <= '1';
            wait for t;
            hss_io_wen <= '0';
            wait for t;
            hss_io_en <= '0';

            hss_enable <= '1';
            wait for t;
            hss_enable <= '0';

            wait until hss_done = '1';
            if hss_valid = '0' then
                report "LMS: Flipping bit of signature invalidated it";
            else
                report "LMS: Incorrectly reported invalid signature as valid";
            end if;
        end if;

        if TARGET /= LMS then 
            hss_mode <= "00";
            hss_scheme_select <= '0';
            hss_random <= XMSS_KEYGEN.public_seed & XMSS_KEYGEN.seed;
            wait for t;
            report "XMSS: Generating public key @ " & integer'image(now/1 ns) & " ns";
            hss_enable <= '1';
            wait for t;
            hss_enable <= '0';
            wait until hss_done = '1';
            report "XMSS: Finished key generation @ " & integer'image(now/1 ns) & " ns";
            wait for t;

            hss_io_en <= '1';
            hss_io_addr <= std_logic_vector(to_unsigned(0, BRAM_IO_ADDR_WIDTH));
            wait for 2 * t;
            if hss_io_output = XMSS_KEYGEN.root then
                report "XMSS: Valid root value generated";
            else
                report "XMSS: Invalid root value generated" severity error;
            end if;

            hss_io_addr <= std_logic_vector(to_unsigned(1, BRAM_IO_ADDR_WIDTH));
            wait for 2 * t;
            if hss_io_output = XMSS_KEYGEN.public_seed then
                report "XMSS: Correct public seed in BRAM";
            else
                report "XMSS: Invalid public seed in BRAM" severity error;
            end if;

            -- Overwriting root / seed
            hss_io_addr <= std_logic_vector(to_unsigned(0, BRAM_IO_ADDR_WIDTH));
            hss_io_input <= (others => '0');
            hss_io_wen <= '1';
            wait for t;
            hss_io_addr <= std_logic_vector(to_unsigned(1, BRAM_IO_ADDR_WIDTH));
            wait for t;
            hss_io_wen <= '0';

            hss_io_en <= '0';
            hss_mdigest <= XMSS_SIGN.mdigest;
            hss_mode <= "01";
            report "XMSS: Looping through signatures to reach leaf index " & integer'image(XMSS_SIGN.leaf_index);
            for i in 0 to XMSS_SIGN.leaf_index - 1 loop
                report "XMSS: Generating signature " & integer'image(i) & " @ " & integer'image(now/1 ns) & " ns";
                hss_enable <= '1';
                wait for t;
                hss_enable <= '0';
                wait until hss_done = '1';
                report "Finished signature @ " & integer'image(now/1 ns) & " ns";
                wait for t;
            end loop;

            report "XMSS: Generating test case signature @ " & integer'image(now/1 ns) & " ns";
            hss_enable <= '1';
            wait for t;
            hss_enable <= '0';
            wait until hss_done = '1';
            report "XMSS: Finished signature @ " & integer'image(now/1 ns) & " ns";
            wait for t;
            hss_io_en <= '1';
            hss_io_addr <= std_logic_vector(to_unsigned(BRAM_IO_PK_ADDR, BRAM_IO_ADDR_WIDTH));
            wait for 2 * t;
            if hss_io_output = XMSS_KEYGEN.root then
                report "XMSS: Correct root value in BRAM";
            else
                report "XMSS: Invalid root value in BRAM" severity error;
            end if;
            hss_io_addr <= std_logic_vector(to_unsigned(BRAM_IO_PK_ADDR + 1, BRAM_IO_ADDR_WIDTH));
            wait for 2 * t;
            if hss_io_output = XMSS_KEYGEN.public_seed then
                report "XMSS: Correct public seed in BRAM";
            else
                report "XMSS: Invalid public seed in BRAM" severity error;
            end if;
            hss_io_addr <= std_logic_vector(to_unsigned(BRAM_IO_SIG_ADDR, BRAM_IO_ADDR_WIDTH));
            wait for 2 * t;
            if unsigned(hss_io_output(TREE_HEIGHT - 1 downto 0)) = XMSS_SIGN.leaf_index then
                report "XMSS: Correct leaf index in BRAM";
            else
                report "XMSS: Invalid leaf index in BRAM" severity error;
            end if;
            for i in 0 to WOTS_LEN - 1 loop
                hss_io_addr <= std_logic_vector(to_unsigned(BRAM_IO_WOTS_SIG_ADDR + i, BRAM_IO_ADDR_WIDTH));
                wait for 2 * t;
                if hss_io_output /= XMSS_SIGN.wots_sig(i) then
                    report "XMSS: Invalid wots sig at " & integer'image(i) severity error;
                    correct := false;
                end if;
            end loop;
            if correct then
                report "XMSS: Correct WOTS signature generated";
            end if;

            correct := true;

            for i in 0 to TREE_HEIGHT - 1 loop
                hss_io_addr <= std_logic_vector(to_unsigned(BRAM_IO_PATH_ADDR + i, BRAM_IO_ADDR_WIDTH));
                wait for 2 * t;
                if hss_io_output /= XMSS_SIGN.path(i) then
                    report "XMSS: Invalid path at " & integer'image(i) severity error;
                    correct := false;
                end if;
            end loop;
            if correct then
                report "XMSS: Correct path generated";
            end if;
            hss_io_en <= '0';

            wait for t;
            hss_mode <= "10";
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

            hss_io_en <= '1';
            hss_io_addr <= std_logic_vector(to_unsigned(3, BRAM_IO_ADDR_WIDTH));
            wait for 2 * t;
            hss_io_input <= hss_io_output xor std_logic_vector(to_unsigned(1, N * 8));
            hss_io_wen <= '1';
            wait for t;
            hss_io_wen <= '0';
            wait for t;
            hss_io_en <= '0';

            hss_enable <= '1';
            wait for t;
            hss_enable <= '0';

            wait until hss_done = '1';
            if hss_valid = '0' then
                report "XMSS: Flipping bit of signature invalidated it";
            else
                report "XMSS: Incorrectly reported invalid signature as valid";
            end if;
        end if;

        done <= '1';
        wait;

    end process;
end architecture;
