library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

use work.hss_types.all;
use work.hss_functions.all;

entity wots_shared_tb is
end entity;

architecture default of wots_shared_tb is
    constant t: time := 10 ns;

    constant TREE_HEIGHT: integer := 10;
    constant N: integer := 32;
    constant CHAINS: integer := 1;
    constant WOTS_W: integer := 16;
    constant WOTS_LEN: integer := calculate_len1(N, WOTS_W) + calculate_len2(N, WOTS_W);

    constant HASH_BUS_ID_WIDTH: integer := work.params.HASH_BUS_ADDRESS_BITS;
    constant HASH_BUS_LEN_WIDTH: integer := work.params.HASH_BUS_LENGTH_BITS;
    constant HASH_BUS_CTR_WIDTH: integer := 8;

    constant BRAM_ADDR_WIDTH: integer := 11;
    constant BRAM_IO_ADDR_WIDTH: integer := 11;
    constant BRAM_WOTS_KEY_ADDR: integer := 10;
    constant BRAM_IO_WOTS_SIG_ADDR: integer := 12;

    constant TARGET: scheme_t := DUAL_SHARED_BRAM;

    type hash_array_t is array(0 to WOTS_LEN - 1) of std_logic_vector(8 * N - 1 downto 0);

    type test_case_xmss_t is record
        pub_seed, secret_seed: std_logic_vector(8 * N - 1 downto 0);
        leaf_index: std_logic_vector(TREE_HEIGHT - 1 downto 0);
        message_digest: std_logic_vector(8 * N - 1 downto 0);
        signature: hash_array_t;
        leaf_value: std_logic_vector(8 * N - 1 downto 0);
    end record;

    type test_case_lms_t is record
        I: std_logic_vector(127 downto 0);
        q: std_logic_vector(TREE_HEIGHT - 1 downto 0);
        message_digest: std_logic_vector(8 * N - 1 downto 0);
        seed: std_logic_vector(8 * N - 1 downto 0);
        signature: hash_array_t;
        leaf_value: std_logic_vector(8 * N - 1 downto 0);
    end record;

    signal clk, reset: std_logic;

    signal h_enable, h_done, h_next, h_busy, h_idle: std_logic;
    signal h_id, h_next_id, h_done_id: unsigned(HASH_BUS_ID_WIDTH - 1 downto 0);
    signal h_block, h_next_block, h_done_block: unsigned(HASH_BUS_CTR_WIDTH - 1 downto 0);
    signal h_output, h_input: std_logic_vector(8 * N - 1 downto 0);
    signal h_len: unsigned(HASH_BUS_LEN_WIDTH - 1 downto 0);

    signal uut_h_enable: std_logic;
    signal uut_h_len: unsigned(HASH_BUS_LEN_WIDTH - 1 downto 0);
    signal uut_h_id: unsigned(HASH_BUS_ID_WIDTH - 1 downto 0);
    signal uut_h_block: unsigned(HASH_BUS_CTR_WIDTH - 1 downto 0);
    signal uut_h_input: std_logic_vector(8 * N - 1 downto 0);
    signal thash_h_enable: std_logic;
    signal thash_h_len: unsigned(HASH_BUS_LEN_WIDTH - 1 downto 0);
    signal thash_h_id: unsigned(HASH_BUS_ID_WIDTH - 1 downto 0);
    signal thash_h_block: unsigned(HASH_BUS_CTR_WIDTH - 1 downto 0);
    signal thash_h_input: std_logic_vector(8 * N - 1 downto 0);

    signal uut_mode: std_logic_vector(1 downto 0);
    signal uut_pub_seed, uut_seed, uut_message_digest: std_logic_vector(8 * N - 1 downto 0);
    signal uut_leaf_index: std_logic_vector(TREE_HEIGHT - 1 downto 0);
    signal uut_enable, uut_done, uut_scheme_select: std_logic;
    signal uut_hash_select: std_logic;
    signal uut_leaf: std_logic_vector(8 * N - 1 downto 0);

    signal th_enable, th_done: std_logic;
    signal th_left, th_right: std_logic_vector(8 * N - 1 downto 0);
    signal th_pub_seed: std_logic_vector(8 * N - 1 downto 0);
    signal th_addr_type: integer range 1 to 2;
    signal th_addr_ltree: std_logic_vector(TREE_HEIGHT - 1 downto 0);
    signal th_addr_height: integer range 0 to TREE_HEIGHT - 1;
    signal th_addr_index: std_logic_vector(31 downto 0);
    signal th_output: std_logic_vector(8 * N - 1 downto 0);

    -- internal bram
    signal b_a_we: std_logic;
    signal b_a_address: std_logic_vector(BRAM_ADDR_WIDTH - 1 downto 0); 
    signal b_a_input: std_logic_vector(8 * N - 1 downto 0);
    signal b_a_output: std_logic_vector(8 * N - 1 downto 0);
    signal b_b_we: std_logic;
    signal b_b_address: std_logic_vector(BRAM_ADDR_WIDTH - 1 downto 0); 
    signal b_b_input: std_logic_vector(8 * N - 1 downto 0);
    signal b_b_output: std_logic_vector(8 * N - 1 downto 0);

    -- io bram
    signal b_io_we: std_logic;
    signal b_io_address: std_logic_vector(BRAM_ADDR_WIDTH - 1 downto 0); 
    signal b_io_input: std_logic_vector(8 * N - 1 downto 0);
    signal b_io_output: std_logic_vector(8 * N - 1 downto 0);

    signal b_check_addr: std_logic_vector(BRAM_ADDR_WIDTH - 1 downto 0); 
    signal b_check_output: std_logic_vector(8 * N - 1 downto 0);

    signal done: std_logic;

    constant TEST_XMSS: test_case_xmss_t := (
        pub_seed => x"747da1dcd0be23030ad7d72d1e10881e330495a0ad0a2932844bacf00ea112a9",
        leaf_index => std_logic_vector(to_unsigned(1, TREE_HEIGHT)),
        message_digest => x"36a5a51fd6003380865edf2f7a7a3277bdf4479ff102102fec782a14c335a88b",
        secret_seed => x"7781de0544c42dca964108451a40804f7939401122173c83425787d4facb49bb", -- sk_seed
        -- secret_seed => x"9e0d9ed377cd16584e886cf4efedf276c0b77e0aeefecf6e4e80e7b82deb702f", -- sk_prf
        signature => (
            x"6c5df01dceaa4db8fbbe2c8a3b5e08c55dce12b3dec86642f89bc77a98039442",
            x"847d467a31ea0df4c9e22bff5d3e24b65fc11f9382212368e5e44a558dc8ac82",
            x"c732e848da0b1f3139e3e5517f922fc4929bf88a5511ff3f12a9d0a7bdb3232f",
            x"5de5814683320b2c625dd6d91916c8ef7a117896f27260e81059584fe6908bb1",
            x"0bd6ca1026e2c4fe0483f92730cb666166c471a028e8f1dedefafa2cde47d8a9",
            x"dcbfe0e6400adb0bfb1f34671259c82d9e9f2b94a10606539b6042a3506cd968",
            x"7aace058e4f9093e93bae37a8de330915886ef7d8d0152295a87c33a3cdf977d",
            x"c70531d6c6fbc5db23e426b60b8676c59791a4fbaa1a5451991c42ad41c06d69",
            x"2b9c73f605156a428597db939af951f4175479758bba641af574fc89d3b71e9b",
            x"e5e8443733a47f248b5bdadb27ce1119aaf475e165bdba9ad2b8890d9d4bf194",
            x"e2b6eba1ba0d052f91154ae74aa8b68d98e198b6bba6b6da8cd46e3b2b3476b1",
            x"08f69062d26ab452fb32a7864a37b9462c73572f948f89f6933a2328a63afe77",
            x"5c6901a050a10425ebde033c5a1d0839c47f8d073e601927cef59b96f86c21f4",
            x"ac765a1530a01df3fbb3eb6a515b3b1943ccb5f2affad365d984de1d1bb251df",
            x"b8e0d774c507475fd035fdd4091e927dcd5ec03204055789d01de8df6103108f",
            x"53e169ef59008aa60a1fbd684bae6dfce214ba7b6b4d36969ae336f682aaddef",
            x"1c9c4c87eb1d3104263bc55a64448ea7dd5d67e10368754e15679de04f1a1460",
            x"ef4c8d9f3ce8eaa76041546d19c52bf8871e51dbf498afff2c7cfb9d808679a2",
            x"fe21552c7f39018e028ca29b1eddb6727cbc8987dfa4b9e53990ea8fbb6c039e",
            x"9ec3381ddb341b6de4de61036317793508fa31fda626953fd7dd79fdc5e8d5a2",
            x"21fe71e374f52b384fe3e038bfa69fa92995b98048593b9d89fc9c143c4e5cb7",
            x"65d3e88f0c2a3186cb1ca88041f6b760fdd33246be207f76cb52ff85fca15311",
            x"4d1afa0714221c067074d54ac82df31cb7d674a18bcec68a16e83052e42e3912",
            x"74707c6da87b0afa85a53d01d6b441ebf21367a2c9eee063d1f67f4ca6f64e3b",
            x"5d70f9248ac34d0b65a7b2f5882633f0ef8042ef95f6399fcc0c7104a6938649",
            x"6c43c322b9e78d405af5c36a19e2d3c527620212b78932678456d10b29b61f28",
            x"52d014d433b9c7180b874ffdcd1820e4286cfbb530c82ebaa321a880d1a935a4",
            x"62dc86b494ef3d8058ac2f6bc2dc257132e42bf87c67ab6adc3c65533a8a15fc",
            x"8652fa6e316e78804ad261cf353a0da6f317b5eeb31b8a467c910dcfe4854da1",
            x"2c8dce3f337cbf29fe0b0fafc8b64c1b9e5e890af7adbc2201689bea6acc54c0",
            x"2d2ddcfac355e8407f752f8388e42be1976b6ddb7dc6f6e1d369d35d81a3c2dd",
            x"e89cb5733cace720df5c9afe26237041e1b266fc5264ed6abe1a120d98f33655",
            x"0c529432c489eaad91473ed9e7a0de4926f359393069341987500b1823db9260",
            x"150d38f254cd9e80b5bda3ddda14ce1eea8795d8eb42e8ffb66db02ba0cfa9a7",
            x"32a7a878a45518acb840c8eb11f0e7a024bced4f49445830f4cf57bbc4f57553",
            x"4189ea81a5c7cbb70acc1c26864ffa6ecb6479e9019cd33ece9461eeb5fa3322",
            x"c39c26a0d170ead26fa876b9be88f407bbf15bac0897995ca913837ca0920c24",
            x"5caf76e86e9d9f71222be20e69616981210e63a22c52f07e046580f129288791",
            x"8aa3b347c66e43542eca9275e91ab81c1ccecaa7e0884cfcbaddb1c4858c5e0d",
            x"1c52d1cdcfc5f7b2f1314de93f71aa936bc3c38a07344712a12f7b5fb58c8d29",
            x"3e28b3cdb819be5679bb1fb2b3f802999f0e6c7857c87a064384cfb4ef135a34",
            x"9bcfab80514e0f669e5f6e097b6a02b12b950b9a193fcf55bf817dc686ae30ed",
            x"ed3cc7faf4bfe6c7913847616e4b4118dd846c2671060f0ce569d515ade72df0",
            x"a069179c88e23c92d83e7a27cc5071f39257a2f2ee95a3c8fde5b9a102b3bdf0",
            x"86c334b0c8801c86d24acd58ca832a14659cea16d6a57ff2d6d9a14da42445e8",
            x"06a40e3e4530e27091c7957fc591420b79886fd4279de4c1c3d15b133e6c950c",
            x"0c53cfe7a387db1cf4228cbbf96a81194e60d4fd51f405a40484564eb6b66742",
            x"2fa620e0e7b3485150cf5f074d214a54a3f6a3b08afc16efb52c3b281ddf6583",
            x"a5b9db35b52d21133264edba54a818801ac00394cb6ebf1bc79f4c14d25cabe8",
            x"84dbacc5cc30e76deff4579133400aff30bf3d9a512d9297d64ec96dd638e120",
            x"6954a07bddc42d12b51947b66862c8ebf38f39c80dd2924444fa570eff8bb8c6",
            x"e34bfeab0e2d23ea32c1f5da57ee6905d7dd6c65f8602763fa82f20b7b495469",
            x"f679305f753624bc6d31258196ab2ffbb409857455514506de26d7342fb392ac",
            x"24e64fb5a811aef07b334a61ece888bea07164a35146df48a7212515ceb01a65",
            x"fe4b5c2eb0c92dba9444140c8a52900b16a09b4890097156c0f51d4bf469915e",
            x"befd8c04b07167509cc33de0fa7a3e0408f4d7792da8a8b3003568c477cbade2",
            x"8805e3d483f821c64c4077946d65eb1f0c863f449dbf4c5a0b2ae0fd5407d5e9",
            x"c5712fa33a00a5359b8cd1e99ecf08f7ca86bbb6ad61a70766f4a03f3f5b157c",
            x"f5557e4bd11cf2dbe2452de81978b6c404cf706dcaaf053a5ccb7b235b3383de",
            x"8907eda7ee100dcbb1ae7a6a48030f636c8db6b2e6481ccde769fc62da592cd8",
            x"91ee1943b6730d8a5113377f40b9a38273bb2a07f80c851d3346f59e2d485045",
            x"304dec6faa3a40645d97b6352349b02ff8637390a4e8a57fd03f2dde8c16b1fe",
            x"a5266d0b76f7fb7b2c8bc18a9da5879ce6d9e2c179a7acb042ca2410242a58ea",
            x"846c7a961b89c4454cadb4212ea721fcdec7f0c225785773beaa2cea123f455b",
            x"454075aeff6aac16f1e416ed765d9ef1203f94dd71d14e806a56a340e2df94a2",
            x"d395d30bb7cc0931377c43fdfd38a307bb42f90d7c9bc0f76d8528b4eb8ee48a",
            x"9f0bff080915786796dd83ed336193b0397943c74e283527d72d428b79b501be"
        ),
        leaf_value => x"0f3d2ac235ec1fdc50c018f3003a3b20d8eebe646ef30d0cf28b7a9fa0ab94f3"
    );

    constant TEST_LMS: test_case_lms_t := (
        I => x"215f83b7ccb9acbcd08db97b0d04dc2b",
        q => std_logic_vector(to_unsigned(4, TREE_HEIGHT)),
        message_digest => x"2ab2665c8ce066e72717fdecab2c95476687bb353bc5f8b47615f36075e106e3",
        seed => x"a1c4696e2608035a886100d05cd99945eb3370731884a8235e2fb3d4d71f2547",
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
        leaf_value => x"10343254c0f9cc00203393051f96d863957f80f26e5d73ad44e41b70f3c9e170"
    );

begin
    uut: entity work.wots_shared
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
        scheme_select => uut_scheme_select,

        mode => uut_mode,
        leaf_index => uut_leaf_index,
        message_digest => uut_message_digest,
        pub_seed => uut_pub_seed,
        hash_select => uut_hash_select,
        seed => uut_seed,

        done => uut_done,
        leaf => uut_leaf,

        th_enable => th_enable,
        th_left => th_left,
        th_right => th_right,
        th_pub_seed => th_pub_seed,
        th_addr_type => th_addr_type,
        th_addr_ltree => th_addr_ltree,
        th_addr_height => th_addr_height,
        th_addr_index => th_addr_index,

        th_output => th_output,
        th_done => th_done,

        h_enable => uut_h_enable,
        h_id => uut_h_id,
        h_block => uut_h_block,
        h_len => uut_h_len,
        h_input => uut_h_input,

        h_done => h_done,
        h_done_id => h_done_id,
        h_done_block => h_done_block,
        h_next => h_next,
        h_next_id => h_next_id,
        h_next_block => h_next_block,
        h_output => h_output,
        h_busy => h_busy,
        h_idle => h_idle,

        b_a_we => b_a_we,
        b_a_address => b_a_address,
        b_a_input => b_a_input,
        b_a_output => b_a_output,
        b_b_we => b_b_we,
        b_b_address => b_b_address,
        b_b_input => b_b_input,
        b_b_output => b_b_output,

        b_io_we => b_io_we,
        b_io_address => b_io_address,
        b_io_input => b_io_input,
        b_io_output => b_io_output
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

    thash: if TARGET /= LMS generate
        thash: entity work.thash
        generic map(
            N           => N,
            TREE_HEIGHT => TREE_HEIGHT,
            CORES       => work.params.HASH_CORES,

            HASH_BUS_ID_WIDTH  => HASH_BUS_ID_WIDTH,
            HASH_BUS_LEN_WIDTH => HASH_BUS_LEN_WIDTH,
            HASH_BUS_CTR_WIDTH => HASH_BUS_CTR_WIDTH
        )
        port map(
            clk => clk,
            reset => reset,

            enable => th_enable,

            pub_seed => th_pub_seed,
            addr_type => th_addr_type,
            addr_ltree => th_addr_ltree,
            addr_height => th_addr_height,
            addr_index => th_addr_index,
            left => th_left,
            right => th_right,

            done => th_done,
            output => th_output,

            h_enable => thash_h_enable,
            h_id => thash_h_id,
            h_block => thash_h_block,
            h_len => thash_h_len,
            h_input => thash_h_input,

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
    end generate;

    io_bram: entity work.blk_mem_gen_0
    port map(
        clka => clk,
        ena => '1',
        wea(0) => b_io_we,
        addra => b_io_address,
        dina => b_io_input,
        douta => b_io_output,
        clkb => '1',
        enb => '1',
        web(0) => '0',
        addrb => b_check_addr,
        dinb => (others => '-'),
        doutb => b_check_output
    );

    block_ram: entity work.blk_mem_gen_0
    port map(
        clka => clk,
        ena => '1',
        wea(0) => b_a_we,
        addra => b_a_address,
        dina => b_a_input,
        douta => b_a_output,
        clkb => clk,
        enb => '1',
        web(0) => b_b_we,
        addrb => b_b_address,
        dinb => b_b_input,
        doutb => b_b_output
    );

    -- assign hash input depending on hash_select
    h_enable <= uut_h_enable when uut_hash_select = '0' else thash_h_enable;
    h_input <= uut_h_input when uut_hash_select = '0' else thash_h_input;
    h_len <= uut_h_len when uut_hash_select = '0' else thash_h_len;
    h_id <= uut_h_id when uut_hash_select = '0' else thash_h_id;
    h_block <= uut_h_block when uut_hash_select = '0' else thash_h_block;

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
        b_check_addr <= (others => '-');

        wait for t + t / 2;

        reset <= '0';

        if TARGET /= LMS then
            uut_scheme_select <= '0';
            uut_pub_seed <= TEST_XMSS.pub_seed;
            uut_leaf_index <= TEST_XMSS.leaf_index;
            uut_message_digest <= TEST_XMSS.message_digest;
            uut_seed <= TEST_XMSS.secret_seed;
            uut_mode <= "00";
            uut_enable <= '1';
            wait for t;
            uut_enable <= '0';

            wait until uut_done = '1';
            assert uut_leaf = TEST_XMSS.leaf_value report "Invalid XMSS leaf value generated" severity error;

            wait for t;

            uut_mode <= "01";
            uut_enable <= '1';
            wait for t;
            uut_enable <= '0';
            wait until uut_done = '1';

            wait for t;

            -- check io bram
            for i in 0 to WOTS_LEN - 1 loop
                b_check_addr <= std_logic_vector(to_unsigned(BRAM_IO_WOTS_SIG_ADDR + i, BRAM_ADDR_WIDTH));
                wait for t;
                assert b_check_output = TEST_XMSS.signature(i) report "Invalid WOTS+ signature at position " & integer'image(i) severity error;
            end loop;
            b_check_addr <= (others => '-');

            uut_mode <= "10";
            uut_enable <= '1';
            wait for t;
            uut_enable <= '0';

            wait until uut_done = '1';
            assert uut_leaf = TEST_XMSS.leaf_value report "Invalid XMSS leaf value generated from signature" severity error;
            wait for t;

        end if;

        if TARGET /= XMSS then
            uut_scheme_select <= '1';
            uut_pub_seed(255 downto 128) <= (others => '-');
            uut_pub_seed(127 downto 0) <= TEST_LMS.I;
            uut_leaf_index <= TEST_LMS.q;
            uut_message_digest <= TEST_LMS.message_digest;
            uut_seed <= TEST_LMS.seed;
            uut_mode <= "00";
            uut_enable <= '1';
            wait for t;
            uut_enable <= '0';

            wait until uut_done = '1';
            assert uut_leaf = TEST_LMS.leaf_value report "Invalid LMS leaf value generated" severity error;

            wait for t;

            uut_mode <= "01";
            uut_enable <= '1';
            wait for t;
            uut_enable <= '0';
            wait until uut_done = '1';

            wait for t;

            -- check io bram
            for i in 0 to WOTS_LEN - 1 loop
                b_check_addr <= std_logic_vector(to_unsigned(BRAM_IO_WOTS_SIG_ADDR + i, BRAM_ADDR_WIDTH));
                wait for t;
                assert b_check_output = TEST_LMS.signature(i) report "Invalid LMOTS signature at position " & integer'image(i) severity error;
            end loop;

            uut_mode <= "10";
            uut_enable <= '1';
            wait for t;
            uut_enable <= '0';
            wait until uut_done = '1';
            assert uut_leaf = TEST_LMS.leaf_value report "Invalid LMS leaf value generated from signature" severity error;
            wait for t;
        end if;

        done <= '1';
        wait;
    end process;

end architecture;
