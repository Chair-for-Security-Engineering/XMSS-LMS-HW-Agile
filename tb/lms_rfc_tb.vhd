library ieee;
use ieee.numeric_std.all;
use ieee.std_logic_1164.all;

use work.lms_types.all;
use work.lms_params.all;
use work.types.all;
use work.module_types.all;
use work.lms_config_types.all;

entity lms_rfc_tb is 
end;

architecture default of lms_rfc_tb is
    constant t : time := 10 ns;

    signal clk, reset : std_logic;
    signal uut_in : lms_bus_input_t;
    signal uut_out : lms_bus_output_t;

    signal bram_in, bram_ctrl_in : dual_port_bram_input_t;
    signal bram_out, bram_ctrl_out : dual_port_bram_output_t;

    signal hash_in : hash_subsystem_input_t;
    signal hash_out : hash_subsystem_output_t;

    signal control_bram, done : std_logic;

    type lms_path_t is array( 0 to TREE_HEIGHT - 1 ) of hash_digest_t;
    type lmots_signature_t is array( 0 to WOTS_LEN - 1 ) of hash_digest_t;

    type test_case_verify_t is record
        I : key_pair_id_t;
        q : unsigned( 31 downto 0 );
        K : hash_digest_t;
        path : lms_path_t;
        C : hash_digest_t;
        signature : lmots_signature_t;
    end record;

    type test_case_sign_t is record
        base : test_case_verify_t;
        seed : hash_digest_t;
    end record;

    -- Test data:
    constant test1 : test_case_verify_t := ( 
        I => x"d2f14ff6346af964569f7d6cb880a1b6", 
        q => x"0000000a", 
        K => x"6c5004917da6eafe4d9ef6c6407b3db0e5485b122d9ebe15cda93cfec582d7ab", 
        path => (
            x"d5c0d1bebb06048ed6fe2ef2c6cef305b3ed633941ebc8b3bec9738754cddd60",
            x"e1920ada52f43d055b5031cee6192520d6a5115514851ce7fd448d4a39fae2ab",
            x"2335b525f484e9b40d6a4a969394843bdcf6d14c48e8015e08ab92662c05c6e9",
            x"f90b65a7a6201689999f32bfd368e5e3ec9cb70ac7b8399003f175c40885081a",
            x"09ab3034911fe125631051df0408b3946b0bde790911e8978ba07dd56c73e7ee"
        ), 
        C => x"0703c491e7558b35011ece3592eaa5da4d918786771233e8353bc4f62323185c", 
        signature => (
            x"95cae05b899e35dffd717054706209988ebfdf6e37960bb5c38d7657e8bffeef",
            x"9bc042da4b4525650485c66d0ce19b317587c6ba4bffcc428e25d08931e72dfb",
            x"6a120c5612344258b85efdb7db1db9e1865a73caf96557eb39ed3e3f426933ac",
            x"9eeddb03a1d2374af7bf77185577456237f9de2d60113c23f846df26fa942008",
            x"a698994c0827d90e86d43e0df7f4bfcdb09b86a373b98288b7094ad81a0185ac",
            x"100e4f2c5fc38c003c1ab6fea479eb2f5ebe48f584d7159b8ada03586e65ad9c",
            x"969f6aecbfe44cf356888a7b15a3ff074f771760b26f9c04884ee1faa329fbf4",
            x"e61af23aee7fa5d4d9a5dfcf43c4c26ce8aea2ce8a2990d7ba7b57108b47dabf",
            x"beadb2b25b3cacc1ac0cef346cbb90fb044beee4fac2603a442bdf7e507243b7",
            x"319c9944b1586e899d431c7f91bcccc8690dbf59b28386b2315f3d36ef2eaa3c",
            x"f30b2b51f48b71b003dfb08249484201043f65f5a3ef6bbd61ddfee81aca9ce6",
            x"0081262a00000480dcbc9a3da6fbef5c1c0a55e48a0e729f9184fcb1407c3152",
            x"9db268f6fe50032a363c9801306837fafabdf957fd97eafc80dbd165e435d0e2",
            x"dfd836a28b354023924b6fb7e48bc0b3ed95eea64c2d402f4d734c8dc26f3ac5",
            x"91825daef01eae3c38e3328d00a77dc657034f287ccb0f0e1c9a7cbdc828f627",
            x"205e4737b84b58376551d44c12c3c215c812a0970789c83de51d6ad787271963",
            x"327f0a5fbb6b5907dec02c9a90934af5a1c63b72c82653605d1dcce51596b3c2",
            x"b45696689f2eb382007497557692caac4d57b5de9f5569bc2ad0137fd47fb47e",
            x"664fcb6db4971f5b3e07aceda9ac130e9f38182de994cff192ec0e82fd6d4cb7",
            x"f3fe00812589b7a7ce515440456433016b84a59bec6619a1c6c0b37dd1450ed4",
            x"f2d8b584410ceda8025f5d2d8dd0d2176fc1cf2cc06fa8c82bed4d944e71339e",
            x"ce780fd025bd41ec34ebff9d4270a3224e019fcb444474d482fd2dbe75efb203",
            x"89cc10cd600abb54c47ede93e08c114edb04117d714dc1d525e11bed8756192f",
            x"929d15462b939ff3f52f2252da2ed64d8fae88818b1efa2c7b08c8794fb1b214",
            x"aa233db3162833141ea4383f1a6f120be1db82ce3630b3429114463157a64e91",
            x"234d475e2f79cbf05e4db6a9407d72c6bff7d1198b5c4d6aad2831db61274993",
            x"715a0182c7dc8089e32c8531deed4f7431c07c02195eba2ef91efb5613c37af7",
            x"ae0c066babc69369700e1dd26eddc0d216c781d56e4ce47e3303fa73007ff7b9",
            x"49ef23be2aa4dbf25206fe45c20dd888395b2526391a724996a44156beac8082",
            x"12858792bf8e74cba49dee5e8812e019da87454bff9e847ed83db07af3137430",
            x"82f880a278f682c2bd0ad6887cb59f652e155987d61bbf6a88d36ee93b6072e6",
            x"656d9ccbaae3d655852e38deb3a2dcf8058dc9fb6f2ab3d3b3539eb77b248a66",
            x"1091d05eb6e2f297774fe6053598457cc61908318de4b826f0fc86d4bb117d33",
            x"e865aa805009cc2918d9c2f840c4da43a703ad9f5b5806163d7161696b5a0adc"
        )
    );
    constant message1 : std_logic_vector( 1295 downto 0 ) := x"54686520706f77657273206e6f742064656c65676174656420746f2074686520556e69746564205374617465732062792074686520436f6e737469747574696f6e2c206e6f722070726f6869626974656420627920697420746f20746865205374617465732c2061726520726573657276656420746f207468652053746174657320726573706563746976656c792c206f7220746f207468652070656f706c652e0a";


    constant test2 : test_case_sign_t := (
        base => (
            I => x"215f83b7ccb9acbcd08db97b0d04dc2b", 
            q => x"00000004", 
            K => x"a1cd035833e0e90059603f26e07ad2aad152338e7a5e5984bcd5f7bb4eba40b7", 
            path => (
                x"4de1f6965bdabc676c5a4dc7c35f97f82cb0e31c68d04f1dad96314ff09e6b3d",
                x"e96aeee300d1f68bf1bca9fc58e4032336cd819aaf578744e50d1357a0e42867",
                x"04d341aa0a337b19fe4bc43c2e79964d4f351089f2e0e41c7c43ae0d49e7f404",
                x"b0f75be80ea3af098c9752420a8ac0ea2bbb1f4eeba05238aef0d8ce63f0c6e5",
                x"e4041d95398a6f7f3e0ee97cc1591849d4ed236338b147abde9f51ef9fd4e1c1"
            ), 
            C => x"0eb1ed54a2460d512388cad533138d240534e97b1e82d33bd927d201dfc24ebb",
            signature => (
                x"11b3649023696f85150b189e50c00e98850ac343a77b3638319c347d7310269d",
                x"3b7714fa406b8c35b021d54d4fdada7b9ce5d4ba5b06719e72aaf58c5aae7aca",
                x"057aa0e2e74e7dcfd17a0823429db62965b7d563c57b4cec942cc865e29c1dad",
                x"83cac8b4d61aacc457f336e6a10b66323f5887bf3523dfcadee158503bfaa89d",
                x"c6bf59daa82afd2b5ebb2a9ca6572a6067cee7c327e9039b3b6ea6a1edc7fdc3",
                x"df927aade10c1c9f2d5ff446450d2a3998d0f9f6202b5e07c3f97d2458c69d3c",
                x"8190643978d7a7f4d64e97e3f1c4a08a7c5bc03fd55682c017e2907eab07e5bb",
                x"2f190143475a6043d5e6d5263471f4eecf6e2575fbc6ff37edfa249d6cda1a09",
                x"f797fd5a3cd53a066700f45863f04b6c8a58cfd341241e002d0d2c0217472bf1",
                x"8b636ae547c1771368d9f317835c9b0ef430b3df4034f6af00d0da44f4af7800",
                x"bc7a5cf8a5abdb12dc718b559b74cab9090e33cc58a955300981c420c4da8ffd",
                x"67df540890a062fe40dba8b2c1c548ced22473219c534911d48ccaabfb71bc71",
                x"862f4a24ebd376d288fd4e6fb06ed8705787c5fedc813cd2697e5b1aac1ced45",
                x"767b14ce88409eaebb601a93559aae893e143d1c395bc326da821d79a9ed41dc",
                x"fbe549147f71c092f4f3ac522b5cc57290706650487bae9bb5671ecc9ccc2ce5",
                x"1ead87ac01985268521222fb9057df7ed41810b5ef0d4f7cc67368c90f573b1a",
                x"c2ce956c365ed38e893ce7b2fae15d3685a3df2fa3d4cc098fa57dd60d2c9754",
                x"a8ade980ad0f93f6787075c3f680a2ba1936a8c61d1af52ab7e21f416be09d2a",
                x"8d64c3d3d8582968c2839902229f85aee297e717c094c8df4a23bb5db658dd37",
                x"7bf0f4ff3ffd8fba5e383a48574802ed545bbe7a6b4753533353d73706067640",
                x"135a7ce517279cd683039747d218647c86e097b0daa2872d54b8f3e508598762",
                x"9547b830d8118161b65079fe7bc59a99e9c3c7380e3e70b7138fe5d9be255150",
                x"2b698d09ae193972f27d40f38dea264a0126e637d74ae4c92a6249fa103436d3",
                x"eb0d4029ac712bfc7a5eacbdd7518d6d4fe903a5ae65527cd65bb0d4e9925ca2",
                x"4fd7214dc617c150544e423f450c99ce51ac8005d33acd74f1bed3b17b7266a4",
                x"a3bb86da7eba80b101e15cb79de9a207852cf91249ef480619ff2af8cabca831",
                x"25d1faa94cbb0a03a906f683b3f47a97c871fd513e510a7a25f283b196075778",
                x"496152a91c2bf9da76ebe089f4654877f2d586ae7149c406e663eadeb2b5c7e8",
                x"2429b9e8cb4834c83464f079995332e4b3c8f5a72bb4b8c6f74b0d45dc6c1f79",
                x"952c0b7420df525e37c15377b5f0984319c3993921e5ccd97e097592064530d3",
                x"3de3afad5733cbe7703c5296263f77342efbf5a04755b0b3c997c4328463e84c",
                x"aa2de3ffdcd297baaaacd7ae646e44b5c0f16044df38fabd296a47b3a838a913",
                x"982fb2e370c078edb042c84db34ce36b46ccb76460a690cc86c302457dd1cde1",
                x"97ec8075e82b393d542075134e2a17ee70a5e187075d03ae3c853cff60729ba4"
            )
        ),
        seed => x"a1c4696e2608035a886100d05cd99945eb3370731884a8235e2fb3d4d71f2547"
    );

    constant message2 : std_logic_vector( 1047 downto 0 ) := x"54686520656e756d65726174696f6e20696e2074686520436f6e737469747574696f6e2c206f66206365727461696e207269676874732c207368616c6c206e6f7420626520636f6e73747275656420746f2064656e79206f7220646973706172616765206f74686572732072657461696e6564206279207468652070656f706c652e0a";

begin
    assert LMOTS_PARAMETER_SET = LMOTS_SHA256_N32_W8 
        report "Wrong LMOTS parameter set." 
        severity error;
    assert LMS_PARAMETER_SET = LMS_SHA256_M32_H5 
        report "Wrong LMS parameter set." 
        severity error;

    uut : entity work.lms_bus
    port map(
        clk => clk,
        reset => reset,

        d => uut_in,
        q => uut_out
    );

    block_ram : entity work.blk_mem_gen_0
    port map(
        clka => clk,
        ena => bram_in.a.enable,
        wea(0) => bram_in.a.write_enable,
        addra => bram_in.a.address,
        dina => bram_in.a.input,
        douta => bram_out.a.output,
        clkb => clk,
        enb => bram_in.b.enable,
        web(0) => bram_in.b.write_enable,
        addrb => bram_in.b.address,
        dinb => bram_in.b.input,
        doutb => bram_out.b.output
    );

    hash_bus : entity work.hash_core_collection
    port map(
        clk => clk,
        reset => reset,

        hash_alg_select => ( others => '0' ),

        d => hash_in,
        q => hash_out
    );

    uut_in.bram <= bram_out;
    uut_in.hash <= hash_out;
    hash_in <= uut_out.hash;
    
    bram_in <= uut_out.bram when control_bram = '0' else bram_ctrl_in;
    bram_ctrl_out <= bram_out;

    bram_ctrl_in.b <= BRAM_INPUT_DONT_CARE;

    clk_gen : process is
    begin
        clk <= '0';
        wait for t / 2;
        clk <= '1';
        wait for t / 2;

        if done = '1' then
            wait;
        end if;
    end process;

    test : process is
        variable padded_message1 : std_logic_vector( message1'length + 256 - (message1'length mod 256) - 1 downto 0 );
        variable padded_message2 : std_logic_vector( message2'length + 256 - (message2'length mod 256) - 1 downto 0 );
    begin
        done <= '0';
        reset <= '1';
        uut_in.enable <= '0';
        control_bram <= '1';
        padded_message1 := ( others => '0' );
        padded_message1( padded_message1'left downto padded_message1'left - message1'left ) := message1;
        padded_message2 := ( others => '0' );
        padded_message2( padded_message2'left downto padded_message2'left - message2'left ) := message2;
        wait for t + t / 2;
        reset <= '0';
        bram_ctrl_in.a.enable <= '1';
        bram_ctrl_in.a.address <= std_logic_vector(to_unsigned( BRAM_LMS_PK, BRAM_ADDR_SIZE ));
        bram_ctrl_in.a.input <= test1.K;
        bram_ctrl_in.a.write_enable <= '1';
        wait for t;
        bram_ctrl_in.a.address <= std_logic_vector(to_unsigned( BRAM_LMS_PK + 1, BRAM_ADDR_SIZE ));
        bram_ctrl_in.a.input <= ( others => '0' );
        bram_ctrl_in.a.input( 16 * 8 - 1 downto 0 ) <= test1.I;
        wait for t;
        bram_ctrl_in.a.address <= std_logic_vector(to_unsigned( BRAM_LMS_SIG, BRAM_ADDR_SIZE ));
        bram_ctrl_in.a.input <= ( others => '0' );
        bram_ctrl_in.a.input( 4 * 8 - 1 downto 0 ) <= std_logic_vector( test1.q );
        wait for t;
        bram_ctrl_in.a.address <= std_logic_vector(to_unsigned( BRAM_LMOTS_C, BRAM_ADDR_SIZE ));
        bram_ctrl_in.a.input <= test1.C;
        wait for t;
        for j in 0 to WOTS_LEN - 1 loop
            bram_ctrl_in.a.input <= test1.signature( j );
            bram_ctrl_in.a.address <= std_logic_vector(to_unsigned( BRAM_LMOTS_SIG + j, BRAM_ADDR_SIZE ));
            wait for t;
        end loop;
        for j in 0 to TREE_HEIGHT - 1 loop
            bram_ctrl_in.a.input <= test1.path( j );
            bram_ctrl_in.a.address <= std_logic_vector(to_unsigned( BRAM_LMS_PATH + j, BRAM_ADDR_SIZE ));
            wait for t;
        end loop;
        bram_ctrl_in.a.enable <= '0';
        bram_ctrl_in.a.write_enable <= '0';

        report "BRAM set up for signature verification test.";

        control_bram <= '0';
        uut_in.mode <= "10";
        uut_in.enable <= '1';
        uut_in.length <= to_unsigned( message1'length, HASH_BUS_LENGTH_BITS );
        uut_in.message_block <= padded_message1( padded_message1'left downto padded_message1'left - 255 );
        wait for t;
        uut_in.enable <= '0';
        for j in 1 to (padded_message1'length / 256) - 1 loop
            wait until uut_out.mnext = '1';
            wait for t;
            uut_in.message_block <= padded_message1( padded_message1'left - j * 256 downto padded_message1'left - 255 - 256 * j );
        end loop;

        wait until uut_out.done = '1';
        assert uut_out.valid = '1' report "Failed RFC signature verification test." severity error;
        wait for t;
        report "Passed RFC signature verification test.";

        uut_in.enable <= '1';
        uut_in.true_random <= test2.base.I & test2.seed;
        uut_in.mode <= "00";
        wait for t;
        uut_in.enable <= '0';
        wait until uut_out.done = '1';

        report "Created secret key for signature generation.";

        uut_in.mode <= "01";

        for j in 0 to to_integer(test2.base.q) - 1 loop
            wait for t;
            uut_in.enable <= '1';
            uut_in.length <= ( others => '0' );
            uut_in.message_block <= ( others => '0' );
            wait for t;
            uut_in.enable <= '0';
            wait until uut_out.done = '1';
        end loop;

        report "Finished signature loop to reach q.";

        wait for t;
        uut_in.enable <= '1';
        uut_in.true_random <= ( others => '0' );
        uut_in.true_random( 255 downto 0 ) <= test2.base.C;
        uut_in.length <= to_unsigned( message2'length, HASH_BUS_LENGTH_BITS );
        uut_in.message_block <= padded_message2( padded_message2'left downto padded_message2'left - 255 );
        wait for t;
        uut_in.enable <= '0';
        for j in 1 to (padded_message2'length / 256) - 1 loop
            wait until uut_out.mnext = '1';
            wait for t;
            uut_in.message_block <= padded_message2( padded_message2'left - j * 256 downto padded_message2'left - 255 - 256 * j );
        end loop;

        wait until uut_out.done = '1';
        report "Generated RFC signature. Checking BRAM...";
        wait for t;

        control_bram <= '1';
        bram_ctrl_in.a.enable <= '1';

        wait for t;

        bram_ctrl_in.a.address <= std_logic_vector(to_unsigned(BRAM_LMS_PK, BRAM_ADDR_SIZE));
        wait for 3 * t;
        assert bram_ctrl_out.a.output = test2.base.K report "Failed RFC signature test case: Wrong PK" severity error;
        bram_ctrl_in.a.address <= std_logic_vector(to_unsigned(BRAM_LMS_PK + 1, BRAM_ADDR_SIZE));
        wait for 3 * t;
        assert bram_ctrl_out.a.output( 16 * 8 - 1 downto 0 ) = test2.base.I report "Failed RFC signature test case: Wrong I" severity error;
        bram_ctrl_in.a.address <= std_logic_vector(to_unsigned(BRAM_LMS_SIG, BRAM_ADDR_SIZE));
        wait for 3 * t;
        assert bram_ctrl_out.a.output( 4 * 8 - 1 downto 0 ) = std_logic_vector(test2.base.q) report "Failed RFC signature test case: Wrong q" severity error;
        bram_ctrl_in.a.address <= std_logic_vector(to_unsigned(BRAM_LMOTS_C, BRAM_ADDR_SIZE));
        wait for 3 * t;
        assert bram_ctrl_out.a.output = test2.base.C report "Failed RFC signature test case: Wrong C" severity error;

        for j in 0 to WOTS_LEN - 1 loop
            bram_ctrl_in.a.address <= std_logic_vector(to_unsigned(BRAM_LMOTS_SIG + j, BRAM_ADDR_SIZE));
            wait for 3 * t;
            assert bram_ctrl_out.a.output = test2.base.signature( j ) report "Failed RFC signature test case: Wrong signature (" & integer'image( j ) & ")" severity error;
        end loop;

        for j in 0 to TREE_HEIGHT - 1 loop
            bram_ctrl_in.a.address <= std_logic_vector(to_unsigned(BRAM_LMS_PATH + j, BRAM_ADDR_SIZE));
            wait for 3 * t;
            assert bram_ctrl_out.a.output = test2.base.path( j ) report "Failed RFC signature test case: Wrong path (" & integer'image( j ) & ")" severity error;
        end loop;

        report "Passed RFC signature generation test.";
        done <= '1';

        wait;

    end process;
end;
