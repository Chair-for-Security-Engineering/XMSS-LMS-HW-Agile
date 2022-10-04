use work.hss_types.all;

package config is
    -- Options:
    -- LMS
    -- XMSS
    -- MULTI_SINGLE_BRAM
    -- MULTI_DUAL_BRAM
    constant SCHEME: scheme_t := DUAL_SHARED_BRAM;

    constant N: integer := 32;
    constant WOTS_W: integer := 16; -- 2**w for LMS
    constant TREE_HEIGHT: integer := 10;
    
    constant BDS_K: integer := 8;

    constant HASH_CORES: integer := 1;
    constant HASH_CHAINS: integer := 1;
end package;
