START_TEST(test_bip32_hycon_hdnode)
{
	HDNode node;

	uint8_t seed[66];
	mnemonic_to_seed("ring crime symptom enough erupt lady behave ramp apart settle citizen junk", "", seed, 0);
    hdnode_from_seed(seed, 64, SECP256K1_NAME, &node);

    ck_assert_mem_eq(seed,  fromhex("f377694f59ca0f152a8623bb218cf30b8512c068fc73cf10263e3f62881726d0356979d3d1751b80596203b5f3f2c5fe002fb2321dcec8b0d4b043de791cca07"), 64);
	ck_assert_mem_eq(node.chain_code,  fromhex("4777e377abba7e7e1f3376a148f878122dd48df77d2a8ec520e78d87dfcd489a"), 32);
	ck_assert_mem_eq(node.private_key, fromhex("b0131e72be2d6935cc46992ae30fe9d5ec859df20e2985a3d77e94a0ebb39ab3"), 32);
    hdnode_fill_public_key(&node);
    ck_assert_mem_eq(node.public_key, fromhex("03c041b71ba82a539d2462464abf7bcf9dffb5950a27f7bcb71850fc8a69a418b1"), 33);

    hdnode_private_ckd_prime(&node, 44);
    hdnode_private_ckd_prime(&node, 1397);
    hdnode_private_ckd_prime(&node, 0);
    hdnode_private_ckd(&node, 0);
    hdnode_private_ckd(&node, 0);
    hdnode_fill_public_key(&node);
    ck_assert_mem_eq(node.private_key, fromhex("f35776c86f811d9ab1c66cadc0f503f519bf21898e589c2f26d646e472bfacb2"), 32);
    ck_assert_mem_eq(node.public_key, fromhex("02c4199d83e47650b854e027188eade5378d19c94c13b226f43310fb144bc224af"), 33);

    size_t hash_length = 32;
    uint8_t output[hash_length];
    blake2b(node.public_key, 33, output, hash_length);
    ck_assert_mem_eq(output, fromhex("dafec57d0062e2317f6d0f294366e2a531a891233fd59cfa5f062a0f1018af6a"), hash_length);

    size_t address_array_length = 20;
    uint8_t address_array[address_array_length];
    size_t start_index = hash_length - address_array_length;
    for(size_t i=start_index; i<hash_length; ++i) {
        address_array[i - start_index] = output[i];
    }
    ck_assert_mem_eq(address_array, fromhex("4366e2a531a891233fd59cfa5f062a0f1018af6a"), address_array_length);

    size_t address_length = 28;
    char address[address_length];
    memset(address, 0, address_length);
    b58enc(address, &address_length, address_array, address_array_length);
    ck_assert_str_eq(address, "wTsQGpbicAZsXcmSHN8XmcNR9wX");

    
    uint8_t hash[hash_length];
    blake2b(address_array, address_array_length, hash, hash_length);
    ck_assert_mem_eq(hash, fromhex("0454038bfa9d19b1649b3978334a325d6feddcc345f4523fd8712182295278a9"), hash_length);

    size_t checksum_all_length = 44;
    char checksum_all[checksum_all_length];
    memset(checksum_all, 0, checksum_all_length);
    b58enc(checksum_all, &checksum_all_length, hash, hash_length);
    ck_assert_str_eq(checksum_all, "Htw7r9y6XHp26UbBx19Dn1hMF6V7niXHjR5vUNZdwvG");

    size_t checksum_length = 4;
    char checksum[checksum_length+1];
    memset(checksum, 0, checksum_length+1);
    memcpy(checksum, checksum_all, checksum_length);
    ck_assert_str_eq(checksum, "Htw7");

    size_t address_str_length = 33;
    char address_str[address_str_length];
    memset(address_str, 0, address_str_length);
    address_str[0] = 'H';
    memcpy(address_str + 1, address, address_length-1);
    memcpy(address_str + address_length, checksum, checksum_length);
    ck_assert_str_eq(address_str, "HwTsQGpbicAZsXcmSHN8XmcNR9wXHtw7");
}
END_TEST

START_TEST(test_hycon_sign)
{
    size_t address_array_length = 20;

    uint8_t from_address_array[address_array_length];
    memset(from_address_array, 0, address_array_length);
    b58tobin(from_address_array, &address_array_length, "wTsQGpbicAZsXcmSHN8XmcNR9wX");
    ck_assert_mem_eq(from_address_array, fromhex("4366e2a531a891233fd59cfa5f062a0f1018af6a"), address_array_length);
    ProtobufCBinaryData from_address;
    from_address.len = address_array_length;
    from_address.data = from_address_array;


    uint8_t to_address_array[address_array_length];
    memset(to_address_array, 0, address_array_length);
    b58tobin(to_address_array, &address_array_length, "3GKJpnAXne7iGBLjmHQLFQxpJU8A");
    ck_assert_mem_eq(to_address_array, fromhex("a28306b5066c6f94d903bc2aae4f7b025ca19823"), address_array_length);
    ProtobufCBinaryData to_address;
    to_address.len = address_array_length;
    to_address.data = to_address_array;

    HyconTx tx = HYCON_TX__INIT;
    tx.to =  to_address;
    tx.from = from_address;
    tx.nonce = 7;
    tx.amount = 100000000;
    tx.fee = 1;
    
    uint8_t* protoTx;
    size_t protoTx_length = hycon_tx__get_packed_size(&tx);
    protoTx = malloc(protoTx_length);
    hycon_tx__pack(&tx, protoTx); 
    ck_assert_mem_eq(protoTx, fromhex("0a144366e2a531a891233fd59cfa5f062a0f1018af6a1214a28306b5066c6f94d903bc2aae4f7b025ca198231880c2d72f20012807"), protoTx_length); 

    size_t hash_length = 32;
    uint8_t txhash[hash_length];
    memset(txhash, 0, hash_length);
    blake2b(protoTx, protoTx_length, txhash, hash_length);
    ck_assert_mem_eq(txhash, fromhex("e8526cbec2aef3534d113ef40d699e77ff927375cd50d6825b586f3c302ceb26"), hash_length);
	
    free(protoTx);

    const uint8_t* iv = fromhex("5c0ee0632b58cc92a443bdbc35caf28e");
    
    size_t iv_length = 16;
    uint8_t iv_char[iv_length];
    memset(iv_char, 0, iv_length);
    memcpy(iv_char, iv, iv_length);
    ck_assert_mem_eq(iv_char, fromhex("5c0ee0632b58cc92a443bdbc35caf28e"), iv_length);

    const uint8_t* data = fromhex("e1002da7462641e041c1d7cb4e870263a1391b9923f82014cddcc6ae83b195fc2deedce795dc0704dde2b1b27a8a8a7aa00e9daffaf8888b2cb12988ba1a530832cb63ca92a804c42222b5eff4e8bf2d");
    size_t data_length = 80;
    uint8_t data_char[data_length];
    memset(data_char, 0, data_length);
    memcpy(data_char, data, data_length);

    uint8_t password_hash[hash_length];
    memset(password_hash, 0, hash_length);
    blake2b(fromhex(""), 0, password_hash, hash_length);

    ck_assert_mem_eq(iv_char, fromhex("5c0ee0632b58cc92a443bdbc35caf28e"), iv_length);
    ck_assert_mem_eq(data_char, fromhex("e1002da7462641e041c1d7cb4e870263a1391b9923f82014cddcc6ae83b195fc2deedce795dc0704dde2b1b27a8a8a7aa00e9daffaf8888b2cb12988ba1a530832cb63ca92a804c42222b5eff4e8bf2d"), data_length);
    ck_assert_mem_eq(password_hash, fromhex("0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"), hash_length);

    AES_KEY aes_key;
    AES_set_decrypt_key(password_hash, 256, &aes_key);
    size_t decrypt_result_length = 65;
    unsigned char decrypt_result[decrypt_result_length];
    size_t private_key_char_length = 65;
    char private_key_char[private_key_char_length];
    memset(decrypt_result, 0, decrypt_result_length);
    memset(private_key_char, 0, private_key_char_length);

    AES_cbc_encrypt(data_char, decrypt_result, data_length, &aes_key, iv_char, AES_DECRYPT);
    decrypt_result[64] = 0;
    sprintf(private_key_char, "%s", decrypt_result);


    ck_assert_str_eq(private_key_char, "f35776c86f811d9ab1c66cadc0f503f519bf21898e589c2f26d646e472bfacb2");

    size_t private_key_length = 32;
    unsigned char private_key[private_key_length];
    memset(private_key, 0, private_key_length);
    memcpy(private_key, fromhex(private_key_char), private_key_length);

    ck_assert_mem_eq(private_key, fromhex("f35776c86f811d9ab1c66cadc0f503f519bf21898e589c2f26d646e472bfacb2"), private_key_length);

    size_t signature_length = 64;
    uint8_t signature[signature_length];
    memset(signature, 0, signature_length);
    
    uint8_t recovery;

    const ecdsa_curve *curve = &secp256k1;
    ecdsa_sign_digest(curve, private_key, txhash, signature, &recovery, NULL);
    ck_assert_mem_eq(signature, fromhex("f0d8d437b9b0c6175fbaee606c7abcdd2e91233a2e4c2ea8e1d42f96a7be1dba68dfa4d05e506825816e0cd5648139afe9b81b5cc43b840d31a3110f6940e8e1"), signature_length);
    ck_assert_int_eq(recovery, 0);
}
END_TEST

START_TEST(test_bip32_hycon_address_checksum)
{
    size_t address_arr_len = 20;
    size_t checksum_len = 4;
    char checksum[checksum_len+1];
    hycon_address_checksum(fromhex("4366e2a531a891233fd59cfa5f062a0f1018af6a"), address_arr_len, checksum, checksum_len);

    ck_assert_str_eq(checksum, "Htw7");
}
END_TEST

START_TEST(test_bip32_hycon_normal_address)
{
    HDNode node;

    size_t seed_len = 64;
    uint8_t seed[seed_len + 2];
    mnemonic_to_seed("way prefer push tooth bench hover orchard brother crumble nothing wink retire", "", seed, 0);
    if(hdnode_from_seed_hycon(seed, seed_len, &node) == 0) 
    {
        ck_assert_str_eq("test_bip32_hycon_normal_address", "hdnode_from_seed_hycon");
    }

    size_t address_char_len = 33;
    char address_char[address_char_len];
    if(hdnode_get_hycon_address(&node, address_char, address_char_len) == 0)
    {
        ck_assert_str_eq("test_bip32_hycon_normal_address", "hdnode_get_hycon_address");
    }

    ck_assert_str_eq(address_char, "Hfq92VRKN4gRsc3pze7JMsWPB2EzADeG");
}
END_TEST

START_TEST(test_bip32_hycon_bip39_address)
{
    HDNode node;

    size_t seed_len = 64;
    uint8_t seed[seed_len + 2];
    mnemonic_to_seed("way prefer push tooth bench hover orchard brother crumble nothing wink retire", "TREZOR", seed, 0);
    hdnode_from_seed_hycon(seed, seed_len, &node);

    size_t address_char_len = 33;
    char address_char[address_char_len];
    if(hdnode_get_hycon_address(&node, address_char, address_char_len) == 0) 
    {
        ck_assert_str_eq("test_bip32_hycon_bip39_address", "hdnode_get_hycon_address");
    }

    ck_assert_str_eq(address_char, "H3fFn71jR6G33sAVMASDtLFhrq38h8FQ1");
}
END_TEST

START_TEST(test_hycon_address_to_address_arr) 
{
    size_t address_arr_len = 20;
    uint8_t address_arr[address_arr_len];
    hycon_address_to_address_arr("HwTsQGpbicAZsXcmSHN8XmcNR9wXHtw7", address_arr, address_arr_len);
    ck_assert_mem_eq(address_arr, fromhex("4366e2a531a891233fd59cfa5f062a0f1018af6a"), address_arr_len);
}
END_TEST

START_TEST(test_hycon_sign_tx)
{
    HDNode node;

    size_t seed_len = 64;
    uint8_t seed[seed_len + 2];
    mnemonic_to_seed("ring crime symptom enough erupt lady behave ramp apart settle citizen junk", "", seed, 0);
    if(hdnode_from_seed_hycon(seed, seed_len, &node) == 0)
    {
        ck_assert_str_eq("test_hycon_sign_tx", "hdnode_from_seed_hycon");
    }

    size_t hash_len = 32;
    uint8_t txhash[hash_len];
    if(hdnode_hycon_encode_tx("HwTsQGpbicAZsXcmSHN8XmcNR9wXHtw7", "H3GKJpnAXne7iGBLjmHQLFQxpJU8A4wJo", 7, 100000000, 1, txhash, hash_len) == 0) 
    {
        ck_assert_str_eq("test_hycon_sign_tx", "hdnode_hycon_encode_tx");
    }

    ck_assert_mem_eq(txhash, fromhex("e8526cbec2aef3534d113ef40d699e77ff927375cd50d6825b586f3c302ceb26"), hash_len);

    size_t signature_len = 64;
    uint8_t signature[signature_len];
    
    uint8_t recovery = 1;
    if(hdnode_hycon_sign_tx(&node, txhash, signature, &recovery) == 0)
    {
        ck_assert_str_eq("test_hycon_sign_tx", "hdnode_hycon_sign_tx");
    }

    ck_assert_mem_eq(signature, fromhex("f0d8d437b9b0c6175fbaee606c7abcdd2e91233a2e4c2ea8e1d42f96a7be1dba68dfa4d05e506825816e0cd5648139afe9b81b5cc43b840d31a3110f6940e8e1"), signature_len);
    ck_assert_int_eq(recovery, 0);
}
END_TEST

START_TEST(test_hycon_sign_tx_with_bip39)
{
    HDNode node;

    size_t seed_len = 64;
    uint8_t seed[seed_len + 2];
    mnemonic_to_seed("ring crime symptom enough erupt lady behave ramp apart settle citizen junk", "TREZOR", seed, 0);
    hdnode_from_seed_hycon(seed, seed_len, &node);

    size_t hash_len = 32;
    uint8_t txhash[hash_len];
    if(hdnode_hycon_encode_tx("H2ijdMAHgqZfFdSkGrLv4eihVgRZcHfSA", "H3GKJpnAXne7iGBLjmHQLFQxpJU8A4wJo", 1, 99999997, 2, txhash, hash_len) == 0)
    {
        ck_assert_str_eq("test_hycon_sign_tx_with_bip39", "hdnode_hycon_encode_tx");
    }

    ck_assert_mem_eq(txhash, fromhex("daffcee3c9287c87e2552ca7b7e34565744417ab44b1227e78caaa97d501479d"), hash_len);

    size_t signature_len = 64;
    uint8_t signature[signature_len];
    
    uint8_t recovery = 1;
    if(hdnode_hycon_sign_tx(&node, txhash, signature, &recovery) == 0)
    {
        ck_assert_str_eq("test_hycon_sign_tx_with_bip39", "hdnode_hycon_sign_tx");
    }

    ck_assert_mem_eq(signature, fromhex("2b8ec67834136270b183ec59232a014e600d8429a2c59cb707beec01b8dc01c9606aeb8fc0c61a414b298095e0c2f96487234f8c356ed071493b9328395c2953"), signature_len);
    ck_assert_int_eq(recovery, 0);
}
END_TEST

START_TEST(test_hycon_decrypt_private_key) 
{
    const uint8_t* iv = fromhex("5c0ee0632b58cc92a443bdbc35caf28e");
    
    size_t iv_length = 16;
    uint8_t iv_char[iv_length];
    memset(iv_char, 0, iv_length);
    memcpy(iv_char, iv, iv_length);
    ck_assert_mem_eq(iv_char, fromhex("5c0ee0632b58cc92a443bdbc35caf28e"), iv_length);

    const uint8_t* data = fromhex("e1002da7462641e041c1d7cb4e870263a1391b9923f82014cddcc6ae83b195fc2deedce795dc0704dde2b1b27a8a8a7aa00e9daffaf8888b2cb12988ba1a530832cb63ca92a804c42222b5eff4e8bf2d");
    size_t data_len = 80;
    uint8_t data_char[data_len];
    memset(data_char, 0, data_len);
    memcpy(data_char, data, data_len);

    size_t hash_len = 32;
    uint8_t password_hash[hash_len];
    hdnode_hycon_hash_password("", password_hash);

    uint8_t private_key[hash_len];

    if(hdnode_hycon_decrypt(iv_char, data_char, data_len, password_hash, private_key) == 0)
    {
        ck_assert_str_eq("test_hycon_decrypt_private_key", "hdnode_hycon_decrypt");
    }

    ck_assert_mem_eq(private_key, fromhex("f35776c86f811d9ab1c66cadc0f503f519bf21898e589c2f26d646e472bfacb2"), hash_len);
}
END_TEST

START_TEST(test_hycon_decrypt_private_key_with_password) 
{
    const uint8_t* iv = fromhex("4cd2042593ea106795d95307fd2716fd");
    
    size_t iv_length = 16;
    uint8_t iv_char[iv_length];
    memset(iv_char, 0, iv_length);
    memcpy(iv_char, iv, iv_length);
    ck_assert_mem_eq(iv_char, fromhex("4cd2042593ea106795d95307fd2716fd"), iv_length);

    const uint8_t* data = fromhex("f56a9f2397c19492e9e225768041e8ba30ea139a154cbd5b0a37da2d9f364f3e6930449593c0839316fda48dd3630c85cc208442f5cf233e48a5778467ee19b083ac378735c6283c6fb32714a8155c1d");
    size_t data_len = 80;
    uint8_t data_char[data_len];
    memset(data_char, 0, data_len);
    memcpy(data_char, data, data_len);

    size_t hash_len = 32;
    uint8_t password_hash[hash_len];
    hdnode_hycon_hash_password("11", password_hash);

    uint8_t private_key[hash_len];

    if(hdnode_hycon_decrypt(iv_char, data_char, data_len, password_hash, private_key) == 0) 
    {
        ck_assert_str_eq("test_hycon_decrypt_private_key_with_password", "hdnode_hycon_decrypt");
    }

    ck_assert_mem_eq(private_key, fromhex("fe5a90b95ae42ef31e3ed674111a880b432a4556aedfe53a5c0109dfe49b3fc7"), hash_len);
}
END_TEST

START_TEST(test_hycon_encrypt_and_decrypt)
{
    HDNode node;

    size_t seed_len = 64;
    uint8_t seed[seed_len + 2];
    mnemonic_to_seed("way prefer push tooth bench hover orchard brother crumble nothing wink retire", "", seed, 0);
    if(hdnode_from_seed_hycon(seed, seed_len, &node) == 0) 
    {
        ck_assert_str_eq("test_hycon_encrypt_and_decrypt", "hdnode_from_seed_hycon");
    }

    size_t hash_len = 32;
    uint8_t password_hash[hash_len];
    memset(password_hash, 0, hash_len);
    hdnode_hycon_hash_password("", password_hash);

    size_t iv_len = 16;
    uint8_t iv[iv_len];

    size_t data_len = 80;
    uint8_t data[data_len];
    if(hdnode_hycon_encrypt(&node, password_hash, iv, iv_len, data, data_len) == 0)
    {
        ck_assert_str_eq("test_hycon_encrypt_and_decrypt", "hdnode_hycon_encrypt");
    }

    uint8_t private_key[hash_len];
    if(hdnode_hycon_decrypt(iv, data, data_len, password_hash, private_key) == 0)
    {
        ck_assert_str_eq("test_hycon_encrypt_and_decrypt", "hdnode_hycon_decrypt");
    }

    ck_assert_mem_eq(private_key, node.private_key, hash_len);
}
END_TEST

START_TEST(test_hycon_encrypt_and_decrypt_with_bip39)
{
    HDNode node;

    size_t seed_len = 64;
    uint8_t seed[seed_len + 2];
    mnemonic_to_seed("way prefer push tooth bench hover orchard brother crumble nothing wink retire", "TREZOR", seed, 0);
    if(hdnode_from_seed_hycon(seed, seed_len, &node) == 0)
    {
        ck_assert_str_eq("test_hycon_encrypt_and_decrypt_with_bip39", "hdnode_from_seed_hycon");
    }

    size_t hash_len = 32;
    uint8_t password_hash[hash_len];
    memset(password_hash, 0, hash_len);
    hdnode_hycon_hash_password("", password_hash);

    size_t iv_len = 16;
    uint8_t iv[iv_len];

    size_t data_len = 80;
    uint8_t data[data_len];
    if(hdnode_hycon_encrypt(&node, password_hash, iv, iv_len, data, data_len) == 0)
    {
        ck_assert_str_eq("test_hycon_encrypt_and_decrypt_with_bip39", "hdnode_hycon_encrypt");
    }

    uint8_t private_key[hash_len];
    if(hdnode_hycon_decrypt(iv, data, data_len, password_hash, private_key) == 0) 
    {
        ck_assert_str_eq("test_hycon_encrypt_and_decrypt_with_bip39", "hdnode_hycon_decrypt");
    }

    ck_assert_mem_eq(private_key, node.private_key, hash_len);
}
END_TEST

START_TEST(test_hycon_encrypt_and_decrypt_with_password)
{
    HDNode node;

    size_t seed_len = 64;
    uint8_t seed[seed_len + 2];
    mnemonic_to_seed("way prefer push tooth bench hover orchard brother crumble nothing wink retire", "TREZOR", seed, 0);
    if(hdnode_from_seed_hycon(seed, seed_len, &node) == 0)
    {
        ck_assert_str_eq("test_hycon_encrypt_and_decrypt_with_password", "hdnode_from_seed_hycon");
    }

    size_t hash_len = 32;
    uint8_t password_hash[hash_len];
    memset(password_hash, 0, hash_len);
    hdnode_hycon_hash_password("11", password_hash);

    size_t iv_len = 16;
    uint8_t iv[iv_len];

    size_t data_len = 80;
    uint8_t data[data_len];
    if(hdnode_hycon_encrypt(&node, password_hash, iv, iv_len, data, data_len) == 0) 
    {
        ck_assert_str_eq("test_hycon_encrypt_and_decrypt_with_password", "hdnode_hycon_encrypt");
    }

    uint8_t private_key[hash_len];
    if(hdnode_hycon_decrypt(iv, data, data_len, password_hash, private_key) == 0)
    {
        ck_assert_str_eq("test_hycon_encrypt_and_decrypt_with_password", "hdnode_hycon_decrypt");
    }

    ck_assert_mem_eq(private_key, node.private_key, hash_len);
}
END_TEST