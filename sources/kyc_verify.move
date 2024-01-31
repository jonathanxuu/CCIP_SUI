module test_ccip_verify_package::kyc_verify {
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};
    use sui::vec_set::{Self, VecSet};

    use sui::hash;
    use sui::ecdsa_k1;
    use std::vector;
    use sui::bcs;
    use std::string::{Self, String};
    use sui::address;
    use sui::clock::{Self, Clock};
    use sui::ed25519;
    use sui::transfer;

    struct AdminCap has key {
        id: UID
    }

    struct AttesterWhiteList has key {
        id: UID,
        attesterWhiteList: VecSet<vector<u8>>
    }
    
    public fun attester_exist(
        attester_to_query: vector<u8>,
        attesterList: &AttesterWhiteList
    ): bool {
        vec_set::contains(&attesterList.attesterWhiteList, &attester_to_query)
    }

    public fun set_whitelist(
        _: &AdminCap,
        attesterList: vector<u8>,
        ctx: &mut TxContext,
        ){
        let m = vec_set::empty();
        vec_set::insert(&mut m, attesterList);

        transfer::share_object(AttesterWhiteList {
            id: object::new(ctx),
            attesterWhiteList: m
        })
    }

    public fun modify_remove_whitelist(
        _: &AdminCap,
        attesterWhiteList: &mut AttesterWhiteList,
        attesterList: vector<u8>,
        ){
        let m = attesterWhiteList.attesterWhiteList;
        vec_set::remove(&mut m, &attesterList);

        attesterWhiteList.attesterWhiteList = m;
    }

    public fun modify_add_whitelist(
        _: &AdminCap,
        attesterWhiteList: &mut AttesterWhiteList,
        attesterList: vector<u8>,
        ){
        let m = attesterWhiteList.attesterWhiteList;
        vec_set::insert(&mut m, attesterList);
        attesterWhiteList.attesterWhiteList = m;
    }


    public fun verify_KYC(
        value_kyc_status: u256,
        onChainAddr: String,
        // the DID address
        holderAddr: vector<u8>, 
        issuanceDate: vector<u8>, 
        expirationDate: vector<u8>, 
        ctypeHash: vector<u8>,
        signature: vector<u8>,
        timestamp: u64,
        verifierSig: vector<u8>,
        clock: &Clock,
        // attesterList: &AttesterWhiteList,
    ) : u256 {
        // Only the vc is valid, return the digest
        let digest = verify_VC(
            value_kyc_status,
            holderAddr, 
            issuanceDate, 
            expirationDate, 
            ctypeHash,
            signature,
            // attesterList,
            onChainAddr);
        
        let current_time = clock::timestamp_ms(clock);

        // If the vc's is already expired, abort with ErrorCode `42`
        assert!(bytes_to_u64(expirationDate) == 0 || bytes_to_u64(expirationDate) > current_time, 42);

        let verifyResult = verifyCCIPSignature(digest, timestamp, verifierSig, current_time);

        // If the CCIP Signature is not valid, abort with ErrorCode `44`
        assert!(verifyResult, 44);
        value_kyc_status
    }

    public fun verify_VC(
        value_kyc_status: u256,
        // the DID address
        holderAddr: vector<u8>, 
        issuanceDate: vector<u8>, 
        expirationDate: vector<u8>, 
        ctypeHash: vector<u8>,
        signature: vector<u8>,
        // attesterWhiteList: &AttesterWhiteList,
        onChainAddr: String
    ) : vector<u8> {
        let bfcPrefix = b"bfc";
        let roothash = compute_roothash(value_kyc_status, bfcPrefix, onChainAddr);

        //  ===========  OK!! calculate DIGEST =================
        let digest = compute_digest(roothash, holderAddr, issuanceDate, expirationDate, ctypeHash);

        // ========= construct EIP191 sign ===============
        let ethSignedMessage = pad_signed_message(digest);
        let verificationResult = erecover_to_eth_address(signature, ethSignedMessage);

        // If the assertionMethod is not in the attester whitelist, abort with ErrorCode `41`
        // assert!(attester_exist(verificationResult, attesterWhiteList), 41);

        let attester = vector<u8>[0x02, 0x25, 0x2f, 0xeE, 0x64, 0xa4, 0x58, 0x27, 0xE4, 0xC0, 0x9A, 0xe2, 0x31, 0x2F, 0x09, 0xCe, 0x15, 0xB0, 0xCb, 0x89];
        assert!(verificationResult == attester, 41);

       
        digest

    }


    
    // compute roothash for KYC PublicVC
    fun compute_roothash(value_u256: u256, value_vec_1: vector<u8>, onChainAddr: String): vector<u8>{
        let hash_1 = hash::keccak256(&keccak256_u256(value_u256));
        let hash_2 = hash::keccak256(&keccak256_vector(value_vec_1));
        let hash_3 = hash::keccak256(&keccak256_string(onChainAddr));

        let parent_vec = std::vector::empty<u8>(); 
        vector::append(&mut parent_vec, hash_1);
        vector::append(&mut parent_vec, hash_2);
        let parent_hash = hash::keccak256(&parent_vec);

        let root_vec = std::vector::empty<u8>(); 
        vector::append(&mut root_vec, parent_hash);
        vector::append(&mut root_vec, hash_3);
        let roothash = hash::keccak256(&root_vec);
        roothash
    }

    fun verifyCCIPSignature(
        digest: vector<u8>, 
        timestamp: u64, 
        signature: vector<u8>,
        currentTimestamp: u64
    ): bool{
        // assert!(currentTimestamp <= timestamp + 1000 * 60 * 5, 43);
        let networkU8a = b"bfc";
        let timestampU8a = pack_u64(timestamp);
        let concatU8a = std::vector::empty<u8>(); 

        vector::append(&mut concatU8a, digest);
        vector::append(&mut concatU8a, networkU8a);
        vector::append(&mut concatU8a, timestampU8a);

        // The publicKey of the server verifier(ed25519)
        let pk = vector<u8>[229, 137, 106,  40,  35, 226, 160, 123, 180,   6, 181, 162, 128, 245, 199, 181, 69, 233, 141, 192,   6, 116, 218,  58, 173, 181, 151, 183,  12, 196, 135, 7];

        let hashedMessage = std::hash::sha2_256(concatU8a);

        let verify = ed25519::ed25519_verify(&signature, &pk, &hashedMessage);
        verify
    }

    // compute digest for KYC PublicVC
    fun compute_digest(roothash: vector<u8>, holder_addr: vector<u8>, issuanceDate: vector<u8>, expirationDate: vector<u8>, ctypeHash: vector<u8>): vector<u8>{
        let digest_concat = std::vector::empty<u8>(); 
        let did_zk_prefix = b"did:zk:";

        vector::append(&mut digest_concat, roothash);
        vector::append(&mut digest_concat, did_zk_prefix);
        vector::append(&mut digest_concat, holder_addr);
        vector::append(&mut digest_concat, issuanceDate);
        vector::append(&mut digest_concat, expirationDate);
        vector::append(&mut digest_concat, ctypeHash);
        
        let digest = hash::keccak256(&digest_concat);
        digest
    }

    fun pad_signed_message(digest: vector<u8>): vector<u8> {
        let ethSignedMessage = std::vector::empty<u8>(); 
        let prefix = b"\x19Ethereum Signed Message:\n32";
        vector::append(&mut ethSignedMessage, prefix);
        vector::append(&mut ethSignedMessage, digest);
        ethSignedMessage
    }

    fun pack_u64(value_to_pack: u64) : vector<u8> {
        let value_vector = bcs::to_bytes(&value_to_pack);
        std::vector::reverse(&mut value_vector);
        value_vector
    }

    fun pack_u256(value_to_pack: u256) : vector<u8> {
        let value_vector = bcs::to_bytes(&value_to_pack);
        std::vector::reverse(&mut value_vector);
        value_vector
    }

        // Helper -- convert sui addr to hashed result (single hash)
    fun keccak256_address(addr: address): vector<u8> {
        // let addressString = address::to_string(tx_context::sender(ctx));
        let addressString = address::to_string(addr);

        let concat = string::utf8(vector::empty());
        let prefix = string::utf8(b"0x");
        string::append(&mut concat, prefix);
        string::append(&mut concat, addressString);

        let address_u8 = bcs::to_bytes(&concat);
        std::vector::reverse(&mut address_u8);
        std::vector::pop_back(&mut address_u8);
        std::vector::reverse(&mut address_u8);


        let hash = hash::keccak256(&address_u8);

        hash
    }


    fun keccak256_string(addr: String): vector<u8> {
        let address_u8 = bcs::to_bytes(&addr);
        std::vector::reverse(&mut address_u8);
        std::vector::pop_back(&mut address_u8);
        std::vector::reverse(&mut address_u8);
        let hash = hash::keccak256(&address_u8);

        hash
    }

    // Helper -- compute keccak256 for u256
    fun keccak256_u256(value: u256): vector<u8> {
        let pack_status = std::vector::empty<u8>(); 
        std::vector::append(&mut pack_status, pack_u256(value));
        // pack_status
        let hash = hash::keccak256(&pack_status);
        hash
    }

    // Helper -- compute keccak256 for vector & string
    fun keccak256_vector(value: vector<u8>): vector<u8> {
        let pack_status = std::vector::empty<u8>(); 
        std::vector::append(&mut pack_status, value);
        // pack_status
        let hash = hash::keccak256(&pack_status);
        hash
    }

    // Init: Module initializer to be executed when this module is published
    fun init(ctx: &mut TxContext) {
        transfer::transfer(AdminCap {
            id: object::new(ctx)
        }, tx_context::sender(ctx));
        

    }

    // Helper -- Recovers and returns the signing address
    fun erecover_to_eth_address(signature: vector<u8>, raw_msg: vector<u8>) : vector<u8> {
        let v = vector::borrow_mut(&mut signature, 64);
        if (*v == 27) {
            *v = 0;
        } else if (*v == 28) {
            *v = 1;
        } else if (*v > 35) {
            *v = (*v - 1) % 2;
        };

        let pubkey = ecdsa_k1::secp256k1_ecrecover(&signature, &raw_msg, 0);
        let uncompressed = ecdsa_k1::decompress_pubkey(&pubkey);


        // Take the last 64 bytes of the uncompressed pubkey.
        let uncompressed_64 = vector::empty<u8>();
        let i = 1;
        while (i < 65) {
            let value = vector::borrow(&uncompressed, i);
            vector::push_back(&mut uncompressed_64, *value);
            i = i + 1;
        };

        // Take the last 20 bytes of the hash of the 64-bytes uncompressed pubkey.
        let hashed = hash::keccak256(&uncompressed_64);
        let addr = vector::empty<u8>();
        let i = 12;
        while (i < 32) {
            let value = vector::borrow(&hashed, i);
            vector::push_back(&mut addr, *value);
            i = i + 1;
        };

        (addr)
    }

    public fun bytes_to_u64(bytes: vector<u8>): u64 {
        let value = 0u64;
        let i = 0u64;
        // std::vector::reverse(&mut bytes);

        let length = vector::length(&bytes);
        while (i < length) {
            value = value | ((*vector::borrow(&bytes, i) as u64) << ((8 * (length - 1 - i)) as u8));
            i = i + 1;
        };
        return value
    }

    #[test]
    fun test_hash_result() {
        use sui::test_scenario;
        use std::debug;

        // create test addresses representing users
        let admin = @0x8fb8eff69462aad4c20884c2cd4b7df33e6eb7cb5eba96319f17ea90ece45ded;

        // Set Some Paras
        let scenario_val = test_scenario::begin(admin);
        let scenario = &mut scenario_val;

        let holder_addr = vector<u8>[0xD0, 0x95, 0xBA, 0x8F, 0x9C, 0x31, 0x09, 0x5a, 0x41, 0x0d, 0x2b, 0x07, 0x41, 0xF7, 0x86, 0x9C, 0x0D, 0x15, 0x8D, 0xf7];
        let issuanceDate =  vector<u8>[0x01,0x8d,0x17,0x5f,0xc3,0x12];
        let expirationDate = vector<u8>[0x01,0xd4,0x93,0x40,0xec,0x00];
        let ctypeHash = vector<u8>[0xbc,0x29,0x95,0x79,0x1c,0xb5,0xb0,0x2f,0x6a,0x35,0xed,0xa4,0x11,0x64,0x8d,0x71,0xbd,0x0c,0x1c,0x03,0xf9,0x48,0x9c,0x05,0xd1,0xbe,0xbb,0xd3,0x7e,0x2d,0x76,0x64];
        let on_chain_addr = string::utf8(b"BFC987a5c1897d743751fcf475ffbf23d76f851f37036f23c21b70262ed38aafc479783");
        let signature = vector<u8>[
      130, 176, 244, 207, 194,   8, 142, 249,  97,  58, 167,
      181, 223,  52, 164,  33,  20,  58,  78, 187, 247, 213,
      226, 165, 254, 144,  82, 250, 139,  95,  81, 207,  50,
      145, 176, 200, 244,   8, 158, 253,  91, 254,  56, 223,
       57,  77,  10, 211, 246,   8,  74, 245, 210, 253, 221,
       86, 157, 250, 184,   8,  77, 246, 254, 185,   1
    ];
        
        let assertionMethod = vector<u8>[0x02, 0x25, 0x2f, 0xeE, 0x64, 0xa4, 0x58, 0x27, 0xE4, 0xC0, 0x9A, 0xe2, 0x31, 0x2F, 0x09, 0xCe, 0x15, 0xB0, 0xCb, 0x89];
        {
            init(test_scenario::ctx(scenario));
        };

        // Add new whitelist attester
        test_scenario::next_tx(scenario, admin);
        {
            // let adminCap = test_scenario::take_from_sender<AdminCap>(scenario);

            // set_whitelist(&adminCap, assertionMethod, test_scenario::ctx(scenario));
            // test_scenario::return_to_sender(scenario, adminCap);

        };
        test_scenario::next_tx(scenario, admin);
        {
            // let whitelist = test_scenario::take_from_sender<AttesterWhiteList>(scenario);

            //  ===========  OK!! calculate ROOTHASH =================
            let roothash = compute_roothash(1, b"bfc", on_chain_addr);

            //  ===========  OK!! calculate DIGEST =================
            let digest = compute_digest(roothash, holder_addr, issuanceDate, expirationDate, ctypeHash);
            debug::print(&digest);
            debug::print(&hash::keccak256(&keccak256_u256(1)));
            
            debug::print(&hash::keccak256(&keccak256_vector(b"bfc")));
            debug::print(&hash::keccak256(&keccak256_string(on_chain_addr)));
            // ========= construct EIP191 sign ===============
            let ethSignedMessage = pad_signed_message(digest);
            let verification_result = erecover_to_eth_address(signature, ethSignedMessage);

            debug::print(&verification_result);
            let clock = clock::create_for_testing(test_scenario::ctx(scenario));

            let a = verify_VC(
                1,
                holder_addr,
                issuanceDate,
                expirationDate,
                ctypeHash,
                signature,
                // &whitelist,
                on_chain_addr,
            );
            debug::print(&a);
        
            let sig = vector<u8>[0xba,0x51,0xc9,0x3f,0x43,0xd9,0x8c,0x4e,0x24,0x8f,0xbf,0xa3,0x78,0x92,0x83,0x8b,0x5e,0x98,0xb6,0x2a,0x36,0xa6,0xfc,0xbe,0x08,0x73,0xfa,0x2b,0x97,0x17,0x5a,0x7e,0x38,0xa8,0x0e,0x83,0xb2,0x18,0x4a,0x45,0xd0,0xff,0xad,0xef,0x00,0x09,0x7b,0x1e,0x4e,0x9b,0x9e,0xb0,0xf3,0x31,0xb8,0x9a,0x7e,0xce,0x66,0xd1,0x66,0x4c,0x2c,0x08];

            let verifyResult = verifyCCIPSignature(digest, 1706086907223, sig, 1700714355001);

            debug::print(&verifyResult);

            let kyc_verify = verify_KYC(
                1,
                on_chain_addr,
                holder_addr,
                issuanceDate,
                expirationDate,
                ctypeHash,
                signature,
                1706086907223,
                sig,
                &clock,
                // &whitelist
                );

            debug::print(&kyc_verify);
            clock::destroy_for_testing(clock);
            // test_scenario::return_to_sender(scenario, whitelist);
        };
        test_scenario::end(scenario_val);
    }
}