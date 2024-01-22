module test_ccip_verify_package::kyc_verify {
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};
    use sui::vec_set::{Self, VecSet};

    use sui::hash;
    use sui::ecdsa_k1;
    use std::vector;
    use sui::bcs;
    use std::string::{Self};
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
        onChainAddr: address,
        // the DID address
        holderAddr: vector<u8>, 
        issuanceDate: vector<u8>, 
        expirationDate: vector<u8>, 
        ctypeHash: vector<u8>,
        signature: vector<u8>,
        timestamp: u64,
        verifierSig: vector<u8>,
        clock: &Clock,
        attesterList: &AttesterWhiteList,
    ) : u256 {
        // Only the vc is valid, return the digest
        let digest = verify_VC(
            value_kyc_status,
            holderAddr, 
            issuanceDate, 
            expirationDate, 
            ctypeHash,
            signature,
            attesterList,
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
        attesterWhiteList: &AttesterWhiteList,
        onChainAddr: address
    ) : vector<u8> {
        let bfcPrefix = b"bfc";
        let roothash = compute_roothash(value_kyc_status, bfcPrefix, onChainAddr);

        //  ===========  OK!! calculate DIGEST =================
        let digest = compute_digest(roothash, holderAddr, issuanceDate, expirationDate, ctypeHash);

        // ========= construct EIP191 sign ===============
        let ethSignedMessage = pad_signed_message(digest);
        let verificationResult = erecover_to_eth_address(signature, ethSignedMessage);

        // If the assertionMethod is not in the attester whitelist, abort with ErrorCode `41`
        assert!(attester_exist(verificationResult, attesterWhiteList), 41);

        // let attester = vector<u8>[0x02, 0x25, 0x2f, 0xeE, 0x64, 0xa4, 0x58, 0x27, 0xE4, 0xC0, 0x9A, 0xe2, 0x31, 0x2F, 0x09, 0xCe, 0x15, 0xB0, 0xCb, 0x89];
        // assert!(verificationResult == attester, 41);

       
        digest

    }

    // compute roothash for KYC PublicVC
    fun compute_roothash(value_u256: u256, value_vec_1: vector<u8>, value_vec_2: address): vector<u8>{
        let hash_1 = hash::keccak256(&keccak256_u256(value_u256));
        let hash_2 = hash::keccak256(&keccak256_vector(value_vec_1));
        let hash_3 = hash::keccak256(&keccak256_address(value_vec_2));

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
        assert!(currentTimestamp <= timestamp + 1000 * 60 * 5, 43);
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

//     #[test]
//     fun test_hash_result() {
//         use sui::test_scenario;
//         use std::debug;

//         // create test addresses representing users
//         let admin = @0x8fb8eff69462aad4c20884c2cd4b7df33e6eb7cb5eba96319f17ea90ece45ded;

//         // Set Some Paras
//         let scenario_val = test_scenario::begin(admin);
//         let scenario = &mut scenario_val;

//         let holder_addr = vector<u8>[0x11, 0xf8, 0xb7, 0x7F, 0x34, 0xFC, 0xF1, 0x4B, 0x70, 0x95, 0xBF, 0x52, 0x28, 0xAc, 0x06, 0x06, 0x32, 0x4E, 0x82, 0xD1];
//         let issuanceDate =  vector<u8>[ 1, 139, 251, 6, 223, 207 ];
//         let expirationDate = vector<u8>[0x00];
//         let ctypeHash = vector<u8>[ 44,  77,  63,   9,  76, 200, 216, 154, 110, 248, 106,  66, 182, 151, 65, 251, 207, 145,  63, 180, 189, 255, 162, 240, 196, 176, 214, 156, 226, 147, 164,  17];
        
//         let signature = vector<u8>[89, 224, 112,  59,  55,  63,  59,  88, 185, 159,   2, 144, 146, 179, 160, 124,  48, 249, 239, 140, 139,   7, 6, 193,   0,  50, 202, 155, 193, 228, 169, 191,  26, 89, 174, 136, 253, 184, 252,  40, 236,  92, 185, 105, 121,  16,  16, 202, 212, 215,  70, 247,  39, 165, 237, 250,  22,  54,  16, 142,  35, 137, 188,  70,   1];
        
//         let assertionMethod = vector<u8>[0x02, 0x25, 0x2f, 0xeE, 0x64, 0xa4, 0x58, 0x27, 0xE4, 0xC0, 0x9A, 0xe2, 0x31, 0x2F, 0x09, 0xCe, 0x15, 0xB0, 0xCb, 0x89];
//         {
//             init(test_scenario::ctx(scenario));
//         };

//         // Add new whitelist attester
//         test_scenario::next_tx(scenario, admin);
//         {
//             let adminCap = test_scenario::take_from_sender<AdminCap>(scenario);

//             set_whitelist(&adminCap, assertionMethod, test_scenario::ctx(scenario));
//             test_scenario::return_to_sender(scenario, adminCap);

//         };
//         test_scenario::next_tx(scenario, admin);
//         {
//             let whitelist = test_scenario::take_from_sender<AttesterWhiteList>(scenario);

//             //  ===========  OK!! calculate ROOTHASH =================
//             let roothash = compute_roothash(1, b"bfc", admin);

//             //  ===========  OK!! calculate DIGEST =================
//             let digest = compute_digest(roothash, holder_addr, issuanceDate, expirationDate, ctypeHash);
//             debug::print(&digest);

//             // ========= construct EIP191 sign ===============
//             let ethSignedMessage = pad_signed_message(digest);
//             let verification_result = erecover_to_eth_address(signature, ethSignedMessage);

//             debug::print(&verification_result);
//             let clock = clock::create_for_testing(test_scenario::ctx(scenario));

//             let a = verify_VC(
//                 1,
//                 holder_addr,
//                 issuanceDate,
//                 vector<u8>[0x00],
//                 ctypeHash,
//                 signature,
//                 &whitelist,
//                 admin,
//             );
//             debug::print(&a);
        
//             let sig = vector<u8>[200, 230, 224, 174,  79, 161,  43, 150, 165, 218,  52, 117, 166,  86, 203, 132, 174, 205, 193, 241, 104,  62, 178,   1, 188,  61,  26, 231,  22,   0,  86, 203,  36, 193, 224,  88, 143, 187, 147, 111, 255, 115, 215, 237, 4, 222, 245,  14, 144, 137, 131, 232, 169,  70, 247, 90, 147,  95, 154,  59, 189, 255,  50,  10];

//             let verifyResult = verifyCCIPSignature(digest, 1700714355000, sig, 1700714355001);

//             debug::print(&verifyResult);

//             let kyc_verify = verify_KYC(
//                 1,
//                 admin,
//                 holder_addr,
//                 issuanceDate,
//                 vector<u8>[0x00],
//                 ctypeHash,
//                 signature,
//                 1700714355000,
//                 sig,
//                 &clock,
//                 &whitelist
//                 );

//             debug::print(&kyc_verify);
//             clock::destroy_for_testing(clock);
//             test_scenario::return_to_sender(scenario, whitelist);
//         };
//         test_scenario::end(scenario_val);
//     }
}