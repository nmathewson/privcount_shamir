
// hybrid encryption with aes and curve25519 and sha3, as documented in
// rend-spec-v3.txt section 2.5.3 and amended in the privcount-shamir spec.

use rand::Rng;

pub trait Encryptor {
    fn encrypt(&self, inp : &[u8], tweak : &[u8],
               rng : &mut Rng) -> Vec<u8>;
}

pub trait Decryptor {
    fn decrypt(&self, inp : &[u8], tweak : &[u8]) -> Option<Vec<u8>>;
}

pub mod hybrid {
    use crypto::sha3;
    use crypto::aes;
    use crypto::curve25519::{curve25519,curve25519_base};
    use crypto::digest::Digest;
    use crypto::util::fixed_time_eq;
    use super::*;

    const SALT_LEN : usize = 16;
    const S_KEY_LEN : usize = 32;
    const S_IV_LEN : usize = 16;
    const MAC_KEY_LEN : usize = 32; // ????????? specified anywhere?
    const MAC_OUT_LEN : usize = 32;
    pub const PK_PUBLIC_LEN : usize = 32;
    pub const PK_SECRET_LEN : usize = 32;
    pub const SIGNING_PUBLIC_LEN : usize = 32;
    pub const ENCRYPTED_OVERHEAD : usize =
        PK_PUBLIC_LEN + SALT_LEN + MAC_OUT_LEN;

    pub struct PrivcountEncryptor {
        key : [u8;PK_PUBLIC_LEN],
        signing_key : [u8;SIGNING_PUBLIC_LEN]
    }

    impl PrivcountEncryptor {
        pub fn new(key : &[u8;PK_PUBLIC_LEN],
                   signing_key : &[u8;SIGNING_PUBLIC_LEN]) -> Self {
            PrivcountEncryptor { key : *key, signing_key : *signing_key }
        }

        pub fn key(&self) -> &[u8;PK_PUBLIC_LEN] {
            &self.key
        }
    }

    impl super::Encryptor for PrivcountEncryptor {
        fn encrypt(&self,
                   inp : &[u8], tweak : &[u8], rng : &mut Rng) -> Vec<u8> {
            let mut keys = [0 ; S_KEY_LEN + S_IV_LEN + MAC_KEY_LEN];

            let seckey_tmp = curve25519_seckey_gen(rng);
            let pubkey_tmp = curve25519_base(&seckey_tmp);

            let shared_key = curve25519(&seckey_tmp, &self.key);
            let mut secret_input = Vec::new();
            secret_input.extend_from_slice(&shared_key);
            secret_input.extend_from_slice(&self.signing_key);

            let salt = generate_salt(rng);

            generate_keys(&secret_input, tweak, &salt, &mut keys);
            let (enc_key, rest) = keys.split_at(S_KEY_LEN);
            let (enc_iv, mac_key) = rest.split_at(S_IV_LEN);
            debug_assert!(mac_key.len() == MAC_KEY_LEN);

            let mut result = Vec::new();
            result.extend_from_slice(&pubkey_tmp);
            result.extend_from_slice(&salt);

            let mut cipher = aes::ctr(aes::KeySize::KeySize256,
                                      enc_key, enc_iv);
            let prefix_len = result.len();
            result.resize(prefix_len + inp.len(), 0);
            cipher.process(&inp, &mut result[prefix_len..]);

            let mut mac_bytes = [ 0 ; MAC_OUT_LEN ];
            mac(&mac_key, &result, &mut mac_bytes);
            result.extend_from_slice(&mac_bytes);

            result
        }
    }

    fn generate_salt(rng : &mut Rng) -> [u8; SALT_LEN] {
        let mut salt = [0;SALT_LEN];
        rng.fill_bytes(&mut salt);
        salt
    }

    fn generate_keys(secret_input : &[u8],
                     string_const : &[u8],
                     salt : &[u8],
                     output : &mut [u8]) {
        let mut xof = sha3::Sha3::shake_256();
        xof.input(secret_input);
        xof.input(salt);
        xof.input(string_const);
        xof.result(output);
    }

    fn mac(key : &[u8],
           val : &[u8],
           result : &mut[u8]) {
        use byteorder::{ByteOrder, BigEndian as NetworkOrder};
        assert!(result.len() <= MAC_OUT_LEN);
        let mut keylen = [0;8];
        NetworkOrder::write_u64(&mut keylen, key.len() as u64);

        let mut d = sha3::Sha3::sha3_256();
        d.input(&keylen);
        d.input(key);
        d.input(val);
        d.result(result);
    }

    pub(crate) fn curve25519_seckey_gen(rng : &mut Rng) -> [u8;PK_SECRET_LEN] {
        let mut result = [0;32];
        rng.fill_bytes(&mut result);
        result[0] &= 248;
        result[31] &= 127;
        result[31] |= 64;
        result
    }

    pub struct PrivcountDecryptor {
        secret_key : [u8;PK_SECRET_LEN],
        signing_key : [u8;SIGNING_PUBLIC_LEN]
    }

    impl PrivcountDecryptor {
        pub fn new(secret_key : &[u8;PK_SECRET_LEN],
                   signing_key : &[u8;SIGNING_PUBLIC_LEN]) -> Self {
            PrivcountDecryptor { secret_key : *secret_key,
                                 signing_key : *signing_key }
        }
    }

    impl Decryptor for PrivcountDecryptor {
        fn decrypt(&self, inp : &[u8], tweak : &[u8]) -> Option<Vec<u8>> {
            // Try to unserialize the input.
            if inp.len() < PK_PUBLIC_LEN + SALT_LEN + MAC_OUT_LEN {
                return None
            }
            let enc_len = inp.len() - PK_PUBLIC_LEN - SALT_LEN - MAC_OUT_LEN;
            let (pubkey, rest) = inp.split_at(PK_PUBLIC_LEN);
            let (salt, rest) = rest.split_at(SALT_LEN);
            let (enc, mac_received) = rest.split_at(enc_len);
            debug_assert_eq!(mac_received.len(), MAC_OUT_LEN);

            let shared_key = curve25519(&self.secret_key, pubkey);
            let mut secret_input = Vec::new();
            secret_input.extend_from_slice(&shared_key);
            secret_input.extend_from_slice(&self.signing_key);

            let mut keys = [0 ; S_KEY_LEN + S_IV_LEN + MAC_KEY_LEN];
            generate_keys(&secret_input, tweak, &salt, &mut keys);
            let (enc_key, rest) = keys.split_at(S_KEY_LEN);
            let (enc_iv, mac_key) = rest.split_at(S_IV_LEN);
            debug_assert_eq!(mac_key.len(), MAC_KEY_LEN);

            let mut mac_computed = [ 0; MAC_OUT_LEN ];
            let mac_covered_portion = &inp[0..inp.len()-MAC_OUT_LEN];
            mac(&mac_key, &mac_covered_portion, &mut mac_computed);
            if ! fixed_time_eq(&mac_computed, &mac_received) {
                return None;
            }

            let mut cipher = aes::ctr(aes::KeySize::KeySize256,
                                      enc_key, enc_iv);
            let mut result = Vec::new();
            result.resize(enc.len(), 0);
            cipher.process(&enc, &mut result);

            Some(result)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::hybrid::*;
    use crypto::curve25519::{curve25519,curve25519_base};
    use rand::os::OsRng;

    #[test]
    fn roundtrip() {
        let msg = b"Why must you record my phonecalls? \
                    Are you planning a bootleg LP?";
        let tweak = b"Said you've been threatened by gangsters.";
        let mut rng = OsRng::new().unwrap();
        let signing_key = [17;SIGNING_PUBLIC_LEN]; // not actually used to sign
        let sk = curve25519_seckey_gen(&mut rng);
        let pk = curve25519_base(&sk);
        let encryptor = PrivcountEncryptor::new(&pk, &signing_key);
        let decryptor = PrivcountDecryptor::new(&sk, &signing_key);

        let encrypted = encryptor.encrypt(&msg[..], &tweak[..], &mut rng);
        assert_eq!(encrypted.len() - msg.len(), ENCRYPTED_OVERHEAD);

        let result = decryptor.decrypt(&encrypted, &tweak[..]);
        let mut expected = Vec::new();
        expected.extend_from_slice(&msg[..]);
        assert_eq!(result, Some(expected));

        let wrong_tweak = b"Now it's you that's threatening me.";
        let result = decryptor.decrypt(&encrypted, &wrong_tweak[..]);
        assert_eq!(result, None);

        let too_short = b"foo";
        let result = decryptor.decrypt(&too_short[..], &tweak[..]);
        assert_eq!(result, None);
    }

    #[test]
    fn is_randomized() {
        let msg = b"Can't fight corruption with con tricks \
                    They use the law to commit crime";
        let tweak = b"I dread to think what the future'll bring \
                      When we're living in gangster times";

        let mut rng = OsRng::new().unwrap();
        let signing_key = [62;SIGNING_PUBLIC_LEN]; // not actually used to sign
        let sk = curve25519_seckey_gen(&mut rng);
        let pk = curve25519_base(&sk);
        let encryptor = PrivcountEncryptor::new(&pk, &signing_key);

        let enc1 = encryptor.encrypt(&msg[..], &tweak[..], &mut rng);
        let enc2 = encryptor.encrypt(&msg[..], &tweak[..], &mut rng);
        assert_ne!(enc1, enc2);
    }

}
