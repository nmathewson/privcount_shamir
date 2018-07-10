
use byteorder::{ByteOrder, NetworkEndian};
use crypto::sha3;
use crypto::digest::Digest;

use math::FE;
#[derive(Debug,Clone,PartialEq,Eq,Hash,Copy)]
pub struct CtrId(pub u32);

#[derive(Debug,Clone,PartialEq,Eq,Hash)]
pub struct ClientKey {
    pub signing_key : [u8;32]
}

#[derive(Debug,Clone,PartialEq,Eq,Hash)]
pub struct TrKeys {
    pub enc_key : [u8;32],
    pub signing_key : [u8;32]
}

// the data that a client exports for a single TR.
pub struct TrData {
    pub keys : TrKeys,
    pub encrypted_seed : Vec<u8>,
    pub x : FE,
    pub encrypted_counters: Vec<u8>
}

// all the data that a client exports
pub struct CounterData {
    pub counter_ids : Vec<CtrId>,
    pub tr_data : Vec<TrData>
}

pub const SEED_ENCRYPTION_TWEAK : &'static [u8] = b"privctr-seed-v1";
pub const Y_ENCRYPTION_TWEAK : &'static [u8] = b"privctr-shares-v1";

pub const SEED_LEN : usize = 32;

pub struct Seed(Vec<u8>);

impl TrKeys {
    pub fn get_x_coord(&self) -> FE {
        FE::new(NetworkEndian::read_u64(&self.signing_key[..8]))
    }
}

impl CounterData {
    pub fn new(counter_ids : Vec<CtrId>, tr_data : Vec<TrData>) -> Self {
        CounterData { counter_ids, tr_data }
    }
}

impl TrData {
    pub fn new(keys : &TrKeys,
               encrypted_seed : Vec<u8>,
               x : FE,
               encrypted_counters : Vec<u8>) -> Self {
        TrData { keys : keys.clone(), encrypted_seed, x, encrypted_counters }
    }
 }

impl Seed {
    pub fn from_bytes(bytes : &[u8]) -> Option<Self> {
        if bytes.len() == SEED_LEN {
            Some(Seed(bytes.to_vec()))
        } else {
            None
        }
    }
    pub fn counter_masks(self, n_masks : usize) -> Vec<FE> {
        const EXTRA_MASKS : usize = 4;
        const EXTRA_BYTES_PER_MASK : usize = 1;

        // With very high probability, this is more data than we need.
        let bytes_needed = (n_masks + EXTRA_MASKS) *
            (8 + EXTRA_BYTES_PER_MASK);

        let mut xof = sha3::Sha3::shake_256();
        let mut bytes = Vec::new();
        bytes.resize(bytes_needed, 0);
        xof.input(&self.0);
        xof.result(&mut bytes);

        let mut result = Vec::new();
        let mut slice = &bytes[..];
        while slice.len() > 0 {
            let (these, remainder) = slice.split_at(8);
            let v64 = NetworkEndian::read_u64(these);
            if let Some(elt) = FE::from_u64_unbiased(v64) {
                result.push(elt)
            }
            slice = remainder;
        }
        result
    }
}
