use std::collections::HashMap;
use std::iter::FromIterator;

use math::FE;
use num::Zero;
use rand::Rng;

use encrypt::hybrid::PrivcountEncryptor;
use encrypt::Encryptor;
use shamir;

use crypto::sha3;
use crypto::digest::Digest;

use byteorder::{ByteOrder, NetworkEndian};

#[derive(Debug,Clone,PartialEq,Eq,Hash,Copy)]
pub struct CtrId(u32);

#[derive(Debug,Clone,PartialEq,Eq,Hash)]
pub struct TrKeys {
    enc_key : [u8;32],
    signing_key : [u8;32]
}

#[derive(Debug,Clone)]
pub struct Counter {
    id : CtrId,
    val : FE
}

const SEED_LEN : usize = 32;
const SEED_ENCRYPTION_TWEAK : &'static [u8] = b"privctr-seed-v1";
const Y_ENCRYPTION_TWEAK : &'static [u8] = b"privctr-shares-v1";

// Stuff that we store about, or transmit to, a TR.
pub struct Seed(Vec<u8>);

pub struct EncryptedSeed(Vec<u8>);

impl EncryptedSeed {
    fn new<R:Rng>(rng : &mut R, keys : &TrKeys) -> (Seed, EncryptedSeed) {
        let mut seed = Vec::new();
        seed.resize(SEED_LEN, 0);
        rng.fill_bytes(&mut seed);

        let enc = PrivcountEncryptor::new(&keys.enc_key, &keys.signing_key);
        let encrypted = enc.encrypt(&seed, SEED_ENCRYPTION_TWEAK, rng);
        (Seed(seed), EncryptedSeed(encrypted))
    }
}

impl TrKeys {
    fn get_x_coord(&self) -> FE {
        FE::new(NetworkEndian::read_u64(&self.signing_key[..8]))
    }
}

impl Seed {
    fn counter_masks(self, n_masks : usize) -> Vec<FE> {

        let bytes_needed = n_masks * 8;
        let mut xof = sha3::Sha3::shake_256();
        let mut bytes = Vec::new();
        bytes.resize(bytes_needed, 0);
        xof.input(&self.0);
        xof.result(&mut bytes);

        let mut result = Vec::new();
        let mut slice = &bytes[..];
        while slice.len() > 0 {
            let (these, remainder) = slice.split_at(8);
            // XXXX This makes some values slightly more likely!!!
            // XXXX spec problem.
            result.push(FE::new(NetworkEndian::read_u64(these)));
            slice = remainder;
        }
        result
    }
}

pub struct TRData {
    keys : TrKeys,
    seed : EncryptedSeed,
    x : FE,
    encrypted_counters: Vec<u8>
}

pub struct TRState {
    keys : TrKeys,
    seed : EncryptedSeed,
    x : FE,
    counters: Vec<FE>,
}

impl TRState {
    fn new<R:Rng>(rng : &mut R, keys : &TrKeys, n_counters : usize) -> Self {
        let (seed, encrypted_seed) = EncryptedSeed::new(rng, keys);
        let counters = seed.counter_masks(n_counters);
        TRState{
            keys : keys.clone(),
            seed : encrypted_seed,
            x : keys.get_x_coord(),
            counters }
    }

    fn finalize<R:Rng>(self, rng : &mut R) -> TRData {

        let enc = PrivcountEncryptor::new(&self.keys.enc_key,
                                          &self.keys.signing_key);
        let u64s = Vec::from_iter(
            self.counters.into_iter().map(|fe| fe.value()));
        let mut encoded = Vec::with_capacity(u64s.len() * 8);
        encoded.resize(u64s.len() * 8, 0);
        NetworkEndian::write_u64_into(&u64s, &mut encoded[..]);
        let encrypted = enc.encrypt(&encoded, Y_ENCRYPTION_TWEAK, rng);

        TRData {
            keys : self.keys,
            seed : self.seed,
            x : self.x,
            encrypted_counters : encrypted
        }
    }
}

pub struct CounterSet {
    counter_ids : Vec<CtrId>, // XXXX use strings??
    counters : HashMap<CtrId, Counter>,
    tr_states : Vec<TRState>,
}

pub struct CounterData {
    counter_ids : Vec<CtrId>,
    tr_data : Vec<TRData>
}

impl Counter {
    fn new(id : CtrId) -> Counter {
        Counter { id, val : FE::zero() }
    }
    pub fn inc(&mut self, v : u32) {
        self.val += FE::from(v);
    }
    pub fn dec(&mut self, v : u32) {
        self.val -= FE::from(v);
    }
}

impl CounterSet {
    pub fn new<R:Rng>(rng : &mut R,
               counter_ids : &[CtrId], tr_ids : &[TrKeys],
               k : usize) -> Self {
        let counter_ids = counter_ids.to_vec();
        let n_counters = counter_ids.len();
        let mut tr_states = Vec::from_iter(
            tr_ids.iter().map(|k| TRState::new(rng, k, n_counters))
        );

        let shamir_params = {
            let mut b = shamir::ParamBuilder::new(k, tr_ids.len());
            for state in tr_states.iter() {
                b.add_x_coordinate(&state.x);
            }
            b.finalize().unwrap()
        };

        let mut counters = HashMap::new();
        for (idx, cid) in counter_ids.iter().enumerate() {
            let mut counter = Counter::new(*cid);
            let noise = FE::new(0); // XXXXX no noise!
            let shares = shamir_params.share_secret(noise, rng);
            assert_eq!(shares.len(), tr_ids.len());
            counter.val = rng.gen();

            for (share, tr_state) in shares.iter().zip(tr_states.iter_mut()) {
                assert_eq!(share.x, tr_state.x);
                let mask = tr_state.counters[idx];
                tr_state.counters[idx] = share.y - mask - counter.val;
            }
            counters.insert(*cid, counter);
        }

        CounterSet{ counter_ids, counters, tr_states }
    }

    pub fn ctr(&mut self, ctr_id : CtrId) -> Option<&mut Counter> {
        self.counters.get_mut(&ctr_id)
    }

    pub fn finalize<R : Rng>(mut self, rng : &mut R) -> CounterData {
        let counter_ids = self.counter_ids;

        for (idx, cid) in counter_ids.iter().enumerate() {
            let counter = self.counters.get(cid).unwrap();
            for trs in self.tr_states.iter_mut() {
                trs.counters[idx] += counter.val;
            }
        }

        let tr_data = Vec::from_iter(
            self.tr_states.into_iter().map(|state| state.finalize(rng))
        );

        CounterData { counter_ids, tr_data }
    }
}

