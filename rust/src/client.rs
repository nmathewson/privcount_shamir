use std::collections::HashMap;
use std::iter::FromIterator;

use math::FE;
use num::Zero;
use rand::Rng;
use crypto::sha3;
use crypto::digest::Digest;
use byteorder::{ByteOrder, NetworkEndian};

use data::*;
use encrypt::hybrid::PrivcountEncryptor;
use encrypt::Encryptor;
use shamir;

// Stuff that we store about, or transmit to, a TR.

fn new_seed<R:Rng>(rng : &mut R, keys : &TrKeys) -> (Seed, Vec<u8>) {
    let mut seed = Vec::new();
    seed.resize(SEED_LEN, 0);
    rng.fill_bytes(&mut seed);

    let enc = PrivcountEncryptor::new(&keys.enc_key, &keys.signing_key);
    let encrypted = enc.encrypt(&seed, SEED_ENCRYPTION_TWEAK, rng);
    (Seed::from_bytes(&seed).unwrap(), encrypted)
}

pub struct TrState {
    keys : TrKeys,
    encrypted_seed : Vec<u8>,
    x : FE,
    counters: Vec<FE>,
}

impl TrState {
    fn new<R:Rng>(rng : &mut R, keys : &TrKeys, n_counters : usize) -> Self {
        let (seed, encrypted_seed) = new_seed(rng, keys);
        let counters = seed.counter_masks(n_counters);
        TrState{
            keys : keys.clone(),
            encrypted_seed : encrypted_seed,
            x : keys.get_x_coord(),
            counters }
    }

    fn finalize<R:Rng>(self, rng : &mut R) -> TrData {

        let enc = PrivcountEncryptor::new(&self.keys.enc_key,
                                          &self.keys.signing_key);
        let u64s = Vec::from_iter(
            self.counters.into_iter().map(|fe| fe.value()));
        let mut encoded = Vec::with_capacity(u64s.len() * 8);
        encoded.resize(u64s.len() * 8, 0);
        NetworkEndian::write_u64_into(&u64s, &mut encoded[..]);
        let encrypted = enc.encrypt(&encoded, Y_ENCRYPTION_TWEAK, rng);

        TrData::new(&self.keys, self.encrypted_seed, self.x, encrypted)
    }
}

pub struct CounterSet {
    counter_ids : Vec<CtrId>, // XXXX use strings??
    counters : HashMap<CtrId, Counter>,
    tr_states : Vec<TrState>,
}

#[derive(Debug,Clone)]
pub struct Counter {
    id : CtrId,
    val : FE
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
            tr_ids.iter().map(|k| TrState::new(rng, k, n_counters))
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

        CounterData::new(counter_ids, tr_data)
    }
}

