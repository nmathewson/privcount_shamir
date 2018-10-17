//! Client implementation for privcount protocols.
//!
//! This module handles creating a bunch of counters, blinding and
//! encrypting them, incrementing them, and finally sending shares of
//! those counters to the Tally Reporters (or "TR"s.)
//!
//! For more information about the design and motivation for this
//! protocol, see the privcount specification.

use std::collections::HashMap;
use std::iter::FromIterator;
use std::u32;

use byteorder::{ByteOrder, NetworkEndian};
use math::FE;
use num::Zero;
use rand::Rng;

use data::*;
use encrypt::hybrid::PrivcountEncryptor;
use encrypt::Encryptor;
use shamir;

/// Create a new random seed for a TR, and encrypt it to the TR.
///
/// On success, returns the Seed object, and the encrypted message.
///
/// Use a secure RNG here, or the seed will be predictable.
fn new_seed<R: Rng>(rng: &mut R, keys: &TrKeys) -> Result<(Seed, Vec<u8>),&'static str> {
    let mut seed = Vec::new();
    seed.resize(SEED_LEN, 0);
    rng.fill_bytes(&mut seed);

    let enc = PrivcountEncryptor::new(&keys.enc_key, &keys.signing_key);
    let encrypted = enc.encrypt(&seed, SEED_ENCRYPTION_TWEAK, rng)?;
    Ok((Seed::from_bytes(&seed)?, encrypted))
}

/// All the data that a client stores about, or transmits to, a TR.
pub struct TrState {
    /// The TR's keys
    keys: TrKeys,
    /// A seed value, encrypted to the TR's public key.
    encrypted_seed: Vec<u8>,
    /// The X coordinate of the TR's shares.
    x: FE,
    /// A set of blinded counters for this TR.
    ///
    /// Note that these counters don't leak any information on their own: They are useless
    /// without being able to decrypt the encrypted seed.
    counters: Vec<FE>,
}

impl TrState {
    /// Create a new TrState for a TR with a given set of keys and a
    /// given number of counters.
    fn new<R: Rng>(rng: &mut R, keys: &TrKeys, n_counters: u32)
                   -> Result<Self, &'static str> {
        let (seed, encrypted_seed) = new_seed(rng, keys)?;
        let counters = seed.counter_masks(n_counters)?;
        Ok(TrState {
            keys: keys.clone(),
            encrypted_seed: encrypted_seed,
            x: keys.get_x_coord(),
            counters,
        })
    }

    /// Convert a TRState to a TRData, ready to be sent to a TR.
    fn finalize<R: Rng>(self, rng: &mut R) -> Result<TrData, &'static str> {
        let enc =
            PrivcountEncryptor::new(&self.keys.enc_key, &self.keys.signing_key);
        let u64s =
            Vec::from_iter(self.counters.into_iter().map(|fe| fe.value()));
        let mut encoded = Vec::with_capacity(u64s.len() * 8);
        encoded.resize(u64s.len() * 8, 0);
        NetworkEndian::write_u64_into(&u64s, &mut encoded[..]);
        let encrypted = enc.encrypt(&encoded, Y_ENCRYPTION_TWEAK, rng)?;

        Ok(TrData::new(&self.keys, self.encrypted_seed, self.x, encrypted))
    }
}

/// A CounterSet is a client's view of all of its counters
pub struct CounterSet {
    /// A list of all of the counter IDs that the client is tracking
    counter_ids: Vec<CtrId>, // XXXX use strings??
    /// A map from couter ID to actual counter values.
    counters: HashMap<CtrId, Counter>,
    /// A set of TR states for all of the TRs that the client knows about.
    ///
    /// Invariant: These objects must have the same number of counters
    /// as are in this CounterSet.
    tr_states: Vec<TrState>,
}

/// Information to track a client's view of a single counter.
///
/// Note that these values are stored in a blinded form, and don't
/// actually convey any information unless you can decrypt the
/// encrypted seed data.
///
/// Note that these values wrap at PRIME_ORDER, so you should make
/// sure that no counter's total is too close to that value.

#[derive(Debug, Clone)]
pub struct Counter {
    id: CtrId,
    val: FE,
}

impl Counter {
    /// Create a new counter with a given counter ID and value zero.
    fn new(id: CtrId) -> Counter {
        Counter {
            id,
            val: FE::zero(),
        }
    }
    /// Add a value to this counter.
    pub fn inc(&mut self, v: u32) {
        self.val += FE::from(v);
    }
    /// Subtract a value from this counter.
    pub fn dec(&mut self, v: u32) {
        self.val -= FE::from(v);
    }
}

impl CounterSet {
    /// Create a new CounterSet to track values for a given number of
    /// counters, enrypted to a given set of TR keys.  Any set of `k`
    /// TRs will be able to find the actual counter values.
    pub fn new<R: Rng>(
        rng: &mut R,
        counter_ids: &[CtrId],
        tr_ids: &[TrKeys],
        k: u32,
    ) -> Result<Self, &'static str> {
        if counter_ids.len() > u32::MAX as usize {
            return Err("Too many counters.");
        }
        if tr_ids.len() > u32::MAX as usize {
            return Err("Too many tr_ids.");
        }

        let counter_ids = counter_ids.to_vec();
        let n_counters = counter_ids.len() as u32;
        let n_trs = tr_ids.len() as u32;
        let mut tr_states = {
            let mut tr_states_result : Result< Vec<_>, _> =
                tr_ids.iter().map(|k| TrState::new(rng, k, n_counters)).collect();
            tr_states_result?
        };

        let shamir_params = {
            let mut b = shamir::ParamBuilder::new(k, n_trs)?;
            for state in tr_states.iter() {
                b.add_x_coordinate(&state.x);
            }
            b.finalize()?
        };

        let mut counters = HashMap::new();
        for (idx, cid) in counter_ids.iter().enumerate() {
            let mut counter = Counter::new(*cid);
            let noise = FE::new(0); // XXXXX no noise!
            let shares = shamir_params.share_secret(noise, rng);
            if shares.len() != tr_ids.len() {
                return Err("Internal error: incorrect number of shares generated.");
            }
            counter.val = rng.gen();

            for (share, tr_state) in shares.iter().zip(tr_states.iter_mut()) {
                if share.x != tr_state.x {
                    return Err("Internal error: mismatched share generated.");
                }
                let mask = tr_state.counters[idx];
                tr_state.counters[idx] = share.y - mask - counter.val;
            }
            counters.insert(*cid, counter);
        }

        Ok(CounterSet {
            counter_ids,
            counters,
            tr_states,
        })
    }

    /// Return a reference to the counter with a given ID, if one exists.
    pub fn ctr(&mut self, ctr_id: CtrId) -> Option<&mut Counter> {
        self.counters.get_mut(&ctr_id)
    }

    /// Finalize this CounterSet, and return a CounterData to be distributed in pieces
    /// to the TRs.
    pub fn finalize<R: Rng>(mut self, rng: &mut R) -> Result<CounterData, &'static str> {
        let counter_ids = self.counter_ids;

        for (idx, cid) in counter_ids.iter().enumerate() {
            let counter = self.counters.get(cid).ok_or("Internal error: missing counter.")?;
            for trs in self.tr_states.iter_mut() {
                trs.counters[idx] += counter.val;
            }
        }

        let tr_data : Result<Vec<_>, _>  =
            self.tr_states.into_iter().map(|state| state.finalize(rng)).collect();

        Ok(CounterData::new(counter_ids, tr_data?))
    }
}
