//! Implements that Tally Reporter side of the privcount algorithm
//!
//! A tally reporter's job is to receive a bunch of reports from
//! various clients, add those shares together, and give the sum of
//! those shares to the other tally reporters so they can reconstruct
//! the true sum.

use byteorder::{ByteOrder, NetworkEndian};
use num::Zero;
use std::collections::HashMap;
use std::iter::FromIterator;
use std::u32;

use data::*;
use encrypt::hybrid::PrivcountDecryptor;
use encrypt::Decryptor;
use math::FE;

/// The data a TR recovers from a single client
pub struct ClientData {
    #[allow(dead_code)]
    client_key: ClientKey,
    shares: Vec<(CtrId, FE)>,
}

/// The keys that a TR uses for itself.
pub struct ServerKeys {
    /// The secret curve25519 private key used to decryption.
    pub enc_secret: [u8; 32],
    /// The public keys for this TR
    pub public: TrKeys,
}

impl ServerKeys {
    /// Decrypt a TrData (as sent by a client) into a TrData (which we will use).
    pub fn decode_from(
        &self,
        client: &ClientKey,
        counters: &[CtrId],
        data: &TrData,
    ) -> Result<ClientData, &'static str> {
        // Is this for us?
        if &data.keys != &self.public {
            return Err("Keys aren't our key.");
        }
        if data.x != self.public.get_x_coord() {
            return Err("Wrong X coordinate.");
        }
        // XX  Use try_from once it's stable
        if counters.len() > u32::MAX as usize {
            return Err("Too many counters.");
        }
        let n_counters: u32 = counters.len() as u32;

        // It is for us.  Recover the encrypted things.
        let dec = PrivcountDecryptor::new(&self.enc_secret, &self.public.signing_key);

        let seedval = dec
            .decrypt(&data.encrypted_seed, SEED_ENCRYPTION_TWEAK)
            .ok_or("Seed decryption failed.")?;
        let ctrs = dec
            .decrypt(&data.encrypted_counters, Y_ENCRYPTION_TWEAK)
            .ok_or("Counter decryption failed.")?;

        let seed = Seed::from_bytes(&seedval)?;
        let masks = seed.counter_masks(n_counters)?;
        if ctrs.len() != masks.len() * 8 {
            return Err("Wrong number of counters.");
        }
        let mut u64s = Vec::with_capacity(masks.len());
        u64s.resize(masks.len(), 0);
        NetworkEndian::read_u64_into(&ctrs, &mut u64s);

        let mut yvals = Vec::new();
        for u in u64s {
            yvals.push(FE::from_reduced(u).ok_or("BadFE")?);
        }
        let shares = Vec::from_iter(
            counters.iter().map(|c| *c).zip(
                masks
                    .into_iter()
                    .zip(yvals.into_iter())
                    .map(|(mask, y)| mask + y),
            ),
        );

        Ok(ClientData {
            client_key: client.clone(),
            shares,
        })
    }
}

/// Given a set of ClientData from different clients, compute the sum
/// for each distinct counter in those ClientDara objects.
pub fn sum_shares(client_data: &[ClientData]) -> HashMap<CtrId, FE> {
    let mut result = HashMap::new();

    for cd in client_data.iter() {
        for &(id, val) in cd.shares.iter() {
            let counter = result.entry(id).or_insert(FE::zero());
            *counter += val;
        }
    }

    result
}
