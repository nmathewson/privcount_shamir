use byteorder::{ByteOrder, NetworkEndian};
use num::Zero;
use std::collections::HashMap;
use std::iter::FromIterator;

use data::*;
use encrypt::hybrid::PrivcountDecryptor;
use encrypt::Decryptor;
use math::FE;

// The data a TR recovers from a single client
pub struct ClientData {
    client_key: ClientKey,
    shares: Vec<(CtrId, FE)>,
}

pub struct ServerKeys {
    pub enc_secret: [u8; 32],
    pub public: TrKeys,
}

impl ServerKeys {
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

        // It is for us.  Recover the encrypted things.
        let dec =
            PrivcountDecryptor::new(&self.enc_secret, &self.public.signing_key);

        let seedval = dec
            .decrypt(&data.encrypted_seed, SEED_ENCRYPTION_TWEAK)
            .ok_or("Seed decryption failed.")?;
        let ctrs = dec
            .decrypt(&data.encrypted_counters, Y_ENCRYPTION_TWEAK)
            .ok_or("Counter decryption failed.")?;

        let seed = Seed::from_bytes(&seedval).ok_or("Bad seed")?;
        let masks = seed.counter_masks(counters.len());
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

pub fn SumShares(client_data: &[ClientData]) -> HashMap<CtrId, FE> {
    let mut result = HashMap::new();

    for cd in client_data.iter() {
        for &(id, val) in cd.shares.iter() {
            let counter = result.entry(id).or_insert(FE::zero());
            *counter += val;
        }
    }

    result
}
