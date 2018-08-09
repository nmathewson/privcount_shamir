//! Data structures used by privcount clients and servers (TRs)

use byteorder::{ByteOrder, NetworkEndian};
use crypto::digest::Digest;
use crypto::sha3;

use math::FE;

/// A mostly-opaque identifier for a single Privcount counter.
///
/// Sementically distinct counters must have different CtrId values.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Copy)]
pub struct CtrId(pub u32);

/// The key material used by a single Privcount client.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClientKey {
    /// An Ed25519 signing key that the client uses to sign its messags
    pub signing_key: [u8; 32],
}

/// The key material, as seen by a Privcount client, for a Privcount TR.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TrKeys {
    /// A Curve25519 key used to encrypt results for a TR
    pub enc_key: [u8; 32],
    /// The TR's long-term Ed25519 signing key.
    pub signing_key: [u8; 32],
}

/// The data that a client exports for a single TR.
pub struct TrData {
    /// The keys for the TR receiving the data.
    pub keys: TrKeys,
    /// A SHAKE256 seed, encrypted to the TR's public key.
    pub encrypted_seed: Vec<u8>,
    /// The X coordinate for all of the shares that are sent to this TR
    pub x: FE,
    /// The encrypted Y coordinates for all of the shares that will be sent to
    /// this TR.  The counters correspond to the `counter_ids` fields within the
    /// `CounterData` structure.
    pub encrypted_counters: Vec<u8>,
}

/// All of the data that a client exports
pub struct CounterData {
    /// A list of the counters that this client is exporting.
    pub counter_ids: Vec<CtrId>,
    /// A TrData object for each TR that the client is sending a share to.
    pub tr_data: Vec<TrData>,
}

/// How many counters will we support?
pub const MAX_COUNTERS : u32 = 1 << 28;

/// Tweak value used when encrypting the privcount seed.
pub const SEED_ENCRYPTION_TWEAK: &'static [u8] = b"privctr-seed-v1";
/// Tweak value used when encrypting the privcount Y coordinates
pub const Y_ENCRYPTION_TWEAK: &'static [u8] = b"privctr-shares-v1";

/// Length of a raw seed
pub const SEED_LEN: usize = 32;

/// A random seed value, extended with SHAKE256, to produce a "mask" value for each counter.
pub struct Seed(Vec<u8>);

impl TrKeys {
    /// Return the X coordinate that we should use for this TR's shares.
    ///
    /// This coordinate is generated from the TR's public signing key, so that it will be
    /// the same for all shares that any client generates for this TR.
    pub fn get_x_coord(&self) -> FE {
        FE::new(NetworkEndian::read_u64(&self.signing_key[..8]))
    }
}

impl CounterData {
    /// Construct a new CounterData object.
    pub fn new(counter_ids: Vec<CtrId>, tr_data: Vec<TrData>) -> Self {
        CounterData {
            counter_ids,
            tr_data,
        }
    }
}

impl TrData {
    /// Construct a new TRData object.
    pub fn new(
        keys: &TrKeys,
        encrypted_seed: Vec<u8>,
        x: FE,
        encrypted_counters: Vec<u8>,
    ) -> Self {
        TrData {
            keys: keys.clone(),
            encrypted_seed,
            x,
            encrypted_counters,
        }
    }
}

impl Seed {
    /// Construct a new Seed from a slice of SEED_LEN random bytes.
    ///
    /// # Errors
    ///
    /// Gives an error if the seed is not the correct length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() == SEED_LEN {
            Ok(Seed(bytes.to_vec()))
        } else {
            Err("Incorrect seed length.")
        }
    }
    /// Create a vector of `n_masks` counter masks from this seed.
    ///
    /// These masks are used to initialize the counters to a value based on the seed,
    /// which can then be encrypted and forgotten.
    pub fn counter_masks(self, n_masks: u32) -> Result<Vec<FE>, &'static str> {
        const EXTRA_MASKS: u32 = 4;
        const EXTRA_BYTES_PER_MASK: usize = 1;

        if n_masks > MAX_COUNTERS {
            return Err("Too many counters to generate masks for.");
        }

        // With very high probability, this is more data than we need.
        let bytes_needed : usize = (n_masks + EXTRA_MASKS) as usize * (8 + EXTRA_BYTES_PER_MASK);

        let mut xof = sha3::Sha3::shake_256();
        let mut bytes = Vec::new();
        bytes.resize(bytes_needed, 0);
        xof.input(&self.0);
        xof.result(&mut bytes);

        let mut result = Vec::new();
        let mut slice = &bytes[..];
        while result.len() < n_masks as usize {
            if slice.len() < 8 {
                return Err("Internal error: too many masks were out-of-range.");
            }
            let (these, remainder) = slice.split_at(8);
            let v64 = NetworkEndian::read_u64(these);
            if let Some(elt) = FE::from_u64_unbiased(v64) {
                result.push(elt)
            }
            slice = remainder;
        }
        Ok(result)
    }
}
