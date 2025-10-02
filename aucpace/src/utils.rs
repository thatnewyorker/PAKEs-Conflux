use crate::{Error, Result};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::{
    digest::consts::U64,
    digest::{Digest, Output},
    ristretto::RistrettoPoint,
    scalar::Scalar,
};
use password_hash::PasswordHash;
use rand_core::{TryCryptoRng, TryRngCore};

#[allow(non_snake_case)]
#[inline]
fn H<D: Digest + Default, const N: u32>() -> D {
    let mut hasher: D = Default::default();
    hasher.update(N.to_le_bytes());
    hasher
}

macro_rules! create_h_impl {
    ($name:ident, $n:literal) => {
        #[allow(non_snake_case)]
        pub fn $name<D: Digest + Default>() -> D {
            H::<D, $n>()
        }
    };
}

// implement H0..H5 hash functions
create_h_impl!(H0, 0);
create_h_impl!(H1, 1);
create_h_impl!(H2, 2);
create_h_impl!(H3, 3);
create_h_impl!(H4, 4);
create_h_impl!(H5, 5);

/// Generate a fixed length nonce using a CSPRNG.
///
/// This function is fallible: it will return `Err(Error::Rng)` if the supplied
/// CSPRNG fails to produce bytes (for example, due to an OS entropy failure).
/// Callers should handle or propagate this error.
///
/// Examples
///
/// Propagate the error with `?`:
///
/// let mut rng = rand::rngs::OsRng;
/// let nonce: [u8; 32] = generate_nonce(&mut rng)?;
///
/// Explicitly match and handle the RNG error:
///
/// match generate_nonce(&mut rng) {
///     Ok(nonce) => { /* use nonce */ }
///     Err(e) => match e {
///         Error::Rng => { /* handle RNG failure */ }
///         _ => { /* other errors */ }
///     },
/// }
#[inline]
pub fn generate_nonce<CSPRNG, const N: usize>(rng: &mut CSPRNG) -> Result<[u8; N]>
where
    CSPRNG: TryRngCore + TryCryptoRng,
{
    let mut nonce = [0; N];
    rng.try_fill_bytes(&mut nonce).map_err(|_| Error::Rng)?;
    Ok(nonce)
}

/// Computes the SSID from two server and client nonces - s and t
#[inline]
pub fn compute_ssid<D: Digest + Default, const K1: usize>(s: [u8; K1], t: [u8; K1]) -> Output<D> {
    let mut hasher: D = H0();
    hasher.update(s);
    hasher.update(t);
    hasher.finalize()
}

/// Generate a Diffie-Hellman keypair for the `CPace` substep of the protocol.
///
/// This function is fallible and will return `Err(Error::Rng)` if the provided
/// RNG fails. Callers should propagate or handle this error appropriately.
///
/// Example (propagate the error):
///
/// let (priv_key, pub_key) = generate_keypair::<sha2::Sha512, _, _>(
///     &mut rng,
///     ssid,
///     prs,
///     channel_identifier,
/// )?;
///
/// Example (explicit handling):
///
/// match generate_keypair::<sha2::Sha512, _, _>(&mut rng, ssid, prs, channel_identifier) {
///     Ok((x, X)) => { /* use keys */ }
///     Err(e) => match e {
///         Error::Rng => { /* handle RNG failure */ }
///         _ => { /* other errors */ }
///     },
/// }
#[inline]
pub fn generate_keypair<D, CSPRNG, CI>(
    rng: &mut CSPRNG,
    ssid: Output<D>,
    prs: [u8; 32],
    ci: CI,
) -> Result<(Scalar, RistrettoPoint)>
where
    D: Digest<OutputSize = U64> + Default,
    CSPRNG: TryRngCore + TryCryptoRng,
    CI: AsRef<[u8]>,
{
    let mut hasher: D = H1();
    hasher.update(ssid);
    hasher.update(prs);
    hasher.update(ci);

    let generator = RistrettoPoint::from_hash(hasher);
    let mut rng_bytes = [0u8; 64];
    rng.try_fill_bytes(&mut rng_bytes).map_err(|_| Error::Rng)?;
    let mut rng_hasher: D = Default::default();
    rng_hasher.update(&rng_bytes);
    let priv_key = Scalar::from_hash(rng_hasher);
    let cofactor = Scalar::ONE;
    let pub_key = generator * (priv_key * cofactor);

    Ok((priv_key, pub_key))
}

/// Compute the first session key sk1 from our private key and the other participant's public key
#[inline]
pub fn compute_first_session_key<D>(
    ssid: Output<D>,
    priv_key: Scalar,
    pub_key: RistrettoPoint,
) -> Output<D>
where
    D: Digest<OutputSize = U64> + Default,
{
    let shared_point = pub_key * priv_key;

    let mut hasher: D = H2();
    hasher.update(ssid);
    hasher.update(shared_point.compress().to_bytes());

    hasher.finalize()
}

/// Compute the two authenticator messages Ta and Tb
#[inline]
pub fn compute_authenticator_messages<D>(ssid: Output<D>, sk1: Output<D>) -> (Output<D>, Output<D>)
where
    D: Digest<OutputSize = U64> + Default,
{
    let mut ta_hasher: D = H3();
    ta_hasher.update(ssid);
    ta_hasher.update(sk1);

    let mut tb_hasher: D = H4();
    tb_hasher.update(ssid);
    tb_hasher.update(sk1);

    (ta_hasher.finalize(), tb_hasher.finalize())
}

/// Compute the session key - sk
#[inline]
pub fn compute_session_key<D>(ssid: Output<D>, sk1: Output<D>) -> Output<D>
where
    D: Digest<OutputSize = U64> + Default,
{
    let mut hasher: D = H5();
    hasher.update(ssid);
    hasher.update(sk1);
    hasher.finalize()
}

/// Compute a scalar from a password hash
#[inline]
pub fn scalar_from_hash(pw_hash: &PasswordHash<'_>) -> Result<Scalar> {
    let hash = pw_hash.hash.ok_or(Error::HashEmpty)?;
    let hash_bytes = hash.as_bytes();

    // support both 32 and 64 byte hashes
    match hash_bytes.len() {
        32 => {
            let arr: [u8; 32] = hash_bytes.try_into().map_err(|_| Error::HashSizeInvalid)?;
            Ok(Scalar::from_bytes_mod_order(arr))
        }
        64 => {
            let arr: [u8; 64] = hash_bytes.try_into().map_err(|_| Error::HashSizeInvalid)?;
            Ok(Scalar::from_bytes_mod_order_wide(&arr))
        }
        _ => Err(Error::HashSizeInvalid),
    }
}

/// Generate a keypair (x, X) for the server
///
/// This function is fallible: it will return `Err(Error::Rng)` if the RNG fails
/// to produce bytes. Callers should treat RNG failures as recoverable errors
/// (for example, by retrying or by reporting the failure to an operator).
///
/// Example (propagate with `?`):
///
/// let (private, public) = generate_server_keypair::<sha2::Sha512, _>(&mut rng)?;
///
/// Example (explicit handling):
///
/// if let Err(e) = generate_server_keypair::<sha2::Sha512, _>(&mut rng) {
///     if let Error::Rng = e {
///         // handle RNG failure (e.g. log and retry or abort)
///     }
/// }
#[inline]
pub fn generate_server_keypair<D, CSPRNG>(rng: &mut CSPRNG) -> Result<(Scalar, RistrettoPoint)>
where
    D: Digest<OutputSize = U64> + Default,
    CSPRNG: TryRngCore + TryCryptoRng,
{
    // for ristretto255 the cofactor is 1, for normal curve25519 it is 8
    // this will need to be provided by a group trait in the future
    let cofactor = Scalar::ONE;
    let mut rng_bytes = [0u8; 64];
    rng.try_fill_bytes(&mut rng_bytes).map_err(|_| Error::Rng)?;
    let mut rng_hasher: D = Default::default();
    rng_hasher.update(&rng_bytes);
    let private = Scalar::from_hash(rng_hasher);
    let public = RISTRETTO_BASEPOINT_POINT * (private * cofactor);

    Ok((private, public))
}

// serde_with helper modules for serialising
#[cfg(feature = "serde")]
pub mod serde_saltstring {
    use core::fmt;
    use password_hash::SaltString;
    use serde::de::{Error, Visitor};
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(data: &SaltString, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(data.as_str())
    }

    struct SaltStringVisitor {}

    impl<'de> Visitor<'de> for SaltStringVisitor {
        type Value = SaltString;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "a valid ASCII salt string")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: Error,
        {
            SaltString::from_b64(v).map_err(Error::custom)
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<SaltString, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(SaltStringVisitor {})
    }
}

#[cfg(feature = "serde")]
pub mod serde_paramsstring {
    use core::fmt;
    use password_hash::ParamsString;
    use serde::de::{Error, Visitor};
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(data: &ParamsString, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(data.as_str())
    }

    struct ParamsStringVisitor {}

    impl<'de> Visitor<'de> for ParamsStringVisitor {
        type Value = ParamsString;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "a valid PHC parameter string")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: Error,
        {
            v.parse().map_err(Error::custom)
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<ParamsString, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(ParamsStringVisitor {})
    }
}
