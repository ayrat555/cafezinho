use dryoc::sign::IncrementalSigner;
use dryoc::sign::PublicKey;
use dryoc::sign::SecretKey;
use dryoc::sign::Signature;
use dryoc::sign::SigningKeyPair;
use rustler::Binary;
use rustler::Encoder;
use rustler::Env;
use rustler::NewBinary;
use rustler::Term;

mod atoms {
    rustler::atoms! {
        ok,
        error,
        wrong_seed_size,
        wrong_secret_key_size,
        signing_failed
    }
}

#[rustler::nif]
fn keypair_from_seed<'a>(env: Env<'a>, seed: Binary) -> Term<'a> {
    let seed_arr: [u8; 32] = match seed.as_slice().try_into() {
        Ok(array) => array,
        Err(_) => return (atoms::error(), atoms::wrong_seed_size()).encode(env),
    };

    let keypair = SigningKeyPair::<PublicKey, SecretKey>::from_seed(&seed_arr);

    let mut pk_bin = NewBinary::new(env, 32);
    pk_bin.as_mut_slice().copy_from_slice(&keypair.public_key);

    let mut sk_bin = NewBinary::new(env, 64);
    sk_bin.as_mut_slice().copy_from_slice(&keypair.secret_key);

    ((atoms::ok(), (Binary::from(pk_bin), Binary::from(sk_bin)))).encode(env)
}

#[rustler::nif]
fn sign<'a>(env: Env<'a>, data: Binary, private_key: Binary) -> Term<'a> {
    let secret_key_arr: [u8; 64] = match private_key.as_slice().try_into() {
        Ok(array) => array,
        Err(_) => return (atoms::error(), atoms::wrong_secret_key_size()).encode(env),
    };

    let mut signer = IncrementalSigner::new();

    signer.update(&data.to_vec());

    let signature: Signature = match signer.finalize(&secret_key_arr) {
        Ok(signature) => signature,
        Err(_) => return (atoms::error(), atoms::signing_failed()).encode(env),
    };

    let mut signature_bin = NewBinary::new(env, 64);
    signature_bin.as_mut_slice().copy_from_slice(&signature);

    (atoms::ok(), Binary::from(signature_bin)).encode(env)
}

rustler::init!("Elixir.Cafezinho.Impl", [keypair_from_seed, sign]);
