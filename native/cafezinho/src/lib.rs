use dryoc::sign::PublicKey;
use dryoc::sign::SecretKey;
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
        wrong_seed_size
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

rustler::init!("Elixir.Cafezinho.Impl", [keypair_from_seed]);
