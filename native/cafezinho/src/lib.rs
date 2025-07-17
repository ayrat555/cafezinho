use dryoc::sign::PublicKey;
use dryoc::sign::SecretKey;
use dryoc::sign::SignedMessage;
use dryoc::sign::SigningKeyPair;
use dryoc::classic::crypto_core::crypto_core_ed25519_is_valid_point_relaxed ;
use dryoc::types::StackByteArray;
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
        wrong_key_size,
        wrong_secret_key_size,
        wrong_public_key_size,
        wrong_signature_size,
        invalid_signature,
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
    let serialized_keypair = serialize_keypair(env, keypair);

    (atoms::ok(), serialized_keypair).encode(env)
}

#[rustler::nif]
fn sign<'a>(env: Env<'a>, data: Binary, private_key: Binary) -> Term<'a> {
    let secret_key: StackByteArray<64> = match private_key.as_slice().try_into() {
        Ok(array) => array,
        Err(_) => return (atoms::error(), atoms::wrong_secret_key_size()).encode(env),
    };

    let signature = match SigningKeyPair::<PublicKey, SecretKey>::from_secret_key(secret_key)
        .sign_with_defaults(data.as_slice())
    {
        Ok(signature) => signature,
        Err(_) => return (atoms::error(), atoms::signing_failed()).encode(env),
    };

    let signature_raw = signature.into_parts().0;

    let mut signature_bin = NewBinary::new(env, 64);
    signature_bin.as_mut_slice().copy_from_slice(&signature_raw);

    (atoms::ok(), Binary::from(signature_bin)).encode(env)
}

#[rustler::nif]
fn valid_point<'a>(env: Env<'a>, key: Binary) -> Term<'a> {
    let key_arr: [u8; 32] = match key.as_slice().try_into() {
        Ok(array) => array,
        Err(_) => return (atoms::error(), atoms::wrong_key_size()).encode(env),
    };


    let result = crypto_core_ed25519_is_valid_point_relaxed(&key_arr);

    (atoms::ok(), result.encode(env)).encode(env)
}

#[rustler::nif]
fn generate<'a>(env: Env<'a>) -> Term<'a> {
    let keypair = SigningKeyPair::<PublicKey, SecretKey>::gen();

    let serialized_keypair = serialize_keypair(env, keypair);

    serialized_keypair.encode(env)
}

#[rustler::nif]
fn verify<'a>(env: Env<'a>, signature: Binary, message: Binary, public_key: Binary) -> Term<'a> {
    let signature: [u8; 64] = match signature.as_slice().try_into() {
        Ok(array) => array,
        Err(_) => return (atoms::error(), atoms::wrong_signature_size()).encode(env),
    };

    let public_key: StackByteArray<32> = match public_key.as_slice().try_into() {
        Ok(array) => array,
        Err(_) => return (atoms::error(), atoms::wrong_public_key_size()).encode(env),
    };

    let message_with_signature = [&signature, message.as_slice()].concat();

    let signed_message =
        match SignedMessage::<Vec<u8>, Vec<u8>>::from_bytes(&message_with_signature) {
            Ok(signed_message) => signed_message,
            Err(_) => return (atoms::error(), atoms::invalid_signature()).encode(env),
        };

    match signed_message.verify(&public_key) {
        Ok(()) => (atoms::ok()).encode(env),
        Err(_) => return (atoms::error(), atoms::invalid_signature()).encode(env),
    }
}

fn serialize_keypair<'a>(
    env: Env<'a>,
    keypair: SigningKeyPair<PublicKey, SecretKey>,
) -> (Binary<'a>, Binary<'a>) {
    let mut pk_bin = NewBinary::new(env, 32);
    pk_bin.as_mut_slice().copy_from_slice(&keypair.public_key);

    let mut sk_bin = NewBinary::new(env, 64);
    sk_bin.as_mut_slice().copy_from_slice(&keypair.secret_key);

    (Binary::from(pk_bin), Binary::from(sk_bin))
}

rustler::init!("Elixir.Cafezinho.Impl");
