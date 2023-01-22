defmodule CafezinhoTest do
  use ExUnit.Case
  doctest Cafezinho

  describe "keypair_from_seed/1" do
    test "generates a keypair from seed" do
      seed =
        <<97, 206, 5, 203, 195, 215, 216, 130, 251, 253, 131, 27, 120, 106, 246, 46, 225, 5, 36,
          46, 60, 19, 106, 211, 197, 217, 46, 162, 244, 214, 170, 41>>

      assert {:ok,
              {<<198, 232, 50, 77, 218, 187, 252, 50, 14, 212, 55, 74, 4, 52, 81, 81, 136, 110,
                 204, 142, 139, 193, 20, 18, 152, 167, 102, 183, 183, 160, 42, 244>>,
               <<97, 206, 5, 203, 195, 215, 216, 130, 251, 253, 131, 27, 120, 106, 246, 46, 225,
                 5, 36, 46, 60, 19, 106, 211, 197, 217, 46, 162, 244, 214, 170, 41, 198, 232, 50,
                 77, 218, 187, 252, 50, 14, 212, 55, 74, 4, 52, 81, 81, 136, 110, 204, 142, 139,
                 193, 20, 18, 152, 167, 102, 183, 183, 160, 42,
                 244>>}} ==
               Cafezinho.keypair_from_seed(seed)
    end

    test "fails if seed of wrong size" do
      assert {:error, :wrong_seed_size} == Cafezinho.keypair_from_seed(<<>>)
    end
  end

  describe "sign/2" do
    test "signs data with private key" do
      assert {:ok,
              <<54, 59, 97, 68, 139, 126, 87, 13, 176, 190, 242, 53, 226, 86, 187, 47, 232, 124,
                215, 57, 205, 91, 194, 57, 22, 82, 93, 77, 179, 128, 28, 115, 32, 159, 105, 215,
                14, 69, 142, 87, 172, 248, 31, 197, 47, 20, 45, 202, 8, 249, 64, 29, 195, 171,
                129, 204, 198, 37, 183, 70, 235, 52, 89,
                2>>} =
               Cafezinho.sign(
                 "hello",
                 <<97, 206, 5, 203, 195, 215, 216, 130, 251, 253, 131, 27, 120, 106, 246, 46, 225,
                   5, 36, 46, 60, 19, 106, 211, 197, 217, 46, 162, 244, 214, 170, 41, 198, 232,
                   50, 77, 218, 187, 252, 50, 14, 212, 55, 74, 4, 52, 81, 81, 136, 110, 204, 142,
                   139, 193, 20, 18, 152, 167, 102, 183, 183, 160, 42, 244>>
               )
    end

    test "fails to sign is a private key is invalid" do
      assert {:error, :wrong_secret_key_size} =
               Cafezinho.sign(
                 "hello",
                 <<97>>
               )
    end
  end

  describe "generate/0" do
    test "generates a key pari" do
      assert {public_key, secret_key} = Cafezinho.generate()

      assert 32 == byte_size(public_key)
      assert 64 == byte_size(secret_key)
    end
  end

  describe "verify/3" do
    test "verifies a signature" do
      message = "hello"
      assert {public_key, secret_key} = Cafezinho.generate()

      assert {:ok, signature} = Cafezinho.sign(message, secret_key)

      assert :ok = Cafezinho.verify(signature, message, public_key)

      assert {:error, :invalid_signature} =
               Cafezinho.verify(signature, message, :crypto.strong_rand_bytes(32))
    end

    test "fails to verify a signature" do
      message = "goodbye"
      assert {_public_key, secret_key} = Cafezinho.generate()
      assert {:ok, signature} = Cafezinho.sign(message, secret_key)

      assert {:error, :invalid_signature} =
               Cafezinho.verify(signature, message, :crypto.strong_rand_bytes(32))
    end

    test "fails if signature size is wrong" do
      assert {:error, :wrong_signature_size} =
               Cafezinho.verify(<<1>>, <<1>>, :crypto.strong_rand_bytes(32))
    end

    test "fails if public key size is wrong" do
      assert {:error, :wrong_public_key_size} =
               Cafezinho.verify(
                 :crypto.strong_rand_bytes(64),
                 <<1>>,
                 :crypto.strong_rand_bytes(55)
               )
    end
  end
end
