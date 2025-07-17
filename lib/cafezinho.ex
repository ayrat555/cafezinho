defmodule Cafezinho do
  @moduledoc """
  NIF for Ed25519 curve functions.

  It uses https://github.com/brndnmtthws/dryoc
  """

  alias Cafezinho.Impl

  @doc """
  Create a keypair from seed

  ## Examples

      iex> seed = <<216, 145, 38, 65, 213, 88, 1, 110, 133, 87, 170, 172, 147, 33, 96, 73, 164, 121, 52, 37, 94, 100, 25, 147, 124, 8, 232, 161, 104, 122, 232, 44>>
      iex> {:ok, {_public_key, _secret_key}} = Cafezinho.keypair_from_seed(seed)
      {:ok,
        {<<218, 140, 98, 244, 76, 48, 223, 187, 117, 177, 228, 75, 120, 10, 202, 138,
           48, 149, 51, 209, 225, 87, 148, 132, 229, 110, 178, 4, 19, 205, 1, 218>>,
         <<216, 145, 38, 65, 213, 88, 1, 110, 133, 87, 170, 172, 147, 33, 96, 73, 164,
           121, 52, 37, 94, 100, 25, 147, 124, 8, 232, 161, 104, 122, 232, 44, 218,
           140, 98, 244, 76, 48, 223, 187, 117, 177, 228, 75, 120, 10, 202, 138, 48,
           149, 51, 209, 225, 87, 148, 132, 229, 110, 178, 4, 19, 205, 1, 218>>}}

      iex> Cafezinho.keypair_from_seed(<<1>>)
      {:error, :wrong_seed_size}
  """
  @spec keypair_from_seed(binary()) :: {:ok, {binary(), binary()}} | {:error, atom()}
  def keypair_from_seed(seed) do
    Impl.keypair_from_seed(seed)
  end

  @doc """
  Sign data with a secret key

  ## Examples

      iex> secret_key = <<216, 145, 38, 65, 213, 88, 1, 110, 133, 87, 170, 172, 147, 33, 96, 73, 164, 121, 52, 37, 94, 100, 25, 147, 124, 8, 232, 161, 104, 122, 232, 44, 218, 140, 98, 244, 76, 48, 223, 187, 117, 177, 228, 75, 120, 10, 202, 138, 48, 149, 51, 209, 225, 87, 148, 132, 229, 110, 178, 4, 19, 205, 1, 218>>
      iex> Cafezinho.sign(<<1>>, secret_key)
      {:ok,
       <<51, 122, 38, 168, 118, 176, 54, 245, 199, 189, 126, 196, 119, 78, 149, 111,
         125, 5, 46, 219, 166, 158, 141, 137, 68, 236, 151, 104, 101, 191, 138, 78,
         53, 119, 225, 244, 115, 101, 250, 155, 3, 177, 193, 130, 141, 19, 13, 30, 14,
         18, 177, 153, 84, 70, 137, 156, 114, 97, 174, 138, 138, 154, 230, 10>>}

      iex> Cafezinho.sign(<<1>>, <<1>>)
      {:error, :wrong_secret_key_size}

  """
  @spec sign(binary(), binary()) :: {:ok, binary()} | {:error, atom()}
  def sign(data, secret_key) do
    Impl.sign(data, secret_key)
  end

  @doc """
  Verify a signature

  ## Examples

      iex> signature =  <<188, 159, 33, 122, 42, 62, 50, 237, 156, 38, 95, 81, 116, 233, 254, 0, 113, 220, 29, 152, 198, 72, 126, 188, 85, 239, 86, 29, 26, 182, 11, 208, 25, 30, 189, 99, 92, 76, 42, 245, 1, 116, 24, 179, 247, 221, 20, 178, 225, 31, 88, 175, 42, 250, 66, 0, 212, 98, 24, 184, 61, 216, 8, 3>>
      iex> message = "hello"
      iex> public_key = <<23, 99, 168, 199, 198, 90, 121, 227, 169, 127, 53, 174, 114, 190, 61, 47, 53, 134, 214, 246, 207, 46, 83, 75, 163, 249, 253, 145, 4, 11, 87, 190>>
      iex> Cafezinho.verify(signature, message, public_key)
      :ok

      iex> Cafezinho.verify("signature", "bye", "public_key")
      {:error, :wrong_signature_size}
  """

  @spec verify(binary(), binary(), binary()) :: :ok | {:error, atom()}
  def verify(signature, message, public_key) do
    Impl.verify(signature, message, public_key)
  end

  @doc """
  Generate a random keypair

  ## Examples

      iex> {<<_public_key::binary-size(32)>>, <<_secret_key::binary-size(64)>>} = Cafezinho.generate()
  """
  @spec generate() :: {binary(), binary()}
  def generate do
    Impl.generate()
  end

  @doc """
  Validates if key is on Ed25519 curve

  ## Examples

      iex> {<<public_key::binary-size(32)>>, _} = Cafezinho.generate()
      iex> Cafezinho.valid_point?(public_key)
      true

      iex> Cafezinho.valid_point?(<<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>)
      false
  """
  @spec valid_point?(binary()) :: boolean()
  def valid_point?(key) do
    case Impl.valid_point(key) do
      {:ok, true} -> true
      _ -> false
    end
  end
end
