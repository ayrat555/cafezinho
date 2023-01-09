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
      iex> Cafezinho.keypair_from_seed(seed)
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
       <<37, 225, 143, 100, 95, 251, 157, 88, 34, 231, 246, 227, 213, 131, 39, 127,
         14, 193, 222, 155, 62, 214, 139, 133, 93, 114, 211, 59, 75, 137, 254, 20,
         212, 157, 16, 246, 108, 150, 29, 177, 177, 239, 132, 166, 194, 137, 182, 159,
         157, 243, 90, 106, 246, 210, 52, 87, 207, 208, 93, 49, 11, 245, 4, 8>>}

      iex> Cafezinho.sign(<<1>>, <<1>>)
      {:error, :wrong_secret_key_size}

  """
  @spec sign(binary(), binary()) :: {:ok, binary()} | {:error, atom()}
  def sign(data, secret_key) do
    Impl.sign(data, secret_key)
  end
end
