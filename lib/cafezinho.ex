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
end
