defmodule Cafezinho.Impl do
  @moduledoc false

  use Rustler, otp_app: :cafezinho, crate: :cafezinho

  def keypair_from_seed(_seed), do: :erlang.nif_error(:nif_not_loaded)

  def sign(_data, _secret_key), do: :erlang.nif_error(:nif_not_loaded)

  def verify(_signature, _message, _public_key), do: :erlang.nif_error(:nif_not_loaded)

  def generate, do: :erlang.nif_error(:nif_not_loaded)
end
