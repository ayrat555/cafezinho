defmodule Cafezinho.Impl do
  @moduledoc false

  use Rustler, otp_app: :cafezinho, crate: :cafezinho

  def keypair_from_seed(_seed),
    do: :erlang.nif_error(:nif_not_loaded)
end
