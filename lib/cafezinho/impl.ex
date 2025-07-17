defmodule Cafezinho.Impl do
  @moduledoc false

  version = Mix.Project.config()[:version]

  use RustlerPrecompiled,
    otp_app: :cafezinho,
    crate: :cafezinho,
    base_url: "https://github.com/ayrat555/cafezinho/releases/download/v#{version}",
    force_build: System.get_env("RUSTLER_BUILD") in ["1", "true"],
    targets: Enum.uniq(["x86_64-unknown-freebsd" | RustlerPrecompiled.Config.default_targets()]),
    nif_versions: ["2.15", "2.16"],
    version: version

  def keypair_from_seed(_seed), do: :erlang.nif_error(:nif_not_loaded)

  def sign(_data, _secret_key), do: :erlang.nif_error(:nif_not_loaded)

  def verify(_signature, _message, _public_key), do: :erlang.nif_error(:nif_not_loaded)

  def generate, do: :erlang.nif_error(:nif_not_loaded)

  def valid_point(_key), do: :erlang.nif_error(:nif_not_loaded)
end
