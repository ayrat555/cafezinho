defmodule Cafezinho.MixProject do
  use Mix.Project

  @version "0.4.4"

  def project do
    [
      app: :cafezinho,
      version: @version,
      elixir: "~> 1.10",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: "NIF for Ed25519 curve functions",
      package: [
        maintainers: ["Ayrat Badykov"],
        licenses: ["MIT"],
        links: %{"GitHub" => "https://github.com/ayrat555/cafezinho"},
        files: [
          "mix.exs",
          "native/cafezinho/.cargo/config.toml",
          "native/cafezinho/src",
          "native/cafezinho/Cargo.toml",
          "native/cafezinho/Cargo.lock",
          "lib",
          "LICENSE",
          "README.md",
          "CHANGELOG.md",
          "checksum-*.exs"
        ]
      ]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:rustler, ">= 0.0.0", optional: true},
      {:rustler_precompiled, "~> 0.8"}
    ]
  end
end
