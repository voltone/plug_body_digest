defmodule PlugBodyDigest.MixProject do
  use Mix.Project

  @version "0.8.0"

  def project do
    [
      app: :plug_body_digest,
      version: @version,
      elixir: "~> 1.6",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: description(),
      package: package(),
      docs: docs(),
      source_url: "https://github.com/voltone/plug_body_digest"
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger, :crypto]
    ]
  end

  defp description do
    "Server side implementation of RFC3230 Instance Digests as a Plug"
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    mime_version =
      if Version.match?(System.version(), ">= 1.10.0") do
        "~> 1.5 or ~> 2.0"
      else
        "~> 1.5"
      end

    [
      {:plug, "~> 1.5"},
      {:mime, mime_version},
      {:ex_doc, "~> 0.21", only: :dev},
      {:credo, "~> 1.1", only: :dev},
      {:jason, "~> 1.0", only: [:dev, :test]}
    ]
  end

  defp package do
    [
      maintainers: ["Bram Verburg"],
      licenses: ["BSD-3-Clause"],
      links: %{"GitHub" => "https://github.com/voltone/plug_body_digest"}
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: ["README.md"],
      source_ref: "v#{@version}"
    ]
  end
end
