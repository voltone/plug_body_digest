defmodule PlugBodyDigest.Crypto do
  @moduledoc false

  defstruct [:algorithm, :hash_state, :expected]

  @spec init(:crypto.hash_algorithm(), binary()) ::
          {:ok, PlugBodyDigest.Crypto.t()} | {:error, :bad_algorithm}
  def init(algorithm, expected) do
    state = %__MODULE__{
      algorithm: algorithm,
      expected: expected,
      hash_state: :crypto.hash_init(algorithm)
    }

    {:ok, state}
  rescue
    ArgumentError ->
      {:error, :bad_algorithm}
  end

  @spec update(PlugBodyDigest.Crypto.t(), binary()) :: PlugBodyDigest.Crypto.t()
  def update(%__MODULE__{hash_state: hash_state} = state, data) do
    %{state | hash_state: :crypto.hash_update(hash_state, data)}
  end

  @spec verify(PlugBodyDigest.Crypto.t()) :: :ok | {:error, :digest_mismatch}
  def verify(%__MODULE__{hash_state: hash_state, expected: expected}) do
    case :crypto.hash_final(hash_state) do
      ^expected -> :ok
      _otherwise -> {:error, :digest_mismatch}
    end
  end

  @spec algorithm_name(:crypto.hash_algorithm()) :: String.t()
  # Standard RFC3230 and associated IANA registry:
  def algorithm_name(:sha512), do: "sha-512"
  def algorithm_name(:sha256), do: "sha-256"
  def algorithm_name(:sha), do: "sha"

  # Non-standard:
  def algorithm_name(:sha384), do: "sha-384"
  def algorithm_name(:sha224), do: "sha-224"
  def algorithm_name(:sha3_512), do: "sha3-512"
  def algorithm_name(:sha3_384), do: "sha3-384"
  def algorithm_name(:sha3_256), do: "sha3-256"
  def algorithm_name(:sha3_224), do: "sha3-224"
  def algorithm_name(:blake2b), do: "blake2b"
  def algorithm_name(:blake2s), do: "blake2s"

  # Fall-through:
  def algorithm_name(id), do: to_string(id)
end
