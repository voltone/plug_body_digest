defmodule PlugBodyDigest.Crypto do
  @moduledoc false

  defstruct [:algorithm, :hash_state, :expected]

  @type t :: %__MODULE__{}

  @spec init(:crypto.hash_algorithm(), binary() | :no_digest_header) ::
          {:ok, t()} | {:error, :bad_algorithm}
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

  @spec update(t(), binary()) :: t()
  def update(%__MODULE__{hash_state: hash_state} = state, data) do
    %{state | hash_state: :crypto.hash_update(hash_state, data)}
  end

  @spec verify(t()) ::
          {:ok, PlugBodyDigest.final_digest()}
          | {:error, :no_digest_header, PlugBodyDigest.final_digest()}
          | {:error, :digest_mismatch, PlugBodyDigest.final_digest()}
  def verify(%__MODULE__{
        algorithm: algorithm,
        hash_state: hash_state,
        expected: :no_digest_header
      }) do
    {:error, :no_digest_header, {algorithm, :crypto.hash_final(hash_state)}}
  end

  def verify(%__MODULE__{algorithm: algorithm, hash_state: hash_state, expected: expected}) do
    digest = :crypto.hash_final(hash_state)

    case digest do
      ^expected -> {:ok, {algorithm, digest}}
      _otherwise -> {:error, :digest_mismatch, {algorithm, digest}}
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
