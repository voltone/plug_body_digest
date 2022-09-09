defmodule PlugBodyDigest.ConnTest do
  @moduledoc """
  Helpers for testing request body digests with Plug/Phoenix.

  ## Note

  When testing with `Plug.Test` or `Phoenix.ConnTest`, the request body is not
  always read through `Plug.Parsers`, in which case the custom `body_reader` is
  not invoked. In particular this happens when setting `params_or_body` to a
  map.

  Digest header verification is skipped when this happens, so in test cases that
  verify the correct handling of the Digest header, both for positive and
  negative test scenarions, always pass in the body as a binary!
  """

  import Plug.Conn

  @doc """
  Add an HTTP Digest header (RFC3230, section 4.3.2).

  When the request body is passed in as a binary, a SHA-256 digest of the body
  is calculated and added as part of the header. Alternatively, a map of
  digest types and values may be provided.
  """
  def with_digest(conn, body_or_digests)

  def with_digest(conn, digests) when is_map(digests) do
    digest_header = Enum.map_join(digests, ",", fn {alg, value} -> "#{alg}=#{value}" end)
    put_req_header(conn, "digest", digest_header)
  end

  def with_digest(conn, body) do
    with_digest(conn, %{"SHA-256" => :crypto.hash(:sha256, body) |> Base.encode64()})
  end
end
