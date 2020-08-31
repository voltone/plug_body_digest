defmodule PlugBodyDigest do
  @moduledoc """
  Plug to verify the request body against the digest value sent in the HTTP
  'Digest' header, as defined in [RFC3230, section 4.3.2](https://tools.ietf.org/html/rfc3230#section-4.3.2).

  Supported digests are "sha-512", "sha-256" and "sha".

  ## Options

    * `:on_success` - an optional callback for updating the `Plug.Conn` state
      upon success; possible values include:
        * `nil` (the default) - do nothing
        * `{m, f, a}` - call the function identified by the atom `f` in module
          `m`; the function receives the current `Plug.Conn` struct along with
          any additional parameters in the list `a`, and is expected to return
          the updated `Plug.Conn` struct; see the example below
    * `:on_failure` - an optional callback for updating the `Plug.Conn` state
      upon failure; possible values include:
        * `{PlugBodyDigest, :failure, []}` (the default) - halt the connection
          with an appropriate response; see `failure/3` below
        * `{PlugBodyDigest, :optional, []}` - make the 'Digest' header
          optional; see `optional/3` below
        * `{m, f, a}` - call the function identified by the atom `f` in module
          `m`; the function receives the current `Plug.Conn` struct, the error
          reason (see `t:error_reason/0`) and the algorithm list (a string,
          for possible use in a 'Want-Digest' response header) along with any
          additional parameters in the list `a`, and is expected to return the
          updated `Plug.Conn` struct
        * `nil` - do nothing

  ## Example

      # Update the Plug.Parsers configuration, adding the `:body_reader`
      # option:
      plug Plug.Parsers,
        parsers: [:urlencoded, :json],
        body_reader: {PlugBodyDigest, :digest_body_reader, []},
        json_decoder: Jason

      # Invoke PlugBodyDigest after Plug.Parsers
      plug PlugBodyDigest,
        on_success: {Plug.Conn, :assign, [:valid_digest, true]},
        on_failure: {PlugBodyDigest, :optional, []}
  """

  import Plug.Conn
  require Logger
  alias PlugBodyDigest.Crypto

  @behaviour Plug

  @algorithms [:sha512, :sha256, :sha]
  @default_on_success nil
  @default_on_failure {__MODULE__, :failure, []}

  @typedoc """
  Error reasons, passed to the failure callback.

  Server errors:

    * `:body_not_read` - the request body was not read, because the request's
      'Content-Type' is not handled by `Plug.Parsers`; see
      `digest_body_reader/3`
    * `:multipart` - the request contained a multipart content-type, which is
      not supported by `PlugBodyDigest`; see `digest_body_reader/3`
    * `:bad_algorithm` - the digest function invocation failed for the
      selected algorithm; verify that the `:crypto` application was started
      and that it supports the necessary algorithms

  Client errors:

    * `:no_digest_header` - no 'Digest' header was included in the request
    * `:algorithm_mismatch` - none of the supported digest algorithms was
      included in the 'Digest' request header
    * `:malformed_digest_value` - the digest value in the 'Digest' request
      header could not be decoded
    * `:digest_mismatch` - the calculated digest value for the request body
      does not match the expected value specified in the 'Digest' request
      header
  """
  @type error_reason ::
          :body_not_read
          | :multipart
          | :bad_algorithm
          | :no_digest_header
          | :algorithm_mismatch
          | :malformed_digest_value
          | :digest_mismatch

  @impl true
  @spec init(Keyword.t()) :: Keyword.t()
  def init(opts), do: opts

  @impl true
  @spec call(Plug.Conn.t(), Keyword.t()) :: Plug.Conn.t()
  def call(conn, opts) do
    # The `algorithms` option is currently undocumented: it is a bit awkward to
    # use, since the configuration of the Plug needs to match that of the
    # `body_reader` function...
    algorithms = Keyword.get(opts, :algorithms, @algorithms)

    case verify(conn, algorithms) do
      :ok ->
        opts
        |> Keyword.get(:on_success, @default_on_success)
        |> on_success(conn)

      {:error, reason} ->
        want_digest =
          algorithms
          |> Enum.map(&Crypto.algorithm_name/1)
          |> Enum.join(",")

        opts
        |> Keyword.get(:on_failure, @default_on_failure)
        |> on_failure(conn, reason, want_digest)
    end
  end

  defp verify(%{private: %{plug_body_digest: {:error, _reason} = error}}, _algorithms) do
    error
  end

  defp verify(%{private: %{plug_body_digest: state}}, _algorithms) do
    Crypto.verify(state)
  end

  defp verify(%{body_params: %Plug.Conn.Unfetched{aspect: :body_params}}, _algorithms) do
    {:error, :body_not_read}
  end

  defp verify(%{private: %{plug_multipart: :done}}, _algorithms) do
    {:error, :multipart}
  end

  defp verify(%{body_params: empty} = conn, algorithms) when empty == %{} do
    conn
    |> update_digest("", algorithms: algorithms)
    |> verify(algorithms)
  end

  defp verify(%Plug.Conn{adapter: {Plug.Adapters.Test.Conn, _}}, _algorithms) do
    # When testing with Plug.Test the request body is not always read through
    # Plug.Parsers, so the custom `body_reader` is not invoked. If realistic
    # Digest header handing is required in tests, always pass in the body
    # as a binary in `Plug.Test.conn/3`!
    :ok
  end

  defp on_success(nil, conn), do: conn
  defp on_success({m, f, a}, conn), do: apply(m, f, [conn | a])
  defp on_success(fun, conn) when is_function(fun, 1), do: fun.(conn)

  defp on_failure(nil, conn, _reason, _want_digest), do: conn

  defp on_failure({m, f, a}, conn, reason, want_digest),
    do: apply(m, f, [conn, reason, want_digest | a])

  defp on_failure(fun, conn, reason, want_digest) when is_function(fun, 3),
    do: fun.(conn, reason, want_digest)

  defp on_failure(fun, conn, reason, _want_digest) when is_function(fun, 2),
    do: fun.(conn, reason)

  @doc """
  The default failure function.

  It logs an error, returns a 500 'Server Error' response and halts the
  connection in the following scenarios:

   * If the request body was not read, because the request's 'Content-Type' is
     not handled by `Plug.Parsers`; see `digest_body_reader/3`
   * If the digest function invocation failed for the selected algorithm

  Otherwise logs the failure, returns a 403 'Forbidden' response with a
  'Want-Digest' response header listing the supported algorithms, and halts
  the connection.
  """
  @spec failure(Plug.Conn.t(), error_reason(), String.t()) :: Plug.Conn.t()
  def failure(conn, :body_not_read, _want_digest) do
    Logger.error("Cannot verify digest: content type not handled by Plug.Parsers")

    conn
    |> send_resp(500, "")
    |> halt()
  end

  def failure(conn, :multipart, _want_digest) do
    Logger.error("Cannot verify digest: multipart content types are not supported")

    conn
    |> send_resp(500, "")
    |> halt()
  end

  def failure(conn, :bad_algorithm, want_digest) do
    Logger.error("Invalid algorithm configuration: #{want_digest}")

    conn
    |> send_resp(500, "")
    |> halt()
  end

  def failure(conn, reason, want_digest) do
    Logger.info("Digest failure: #{reason}")

    conn
    |> put_resp_header("want-digest", want_digest)
    |> send_resp(403, "")
    |> halt()
  end

  @doc """
  An alternative failure handler function, allowing requests without a
  'Digest' request header.

  All other errors are handled as described for `failure/3`.
  """
  @spec optional(Plug.Conn.t(), error_reason(), String.t()) :: Plug.Conn.t()
  def optional(conn, :no_digest_header, _want_digest), do: conn
  def optional(conn, reason, want_digest), do: failure(conn, reason, want_digest)

  @doc """
  Custom request body reader for `Plug.Parsers`, updating the digest
  value(s) while the request body is being read.

  Add or update `Plug.Parsers` (e.g. in the application's Phoenix endpoint)
  with the `:body_reader` option:

      plug Plug.Parsers,
        parsers: [:urlencoded, :json],
        body_reader: {PlugBodyDigest, :digest_body_reader, []},
        json_decoder: Jason

  Only works for parsers that respect the `:body_reader` option, including
  `Plug.Parsers.URLENCODED` and `Plug.Parsers.JSON`. Not supported are
  `Plug.Parsers.MULTIPART` and content types that are ignored by `Plug.Parsers`
  through the `:pass` option.
  """
  @spec digest_body_reader(Plug.Conn.t(), Keyword.t(), Keyword.t()) ::
          {:ok, binary(), Plug.Conn.t()} | {:more, binary(), Plug.Conn.t()} | {:error, term()}
  def digest_body_reader(conn, read_opts, digest_opts \\ []) do
    case Plug.Conn.read_body(conn, read_opts) do
      {status, body, conn} ->
        {status, body, update_digest(conn, body, digest_opts)}

      error ->
        error
    end
  end

  # Error condition, no need to do anything
  defp update_digest(%{private: %{plug_body_digest: {:error, _}}} = conn, _data, _opts), do: conn

  # This is not the first pass: update with new data
  defp update_digest(%{private: %{plug_body_digest: state}} = conn, data, _opts) do
    put_private(conn, :plug_body_digest, Crypto.update(state, data))
  end

  # First pass, look for Digest header and select one algorithm
  defp update_digest(conn, data, opts) do
    algorithms = Keyword.get(opts, :algorithms, @algorithms)

    with {:ok, digest_header} <- get_digest_header(conn),
         {:ok, algorithm, expected} <- select_algorithm(digest_header, algorithms),
         {:ok, initial} <- Crypto.init(algorithm, expected) do
      put_private(conn, :plug_body_digest, Crypto.update(initial, data))
    else
      error ->
        put_private(conn, :plug_body_digest, error)
    end
  end

  defp get_digest_header(conn) do
    case get_req_header(conn, "digest") do
      [] -> {:error, :no_digest_header}
      digest_headers -> {:ok, parse_digest(digest_headers)}
    end
  end

  defp parse_digest(digest_headers) do
    digest_headers
    |> Enum.flat_map(&:binary.split(&1, ",", [:global]))
    |> Enum.map(&String.trim/1)
    |> Enum.map(fn instance ->
      case :binary.split(instance, "=") do
        [algorithm, digest] -> {String.downcase(algorithm), digest}
        _otherwise -> nil
      end
    end)
    |> Enum.into(%{})
  end

  defp select_algorithm(_digests, []), do: {:error, :algorithm_mismatch}

  defp select_algorithm(digests, [algorithm | more]) do
    case Map.get(digests, Crypto.algorithm_name(algorithm)) do
      nil ->
        select_algorithm(digests, more)

      expected_b64 ->
        case Base.decode64(expected_b64) do
          :error -> {:error, :malformed_digest_value}
          {:ok, expected} -> {:ok, algorithm, expected}
        end
    end
  end
end
