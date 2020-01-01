defmodule PlugBodyDigestTest do
  use ExUnit.Case
  doctest PlugBodyDigest

  import Plug.Conn
  import ExUnit.CaptureLog

  describe "success" do
    test "with empty body" do
      conn =
        conn(:get)
        |> with_digest("")
        |> call()

      refute conn.halted
    end

    test "with correct digest" do
      body = "test=123"

      conn =
        conn(:post, body)
        |> with_digest(body)
        |> call()

      refute conn.halted
      assert %{body_params: %{"test" => "123"}} = conn
    end

    test "with JSON body" do
      body = ~S({"test": 123})

      conn =
        conn(:post, body, "application/json")
        |> with_digest(body)
        |> call()

      refute conn.halted
      assert %{body_params: %{"test" => 123}} = conn
    end
  end

  describe "failure" do
    test "missing header" do
      scenario = fn ->
        conn =
          conn(:post, "test=123")
          |> call()

        assert conn.halted
        assert conn.status == 403
        assert [want_digest] = get_resp_header(conn, "want-digest")
        assert want_digest =~ "sha-256"
      end

      assert capture_log(scenario) =~ "no_digest_header"
    end

    test "with correct digest, no parser" do
      body = "test=123"

      scenario = fn ->
        conn =
          conn(:post, body, "text/plain")
          |> with_digest(body)
          |> call()

        assert conn.halted
        assert conn.status == 500
        assert [] = get_resp_header(conn, "want-digest")
      end

      assert capture_log(scenario) =~ "content type not handled by Plug.Parsers"
    end

    test "with multipart body" do
      multipart = """
      ------9H7VjX76etDQKRuR\r
      Content-Disposition: form-data; name=\"test\"\r
      \r
      123\r
      ------9H7VjX76etDQKRuR\r
      Content-Disposition: form-data; name=\"file\"; filename=\"foo.txt\"\r
      Content-Type: text/plain\r
      \r
      hello
      \r
      ------9H7VjX76etDQKRuR--\r
      """

      scenario = fn ->
        conn =
          conn(:post, multipart, "multipart/mixed; boundary=----9H7VjX76etDQKRuR")
          |> with_digest(multipart)
          |> call()

        assert conn.halted
        assert conn.status == 500
        assert [] = get_resp_header(conn, "want-digest")
      end

      assert capture_log(scenario) =~ "multipart content types are not supported"
    end

    test "unknown algorithm" do
      body = "test=123"

      scenario = fn ->
        conn =
          conn(:post, body)
          |> with_digest(%{"MD5" => :crypto.hash(:md5, body) |> Base.encode64()})
          |> call()

        assert conn.halted
        assert conn.status == 403
        assert [want_digest] = get_resp_header(conn, "want-digest")
        assert want_digest =~ "sha-256"
      end

      assert capture_log(scenario) =~ "algorithm_mismatch"
    end

    test "disabled algorithm" do
      body = "test=123"

      scenario = fn ->
        conn =
          conn(:post, body)
          |> with_digest(body)
          |> call(
            algorithms: [:sha512, :sha],
            parsers_opts: [
              body_reader: {PlugBodyDigest, :digest_body_reader, [[algorithms: [:sha512, :sha]]]}
            ]
          )

        assert conn.halted
        assert conn.status == 403
        assert [want_digest] = get_resp_header(conn, "want-digest")
        refute want_digest =~ "sha-256"
        assert want_digest =~ "sha-512"
      end

      assert capture_log(scenario) =~ "algorithm_mismatch"
    end

    test "unsupported algorithm" do
      body = "test=123"

      scenario = fn ->
        conn =
          conn(:post, body)
          |> with_digest(%{"nosuchthing" => Base.encode64("nosuchthing")})
          |> call(
            algorithms: [:nosuchthing],
            parsers_opts: [
              body_reader: {PlugBodyDigest, :digest_body_reader, [[algorithms: [:nosuchthing]]]}
            ]
          )

        assert conn.halted
        assert conn.status == 500
        assert [] = get_resp_header(conn, "want-digest")
      end

      assert capture_log(scenario) =~ "Invalid algorithm configuration"
      assert capture_log(scenario) =~ "nosuchthing"
    end
  end

  describe "callbacks" do
    test "on_success" do
      body = "test=123"

      conn =
        conn(:post, body)
        |> with_digest(body)
        |> call(on_success: {Plug.Conn, :assign, [:valid_digest, true]})

      assert conn.assigns[:valid_digest] == true
    end

    test "on_failure" do
      conn =
        conn(:post, "test=123")
        |> call(on_failure: fn conn, reason -> assign(conn, :failure_reason, reason) end)

      assert conn.assigns[:failure_reason] == :no_digest_header
    end
  end

  # Prepare a test connection without body
  defp conn(method) do
    Plug.Test.conn(method, "http://localhost:4000/")
  end

  # Prepare a test connection with body, and optional content-type
  defp conn(method, body, content_type \\ "application/x-www-form-urlencoded") do
    Plug.Test.conn(method, "http://localhost:4000/", body)
    |> put_req_header("content-type", content_type)
  end

  # Add a digest header with the given digest values
  defp with_digest(conn, digests) when is_map(digests) do
    digest_header =
      digests
      |> Enum.map(fn {alg, value} -> "#{alg}=#{value}" end)
      |> Enum.join(",")

    put_req_header(conn, "digest", digest_header)
  end

  # Add a digest header with a SHA-256 digest over the given body
  defp with_digest(conn, body) do
    with_digest(conn, %{"SHA-256" => :crypto.hash(:sha256, body) |> Base.encode64()})
  end

  @parsers_opts [
    parsers: [:urlencoded, :json, :multipart],
    pass: ["text/plain"],
    body_reader: {PlugBodyDigest, :digest_body_reader, []},
    json_decoder: Jason
  ]

  # Call Plug.Parsers and PlugBodyDigest
  defp call(conn, opts \\ []) do
    parsers_opts = Keyword.merge(@parsers_opts, Keyword.get(opts, :parsers_opts, []))

    conn
    |> Plug.Parsers.call(Plug.Parsers.init(parsers_opts))
    |> PlugBodyDigest.call(PlugBodyDigest.init(opts))
  end
end
