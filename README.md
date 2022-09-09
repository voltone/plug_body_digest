# PlugBodyDigest

[![Github.com](https://github.com/voltone/plug_body_digest/workflows/CI/badge.svg)](https://github.com/voltone/plug_body_digest/actions)
[![Hex.pm](https://img.shields.io/hexpm/v/plug_body_digest.svg)](https://hex.pm/packages/plug_body_digest)
[![Hexdocs.pm](https://img.shields.io/badge/hex-docs-lightgreen.svg)](https://hexdocs.pm/plug_body_digest/)
[![Hex.pm](https://img.shields.io/hexpm/dt/plug_body_digest.svg)](https://hex.pm/packages/plug_body_digest)
[![Hex.pm](https://img.shields.io/hexpm/l/plug_body_digest.svg)](https://hex.pm/packages/plug_body_digest)
[![Github.com](https://img.shields.io/github/last-commit/voltone/plug_body_digest.svg)](https://github.com/voltone/plug_body_digest/commits/master)

Plug to verify the request body against the digest value sent in the HTTP
'Digest' header, as defined in [RFC3230, section 4.3.2](https://tools.ietf.org/html/rfc3230#section-4.3.2).
Typically used in combination with an HTTP request signature covering the
'Digest' header value, to protect the integrity of the complete request.

By default halts the request in case of failure, for example if no Digest
header was sent or the request body did not match the specified digest value.
Failure and success handling can be customized using the configuration options
documented in the `PlugBodyDigest` module.

***Please note***: this package supports parsers that respect the
`:body_reader` option of `Plug.Parsers`, including `Plug.Parsers.URLENCODED`
and `Plug.Parsers.JSON`. ***Not*** supported are `Plug.Parsers.MULTIPART` and
content types that are ignored by `Plug.Parsers` through the `:pass` option.

Development and public release of this package were made possible by
[Bluecode](https://bluecode.com/).

## Example

Update the `Plug.Parsers` configuration, e.g. in application's Phoenix
Endpoint, to use the `PlugBodyDigest.digest_body_reader/2,3` function for
reading the request body:

```elixir
plug Plug.Parsers,
  parsers: [:urlencoded, :json],
  body_reader: {PlugBodyDigest, :digest_body_reader, []},
  json_decoder: Jason
```

Add `PlugBodyDigest`, somewhere after `Plug.Parsers`, for example in a
Phoenix Router pipeline:

```elixir
pipeline :api do
  plug :accepts, ["json"]
  plug PlugBodyDigest
end
```

Or in a Phoenix Controller:

```elixir
defmodule MyAppWeb.APIController do
  use MyAppWeb, :controller

  # Failure handling options or PlugBodyDigest
  @mandatory []
  @optional [on_failure: {PlugBodyDigest, :optional, []}]

  # Digest header is required for POST and PUT, optional otherwise
  plug PlugBodyDigest, @mandatory when action in [:create, :update]
  plug PlugBodyDigest, @optional when action in [:index, :show, :delete]

  # ...
end
```

## Testing

When testing with `Plug.Test` or `Phoenix.ConnTest`, the request body is not
always read through `Plug.Parsers`, in which case the custom `body_reader` is
not invoked. In particular this happens when setting `params_or_body` to a
map.

Digest header verification is skipped when this happens, so in test cases that
verify the correct handling of the Digest header, both for positive and
negative test scenarions, always pass in the body as a binary!

## Installation

Add `plug_body_digest` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:plug_body_digest, "~> 0.5.0"}
  ]
end
```

Documentation can be found at [https://hexdocs.pm/plug_body_digest](https://hexdocs.pm/plug_body_digest).

## License

Copyright (c) 2019, Bram Verburg
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of the copyright holder nor the names of its contributors
  may be used to endorse or promote products derived from this software
  without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
