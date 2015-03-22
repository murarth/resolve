# resolve

`resolve` is a pure Rust implementation of the DNS communication protocol.

It also provides high level facilities for hostname resolution and address
reverse resolution.

[Documentation](http://murarth.github.io/resolve/resolve/index.html)

## Platform Support

Presently, `resolve` depends on [`mio`](https://github.com/carllerche/mio)
for non-blocking socket read operations. At this time, `mio` does not support
Windows. Therefore, `resolve` does not currently support Windows.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
resolve = "*"
```

And this to your crate root:

```rust
extern crate resolve;
```

## License

`resolve` is distributed under the terms of both the MIT license and the
Apache License (Version 2.0).

See LICENSE-APACHE and LICENSE-MIT for details.
