# dnf-compat-layer

Compatibility libraries for running Dungeon & Fighter (DNF) server components on modern Linux.

## Libraries

### geoip-compat

Replacement for the GeoIP Legacy C library `libGeoIP.so`. Reads `.dat` database files and returns country codes. Only the Country edition is supported.

Exported functions:

| Function | Description |
|---|---|
| `GeoIP_new` | Opens the database from default search paths |
| `GeoIP_open` | Opens the database from a given file path |
| `GeoIP_country_code_by_addr` | Returns country code for an IPv4 address string |
| `GeoIP_country_code_by_name` | Alias for `GeoIP_country_code_by_addr` |
| `GeoIP_delete` | Frees the database handle |

Default database search paths:

- `/usr/local/share/GeoIP/GeoIP.dat`
- `/usr/share/GeoIP/GeoIP.dat`
- `/var/lib/GeoIP/GeoIP.dat`
- `/data/GeoIP/GeoIP.dat`

### glibc-compat

Replaces several glibc functions through `LD_PRELOAD` to fix compatibility issues on modern linux.

**shm_open / shm_unlink**

Replaces embedded slashes in shared memory object names with underscores. Newer glibc versions reject names with slashes after the leading `/`.

**stat family**

Replaces `__xstat`, `__xstat64`, `__fxstat`, `__fxstat64`, `__lxstat`, `__lxstat64`. Calls the kernel directly through `int 0x80` syscalls instead of glibc wrappers.

Applies the same slash-to-underscore rewrite to `/dev/shm/` paths. A `stat` on `/dev/shm/a/b` then resolves to `/dev/shm/a_b`.

**mkdir**

Treats `EEXIST` as success. The call does not fail when the target directory already exists.


## Building

**Prerequisites:**

- [Rust](https://rustup.rs/) toolchain (stable channel)

**Build commands:**

```bash
# Build all crates for the host platform
cargo build --release

# Build for 32-bit Linux
rustup target add i686-unknown-linux-gnu
cargo build --release --target i686-unknown-linux-gnu

# Run tests
cargo test
```

## License

MIT License - see the [LICENSE](LICENSE) file for details.
