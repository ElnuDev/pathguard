# pathguard

> [!NOTE]
> **AI usage disclosure.** The project itself is hand-written; AI was
> not used in its design or original implementation. AI assistance was
> used only for two narrowly scoped tasks: a recent security audit and
> the follow-up fixes that came out of it, and the first draft of this
> README.

A small, customizable password-protection layer that sits in front of an
HTTP service or a local directory. Think "put a login wall on the thing"
for self-hosted setups where you don't want to wire up a full identity
provider.

pathguard ships with:

- An admin dashboard for managing users, groups, and access rules.
- A rule engine that controls which URL paths each group can reach.
- An activity log of every authenticated and anonymous access decision.
- A NixOS module for the impatient.

It's a one-binary, one-SQLite-file deployment with no external dependencies
at runtime.

## Modes

pathguard runs in one of two modes, picked as a subcommand:

```
pathguard [options] proxy <port>     # reverse-proxy to 127.0.0.1:<port>
pathguard [options] files <root>     # serve files from <root> with a browser UI
```

In **proxy** mode, authenticated requests are forwarded to a backend
listening on the given local port; the backend sees an added
`X-Pathguard-User` header identifying the caller.

In **files** mode, pathguard itself serves the directory tree, hides
files that the caller's rules don't permit, and renders a minimal
file-browser UI.

In both modes, the admin dashboard is mounted at `/pathguard` (or
wherever `--dashboard` points).

## Quick start

You'll need a nightly Rust toolchain.

```sh
# Serve ./public behind a login wall.
cargo run -p pathguard -- files ./public

# Or reverse-proxy a service already running on port 3000.
cargo run -p pathguard -- proxy 3000
```

Visit <http://localhost:8000/pathguard>. Log in as `admin` / `password`
(change this immediately — see [Security](#security)). From the
dashboard you can create groups, add rules, and create additional
users.

## Concepts

### Users and groups

- A **user** has a name and password and belongs to one or more groups.
- A **group** is a named, ordered collection of access rules.
- The seeded `admin` user bypasses all rules and has access to the
  dashboard.
- The seeded `default` group governs **anonymous** (not-logged-in)
  access. Add allow rules here to expose specific paths publicly.

### Rules

A rule is `(path_prefix, allow | block | unset)`. When a request comes
in, pathguard walks all rules for all groups the caller belongs to in
sort order; the **last matching rule's verdict wins**. If nothing
matches, the request is blocked.

Prefix matching is on path-component boundaries: a rule for `/public`
matches `/public` and `/public/anything` but **not** `/publicfile`.

`unset` rules are placeholders — useful when you want to keep a rule's
position in the sort order but neither allow nor block.

### Activity log

Every authenticated and anonymous access decision is written to the
`activities` table and surfaced at `/pathguard/activity`, with
filtering by user and path. Admin actions are not logged (you can see
who the admin is by definition).

## CLI

```
pathguard [OPTIONS] <COMMAND>

Options:
      --db <PATH>                       Database file (default: database.db)
  -k, --key <PATH>                      Session-key file (default: session.key)
  -p, --port <PORT>                     Listen port on 127.0.0.1 (default: 8000)
  -d, --dashboard <PATH>                Dashboard mount path (default: /pathguard)
  -m, --min-password-strength <SCORE>   Reject passwords below this score, 0–100
                                        (default: 60.0)
      --trust-forwarded-for             Trust Forwarded / X-Forwarded-For when
                                        recording the client IP in the activity
                                        log. Only enable when behind a reverse
                                        proxy that strips client-supplied copies.
                                        Default: off.

Commands:
  proxy <PORT>    Reverse-proxy authenticated requests to 127.0.0.1:<PORT>
  files <ROOT>    Serve files from <ROOT>
```

The database and session-key files are created with mode `0600` on
first run.

## Proxy mode: passing user identity to the backend

Every proxied request carries an `X-Pathguard-User` header:

```
X-Pathguard-User: alice       # authenticated user "alice"
X-Pathguard-User:             # anonymous-but-allowed caller
```

The header is **always present** on requests pathguard forwards — its
presence is the signal "this came through pathguard." Any client-supplied
copy of the header is stripped before pathguard injects its own, so a
backend can trust the value as long as the only path to it is through
pathguard (enforce that with a firewall or by binding the backend to
`127.0.0.1`).

pathguard's own session cookie (`pathguard_id`) is stripped from the
forwarded `Cookie` header. Other cookies pass through unchanged.

## Deploying with Nix

The flake exposes both a package and a NixOS module:

```nix
{
  inputs.pathguard.url = "github:ElnuDev/pathguard";

  outputs = { self, nixpkgs, pathguard, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        pathguard.nixosModules.default
        ({ ... }: {
          services.pathguard = {
            enable = true;
            port = 8000;
            dashboard = "/pathguard";
            minPasswordStrength = 60;
            mode = {
              kind = "files";
              root = "/srv/public";
            };
            # Set to true ONLY if you're behind a proxy that
            # strips client-supplied X-Forwarded-For. The default
            # is false; the activity log uses the peer address.
            trustForwardedFor = false;
          };
        })
      ];
    };
  };
}
```

The systemd unit uses `DynamicUser=true` and a `StateDirectory`, so the
database and session key live in `/var/lib/pathguard` with restrictive
permissions out of the box.

Running ad hoc against this flake:

```sh
nix run github:ElnuDev/pathguard -- files ./public
```

## Security

pathguard is designed for a specific threat model: keeping casual
internet traffic and untrusted LAN peers out of a self-hosted service.
It is **not** designed to replace SSO, MFA, or any system where the
passwords being protected are high-value credentials in their own right.

Some specifics worth knowing up front:

- **Passwords are stored in plaintext** in the database. This is
  intentional: pathguard's intended use is *informal access
  passwords* — the kind you'd share with a friend in chat to let them
  see your photo gallery. The integrity of who can change passwords
  (admin re-authentication is required to rotate the admin password)
  matters more than the confidentiality of the password values
  themselves. If you have a credential that you wouldn't want leaked
  from a database backup, don't use it as a pathguard password.

- **The default admin password is `password`.** Change it on first
  login. There is currently no forced-rotation gate.

- **Logins are rate-limited** per source IP with exponential backoff,
  capped at 60 seconds, so brute-force is not practical even with the
  plaintext storage.

- **Sessions** are encrypted cookies (the actix-session default). The
  key is persisted to `session.key` (mode `0600`) and survives
  restarts.

- **Audit log** records every protected access. The IP recorded is the
  socket peer by default; enable `--trust-forwarded-for` only when
  pathguard is behind a proxy that overwrites the header.

- **Defense-in-depth headers** (`X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`)
  are set globally and only on responses where the backend hasn't set
  its own value.

## Development

The project is a Cargo workspace with a single member crate in
`pathguard/`. Nightly Rust is required (`#![feature(impl_trait_in_assoc_type)]`).

Common commands, run from the repo root:

```sh
cargo run -p pathguard -- files ./public    # run with debug build
cargo test                                  # unit tests (robots_txt + proxy helpers)
cargo fmt                                   # rustfmt is configured to use hard tabs
```

Diesel migrations live in `pathguard/migrations/` and are compiled
into the binary, so a deployed binary self-bootstraps its schema on
first run. To work on the schema:

```sh
cd pathguard
diesel migration generate <name>
diesel migration run
diesel print-schema > src/schema.rs
```

The Nix dev shell (`nix develop`) ships the nightly toolchain plus
`bacon`, `cargo-edit`, `cargo-shear`, and `diesel-cli`.

Per `CLAUDE.md`, the proc macros that minify `script.js` and
`override.css` don't trigger recompiles when their source files
change; touch `main.rs` (or `cargo clean -p pathguard`) to pick up
CSS/JS edits in release builds.

## License

GPL-3.0. See [LICENSE.md](LICENSE.md).
