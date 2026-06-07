# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`pathguard` is a customizable password-protection layer in front of an HTTP service or local directory. It runs in one of two modes:

- `proxy <port>` — reverse-proxies authenticated requests to `127.0.0.1:<port>`.
- `files <root>` — serves files from `<root>` with a built-in browser UI.

Either way, a `/pathguard` admin dashboard is mounted alongside (path configurable via `--dashboard`).

User-facing documentation (install, CLI reference, NixOS module, threat model) lives in [`README.md`](README.md). Read it before assuming a behavior is undocumented — much of what an end user would ask is already written down there in a more digestible form than this file.

## Layout

Cargo workspace at the repo root with a single member crate in `pathguard/`. All source lives in `pathguard/src/`; migrations in `pathguard/migrations/`.

Requires **nightly Rust** (`main.rs` enables `#![feature(impl_trait_in_assoc_type)]`).

## Common commands

Run from the repo root unless noted:

- Build / run: `cargo run -p pathguard -- <mode> [args]`
  - Example file server: `cargo run -p pathguard -- files ./some-dir`
  - Example proxy: `cargo run -p pathguard -- proxy 3000`
- Tests: `cargo test` (unit test suites in `robots_txt.rs` and `proxy.rs`)
- Format: `cargo fmt` (rustfmt is configured to use hard tabs — see `rustfmt.toml`)
- Nix build / run: `nix build .` / `nix run .` (also `nix build .#pathguard`)
- After changing `flake.nix` deps, `cargoHash` in `flake.nix` must be updated.

Diesel (run inside `pathguard/`, which is what `diesel.toml` and `.env` are scoped to):

- New migration: `diesel migration generate <name>`
- Apply migrations: `diesel migration run` (note: the app *also* runs `embed_migrations!()` on startup, so this is usually unnecessary for local dev)
- Regenerate schema: `diesel print-schema > src/schema.rs`

Nix dev shell (`nix develop`) ships `bacon`, `cargo-edit`, `cargo-shear`, and `diesel-cli` alongside the nightly toolchain.

## Architecture

### Request flow

`main.rs` wires every route under `ARGS.dashboard` (default `/pathguard`) to specific dashboard handlers; everything else falls through to `default_service`, which is set to `proxy::proxy` or `files::files` depending on the chosen mode.

Three layers of middleware wrap the app: `actix_session` (cookie-backed sessions, key persisted to `session.key` and auto-generated on first run), `actix_htmx`, and a `DefaultHeaders` middleware that sets `Content-Type: text/html` plus the defense-in-depth response headers `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and `Referrer-Policy: no-referrer`. `DefaultHeaders` only inserts a header when it's missing, so individual handlers (and proxied backends) can override any of these by emitting their own value. Handlers serving JS/CSS set `Content-Type` manually for this reason.

### Auth extractors (`auth.rs`)

Routes opt into protection by taking a FromRequest extractor:

- `AuthorizedNoCheck(User)` — must be logged in, no rule check, no activity log.
- `Unauthorized { user, fallback_err }` — anyone (logged in or not); used by `files::files` which makes its own per-entry rule decisions.
- `Authorized(Option<User>)` — must pass `user_rules_allowed` for the requested path; logs an `Activity` row. Anonymous users are evaluated against the `default` group's rules.
- `AuthorizedAdmin` — must be the literal `admin` user (`ADMIN_USERNAME`).

`Fancy<T>` wraps any of these so that errors render as a full styled HTML page via `FancyError`/`RenderError` instead of a plain status response. `RenderError` is auto-implemented for anything that implements `maud::Render`.

### Rules model

A `Rule` is `(group, path_prefix, allowed: Option<bool>)` plus a sort index. `user_rules` loads all rules across all groups the user belongs to, ordered by `(group.sort, rule.sort)`. `user_rules_allowed` walks that list and returns the `allowed` flag of the **last** matching prefix — so later rules in sort order override earlier ones. `None` means "no opinion, keep looking." Default if nothing matches: blocked.

"Matching" is on **path-component boundaries**, not raw bytes — see `path_matches_prefix` in `auth.rs`. A rule for `/foo` matches `/foo` and `/foo/anything` but not `/foobar`. The byte-prefix version was an authorization-bypass bug (allow rules leaked to sibling subtrees); do not regress this back to `str::starts_with`.

The `admin` user bypasses rules entirely. The seeded `default` group governs anonymous access.

### Proxy mode (`proxy.rs`)

In proxy mode, `proxy::proxy` is wired as `default_service`. Every forwarded request is mutated in three ways before being sent to `127.0.0.1:<port>`, and the response is filtered on the way back:

- **Hop-by-hop headers** (`Connection`, `Keep-Alive`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`, `Proxy-Authenticate`, `Proxy-Authorization`) are stripped in both directions per RFC 7230 §6.1. Forwarding them can enable request smuggling and breaks WebSocket upgrades.

- **`X-Pathguard-User`** is injected so the backend can identify the caller. The strip-then-insert ordering is structural and load-bearing: `headers.remove(&PATHGUARD_USER_HEADER)` must run before `headers.insert(...)`, or any client can spoof the value. If you refactor this, preserve the order and the inline comment that calls it out. Value contract: the authenticated username, or empty string for anonymous-but-allowed callers; the header is always present on requests pathguard forwarded.

- **`pathguard_id` cookie** is stripped from the forwarded `Cookie` header (`strip_session_cookie`). The backend can't decrypt it anyway, and the user identity is now carried by the header above. The cookie name is the `SESSION_COOKIE_NAME` const in `main.rs`, shared with the session middleware so renames stay in sync.

### Login rate limiting (`dashboard.rs`)

`post_login` consults a process-static `LOGIN_FAILURES: Mutex<Option<HashMap<String, (u32, Instant)>>>` ledger keyed by source IP, with exponential backoff (1s, 2s, ..., capped at 60s) over a 15-minute window. Successful logins clear the ledger entry. The IP source respects `--trust-forwarded-for` the same way the activity log does. The ledger isn't dead code — leave it in place unless the throttle is being intentionally replaced.

### Admin self-rotation re-auth (`dashboard.rs`)

`patch_user`, when the target is `ADMIN_USERNAME`, requires the form to carry a `current_password` field matching the stored admin password before any write happens. This guards against a momentarily-compromised admin session being upgraded into permanent control. The check has to come before `validate_password` and before any DB write, and the admin edit form in `models/user.rs` renders the matching input. If you touch either, keep them in sync.

### Database (`database.rs`, `models/`)

SQLite via Diesel + r2d2 pool. `Database::new` runs embedded migrations and seeds the `admin` user (default password `password`) and the `default` group on every startup (`insert_or_ignore_into`). A `ConnectionCustomizer` runs `database.sql` (WAL mode + foreign keys) on every checked-out connection.

Tables (see `schema.rs`): `users`, `groups`, `user_groups` (M2M), `rules`, `activities`. Migrations live in `pathguard/migrations/` and are compiled into the binary, so the deployed binary is self-bootstrapping.

User deletion is soft (`users.deleted` flag) so historical `activities` rows still resolve to a username — the activity log shows "(deleted)" for those.

### Templates and assets (`templates.rs`, etc.)

UI is server-rendered with `maud` and progressively enhanced with HTMX. The dashboard uses `hx-boost` for navigation and per-button `hx-post`/`hx-patch`/`hx-delete` for inline edits.

Static assets (`htmx.js` / `htmx.min.js`, `script.js`, `missing.css`, `override.css`) are bundled via `include_str!`. In release builds, `script.js` and `override.css` are run through `static_web_minify` / `const_css_minify` proc macros. Debug builds serve the unminified sources so edits hot-reload via `cargo run`. **Note:** the minify proc macros do not trigger recompiles when their source files change — touching `main.rs` (or `cargo clean -p pathguard`) is required to pick up CSS/JS edits in release.

### NixOS module

`flake.nix` exposes `nixosModules.default` which defines `services.pathguard` with options for `mode` (proxy/files), `port`, `dashboard`, `minPasswordStrength`, and `trustForwardedFor`. Service runs as `DynamicUser` with state in `/var/lib/pathguard`.

`trustForwardedFor` is the gate for whether the activity log (and the login rate-limit ledger) keys off `Forwarded` / `X-Forwarded-For` instead of the socket peer. Default is `false`. The option's `mdDoc` description names the canonical Cloudflare-tunnel deployment as the fitting case and warns that enabling it without a header-stripping proxy in front is exactly the spoofing bug the gating exists to prevent.

## Conventions

- `rustfmt.toml` enforces hard tabs — don't reformat to spaces.
- `.tokeignore` excludes vendored assets (htmx, missing.css) from line counts.
- New routes follow the `<ROUTE>_ROUTE` const + `web::resource(ARGS.dashboard.to_string() + ROUTE)` pattern in `main.rs`.
- New rule/group/user mutations: prefer returning `204 No Content` for successful deletes (see commit `0d57ac0`).
