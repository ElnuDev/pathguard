# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`pathguard` is a customizable password-protection layer in front of an HTTP service or local directory. It runs in one of two modes:

- `proxy <port>` — reverse-proxies authenticated requests to `127.0.0.1:<port>`.
- `files <root>` — serves files from `<root>` with a built-in browser UI.

Either way, a `/pathguard` admin dashboard is mounted alongside (path configurable via `--dashboard`).

## Layout

Cargo workspace at the repo root with a single member crate in `pathguard/`. All source lives in `pathguard/src/`; migrations in `pathguard/migrations/`.

Requires **nightly Rust** (`main.rs` enables `#![feature(impl_trait_in_assoc_type)]`).

## Common commands

Run from the repo root unless noted:

- Build / run: `cargo run -p pathguard -- <mode> [args]`
  - Example file server: `cargo run -p pathguard -- files ./some-dir`
  - Example proxy: `cargo run -p pathguard -- proxy 3000`
- Tests: `cargo test` (there is a unit test suite in `robots_txt.rs`)
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

Three layers of middleware wrap the app: `actix_session` (cookie-backed sessions, key persisted to `session.key` and auto-generated on first run), `actix_htmx`, and a `DefaultHeaders` that sets `Content-Type: text/html` globally — individual handlers serving JS/CSS override this manually.

### Auth extractors (`auth.rs`)

Routes opt into protection by taking a FromRequest extractor:

- `AuthorizedNoCheck(User)` — must be logged in, no rule check, no activity log.
- `Unauthorized { user, fallback_err }` — anyone (logged in or not); used by `files::files` which makes its own per-entry rule decisions.
- `Authorized(Option<User>)` — must pass `user_rules_allowed` for the requested path; logs an `Activity` row. Anonymous users are evaluated against the `default` group's rules.
- `AuthorizedAdmin` — must be the literal `admin` user (`ADMIN_USERNAME`).

`Fancy<T>` wraps any of these so that errors render as a full styled HTML page via `FancyError`/`RenderError` instead of a plain status response. `RenderError` is auto-implemented for anything that implements `maud::Render`.

### Rules model

A `Rule` is `(group, path_prefix, allowed: Option<bool>)` plus a sort index. `user_rules` loads all rules across all groups the user belongs to, ordered by `(group.sort, rule.sort)`. `user_rules_allowed` walks that list and returns the `allowed` flag of the **last** matching prefix — so later rules in sort order override earlier ones. `None` means "no opinion, keep looking." Default if nothing matches: blocked.

The `admin` user bypasses rules entirely. The seeded `default` group governs anonymous access.

### Database (`database.rs`, `models/`)

SQLite via Diesel + r2d2 pool. `Database::new` runs embedded migrations and seeds the `admin` user (default password `password`) and the `default` group on every startup (`insert_or_ignore_into`). A `ConnectionCustomizer` runs `database.sql` (WAL mode + foreign keys) on every checked-out connection.

Tables (see `schema.rs`): `users`, `groups`, `user_groups` (M2M), `rules`, `activities`. Migrations live in `pathguard/migrations/` and are compiled into the binary, so the deployed binary is self-bootstrapping.

User deletion is soft (`users.deleted` flag) so historical `activities` rows still resolve to a username — the activity log shows "(deleted)" for those.

### Templates and assets (`templates.rs`, etc.)

UI is server-rendered with `maud` and progressively enhanced with HTMX. The dashboard uses `hx-boost` for navigation and per-button `hx-post`/`hx-patch`/`hx-delete` for inline edits.

Static assets (`htmx.js` / `htmx.min.js`, `script.js`, `missing.css`, `override.css`) are bundled via `include_str!`. In release builds, `script.js` and `override.css` are run through `static_web_minify` / `const_css_minify` proc macros. Debug builds serve the unminified sources so edits hot-reload via `cargo run`. **Note:** the minify proc macros do not trigger recompiles when their source files change — touching `main.rs` (or `cargo clean -p pathguard`) is required to pick up CSS/JS edits in release.

### NixOS module

`flake.nix` exposes `nixosModules.default` which defines `services.pathguard` with options for `mode` (proxy/files), `port`, `dashboard`, and `minPasswordStrength`. Service runs as `DynamicUser` with state in `/var/lib/pathguard`.

## Conventions

- `rustfmt.toml` enforces hard tabs — don't reformat to spaces.
- `.tokeignore` excludes vendored assets (htmx, missing.css) from line counts.
- New routes follow the `<ROUTE>_ROUTE` const + `web::resource(ARGS.dashboard.to_string() + ROUTE)` pattern in `main.rs`.
- New rule/group/user mutations: prefer returning `204 No Content` for successful deletes (see commit `0d57ac0`).
