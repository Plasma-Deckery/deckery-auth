# deckery-auth

Controller-native authentication for the Steam Deck — a way to authenticate `sudo`, polkit, and the lock screen with a short PIN entered via the controller, instead of typing a keyboard password.

Part of [Deckery](https://github.com/Plasma-Deckery/deckery). Design and implementation plan: [deckery#19](https://github.com/Plasma-Deckery/deckery/issues/19), parent epic [deckery#17](https://github.com/Plasma-Deckery/deckery/issues/17).

## Status

**Step 1 (in progress):** PIN storage + `pam_deckery.so` proof of concept. No daemon, no popup, no controller input yet — the PIN is entered via the standard PAM conversation prompt (keyboard) to validate the PAM stack wiring before adding the UI layers.

The full staged plan:

1. **PIN storage + `pam_deckery.so`** (current) — proves the PAM chain works end-to-end, keyboard input into the standard PAM prompt
2. **`deckery-auth` daemon + Layer Shell popup** — visual PIN entry, still keyboard for now
3. **`deckery-input-reader`** — controller replaces keyboard as the input source
4. **Polish** — makima paused during auth, timeouts, retry limits, tested across sudo/polkit/lockscreen

`deckery-lockscreen` (the kscreenlocker QML theme, [deckery#18](https://github.com/Plasma-Deckery/deckery/issues/18)) and `deckery-polkit` (the custom polkit agent, [deckery#20](https://github.com/Plasma-Deckery/deckery/issues/20)) are separate, optional UI improvements — the PAM module from Step 1 already covers lock screen and polkit authentication via PAM directly, without either of them.

See [deckery#19](https://github.com/Plasma-Deckery/deckery/issues/19) and its comments for the full discussion.

## Crates

- **`crates/deckery-pin-set`** — a standalone CLI tool, run once with `sudo`, that sets the controller PIN (argon2id hash written to `/etc/deckery/pin.hash`). This is **not** part of the PAM module itself — it only shares the hash file convention with it.
- **`crates/deckery-pam`** — the PAM module. Builds to `pam_deckery.so` (PAM modules follow the `pam_*.so` naming convention — e.g. `pam_unix.so`, `pam_google_authenticator.so` — so the compiled artifact keeps that prefix even though the crate/directory is named `deckery-pam` per Deckery's own naming convention).

## How the PAM module works

`crates/deckery-pam/src/lib.rs` is the interface that `libpam` actually loads. The `pamsm::pam_module!(PamDeckery)` macro at the bottom generates the C ABI entry points (`pam_sm_authenticate`, `pam_sm_setcred`, etc.) that PAM calls via `dlopen()`. The `impl PamServiceModule for PamDeckery` block is the Rust-side implementation PAM dispatches into.

Three trait methods are implemented, each for a different reason:

- **`authenticate`** — the actual check. Reads the stored PIN hash, prompts via the standard PAM conversation function (`PAM_PROMPT_ECHO_OFF`, same mechanism a password prompt uses), and verifies the input against the hash with argon2id.

- **`setcred`** — required, not decorative. It belongs to the same PAM group as `authenticate` ("auth"). Applications like sudo call `pam_setcred()` automatically right after a successful `pam_authenticate()`, as part of the standard PAM flow, to set up session credentials. `pamsm`'s default (unimplemented) behavior for every trait method is `PamError::SERVICE_ERR` — leaving this unimplemented would make sudo fail *after* a correct PIN, once it tries to set up credentials. We have none to establish, so returning `SUCCESS` (a no-op "nothing to do here") is correct and safe: `setcred` only runs after identity is already verified, so it cannot grant access on its own.

- **`acct_mgmt`** — belongs to PAM's "account" group, not "auth". Since `pam_deckery.so` is only registered under `auth` in `/etc/pam.d/`, this is never actually invoked by the intended stack config. It's implemented anyway, but deliberately returns `PamError::IGNORE`, not `SUCCESS`. Unlike `setcred`, account management *is* a real security decision (expired accounts, locked accounts, forced password changes) — returning unconditional `SUCCESS` here would silently wave through those checks if this module ever ended up in an `account` stack by mistake. `IGNORE` tells PAM to disregard this module's verdict entirely, regardless of whether it's `required`, `sufficient`, or `optional` — unlike `SUCCESS`, it cannot short-circuit a stack it has no business deciding.

## Building

```bash
cargo build --release
```

`deckery-pam` requires the `libpam` headers to be available at build time (via the `pamsm` crate's `libpam` feature).

## PAM stack

`pam_deckery.so` must be listed **before** `pam_unix.so` as `sufficient`, so the controller PIN is tried first — ahead of, not instead of, the keyboard password:

```
auth  sufficient  pam_deckery.so
auth  sufficient  pam_unix.so
auth  required    pam_deny.so
```

Order matters here: PAM tries `sufficient` modules strictly in stack order, and the *first* module listed runs *first* — including its own prompt. Listing `pam_unix.so` first would show the terminal password prompt before the controller PIN ever gets a chance.

Resulting behavior for e.g. `sudo`:

- Typing `sudo <command>` triggers `pam_deckery.so` first — the PIN prompt appears immediately, no terminal password prompt yet.
- Wrong PIN entries are retried within `pam_deckery`/the auth daemon itself (internal retry count, TBD in later steps).
- If the PIN ultimately fails (or a later popup is dismissed/times out), PAM falls through to `pam_unix.so` in the same stack evaluation, which prompts for the normal keyboard password as a fallback.
- sudo's own outer retry loop (`passwd_tries` in `/etc/sudoers`, default 3) re-runs the whole stack from the top on complete failure — so the PIN prompt can reappear more than once before the keyboard fallback is reached.

Both auth paths remain fully functional side by side; the PIN is just tried first.

## Why argon2id

PIN hashes are stored with argon2id — the current OWASP-recommended default for password storage, memory-hard against GPU/ASIC cracking. Alternatives considered:

| Algorithm | Notes |
|---|---|
| **argon2id** ✅ | OWASP's first-choice recommendation, winner of the Password Hashing Competition (2015) |
| yescrypt | What Fedora/glibc actually uses for `/etc/shadow` (Bazzite is Fedora-based) — similar design goals, but far less mature Rust tooling |
| scrypt | Also memory-hard, less commonly chosen today now that argon2 exists |
| bcrypt | No memory-hardness, still acceptable at a high cost factor, but not the current best practice |
| PBKDF2 | No memory-hardness — OWASP recommends it only where FIPS-140 compliance is required |

Since PIN verification happens rarely and locally (not a high-throughput API), parameters are set well above the OWASP minimums — 64 MiB memory, 3 iterations, 4-way parallelism — with no noticeable UX cost.

## Security notes

- The controller PIN is a separate secret from the user's login password. `pam_unix.so` remains fully functional as a fallback — nothing about the existing authentication path is removed or weakened.
- `pam_deckery.so` is scoped to the `auth` PAM group only. It does not, and should not, appear in `account`, `session`, or `password` stacks — see the `acct_mgmt` note above for why that distinction matters.
- `/etc/deckery/pin.hash` is written with `0600` permissions (root-only read/write).

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
