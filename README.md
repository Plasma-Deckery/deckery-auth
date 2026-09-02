# deckery-auth

Controller-native authentication for the Steam Deck — authenticate `sudo`, polkit, and the lock screen with a short PIN entered via the controller, instead of typing a keyboard password.

Part of [Deckery](https://github.com/Plasma-Deckery/deckery). Design and implementation plan: [deckery#19](https://github.com/Plasma-Deckery/deckery/issues/19), parent epic [deckery#17](https://github.com/Plasma-Deckery/deckery/issues/17).

## Status

**Functional end-to-end.** All core components are implemented and working on Bazzite:

- Controller PIN entry via the Steam Deck hardware (face buttons, D-pad, shoulder buttons, triggers, back paddles)
- Full-screen Layer Shell overlay (`deckery-auth-ui`) showing the Steam Deck graphic with live token display
- Auth daemon (`deckery-auth-daemon`) managing session queuing, priority, and display events
- PAM module (`pam_deckery.so`) integrating with `sudo`
- Hard cancel (QAM / ✕ button) aborts the PAM transaction entirely — no keyboard fallback
- "Switch to Password" falls through to `pam_unix.so` — shows the standard keyboard password prompt
- Session replay: if the UI reconnects mid-session, the overlay reopens automatically
- PIN hashed with argon2id; stored in `/etc/deckery/pin.hash`

**Remaining work:**

- Additional PAM stacks: polkit-1, kscreenlocker, su, login (tracked in [#13](https://github.com/Plasma-Deckery/deckery-auth/issues/13))
- Session priority / preemption (screenlock should pre-empt sudo, tracked in [#11](https://github.com/Plasma-Deckery/deckery-auth/issues/11))
- Polkit agent replacement — "Switch to Password" in that context requires in-overlay keyboard input (no pam_unix fallback available)

## Crates

| Crate | Description |
|---|---|
| `deckery-auth-daemon` | Auth daemon — manages controller sessions, display events, socket protocol |
| `deckery-auth-ui` | Layer Shell overlay — QML UI showing the Steam Deck graphic and token display |
| `deckery-input` | Controller event → auth token translation (`TokenReader`) |
| `deckery-pam` | PAM module (`pam_deckery.so`) — collects PIN via daemon, verifies against argon2id hash |
| `deckery-pam-test` | Dev/CI smoke-test binary — calls `pam_authenticate` without touching `/etc/pam.d/sudo` |
| `deckery-pin-set` | One-time CLI tool to set the controller PIN (writes argon2id hash to `/etc/deckery/pin.hash`) |

## Architecture

```
sudo / polkit / kscreenlocker
        │
   pam_deckery.so          ← PAM module: connects to daemon socket, waits for PIN
        │  auth.sock
   deckery-auth-daemon     ← daemon: owns controller, queues sessions, routes events
        │  display.sock
   deckery-auth-ui         ← Layer Shell overlay: shows token display, cancel/switch buttons
```

The daemon verifies connecting UI binaries via `SO_PEERCRED` + `/proc/<pid>/exe` before accepting display connections.

## Socket protocol

**`auth.sock`** (PAM → daemon, root-only):
- PAM sends: `<source>\n` (e.g. `sudo\n`)
- Daemon replies: `<pin>\n` | `CANCEL\n` | `SWITCH_KB\n` | `ERROR:<msg>\n`

**`display.sock`** (daemon → UI, allowlisted binaries only):
- Daemon sends: `SESSION_START:<source>:<id>\n`, `TOKEN:<token>\n`, `BACKSPACE\n`, `CONFIRM:<id>\n`, `CANCEL:<id>\n`, `SESSION_END:<id>\n`
- UI sends: `UI_CANCEL:<id>\n`, `UI_SWITCH_KB:<id>\n`

## PAM stack

```
auth  sufficient  pam_deckery.so  source=sudo
auth  sufficient  pam_unix.so
auth  required    pam_deny.so
```

PAM return codes from `pam_deckery.so`:

| Situation | Return code | PAM behaviour |
|---|---|---|
| Correct PIN | `SUCCESS` | Auth succeeds immediately |
| No PIN hash stored | `AUTHINFO_UNAVAIL` | Skip → pam_unix |
| Daemon not running | `AUTHINFO_UNAVAIL` | Skip → pam_unix |
| User cancelled (QAM / ✕) | `ABORT` | Entire PAM transaction aborted — no keyboard fallback |
| "Switch to Password" pressed | `AUTH_ERR` | Skip → pam_unix (keyboard dialog appears) |
| Wrong PIN | `AUTH_ERR` | Skip → pam_unix |
| PIN entry timeout (5 min) | `AUTHINFO_UNAVAIL` | Skip → pam_unix |

## Building and deploying

### Development (Bazzite / immutable Fedora)

```bash
./deploy.sh
```

Builds all crates inside the `deckery` Arch distrobox (daemon, PAM, input), and `deckery-ui-build` Fedora 43 distrobox (Qt UI — matches host Qt 6.10.3). Installs to `/usr/local/`.

Set your PIN once after installing:

```bash
sudo ./target/release/deckery-pin-set
```

### glibc compatibility

Built in the Arch distrobox (glibc 2.43); host Bazzite has glibc 2.42. Both `libpam_deckery.so` and `deckery-pin-set` require only symbols up to `GLIBC_2.34` — no compatibility issue.

## Security notes

- The controller PIN is a separate secret from the user's login password. `pam_unix.so` remains fully functional as a fallback — nothing about the existing authentication path is removed or weakened.
- `pam_deckery.so` is scoped to the `auth` PAM group only.
- `/etc/deckery/pin.hash` is written with `0600` permissions (root-only).
- The display socket (`display.sock`) only accepts connections from allowlisted binaries, verified via `SO_PEERCRED` and `/proc/<pid>/exe`.
- Hard cancel returns `PAM_ABORT`, which prevents `pam_unix.so` from running — no keyboard dialog appears after an explicit cancel.

## Why argon2id

PIN hashes use argon2id — the current OWASP-recommended default for password storage, memory-hard against GPU/ASIC cracking. Parameters: 64 MiB memory, 3 iterations, 4-way parallelism — well above OWASP minimums, with no noticeable UX cost given how rarely PIN verification runs.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
