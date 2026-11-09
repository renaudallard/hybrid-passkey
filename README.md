# hybrid-passkey

Native messaging helper that answers the passkey requests of a web page with
a passkey kept on a phone, over the FIDO hybrid transport (the "use a phone"
option of browsers): a QR code to scan with the phone, a Bluetooth check that
the phone is near the computer, then a tunnel through the relay server of the
phone's vendor.

Thunderbird and Firefox on Linux have no hybrid transport. These add-ons use
this helper for it:

*   [Towa](https://github.com/renaudallard/Towa), Exchange for Thunderbird,
    for the Microsoft sign-in page.
*   [phonekey](https://github.com/renaudallard/phonekey), for signing in to
    any web site in Firefox.

## Requirements

*   Linux with Bluetooth (BlueZ).
*   The public suffix list in `/usr/share/publicsuffix` (the `publicsuffix`
    package on Debian and Ubuntu, `publicsuffix-list-dafsa` on Fedora).
*   A phone with Bluetooth and internet access.

## Installation

1.  Install the helper in any directory, for example `~/.local/bin`. The
    [releases](https://github.com/renaudallard/hybrid-passkey/releases/latest)
    have it prebuilt for x86-64 (`hybrid-passkey-amd64`), for distributions
    with glibc 2.34 or later:

        install -m 755 hybrid-passkey-amd64 ~/.local/bin/hybrid-passkey

    Or build it, with Rust 1.88 or later and the D-Bus and udev development
    files (`libdbus-1-dev` and `libudev-dev` on Debian):

        cargo build --release --locked
        install -m 755 target/release/hybrid-passkey ~/.local/bin/hybrid-passkey

2.  Register it for the current user:

        hybrid-passkey --install

    This writes `~/.mozilla/native-messaging-hosts/hybrid_passkey.json`,
    which Thunderbird and Firefox read, pointing at the helper. Run it again
    after moving the helper, and `hybrid-passkey --uninstall` removes it.
    The manifest of the older `towa-passkey` helper, `towa_passkey.json`, is
    removed by `--install`.

## Protocol

The add-on sends one message, `{"origin": ..., "options": ...}`. `origin` is
the origin of the page, taken by the add-on from the tab and never from the
page, and `options` is the `PublicKeyCredentialRequestOptionsJSON` of the
page. The helper checks the relying party id against the origin as a browser
does, then answers with `{"qr": svg}`, `{"status": ...}` updates, and finally
either `{"credential": AuthenticationResponseJSON}` or `{"error": text}`.
Closing the port cancels the request. Only signing in is supported, related
origin requests are not.

The helper uses [libwebauthn](https://github.com/linux-credentials/libwebauthn)
(LGPL-2.1-or-later).
