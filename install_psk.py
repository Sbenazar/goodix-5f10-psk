#!/usr/bin/env python3
"""End-to-end installer for the Goodix 27c6:5F10 TLS-PSK.

Thin wrapper around goodix_psk.py: recover the PSK (or accept one from the
caller) and write it as raw 32 bytes to the location the libfprint
goodixtls5f10 driver looks at, with the correct ownership and permissions.

Typical usage (root, dual-boot machine with Windows partition mounted RO):

    sudo ./install_psk.py --win-root /mnt/win

Other inputs:

    sudo ./install_psk.py \\
        --system /path/SYSTEM --security /path/SECURITY \\
        --masterkey /path/mk-dir --cache /path/Goodix_Cache.bin

    sudo ./install_psk.py --psk-hex <64 hex chars>
    sudo ./install_psk.py --psk-file /path/to/raw32bytes

Destination defaults to /var/lib/fprint/goodix-5f10/psk and gets installed
with mode 0600 / owner root. Override with --dest.
"""

import argparse
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import goodix_psk as g  # noqa: E402

DEFAULT_DEST = "/var/lib/fprint/goodix-5f10/psk"
PSK_LEN = 32


def _restore_selinux_context(*paths: str) -> None:
    """Relabel `paths` the way the local SELinux policy wants, if there is one.

    See Sbenazar/goodix-5f10-libfprint#2 for why the PSK needs this."""
    try:
        if subprocess.run(["selinuxenabled"], check=False).returncode != 0:
            return
    except FileNotFoundError:
        return

    hint = ("If fprintd cannot read the PSK, label it by hand:\n"
            "    sudo chcon -t fprintd_var_lib_t %s" % paths[-1])
    try:
        rc = subprocess.run(["restorecon", *paths], check=False).returncode
    except FileNotFoundError:
        print("warning: SELinux is on but restorecon is missing. " + hint,
              file=sys.stderr)
        return
    if rc != 0:
        print("warning: restorecon exited %d. " % rc + hint, file=sys.stderr)


def _makedirs_tracked(path: str) -> list:
    """Create `path`, and report which directories that actually took, outermost
    first. os.makedirs can make more than one level -- with no /var/lib/fprint
    on the machine it creates that as well -- and each one inherits its parent's
    SELinux type, so the caller can relabel the lot instead of leaving half a
    mislabelled tree behind it."""
    missing = []
    probe = os.path.abspath(path)
    while not os.path.isdir(probe):
        missing.append(probe)
        probe = os.path.dirname(probe)
    os.makedirs(path, exist_ok=True)
    missing.reverse()
    return missing


def _atomic_install(dest: str, data: bytes, *, mode: int = 0o600) -> None:
    """Write `data` to `dest` atomically: write to a sibling tmp file, fsync,
    chmod, rename. Avoids leaving a half-written PSK file if interrupted.
    Caller is responsible for being root if `dest` is a privileged path."""
    dest_dir = os.path.dirname(os.path.abspath(dest)) or "."
    fresh = _makedirs_tracked(dest_dir)
    tmp = dest + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, "wb") as fp:
            fp.write(data)
            fp.flush()
            os.fsync(fp.fileno())
        os.chmod(tmp, mode)
        if os.geteuid() == 0:
            os.chown(tmp, 0, 0)
        os.rename(tmp, dest)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise

    targets = fresh + [dest_dir, dest]
    fprint_dir = os.path.dirname(os.path.dirname(DEFAULT_DEST))
    if os.path.abspath(dest).startswith(fprint_dir + os.sep):
        # An older version of this installer could have left it mislabelled.
        targets.insert(0, fprint_dir)
    _restore_selinux_context(*dict.fromkeys(targets))


def _resolve_psk(args, ap) -> bytes:
    """Pick the PSK source the user specified, in priority order:
       --psk-hex, --psk-file, then full extraction from Windows material."""
    if args.psk_hex:
        psk = bytes.fromhex(args.psk_hex)
        if len(psk) != PSK_LEN:
            ap.error("--psk-hex must decode to exactly %d bytes (got %d)"
                     % (PSK_LEN, len(psk)))
        return psk

    if args.psk_file:
        with open(args.psk_file, "rb") as fp:
            psk = fp.read()
        if len(psk) != PSK_LEN:
            ap.error("%s: expected %d raw bytes, got %d"
                     % (args.psk_file, PSK_LEN, len(psk)))
        return psk

    # Full extraction path -- mirrors goodix_psk.py CLI plumbing.
    if args.win_root:
        system, security, masterkey, cache = g._resolve_auto(args.win_root)
    else:
        need = {"--system": args.system, "--security": args.security,
                "--masterkey": args.masterkey, "--cache": args.cache}
        missing = [k for k, v in need.items() if not v]
        if missing:
            ap.error("provide either --win-root, --psk-hex, --psk-file, or "
                     "all of --system/--security/--masterkey/--cache "
                     "(missing: %s)" % ", ".join(missing))
        system, security, masterkey, cache = (
            args.system, args.security, args.masterkey, args.cache)

    result = g.extract_psk(system, security, masterkey, cache)
    return result["psk"]


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Extract and install the Goodix 27c6:5F10 TLS-PSK for "
                    "the libfprint goodixtls5f10 driver.",
        formatter_class=argparse.RawDescriptionHelpFormatter)

    src = ap.add_argument_group("PSK source (pick one)")
    src.add_argument("--win-root", metavar="DIR",
                     help="auto-locate all DPAPI inputs under a mounted "
                          "Windows partition (e.g. /mnt/win), read-only")
    src.add_argument("--system",   help="path to SYSTEM hive")
    src.add_argument("--security", help="path to SECURITY hive")
    src.add_argument("--masterkey",
                     help="DPAPI master-key file, or directory of GUID-named keys")
    src.add_argument("--cache",    help="path to Goodix_Cache.bin")
    src.add_argument("--psk-hex",  metavar="HEX",
                     help="skip extraction; install this 64-hex-char PSK")
    src.add_argument("--psk-file", metavar="FILE",
                     help="skip extraction; install the 32-raw-byte PSK from FILE")

    ap.add_argument("--dest", default=DEFAULT_DEST,
                    help="install location (default: %(default)s)")
    ap.add_argument("--allow-non-root", action="store_true",
                    help="skip the root check (useful for --dest to a user path)")
    ap.add_argument("--print-hex", action="store_true",
                    help="also print the PSK as hex to stdout")
    args = ap.parse_args(argv)

    if args.dest == DEFAULT_DEST and os.geteuid() != 0 and not args.allow_non_root:
        ap.error("installing to %s requires root; re-run with sudo, or pass "
                 "--dest to write somewhere user-writable" % DEFAULT_DEST)

    try:
        psk = _resolve_psk(args, ap)
    except g.PSKExtractError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2

    try:
        _atomic_install(args.dest, psk)
    except OSError as exc:
        print("error: writing %s: %s" % (args.dest, exc), file=sys.stderr)
        return 2

    print("Installed Goodix 5F10 TLS-PSK -> %s (32 bytes, mode 0600)" % args.dest)
    print("Restart fprintd to pick up the new key:")
    print("    sudo systemctl restart fprintd")
    if args.print_hex:
        print("PSK (hex): %s" % psk.hex())
    return 0


if __name__ == "__main__":
    sys.exit(main())
