#!/usr/bin/env python3
"""Goodix 27c6:5F10 TLS Session PSK extraction (offline, read-only).

Recover the per-device TLS-PSK that the Goodix Windows driver stored on disk
for the local fingerprint sensor, so the libfprint goodixtls5f10 driver can
reuse it for the same chip on Linux. The Windows partition is read-only:
no hardware interaction, no booted Windows, no network access.

Pipeline:
  1. SYSTEM hive               -> bootKey                  (impacket LocalOperations)
  2. SECURITY hive + bootKey   -> DPAPI_SYSTEM             (impacket LSASecrets)
                                     MachineKey / UserKey
  3. DPAPI system master-key + DPAPI_SYSTEM                (impacket MasterKey.decrypt)
                               -> decrypted 64-byte master key
  4. Goodix application "entropy" (48B) from Goodix_Cache.bin seed
                                  (Goodix-specific derivation; constants live
                                  inside the shipped gfusb.dll)
  5. DPAPI_BLOB(cache[:324]).decrypt(masterkey, entropy)
                               -> 32-byte PSK

Only step 4 is custom Goodix crypto. Steps 1-3 and 5 reuse impacket verbatim,
so we never reinvent DPAPI.

PER-DEVICE: the recovered PSK is unique to the chip it came from. Running the
tool on another laptop's Windows partition recovers that laptop's PSK; it is
never re-usable across devices.

Scope: this tool only reads existing Windows-stored secrets. It does not
write to the sensor and does not provision a fresh PSK. A Linux-only
greenfield install (no Windows ever activated) is out of scope.

Run with --help for CLI usage.
"""

import argparse
import glob
import hashlib
import os
import sys
import uuid
from binascii import unhexlify

from impacket.examples.secretsdump import LocalOperations, LSASecrets
from impacket.dpapi import MasterKeyFile, MasterKey, CredHist, DomainKey, DPAPI_BLOB

# --- Goodix entropy constants -----------------------------------------------
# Three 16-byte constants the Goodix Windows driver mixes into the DPAPI
# optional-entropy field. They live as immediate data inside the shipped
# gfusb.dll. These are NOT secrets: anyone who has the Windows driver installed has
# these exact bytes on disk.
CONST_1 = bytes.fromhex("9d7992b38402b66c81d1f555218942a9")
CONST_2 = bytes.fromhex("1848d71550d270d219c80632ab4f8bb3")
CONST_3 = bytes.fromhex("e47c8938db5250f0205617ee17da4eb4")

# Goodix_Cache.bin layout: 324-byte DPAPI blob followed by an 8-byte random seed.
CACHE_BLOB_LEN = 324
CACHE_SEED_OFF = 324
CACHE_SEED_LEN = 8


class PSKExtractError(Exception):
    pass


def _root_key() -> bytes:
    """Asymmetric XOR of the three driver constants -> 16-byte root key."""
    rk = bytearray(16)
    for i in range(8):          # low half:  C1 ^ C2 ^ C1[i+8]
        rk[i] = CONST_1[i] ^ CONST_2[i] ^ CONST_1[i + 8]
    for i in range(8, 16):      # high half: C2 ^ C3 ^ C3[i-8]
        rk[i] = CONST_2[i] ^ CONST_3[i] ^ CONST_3[i - 8]
    return bytes(rk)


def seed_from_cache(cache_bytes: bytes) -> bytes:
    """Return the 8-byte entropy seed embedded at Goodix_Cache.bin[324:332]."""
    if len(cache_bytes) < CACHE_SEED_OFF + CACHE_SEED_LEN:
        raise PSKExtractError(
            "Goodix_Cache.bin too short to contain a seed (%d bytes); expected "
            ">= %d. Supply the full Goodix_Cache.bin."
            % (len(cache_bytes), CACHE_SEED_OFF + CACHE_SEED_LEN))
    return cache_bytes[CACHE_SEED_OFF:CACHE_SEED_OFF + CACHE_SEED_LEN]


def derive_entropy_from_seed(seed: bytes) -> bytes:
    """48-byte DPAPI optional entropy from the 8-byte seed.

    entropy = SHA256(seed)[16:] + SHA256(SHA256(seed)[:16] + root_key)
    where seed = Goodix_Cache.bin[324:332].
    """
    if len(seed) != CACHE_SEED_LEN:
        raise PSKExtractError(
            "seed must be exactly %d bytes (got %d)" % (CACHE_SEED_LEN, len(seed)))
    seed_hash = hashlib.sha256(seed).digest()
    material = seed_hash[:16] + _root_key()
    return seed_hash[16:] + hashlib.sha256(material).digest()   # 16 + 32 = 48


def derive_entropy(cache_bytes: bytes) -> bytes:
    """48-byte DPAPI optional entropy.

    Convenience wrapper: extract the seed from a full cache file then derive.
    """
    return derive_entropy_from_seed(seed_from_cache(cache_bytes))


def blob_masterkey_guid(cache_bytes: bytes) -> str:
    """Return the master-key GUID the cache DPAPI blob is bound to (lowercase)."""
    blob = DPAPI_BLOB(cache_bytes[:CACHE_BLOB_LEN])
    return str(uuid.UUID(bytes_le=blob['GuidMasterKey']))


# --- Steps 1-3: DPAPI_SYSTEM + master key (pure impacket) --------------------

def get_dpapi_system(system_hive: str, security_hive: str) -> dict:
    """Run impacket's secretsdump logic offline -> {MachineKey, UserKey}."""
    bootKey = LocalOperations(system_hive).getBootKey()
    result = {}

    def _cb(secretType, secret):
        if secret.startswith("dpapi_machinekey:"):
            machineKey, userKey = secret.split('\n')
            result['MachineKey'] = unhexlify(machineKey.split(':')[1][2:])
            result['UserKey'] = unhexlify(userKey.split(':')[1][2:])

    lsa = LSASecrets(security_hive, bootKey, None, isRemote=False,
                     history=False, perSecretCallback=_cb)
    lsa.dumpSecrets()
    if 'MachineKey' not in result or 'UserKey' not in result:
        raise PSKExtractError(
            "Could not extract DPAPI_SYSTEM (MachineKey/UserKey) from SECURITY hive")
    return result


def decrypt_masterkey(masterkey_file: str, dpapi_system: dict) -> bytes:
    """Decrypt a DPAPI system master-key file using DPAPI_SYSTEM keys.

    Mirrors `dpapi.py masterkey -system -security` (UserKey then MachineKey,
    primary then backup key).
    """
    with open(masterkey_file, 'rb') as fp:
        data = fp.read()

    mkf = MasterKeyFile(data)
    data = data[len(mkf):]

    mk = bkmk = None
    if mkf['MasterKeyLen'] > 0:
        mk = MasterKey(data[:mkf['MasterKeyLen']])
        data = data[len(mk):]
    if mkf['BackupKeyLen'] > 0:
        bkmk = MasterKey(data[:mkf['BackupKeyLen']])
        data = data[len(bkmk):]
    if mkf['CredHistLen'] > 0:
        ch = CredHist(data[:mkf['CredHistLen']])
        data = data[len(ch):]
    if mkf['DomainKeyLen'] > 0:
        dk = DomainKey(data[:mkf['DomainKeyLen']])
        data = data[len(dk):]

    candidates = []
    for keyname in ('UserKey', 'MachineKey'):
        if keyname in dpapi_system:
            if mk is not None:
                candidates.append(mk)
            if bkmk is not None:
                candidates.append(bkmk)
            # try this key against all available master keys
            for blob in candidates:
                decrypted = blob.decrypt(dpapi_system[keyname])
                if decrypted:
                    return decrypted
            candidates = []
    raise PSKExtractError("Master key decryption failed with DPAPI_SYSTEM keys")


def unprotect_psk(cache_bytes: bytes, masterkey: bytes, entropy: bytes) -> bytes:
    """DPAPI-unprotect cache[:324] with master key + entropy -> 32-byte PSK."""
    blob = DPAPI_BLOB(cache_bytes[:CACHE_BLOB_LEN])
    decrypted = blob.decrypt(masterkey, entropy)
    if decrypted is None:
        raise PSKExtractError(
            "DPAPI unprotect of Goodix cache blob returned None "
            "(wrong master key or entropy?)")
    return decrypted


def resolve_masterkey_file(masterkey_path, cache_bytes):
    """Resolve the master-key file the cache blob is bound to.

    `masterkey_path` may be the master-key file itself, or a directory (e.g. the
    DPAPI 'Protect/S-1-5-18/User' folder) containing GUID-named files; in the
    latter case we pick the one matching the cache blob's GuidMasterKey.
    """
    guid = blob_masterkey_guid(cache_bytes)
    if os.path.isdir(masterkey_path):
        candidate = os.path.join(masterkey_path, guid)
        if os.path.isfile(candidate):
            return candidate
        raise PSKExtractError(
            "no master-key file named %s found in directory %s"
            % (guid, masterkey_path))
    return masterkey_path


def extract_psk(system_hive, security_hive, masterkey_file, cache_file):
    """Full pipeline. Returns dict with psk_hex, entropy_hex, masterkey_hex,
    masterkey_guid.
    """
    with open(cache_file, 'rb') as fp:
        cache = fp.read()

    entropy = derive_entropy(cache)

    masterkey_file = resolve_masterkey_file(masterkey_file, cache)
    dpapi_system = get_dpapi_system(system_hive, security_hive)
    masterkey = decrypt_masterkey(masterkey_file, dpapi_system)
    psk = unprotect_psk(cache, masterkey, entropy)

    return {
        'psk': psk,
        'psk_hex': psk.hex(),
        'entropy': entropy,
        'entropy_hex': entropy.hex(),
        'masterkey_hex': masterkey.hex(),
        'masterkey_guid': blob_masterkey_guid(cache),
        'masterkey_file': masterkey_file,
    }



# --- CLI ---------------------------------------------------------------------

# Where each input lives relative to a mounted Windows partition root.
# (See README.md for the full table.)
_AUTO_PATHS = {
    'system':   ['Windows/System32/config/SYSTEM'],
    'security': ['Windows/System32/config/SECURITY'],
    'masterkey_dir': [
        'Windows/System32/Microsoft/Protect/S-1-5-18/User',
        'Windows/System32/Microsoft/Protect/S-1-5-18',
    ],
    'cache': [
        'Windows/ServiceProfiles/LocalService/AppData/Local/Goodix/'
        'FingerPrint/Goodix_Cache.bin',
        'ProgramData/Goodix/Goodix_Cache.bin',
    ],
}


def _first_existing(win_root, candidates):
    for rel in candidates:
        path = os.path.join(win_root, rel)
        if os.path.exists(path):
            return path
    # case-insensitive fallback (Windows paths on a case-sensitive mount)
    for rel in candidates:
        pat = os.path.join(win_root, *(p + '*' for p in rel.split('/')))
        hits = glob.glob(pat, recursive=False)
        if hits:
            return hits[0]
    return None


def _resolve_auto(win_root):
    system = _first_existing(win_root, _AUTO_PATHS['system'])
    security = _first_existing(win_root, _AUTO_PATHS['security'])
    mk_dir = _first_existing(win_root, _AUTO_PATHS['masterkey_dir'])
    cache = _first_existing(win_root, _AUTO_PATHS['cache'])
    missing = [n for n, v in (('SYSTEM', system), ('SECURITY', security),
                              ('master-key dir', mk_dir), ('Goodix_Cache.bin', cache))
               if v is None]
    if missing:
        raise PSKExtractError(
            "auto-locate under %s failed; not found: %s. Use explicit "
            "--system/--security/--masterkey/--cache." % (win_root, ', '.join(missing)))
    return system, security, mk_dir, cache


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Recover the per-device Goodix 27c6:5F10 TLS Session PSK "
                    "from offline Windows DPAPI material.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="The recovered PSK is PER-DEVICE. See README.md.")
    ap.add_argument('--win-root', metavar='DIR',
                    help="auto-locate all inputs under a mounted Windows "
                         "partition (e.g. /mnt/win), read-only.")
    ap.add_argument('--system', help="path to SYSTEM hive")
    ap.add_argument('--security', help="path to SECURITY hive")
    ap.add_argument('--masterkey',
                    help="path to the DPAPI master-key file, or a directory of "
                         "GUID-named master keys (the right one is auto-selected)")
    ap.add_argument('--cache', help="path to Goodix_Cache.bin (blob[+seed])")
    ap.add_argument('--quiet', action='store_true',
                    help="print only the PSK hex")
    args = ap.parse_args(argv)

    try:
        if args.win_root:
            system, security, masterkey, cache = _resolve_auto(args.win_root)
        else:
            need = {'--system': args.system, '--security': args.security,
                    '--masterkey': args.masterkey, '--cache': args.cache}
            missing = [k for k, v in need.items() if not v]
            if missing:
                ap.error("either --win-root, or all of "
                         "--system/--security/--masterkey/--cache "
                         "(missing: %s)" % ', '.join(missing))
            system, security, masterkey, cache = (
                args.system, args.security, args.masterkey, args.cache)

        result = extract_psk(system, security, masterkey, cache)
    except PSKExtractError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2

    if args.quiet:
        print(result['psk_hex'])
        return 0

    print("Goodix 27c6:5F10 TLS Session PSK")
    print("  PSK            : %s" % result['psk_hex'])
    print("  PSK identity   : Client_identity")
    print("  Cipher         : TLS_PSK_WITH_AES_128_GCM_SHA256")
    print("  master-key GUID: %s" % result['masterkey_guid'])
    print("  master-key file: %s" % result['masterkey_file'])
    print("  entropy (48B)  : %s" % result['entropy_hex'])

    return 0


if __name__ == '__main__':
    sys.exit(main())
