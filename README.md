# goodix_psk -- offline TLS Session PSK recovery for Goodix 27c6:5F10

Recovers the per-device TLS-PSK that the Goodix Windows driver stored on disk
for the `27c6:5F10` fingerprint sensor, so the libfprint `goodixtls5f10`
driver can talk to the same chip on Linux. The Windows partition is read
**offline and read-only**: no booted Windows, no hardware contact, no
network.

The DPAPI primitives are not reimplemented -- steps 1-3 and 5 reuse
[impacket](https://github.com/fortra/impacket) as a library. Only the Goodix
"entropy" derivation (step 4) is device-vendor-specific.

## Scope

This tool **only reads existing Windows-stored secrets** for the local
sensor. It does not write to the chip and does not provision a fresh PSK on
its own. In practice:

- Suited for any laptop where Windows + the Goodix driver have run at
  least once and the driver has provisioned a PSK (this happens
  automatically -- see "Prepare Windows" below; **no fingerprint enrollment
  in Windows Hello is required**).
- A Linux-only greenfield install (the laptop has never booted Windows
  with the Goodix driver) is out of scope: this tool recovers a PSK that
  Windows already provisioned, it does not create one.

> **The recovered PSK is PER-DEVICE.** Each chip is provisioned with its own
> key. Running this tool against another machine's DPAPI material yields
> that machine's PSK and nothing else. Do not copy PSKs between devices.

## Prepare Windows (one-time, no fingerprint enrolment needed)

The PSK is created by the **Goodix Windows driver**, not by Windows Hello
fingerprint enrolment. The driver provisions a random 32-byte PSK the first
time it talks to the chip and seals it into a DPAPI cache file. We just need
to make sure that has happened at least once on your laptop.

1. **Install the official Goodix driver in Windows.** Usually Windows Update
   or your OEM's update tool (HONOR PC Manager, Lenovo Vantage, MyASUS, etc.)
   pulls it automatically. If not, install manually:
   - The tested version is **1.1.127.6** (signed 2024-03-12, provider
     "Goodix FP"), distributed via Microsoft Update Catalog.
   - Search the catalog by hardware ID:
     <https://www.catalog.update.microsoft.com/Search.aspx?q=USB%5CVID_27C6%26PID_5F10>
   - Or by name: <https://www.catalog.update.microsoft.com/Search.aspx?q=Goodix+Fingerprint>
   - The driver INF file is `gfusb.inf`; the matching binary is `gfusb.dll`.
2. **Trigger PSK provisioning.** Open
   *Settings -> Accounts -> Sign-in options -> Fingerprint recognition (Windows
   Hello)* and click **Set up**. This wakes the driver, which writes the PSK
   to the chip and seals a copy into `Goodix_Cache.bin`. You can **cancel
   the wizard immediately** -- do not swipe a finger. The PSK is already on
   disk by the time the wizard asks you to swipe.
3. **Reboot once.** This guarantees the DPAPI cache and the SYSTEM/SECURITY
   hives are flushed to disk in a consistent state before you read them
   from Linux.

After this, the rest of teh flow is Linux-only and read-only.

## Pipeline

| # | Step | Implementation |
|---|------|----------------|
| 1 | SYSTEM hive -> bootKey | impacket `LocalOperations` |
| 2 | SECURITY hive + bootKey -> `DPAPI_SYSTEM` (Machine/User key) | impacket `LSASecrets` |
| 3 | DPAPI system master-key file + `DPAPI_SYSTEM` -> decrypted master key | impacket `MasterKey.decrypt` |
| 4 | Goodix 48-byte entropy from the cache seed | this tool (vendor-specific) |
| 5 | `DPAPI_BLOB(cache[:324]).decrypt(masterkey, entropy)` -> 32-byte PSK | impacket `DPAPI_BLOB` |

Step 4: `entropy = SHA256(seed)[16:] + SHA256(SHA256(seed)[:16] + root_key)`,
where `seed = Goodix_Cache.bin[324:332]` and `root_key` is an asymmetric XOR
of three constants found verbatim inside the shipped Windows `gfusb.dll`.

## Requirements

- Python >= 3.9 with `impacket` and `pycryptodome`:
  ```sh
  python3 -m venv venv
  ./venv/bin/pip install impacket pycryptodome
  ```
- The four input files below, copied off your Windows install.

## Getting the input files (read-only)

You need, from the Windows partition:

| Input | Windows location |
|-------|------------------|
| SYSTEM hive | `C:\Windows\System32\config\SYSTEM` |
| SECURITY hive | `C:\Windows\System32\config\SECURITY` |
| DPAPI master key(s) | `C:\Windows\System32\Microsoft\Protect\S-1-5-18\User\<GUID>` |
| Goodix cache blob | `C:\Windows\ServiceProfiles\LocalService\AppData\Local\Goodix\FingerPrint\Goodix_Cache.bin` (location can vary by driver version; also seen under `C:\ProgramData\Goodix\`) |

The cleanest way is to mount the Windows partition **read-only** from Linux
so nothing is modified (Windows Hello stays intact):

```sh
# identify the Windows (NTFS) partition, e.g. /dev/nvme0n1p3
lsblk -f
# mount read-only (run as root)
sudo mkdir -p /mnt/win
sudo mount -o ro /dev/nvme0n1pN /mnt/win
```

`-o ro` guarantees the source is never written. The master-key folder and
the config hives are normally ACL-protected even when mounted, so copy with
root privileges. When done: `sudo umount /mnt/win`.

## Usage -- one shot (typical)

`install_psk.py` is a thin wrapper that recovers the PSK and writes it to
the place the libfprint goodixtls5f10 driver looks at
(`/var/lib/fprint/goodix-5f10/psk`, mode 0600, atomic write):

```sh
sudo ./venv/bin/python install_psk.py --win-root /mnt/win
sudo systemctl restart fprintd
fprintd-enroll
```

That's the whole dual-boot setup.

## Usage -- extraction only

If you just want to inspect or pipe the recovered PSK without installing
it, call `goodix_psk.py` directly:

```sh
./venv/bin/python goodix_psk.py --win-root /mnt/win
```

Explicit files instead of `--win-root`:

```sh
./venv/bin/python goodix_psk.py \
  --system    /path/to/SYSTEM \
  --security  /path/to/SECURITY \
  --masterkey /path/to/mk-dir-or-file \
  --cache     /path/to/Goodix_Cache.bin
```

`--masterkey` accepts either the master-key file itself or a **directory**
of GUID-named keys (the tool auto-selects the one the cache blob is bound
to).

Other flags:

- `--quiet` -- print just the PSK hex (handy for scripting).

Sample output (PSK bytes elided):

```
Goodix 27c6:5F10 TLS Session PSK
  PSK            : <32-byte hex>
  PSK identity   : Client_identity
  Cipher         : TLS_PSK_WITH_AES_128_GCM_SHA256
  master-key GUID: <GUID of the master key the cache blob was bound to>
  master-key file: /path/to/that/master-key/file
  entropy (48B)  : <48-byte hex>
```

## Installer flags (`install_psk.py`)

Same source flags as `goodix_psk.py` (`--win-root` or explicit
`--system/--security/--masterkey/--cache`), plus:

- `--psk-hex <64 hex chars>` -- skip extraction, install a PSK you already
  have (e.g. from a different machine where you ran the extractor).
- `--psk-file FILE` -- same, but read 32 raw bytes from a file.
- `--dest PATH` -- install somewhere other than
  `/var/lib/fprint/goodix-5f10/psk` (root not required if the target is
  user-writable; pass `--allow-non-root` to bypass the root check).
- `--print-hex` -- also echo the installed PSK as hex to stdout (for
  scripting / verification).

## License

LGPL-2.1-or-later, matching libfprint.
