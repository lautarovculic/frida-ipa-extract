# frida-ipa-extract

This project was inspired by `frida-ios-dump`.
Since I recently encountered problems with that tool, I decided to create `frida-ipa-extract` with greater robustness and additions to address problems we face today.
Extract a decrypted `.ipa` from a jailbroken iOS device using Frida. Supports apps installed via App Store, sideload, and system apps.

## Requirements

- Python 3.9+
- Jailbroken iOS device with `frida-server` running
- For SSH mode: OpenSSH on the device

Installation:

```bash
# Install as a standalone tool using uv or pipx
uv tool install git+https://github.com/lautarovculic/frida-ipa-extract.git

# Or install as an editable package (for development)
pip install -e .
```

## Usage

```bash
# Using the entry point (if installed as standalone tool)
frida-ipa-extract

# Or using the script directly
python extract.py -U -f com.example.app -o MyApp.ipa
python extract.py -U -f com.example.app -o MyApp.ipa --sandbox
python extract.py -U -f com.example.app -o MyApp.ipa --no-resume
python -m frida_ipa_extract -U --pid 1234 -o MyApp.ipa
./extract.py -U "My Running App"
python extract.py -H 192.168.100.32 -P 2222 -u root -p password -f com.example.app
```

Arguments:

- `-f <target>`: spawn an app (bundle id or app name)
- `--pid <pid>`: attach to a running PID
- `target` (positional): app name/bundle id of a running app
- `-o <path>`: output IPA path (defaults to `<AppName>.ipa`)
- `-U`: connect via USB
- `-H <host> -P <port> -u <user> -p <pass>`: connect via SSH (paramiko)
- `--sandbox`: dump the app sandbox to `<AppName>-sandbox` in the current directory
- `--no-resume`: keep a spawned app suspended (useful if the app crashes due jailbreaks detections when instrumented)

If you do not pass `-f` or `--pid`, the tool attaches to a running app. If no target is provided, it will list running apps and prompt you to choose.

## Notes

- When using SSH without `-U`, the tool opens a local tunnel to `frida-server` on port `27042` and uses SFTP to download the app bundle. If you pass both `-U` and `-H`, USB is used for Frida and SSH is used only for file transfer.
- When using USB without SSH, the bundle is pulled via Frida RPC (slower for large apps).
- If the app is not running, use `-f` to spawn it.
- Make sure `frida-server` is running on the device before dumping.
- A progress bar is shown while files are being downloaded.
- If a Frida session is lost mid-download, the tool retries by switching to a stable system process; for stubborn apps use `--no-resume` or SSH transfer.

## Troubleshooting

- `Frida attach timed out`: the app may block attach; use `-f` to spawn or try `--no-resume`.
- `script has been destroyed` during download: the app crashed; retry with `--no-resume` or use SSH transfer (`-H/-u/-p`).
- `No running apps found`: the app is not running; use `-f` to spawn it.
