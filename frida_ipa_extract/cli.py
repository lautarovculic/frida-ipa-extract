import argparse
import getpass
import os
import shutil
import sys
import tempfile

import frida

from .device import connect_device
from .frida_client import FridaDumper
from .ipa import build_ipa
from .progress import ProgressBar
from .ssh import SshConfig
from .transfer import enumerate_bundle_files, pull_bundle_via_frida, pull_file_via_frida
from .utils import prompt_choice, sanitize_filename


def build_parser():
    parser = argparse.ArgumentParser(
        description="Extract a decrypted IPA from a jailbroken iOS device using Frida."
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="App name/bundle id for a running app (when -f/--pid is not used)",
    )
    parser.add_argument("-f", dest="spawn", help="Spawn an app by name or bundle id")
    parser.add_argument("--pid", type=int, help="Attach to an existing PID")
    parser.add_argument("-o", dest="output", help="Output IPA path")
    parser.add_argument(
        "--sandbox",
        action="store_true",
        help="Dump the app sandbox to <AppName>-sandbox",
    )
    parser.add_argument(
        "--no-resume",
        action="store_true",
        help="Do not resume a spawned process (useful for crashy apps)",
    )
    parser.add_argument("-U", dest="usb", action="store_true", help="Use USB device")
    parser.add_argument("-H", dest="host", help="SSH host for the device")
    parser.add_argument("-P", dest="port", type=int, help="SSH port (default 22)")
    parser.add_argument("-u", dest="username", help="SSH username")
    parser.add_argument("-p", dest="password", help="SSH password")
    return parser


def resolve_app(apps, target):
    target_lower = target.lower()
    for app in apps:
        if app.identifier == target or app.name == target:
            return app
        name = app.name or ""
        if app.identifier.lower() == target_lower or name.lower() == target_lower:
            return app
    return None


def running_apps(apps, running_pids):
    return [app for app in apps if getattr(app, "pid", 0) in running_pids]


def choose_running_app(apps):
    if not apps:
        raise RuntimeError("No running apps found.")

    for idx, app in enumerate(apps, start=1):
        name = app.name or app.identifier
        print(f"{idx}) {name} ({app.identifier}) pid={app.pid}")
    return prompt_choice(apps, "Select an app to extract: ")


def get_ssh_config(args):
    if not args.host:
        return None

    port = args.port or 22
    username = args.username or input("SSH username: ")
    password = args.password or getpass.getpass("SSH password: ")
    return SshConfig(host=args.host, port=port, username=username, password=password)


def spawn_fallback(dumper, app, reason: str, resume: bool):
    if app and getattr(app, "identifier", None) and sys.stdin.isatty():
        print(reason)
        answer = input(f"Spawn {app.identifier} instead? [y/N] ").strip().lower()
        if answer in {"y", "yes"}:
            print(f"Spawning {app.identifier}")
            dumper.spawn(app.identifier, resume=resume)
            return True
    return False


def switch_to_transfer_process(ctx, dumper, attach_timeout: float):
    candidates = ["SpringBoard", "backboardd", "launchd", "installd"]
    try:
        processes = ctx.device.enumerate_processes()
    except Exception:
        return False

    for name in candidates:
        proc = next((p for p in processes if p.name == name), None)
        if proc and proc.pid != dumper.pid:
            print(f"Switching transfer process to {name} (pid {proc.pid})")
            try:
                dumper.detach()
            except Exception:
                pass
            dumper.attach(proc.pid, retries=1, timeout=attach_timeout)
            return True
    return False


def download_bundle_via_frida(
    dumper,
    bundle_path: str,
    local_bundle_dir: str,
    remote_dump_path: str,
    local_decrypted: str,
):
    bundle_dirs, bundle_files, bundle_sizes, bundle_total = enumerate_bundle_files(
        dumper, bundle_path
    )
    dump_stat = dumper.stat_path(remote_dump_path)
    dump_size = int(dump_stat.get("size", 0))
    progress = ProgressBar(bundle_total + dump_size, label="Downloading")

    pull_bundle_via_frida(
        dumper,
        bundle_path,
        local_bundle_dir,
        files=bundle_files,
        dirs=bundle_dirs,
        sizes=bundle_sizes,
        progress=progress,
    )
    pull_file_via_frida(
        dumper,
        remote_dump_path,
        local_decrypted,
        size=dump_size,
        progress=progress,
    )
    progress.finish()


def download_dir_via_frida(dumper, root_path: str, local_dir: str, label: str):
    dirs, files, sizes, total = enumerate_bundle_files(dumper, root_path)
    progress = ProgressBar(total, label=label)
    pull_bundle_via_frida(
        dumper,
        root_path,
        local_dir,
        files=files,
        dirs=dirs,
        sizes=sizes,
        progress=progress,
    )
    progress.finish()


def main():
    args = build_parser().parse_args()

    if args.spawn and args.pid:
        raise SystemExit("Choose either -f or --pid, not both.")

    ssh_config = get_ssh_config(args)
    use_usb = args.usb or not args.host

    ctx = connect_device(use_usb=use_usb, ssh_config=ssh_config)
    dumper = FridaDumper(ctx.device)
    selected_identifier = None
    selected_name = None

    try:
        if use_usb:
            print("Connection: USB")
        else:
            print("Connection: remote Frida (SSH tunnel)")
        if ctx.ssh:
            print("Transfer: SSH/SFTP")
        else:
            print("Transfer: Frida RPC")

        apps = ctx.device.enumerate_applications()
        try:
            processes = ctx.device.enumerate_processes()
        except Exception:
            processes = []
        running_pids = {proc.pid for proc in processes}
        attach_timeout = 6.0

        try:
            if args.pid:
                print(f"Attaching to PID {args.pid}")
                app_by_pid = next((app for app in apps if app.pid == args.pid), None)
                proc_by_pid = next((proc for proc in processes if proc.pid == args.pid), None)
                if app_by_pid:
                    selected_identifier = app_by_pid.identifier
                    selected_name = app_by_pid.name
                elif proc_by_pid:
                    selected_name = proc_by_pid.name
                if args.pid not in running_pids:
                    raise SystemExit(
                        f"PID {args.pid} is not running. Use -f to spawn the app."
                    )
                try:
                    dumper.attach(args.pid, retries=1, timeout=attach_timeout)
                except (
                    frida.TransportError,
                    frida.NotSupportedError,
                    frida.OperationCancelledError,
                ) as exc:
                    reason = f"Attach failed: {exc}"
                    if app_by_pid and spawn_fallback(
                        dumper, app_by_pid, reason, resume=not args.no_resume
                    ):
                        pass
                    else:
                        raise
            elif args.spawn:
                app = resolve_app(apps, args.spawn)
                target = app.identifier if app else args.spawn
                selected_identifier = app.identifier if app else args.spawn
                selected_name = app.name if app else None
                print(f"Spawning {target}")
                dumper.spawn(target, resume=not args.no_resume)
            else:
                if args.target:
                    app = resolve_app(apps, args.target)
                    if not app or app.pid not in running_pids:
                        raise SystemExit(
                            f"App '{args.target}' is not running. Use -f to spawn it."
                        )
                else:
                    available = running_apps(apps, running_pids)
                    if not available:
                        raise SystemExit(
                            "No running apps found. Use -f to spawn the app."
                        )
                    app = choose_running_app(available)
                name = app.name or app.identifier
                selected_identifier = app.identifier
                selected_name = app.name
                print(f"Attaching to {name} (pid {app.pid})")
                try:
                    dumper.attach(app.pid, retries=1, timeout=attach_timeout)
                except (frida.TransportError, frida.OperationCancelledError) as exc:
                    if not spawn_fallback(
                        dumper, app, f"Attach timed out: {exc}", resume=not args.no_resume
                    ):
                        raise
                except frida.NotSupportedError as exc:
                    if not spawn_fallback(
                        dumper, app, f"Attach not supported: {exc}", resume=not args.no_resume
                    ):
                        raise
        except frida.TransportError as exc:
            raise SystemExit(
                "Frida attach timed out. Try `-f` to spawn the app, "
                "or verify frida-server is running and matches the client version."
            ) from exc
        except frida.OperationCancelledError as exc:
            raise SystemExit(
                "Frida attach timed out. Try `-f` to spawn the app."
            ) from exc
        except frida.NotSupportedError as exc:
            raise SystemExit(
                "Frida could not attach to the running process. "
                "Some apps block attach; try `-f` to spawn instead."
            ) from exc

        info = dumper.get_bundle_info()
        app_name = info.get("appName") or selected_name or selected_identifier or info.get("executableName")
        default_output = sanitize_filename(app_name) + ".ipa"
        output_path = args.output or default_output

        bundle_path = info.get("bundlePath")
        executable_name = info.get("executableName")
        bundle_id = info.get("bundleId") or selected_identifier
        if not bundle_path or not executable_name:
            raise SystemExit("Unable to resolve bundle path or executable name.")
        dump_dir = bundle_id or sanitize_filename(app_name)
        
        sandbox_path = dumper.get_sandbox_path()
        if not sandbox_path:
            raise SystemExit("Unable to resolve sandbox path.")
        remote_dump_path = f"{sandbox_path}/tmp/{dump_dir}/{executable_name}.decrypted"

        print(f"Bundle ID: {bundle_id or 'unknown'}")
        print(f"Bundle path: {bundle_path}")
        print(f"Executable: {executable_name}")
        print(f"Output: {output_path}")

        print("Dumping decrypted binary via Frida...")
        dumper.dump_executable(remote_dump_path)

        sandbox_path = None
        sandbox_out_dir = None
        if args.sandbox:
            sandbox_out_dir = f"{sanitize_filename(app_name)}-sandbox"
            if os.path.exists(sandbox_out_dir):
                raise SystemExit(
                    f"Sandbox output directory already exists: {sandbox_out_dir}"
                )
            print(f"Sandbox path: {sandbox_path}")

        with tempfile.TemporaryDirectory() as tmpdir:
            local_bundle_dir = os.path.join(tmpdir, os.path.basename(bundle_path))
            local_decrypted = os.path.join(tmpdir, f"{executable_name}.decrypted")

            if ctx.ssh:
                print("Scanning bundle over SSH...")
                bundle_files, bundle_dirs = ctx.ssh.walk(bundle_path)
                bundle_total = sum(size for _, _, size in bundle_files)
                dump_size = ctx.ssh.stat(remote_dump_path).st_size
                progress = ProgressBar(bundle_total + dump_size, label="Downloading")

                ctx.ssh.download_dir(
                    bundle_path,
                    local_bundle_dir,
                    files=bundle_files,
                    dirs=bundle_dirs,
                    progress=progress,
                )
                ctx.ssh.download_file(remote_dump_path, local_decrypted, progress=progress)
                progress.finish()
            else:
                print("Scanning bundle via Frida...")
                try:
                    download_bundle_via_frida(
                        dumper,
                        bundle_path,
                        local_bundle_dir,
                        remote_dump_path,
                        local_decrypted,
                    )
                except (frida.InvalidOperationError, frida.TransportError) as exc:
                    if ctx.ssh:
                        print(f"Frida session lost: {exc}")
                        print("Falling back to SSH download...")
                        bundle_files, bundle_dirs = ctx.ssh.walk(bundle_path)
                        bundle_total = sum(size for _, _, size in bundle_files)
                        dump_size = ctx.ssh.stat(remote_dump_path).st_size
                        progress = ProgressBar(
                            bundle_total + dump_size, label="Downloading"
                        )
                        ctx.ssh.download_dir(
                            bundle_path,
                            local_bundle_dir,
                            files=bundle_files,
                            dirs=bundle_dirs,
                            progress=progress,
                        )
                        ctx.ssh.download_file(
                            remote_dump_path, local_decrypted, progress=progress
                        )
                        progress.finish()
                    else:
                        print(f"Frida session lost: {exc}")
                        if switch_to_transfer_process(ctx, dumper, attach_timeout):
                            print("Retrying download with transfer process...")
                            download_bundle_via_frida(
                                dumper,
                                bundle_path,
                                local_bundle_dir,
                                remote_dump_path,
                                local_decrypted,
                            )
                        else:
                            raise SystemExit(
                                "Frida session lost while downloading. "
                                "Retry with --no-resume or use SSH transfer (-H/-u/-p)."
                            ) from exc

            local_bin_path = os.path.join(local_bundle_dir, executable_name)
            shutil.copy2(local_decrypted, local_bin_path)

            print(f"Building IPA at {output_path}...")
            build_ipa(local_bundle_dir, output_path)

        if args.sandbox and sandbox_path and sandbox_out_dir:
            if ctx.ssh:
                print("Scanning sandbox over SSH...")
                sandbox_files, sandbox_dirs = ctx.ssh.walk(sandbox_path)
                sandbox_total = sum(size for _, _, size in sandbox_files)
                progress = ProgressBar(sandbox_total, label="Downloading sandbox")
                ctx.ssh.download_dir(
                    sandbox_path,
                    sandbox_out_dir,
                    files=sandbox_files,
                    dirs=sandbox_dirs,
                    progress=progress,
                )
                progress.finish()
            else:
                print("Scanning sandbox via Frida...")
                try:
                    download_dir_via_frida(
                        dumper, sandbox_path, sandbox_out_dir, "Downloading sandbox"
                    )
                except (frida.InvalidOperationError, frida.TransportError) as exc:
                    if ctx.ssh:
                        print(f"Frida session lost: {exc}")
                        print("Falling back to SSH download...")
                        sandbox_files, sandbox_dirs = ctx.ssh.walk(sandbox_path)
                        sandbox_total = sum(size for _, _, size in sandbox_files)
                        progress = ProgressBar(
                            sandbox_total, label="Downloading sandbox"
                        )
                        ctx.ssh.download_dir(
                            sandbox_path,
                            sandbox_out_dir,
                            files=sandbox_files,
                            dirs=sandbox_dirs,
                            progress=progress,
                        )
                        progress.finish()
                    else:
                        print(f"Frida session lost: {exc}")
                        if switch_to_transfer_process(ctx, dumper, attach_timeout):
                            print("Retrying sandbox download with transfer process...")
                            download_dir_via_frida(
                                dumper,
                                sandbox_path,
                                sandbox_out_dir,
                                "Downloading sandbox",
                            )
                        else:
                            raise SystemExit(
                                "Frida session lost while downloading sandbox. "
                                "Retry with --no-resume or use SSH transfer (-H/-u/-p)."
                            ) from exc

        try:
            dumper.remove_path(remote_dump_path)
        except Exception:
            pass

        print("Done.")
    finally:
        try:
            dumper.detach()
        except Exception:
            pass
        try:
            ctx.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()
