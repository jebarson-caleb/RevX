#!/usr/bin/env python3
"""Disposable-VM rehearsal of `nousb boot arm` with the real Linux backend.

Boots an Ubuntu cloud image as the "current OS" under KVM + OVMF, using a throwaway qcow2
overlay and a private copy of the OVMF variable store. Nothing from the host is attached
writable except those run-local files. Inside the guest a `real-linux-boot` nousb binary:

  1. records BootCurrent/BootOrder, runs `boot plan`, then `boot arm` with the typed phrase;
  2. reboots; firmware must take BootNext into the ISO's shim/GRUB and the live installer;
  3. the host resets the VM once the installer is observed (serial, disk reads, OCR);
  4. the guest must come back with the original BootCurrent, unchanged BootOrder and no
     BootNext, then runs `boot cleanup` and checks nothing is left behind.

Usage:
  linux_host_boot_rehearsal.py --nousb target/x86_64-unknown-linux-musl/release/nousb \
      --iso .nousb/artifacts/ubuntu-24.04-server/ubuntu-24.04.4-live-server-amd64.iso \
      --cloud-image .nousb/vm/linux-host-boot/ubuntu-24.04-server-cloudimg-amd64.img
"""

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import functools
print = functools.partial(print, flush=True)
from pathlib import Path

OVMF_DIR = Path("/usr/share/edk2/x64")
INSTALLER_SCREEN = re.compile(
    r"preferred language|use up, down|welcome!|subiquity|install (ubuntu|fedora)|try (ubuntu|fedora)"
    r"|welcome to (ubuntu|fedora)|choose your language|install to hard drive",
    re.I,
)

GUEST_SCRIPT = r"""#!/bin/bash
set -u
S=/var/lib/nousb-rehearsal; mkdir -p "$S"; cd "$S"
P=__PROFILE__
log() { echo "NOUSB-REHEARSAL: $*" > /dev/ttyS0; }
field() { efibootmgr | sed -n "s/^$1: //p"; }
dump() { efibootmgr -v 2>&1 | sed 's/^/NOUSB-EFI: /' > /dev/ttyS0; }
run() { log "\$ $*"; "$@" 2>&1 | sed 's/^/NOUSB-OUT: /' > /dev/ttyS0; return "${PIPESTATUS[0]}"; }
finish() { echo "$1" > stage; sync; log "$1 $2"; systemctl poweroff; exit 0; }
# The live installer's own cloud-init also reads this seed; there we only report and stay idle.
if grep -q "iso-scan/filename=" /proc/cmdline; then
  log "LIVE-INSTALLER cmdline=$(cat /proc/cmdline)"
  log "LIVE-INSTALLER mounts=$(grep -E ' /cdrom | /isodevice | /run/live' /proc/mounts | tr '\n' ';')"
  log "LIVE-INSTALLER BootCurrent=$(field BootCurrent) BootNext=$(field BootNext)"
  exit 0
fi
SRC=/mnt/nousb-src; mkdir -p "$SRC"
mountpoint -q "$SRC" || mount -o ro -L NOUSBSRC "$SRC" || finish FAIL "cannot mount source disk"
N="$SRC/nousb"; ISO=$(ls "$SRC"/*.iso)
stage=$(cat stage 2>/dev/null || echo fresh)
log "boot stage=$stage BootCurrent=$(field BootCurrent) BootOrder=$(field BootOrder) BootNext=$(field BootNext)"
case "$stage" in
fresh)
  # A brand-new varstore first boots through an auto-created option; reboot once so the
  # baseline is the steady-state default, as on a real computer.
  echo settled > stage; sync; log "SETTLING reboot"; systemctl reboot ;;
settled)
  if ! command -v efibootmgr >/dev/null; then
    # The plan must name the missing tool as a blocker before anything is installed.
    "$N" boot plan "$P" --iso "$ISO" 2>&1 | grep -q "required tool efibootmgr is not installed" \
      || finish FAIL "plan did not block on missing efibootmgr"
    log "MISSING-TOOL blocker reported; installing efibootmgr"
    { apt-get update -qq && apt-get install -y -qq efibootmgr; } >/dev/null 2>&1 || dnf -y -q install efibootmgr >/dev/null 2>&1
  fi
  field BootCurrent > base_current; field BootOrder > base_order; dump
  run "$N" doctor
  run "$N" boot plan "$P" --iso "$ISO"
  run "$N" boot arm "$P" "BOOT ONCE INTO wrong-profile" --iso "$ISO" && finish FAIL "wrong phrase was accepted"
  run "$N" boot arm "$P" "BOOT ONCE INTO $P" --iso "$ISO" || finish FAIL "arm failed"
  run "$N" boot status; dump
  [ "$(field BootOrder)" = "$(cat base_order)" ] || finish FAIL "arm changed BootOrder"
  [ -n "$(field BootNext)" ] || finish FAIL "arm did not set BootNext"
  echo armed > stage; sync; log "ARMED BootNext=$(field BootNext)"
  systemctl reboot ;;
armed)
  dump; fails=""
  [ "$(field BootCurrent)" = "$(cat base_current)" ] || fails="$fails; BootCurrent is not the original OS"
  [ "$(field BootOrder)" = "$(cat base_order)" ] || fails="$fails; BootOrder changed"
  [ -z "$(field BootNext)" ] || fails="$fails; BootNext still pending"
  run "$N" boot status
  run "$N" boot cleanup "CLEAN UP NOUSB BOOT" || fails="$fails; cleanup failed"
  run "$N" boot status; dump
  efibootmgr | grep -qi nousb && fails="$fails; NoUSB firmware entry remains"
  [ -e /boot/efi/EFI/NoUSB ] && fails="$fails; ESP EFI/NoUSB remains"
  [ -e /boot/efi/.disk/info ] && fails="$fails; ESP .disk/info remains"
  [ -e /boot/efi/boot/grub/grub.cfg ] && fails="$fails; ESP boot/grub/grub.cfg remains"
  [ -e /NoUSB ] && fails="$fails; staging /NoUSB remains"
  [ "$(field BootOrder)" = "$(cat base_order)" ] || fails="$fails; BootOrder changed after cleanup"
  [ -z "$fails" ] && finish PASS "returned to original OS and cleaned up" || finish FAIL "${fails#; }" ;;
*) log "already finished: $stage"; systemctl poweroff ;;
esac
"""

USER_DATA = """#cloud-config
hostname: nousb-current-os
password: nousb
chpasswd: {expire: false}
ssh_pwauth: false
growpart: {mode: auto, devices: ['/']}
write_files:
  - path: /usr/local/sbin/nousb-rehearsal
    permissions: '0755'
    encoding: b64
    content: __SCRIPT__
  - path: /etc/systemd/system/nousb-rehearsal.service
    content: |
      [Unit]
      Description=NoUSB host-boot rehearsal step
      After=local-fs.target
      [Service]
      Type=oneshot
      ExecStart=/usr/local/sbin/nousb-rehearsal
      [Install]
      WantedBy=multi-user.target
runcmd:
  - [systemctl, daemon-reload]
  - [systemctl, enable, nousb-rehearsal.service]
  - [systemctl, start, --no-block, nousb-rehearsal.service]
"""


def sh(*args):
    subprocess.run([str(a) for a in args], check=True, stdout=subprocess.DEVNULL)


class Qmp:
    def __init__(self, path):
        for _ in range(100):
            try:
                self.sock = socket.socket(socket.AF_UNIX)
                self.sock.connect(str(path))
                break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError("QMP socket did not appear")
        self.file = self.sock.makefile("rw")
        self.file.readline()
        self.cmd("qmp_capabilities")

    def cmd(self, name, **arguments):
        self.file.write(json.dumps({"execute": name, "arguments": arguments}) + "\n")
        self.file.flush()
        while True:
            reply = json.loads(self.file.readline())
            if "return" in reply or "error" in reply:
                return reply


def prepare(args, run):
    import base64

    sh("qemu-img", "create", "-q", "-f", "qcow2", "-b", args.cloud_image.resolve(), "-F", "qcow2",
       run / "root.qcow2", args.root_size)
    vars_src = args.secure_boot_vars or OVMF_DIR / "OVMF_VARS.4m.fd"
    shutil.copy(vars_src, run / "vars.fd")
    src = run / "src"
    src.mkdir()
    shutil.copy(args.nousb, src / "nousb")
    os.link(args.iso.resolve(), src / args.iso.name)
    size = args.iso.stat().st_size + 256 * 1024 * 1024
    with open(run / "src.img", "wb") as image:
        image.truncate(size)
    sh("mkfs.ext4", "-q", "-L", "NOUSBSRC", "-d", src, run / "src.img")
    seed = run / "seed"
    seed.mkdir()
    script = base64.b64encode(GUEST_SCRIPT.replace("__PROFILE__", args.profile).encode()).decode()
    (seed / "user-data").write_text(USER_DATA.replace("__SCRIPT__", script))
    (seed / "meta-data").write_text("instance-id: nousb-rehearsal\nlocal-hostname: nousb-current-os\n")
    sh("xorriso", "-as", "genisoimage", "-quiet", "-output", run / "seed.iso", "-volid", "CIDATA",
       "-joliet", "-rock", seed / "user-data", seed / "meta-data")


def ocr(png):
    from PIL import Image

    big = png.with_suffix(".x2.png")
    with Image.open(png) as image:
        image.convert("L").resize((image.width * 2, image.height * 2)).save(big)
    result = subprocess.run(["tesseract", str(big), "-"], capture_output=True, text=True)
    return result.stdout


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--nousb", type=Path, required=True)
    parser.add_argument("--iso", type=Path, required=True)
    parser.add_argument("--cloud-image", type=Path, required=True)
    parser.add_argument("--work", type=Path, default=Path(".nousb/vm/linux-host-boot"))
    parser.add_argument("--secure-boot-vars", type=Path,
                        help="OVMF vars with Secure Boot keys enrolled; uses the secboot firmware")
    parser.add_argument("--memory", default="8G")
    parser.add_argument("--profile", default="ubuntu-24.04-server")
    parser.add_argument("--root-size", default="24G")
    args = parser.parse_args()

    run = args.work / f"run-{int(time.time())}-{os.getpid()}"
    run.mkdir(parents=True)
    prepare(args, run)
    code = OVMF_DIR / ("OVMF_CODE.secboot.4m.fd" if args.secure_boot_vars else "OVMF_CODE.4m.fd")
    serial = run / "serial.log"
    qmp_path = run / "qmp.sock"
    qemu = subprocess.Popen([
        "qemu-system-x86_64", "-enable-kvm", "-cpu", "host", "-smp", "4", "-m", args.memory,
        "-machine", "q35,smm=on", "-global", "driver=cfi.pflash01,property=secure,value=on",
        "-drive", f"if=pflash,format=raw,unit=0,readonly=on,file={code}",
        "-drive", f"if=pflash,format=raw,unit=1,file={run / 'vars.fd'}",
        "-drive", f"file={run / 'root.qcow2'},if=none,id=root,format=qcow2",
        "-device", "virtio-blk-pci,drive=root,bootindex=0",
        "-drive", f"file={run / 'src.img'},if=none,id=src,format=raw,readonly=on",
        "-device", "virtio-blk-pci,drive=src",
        "-drive", f"file={run / 'seed.iso'},if=none,id=seed,format=raw,readonly=on,media=cdrom",
        "-device", "ide-cd,drive=seed",
        "-netdev", "user,id=net0", "-device", "virtio-net-pci,netdev=net0",
        "-vga", "std", "-display", "none", "-serial", f"file:{serial}",
        "-qmp", f"unix:{qmp_path},server=on,wait=off", "-name", "nousb-rehearsal",
    ], stderr=open(run / "qemu.stderr", "w"))
    qmp = Qmp(qmp_path)
    report = {"profile": args.profile, "cloud_image": args.cloud_image.name, "run": str(run), "secure_boot": bool(args.secure_boot_vars), "phases": {}}
    start = time.time()

    def log_text():
        return serial.read_text(errors="replace") if serial.exists() else ""

    def wait_for(pattern, timeout):
        deadline = time.time() + timeout
        while time.time() < deadline and qemu.poll() is None:
            match = re.search(pattern, log_text())
            if match:
                return match
            time.sleep(2)
        return re.search(pattern, log_text())

    def rd_bytes():
        stats = qmp.cmd("query-blockstats")["return"]
        return next(s["stats"]["rd_bytes"] for s in stats if s.get("device") == "root")

    try:
        armed = wait_for(r"NOUSB-REHEARSAL: (ARMED|FAIL.*)", 1200)
        report["phases"]["arm"] = armed.group(0) if armed else "timeout"
        if not armed or not armed.group(1).startswith("ARMED"):
            raise SystemExit(f"arm phase failed: {report['phases']['arm']}")
        print(f"[{time.time() - start:.0f}s] armed")
        offset = len(log_text())
        reads_before = rd_bytes()
        installer = {"grub_menu_on_serial": False, "live_markers": [], "screen_text": "",
                     "rd_bytes": 0}
        deadline = time.time() + 900
        live_seen_at = None
        shot = 0
        while time.time() < deadline and qemu.poll() is None:
            time.sleep(15)
            tail = log_text()[offset:]
            installer["grub_menu_on_serial"] |= "NoUSB one-shot" in tail
            installer["live_markers"] = re.findall(r"NOUSB-REHEARSAL: LIVE-INSTALLER[^\n]*", tail)
            if installer["live_markers"] and live_seen_at is None:
                live_seen_at = time.time()
            installer["rd_bytes"] = rd_bytes() - reads_before
            png = run / f"installer-{shot:02d}.png"
            qmp.cmd("screendump", filename=str(png.resolve()), format="png")
            shot += 1
            text = ocr(png) if png.exists() else ""
            if INSTALLER_SCREEN.search(text):
                installer["screen_text"] = " ".join(text.split())[:300]
                installer["screenshot"] = png.name
            # Stop once the installer screen is up, or two minutes after the live marker.
            if installer["screen_text"]:
                break
            if live_seen_at and time.time() - live_seen_at > 120:
                break
        report["phases"]["installer"] = installer
        print(f"[{time.time() - start:.0f}s] installer: {installer}")
        if not (installer["live_markers"] or installer["screen_text"]):
            raise SystemExit("live installer was not observed within 15 minutes")
        # The user reboots from the live system without installing.
        qmp.cmd("system_reset")
        done = wait_for(r"NOUSB-REHEARSAL: (PASS|FAIL)[^\n]*", 900)
        report["phases"]["return_and_cleanup"] = done.group(0) if done else "timeout"
        print(f"[{time.time() - start:.0f}s] {report['phases']['return_and_cleanup']}")
        report["passed"] = bool(done and done.group(1) == "PASS")
    finally:
        try:
            qemu.wait(timeout=120)
        except subprocess.TimeoutExpired:
            qemu.kill()
        text = log_text()
        report["boot_current_trace"] = re.findall(r"NOUSB-REHEARSAL: boot stage=[^\n]*", text)
        report["firmware_boot_lines"] = re.findall(r"BdsDxe: [^\n]*", text)
        report.setdefault("passed", False)
        report["duration_seconds"] = round(time.time() - start)
        (run / "report.json").write_text(json.dumps(report, indent=2))
        for big in ["root.qcow2", "src.img"] if report["passed"] else []:
            (run / big).unlink(missing_ok=True)
        shutil.rmtree(run / "src", ignore_errors=True)
        print(f"report: {run / 'report.json'} passed={report['passed']}")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
