#!/usr/bin/env python3
"""
zsmagent — a small, read-only-by-default driver for IBM zSecure Secret Manager
commands on z/OS, over SSH into z/OS UNIX System Services.

Design notes
------------
This does NOT touch ZOC9 or the 3270 session. It opens the same SSH connection
you open by hand from Terminal and issues the same `irrsadmin` commands.

Result convention (observed in the reference run): a successful slp/slsi/srp
prints NOTHING at all. Failures print a structure containing racf_major_rc and
a `description` field that usually states the fix. So:

    empty output            -> success
    racf_major_rc: 0        -> success
    anything else           -> failure; read `description` first

Safety
------
Writes are blocked unless you pass allow_writes=True (or --allow-writes).
Prove the read path first. Every command issued is appended to an audit log,
because these commands are attributable to YOUR user ID on a shared system.

Usage
-----
    export ZSM_HOST=tvt8017.pok.stglabs.ibm.com
    export ZSM_USER=CRMBSM1
    export ZSM_PASSWORD=...          # or use ZSM_KEYFILE=~/.ssh/id_ed25519

    python3 zsmagent.py check
    python3 zsmagent.py glp '*'
    python3 zsmagent.py glsi LP LS
    python3 zsmagent.py refresh RDATALIB

Requires: pip install paramiko
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Sequence

try:
    import paramiko
except ImportError:  # pragma: no cover
    paramiko = None  # only needed for live sessions; dry-run works without it


# --------------------------------------------------------------------------
# Command allowlist
#
# Only the verbs confirmed from the July reference run are listed. Before you
# add more, check them against the product docs -- do not guess a verb name.
# --------------------------------------------------------------------------

READ_VERBS = {
    "glp":  "get local provider",
    "glsi": "get local secret info",
}

WRITE_VERBS = {
    "slp":  "set local provider",
    "slsi": "set local secret info",
    "srp":  "set remote provider",
}

AUDIT_LOG = Path(os.environ.get("ZSM_AUDIT_LOG", "~/.zsmagent-audit.log")).expanduser()


class WriteBlocked(RuntimeError):
    """Raised when a mutating command is attempted in read-only mode."""


class UnknownVerb(ValueError):
    """Raised for a verb that is not in either allowlist."""


# --------------------------------------------------------------------------
# Result parsing
# --------------------------------------------------------------------------

_RC_RE = re.compile(r"racf_major_rc\s*[:=]\s*(-?\d+)", re.IGNORECASE)
_DESC_RE = re.compile(r"description\s*[:=]\s*\"?([^\"\n]+)\"?", re.IGNORECASE)


@dataclass
class Result:
    ok: bool
    rc: Optional[int]
    description: Optional[str]
    payload: Optional[Any]
    raw: str
    stderr: str = ""
    exit_status: int = 0

    def __str__(self) -> str:
        if self.ok:
            return f"OK (rc={self.rc if self.rc is not None else 'silent'})"
        return f"FAILED (rc={self.rc}): {self.description or self.raw.strip()[:200]}"


def parse_result(stdout: str, stderr: str = "", exit_status: int = 0) -> Result:
    """Turn raw irrsadmin output into a Result.

    Silence is success. A zero racf_major_rc is success. Everything else is a
    failure whose `description` field is the thing worth reading.
    """
    raw = stdout or ""
    text = raw.strip()

    payload = None
    if text.startswith("{") or text.startswith("["):
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            payload = None

    rc: Optional[int] = None
    if isinstance(payload, dict):
        for key in ("racf_major_rc", "racfMajorRc", "rc"):
            if key in payload:
                try:
                    rc = int(payload[key])
                except (TypeError, ValueError):
                    pass
                break
    if rc is None:
        m = _RC_RE.search(raw)
        if m:
            rc = int(m.group(1))

    description = None
    if isinstance(payload, dict) and payload.get("description"):
        description = str(payload["description"])
    else:
        m = _DESC_RE.search(raw)
        if m:
            description = m.group(1).strip()

    # Shell-level failures (bad PATH, irrsadmin not on the system) never reach
    # the product, so there is no racf_major_rc -- the message is on stderr.
    if description is None and stderr.strip():
        description = stderr.strip().splitlines()[0]

    if not text and exit_status == 0:
        ok = True                      # silent success
    elif rc is not None:
        ok = rc == 0
    else:
        # No rc to go on -- trust the exit status alone. Do NOT treat stderr
        # output as failure: tsocmd echoes the command name to stderr even on
        # a completely successful run (`tsocmd "TIME"` emits "TIME" there).
        ok = exit_status == 0

    return Result(
        ok=ok,
        rc=rc,
        description=description,
        payload=payload,
        raw=raw,
        stderr=stderr,
        exit_status=exit_status,
    )


# --------------------------------------------------------------------------
# Session
# --------------------------------------------------------------------------

@dataclass
class ZSMSession:
    host: str
    user: str
    password: Optional[str] = None
    keyfile: Optional[str] = None
    port: int = 22
    allow_writes: bool = False
    # exec_command does not source a login profile, so PATH may not include
    # irrsadmin. Set ZSM_PRELUDE if your site needs extra setup first.
    prelude: str = field(default_factory=lambda: os.environ.get("ZSM_PRELUDE", ""))
    _client: Optional["paramiko.SSHClient"] = field(default=None, repr=False)

    def __enter__(self) -> "ZSMSession":
        self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def connect(self) -> None:
        if paramiko is None:
            sys.exit("paramiko is required for live sessions:  pip install paramiko")
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        # Matches the manual first-connection prompt you answer with "yes".
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=self.host,
            port=self.port,
            username=self.user,
            password=self.password,
            key_filename=self.keyfile,
            look_for_keys=bool(self.keyfile) or not self.password,
            timeout=30,
        )
        self._client = client

    def close(self) -> None:
        if self._client:
            self._client.close()
            self._client = None

    # -- raw shell ---------------------------------------------------------

    def _exec(self, command: str, timeout: int = 120) -> Result:
        if not self._client:
            raise RuntimeError("not connected; call connect() first")

        full = f"{self.prelude}; {command}" if self.prelude else command
        self._audit(command)

        _, stdout, stderr = self._client.exec_command(full, timeout=timeout)
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        status = stdout.channel.recv_exit_status()
        return parse_result(out, err, status)

    def _audit(self, command: str) -> None:
        stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        line = f"{stamp}\t{self.user}@{self.host}\t{command}\n"
        try:
            AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
            with AUDIT_LOG.open("a", encoding="utf-8") as fh:
                fh.write(line)
        except OSError:
            pass  # never let logging break the command

    # -- irrsadmin ---------------------------------------------------------

    def irrsadmin(self, verb: str, *args: str) -> Result:
        verb = verb.lower()
        if verb in WRITE_VERBS:
            if not self.allow_writes:
                raise WriteBlocked(
                    f"'{verb}' ({WRITE_VERBS[verb]}) is a mutating command and "
                    f"writes are disabled. Prove the read path first, then pass "
                    f"allow_writes=True."
                )
        elif verb not in READ_VERBS:
            known = ", ".join(sorted(READ_VERBS | WRITE_VERBS.keys()))
            raise UnknownVerb(f"unknown verb '{verb}'. Known: {known}")

        cmd = " ".join(["irrsadmin", verb] + [shlex.quote(a) for a in args])
        return self._exec(cmd)

    # Convenience wrappers for the read path.

    def get_local_provider(self, name: str = "*") -> Result:
        return self.irrsadmin("glp", "-p", name)

    def get_local_secret(self, provider: str, secret: str) -> Result:
        return self.irrsadmin("glsi", "-p", provider, "-s", secret)

    # -- the thing that cost 40 minutes ------------------------------------

    def raclist_refresh(self, racf_class: str) -> Result:
        """SETROPTS RACLIST(<class>) REFRESH via tsocmd.

        A PERMIT does not take effect until the class is refreshed. Run this
        after every permit; it is cheap and forgetting it is expensive.
        """
        racf_class = racf_class.upper()
        if not re.fullmatch(r"[A-Z0-9$#@]{1,8}", racf_class):
            raise ValueError(f"implausible RACF class name: {racf_class!r}")
        cmd = f'tsocmd "SETROPTS RACLIST({racf_class}) REFRESH"'
        return self._exec(cmd)

    def check(self) -> Result:
        """Prove the SSH path works at all, before blaming the product."""
        return self._exec('tsocmd "TIME"')

    def home_dir(self) -> Optional[str]:
        """The connected user's z/OS UNIX home, with a trailing slash.

        Used to default PATHPFX so a shipped values file never carries someone
        else's home directory into a new tester's install.
        """
        r = self._exec("echo $HOME")
        path = r.raw.strip().splitlines()[-1].strip() if r.raw.strip() else ""
        if not path.startswith("/"):
            return None
        return path if path.endswith("/") else path + "/"

    def dataset_exists(self, dsn: str) -> Optional[bool]:
        """True/False if determinable, None if the check itself was unclear.

        Uses LISTCAT because the CSI is a VSAM cluster, which the z/OS UNIX
        //'DSN' syntax cannot see.
        """
        if not re.fullmatch(r"[A-Z0-9$#@.]{1,44}", dsn.upper()):
            raise ValueError(f"implausible dataset name: {dsn!r}")
        r = self._exec(f"tsocmd \"LISTCAT ENT('{dsn.upper()}')\"")
        blob = (r.raw + r.stderr).upper()
        if "NOT FOUND" in blob or "NOTFND" in blob:
            return False
        if dsn.upper() in blob:
            return True
        return None


# --------------------------------------------------------------------------
# Diagnostics
#
# Maps the message IDs that actually come back from z/OS, SMP/E and the shell
# to a plain-language cause and a concrete fix. Deterministic lookup, no
# guessing: if nothing matches, say so rather than inventing an explanation.
#
# Every entry below was either observed in a real run or is taken from the
# Program Directory. Add to it when you hit something new -- that is how the
# knowledge stops living in someone's head.
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Diagnosis:
    pattern: str
    title: str
    cause: str
    fix: str


DIAGNOSTICS: list[Diagnosis] = [
    Diagnosis(
        r"EDC5003I|Truncation of a record",
        "A value is too long for the 80-character line limit",
        "PDS members hold fixed 80-byte records. A substituted value pushed a "
        "line past 80 characters and the rest was cut off. IBM's sample jobs "
        "have comment lines that already run to about column 73, so there is "
        "very little room.",
        "Almost always PATHPFX. Shorten it -- /home/yourid/t1/ works, anything "
        "much longer does not. Then re-run `smpe --dry-run` first: it now "
        "reports the exact line and how many characters to remove.",
    ),
    Diagnosis(
        r"EDC5049I|could not be located",
        "A dataset does not exist",
        "Something tried to open a dataset that is not there. Usually the "
        "scratch JCL PDS.",
        "Allocate it:\n"
        "  ssh USER@HOST \"tsocmd \\\"ALLOCATE DATASET('USER.TEST.JCL') NEW "
        "CATALOG SPACE(5,5) TRACKS DIR(10) RECFM(F,B) LRECL(80) BLKSIZE(0)\\\"\"",
    ),
    Diagnosis(
        r"EDC5129I|FSUM7343",
        "A directory or path does not exist",
        "A file could not be opened for output because its directory is "
        "missing. Note that z/OS UNIX does not necessarily have /tmp.",
        "If this names your mount point, create it:\n"
        "  ssh USER@HOST \"mkdir -p /home/yourid/t1\"\n"
        "If it names a staging file under $HOME, check your home directory is "
        "mounted and writable.",
    ),
    Diagnosis(
        r"GIM20301S|SYNTAX ERROR IN THE COMMAND AT COLUMN",
        "SMP/E rejected a command's syntax",
        "The column number in the message is where SMP/E stopped. The most "
        "common cause by far is a QUOTED value -- RFPREFIX and similar "
        "operands do not take quotes. Once the command is dead, SMP/E flags "
        "every continuation line too, so one mistake looks like four errors.",
        "Fix only the FIRST error; the rest are cascade. Check your values "
        "file for stray ' or \" characters. Values must be bare: "
        "RFPREFIX(CONSUL.BRS320.GA) not RFPREFIX('CONSUL.BRS320.GA').",
    ),
    Diagnosis(
        r"CERTIFICATE_VERIFY_FAILED|unable to get local issuer",
        "Your machine does not trust the mainframe's TLS certificate",
        "z/OSMF is presenting a certificate signed by an internal CA that is "
        "not in your workstation's trust store. This is expected on internal "
        "systems.",
        "Add --zosmf-insecure to the command for a test run. Confirm who "
        "issued the certificate first:\n"
        "  openssl s_client -connect HOST:443 </dev/null 2>/dev/null | "
        "openssl x509 -noout -issuer\n"
        "The proper fix is installing your organisation's CA bundle.",
    ),
    Diagnosis(
        r"JrUserUnMountNotAllowed|EPERM.*not permitted",
        "You cannot unmount a file system someone else mounted",
        "z/OS only lets a non-privileged user unmount file systems they "
        "mounted themselves. A file system remounted at IPL belongs to the "
        "system, not to you.",
        "Do not try to reuse that prefix. Choose an unused TARGETPFX and a "
        "mount point under your own home directory, which you can mount and "
        "unmount freely.",
    ),
    Diagnosis(
        r"\bS?[BDE]37\b|IEF257I|SPACE.*(EXCEEDED|NOT AVAILABLE)|NOT ENOUGH SPACE",
        "The volume ran out of space",
        "An x37 abend (B37/D37/E37) means a dataset could not be extended. "
        "The Program Directory needs about 5,680 tracks (380 cylinders) in "
        "total, and the zFS is 5,250 of that.",
        "Pick a volume with room, or ask your system programmer which volume "
        "to use. Check free space in ISPF option 3.4 by entering the volume "
        "serial and using the V line command.",
    ),
    Diagnosis(
        r"JCL ERROR",
        "The job was rejected before it ran",
        "JES could not interpret the JCL. Nothing executed, so nothing was "
        "changed. Usually a malformed statement, a bad continuation, or a "
        "dataset name JES could not resolve.",
        "Read the job's JESMSGLG output for the IEF message naming the line. "
        "Run `smpe --dry-run` and inspect that job's text -- a value "
        "containing an unexpected character is the usual cause.",
    ),
    Diagnosis(
        r"IEF212I|DATA SET NOT FOUND",
        "A dataset named in the JCL does not exist",
        "A DD statement referenced something that is not there. On a fresh "
        "install this usually means an earlier job in the sequence did not "
        "actually create what this one expects.",
        "Check the previous job really ended RC 00, not just 'submitted'. If "
        "you skipped jobs with --from, you may have skipped one that was "
        "needed.",
    ),
    Diagnosis(
        r"racf_major_rc\s*[:=]\s*8|ICH408I|NOT AUTHORIZED",
        "RACF refused the request",
        "Your userid does not have the access this operation needs. The agent "
        "runs with exactly your authority -- it cannot and does not escalate.",
        "For a zFS mount failure: point PATHPFX inside your own home "
        "directory, which needs no special authority. Otherwise the profile "
        "name in the message is what a RACF administrator needs to permit. "
        "Remember a PERMIT needs SETROPTS RACLIST(class) REFRESH afterwards.",
    ),
    Diagnosis(
        r"Authentication failed|Bad authentication|Permission denied \(publickey",
        "SSH could not log you in",
        "Wrong password, expired password, or a key that is not installed on "
        "the host.",
        "Re-enter the password with `read -s ZSM_PASSWORD && export "
        "ZSM_PASSWORD`, then check it registered with `echo ${#ZSM_PASSWORD}`. "
        "If you use a key, re-run `ssh-copy-id USER@HOST`.",
    ),
    Diagnosis(
        r"ABEND\s*S?[0-9A-F]{3}",
        "The job abended",
        "A program ended abnormally. The code after ABEND identifies why; "
        "S806 means a module was not found, S878/S80A are storage, x37 codes "
        "are space.",
        "Look up the abend code in z/OS MVS System Codes. Check the spool "
        "output for the step that failed -- the messages just before the "
        "abend usually name the cause.",
    ),
    Diagnosis(
        r"GIM4[0-9]{4}[SW]|GIM5[0-9]{4}[SW]",
        "SMP/E reported a processing error",
        "An S-suffix message is severe, W is a warning. The message ID is the "
        "thing to look up.",
        "Search the message ID in SMP/E for z/OS Messages, Codes, and "
        "Diagnosis (GA32-0883). The full text in the spool file usually names "
        "the dataset or element involved.",
    ),
]

_DIAG_COMPILED = [(re.compile(d.pattern, re.IGNORECASE), d) for d in DIAGNOSTICS]


def diagnose(*texts: str) -> list[Diagnosis]:
    """Match failure text against the table. Order preserved, no duplicates."""
    blob = "\n".join(t for t in texts if t)
    seen, out = set(), []
    for rx, d in _DIAG_COMPILED:
        if d.title not in seen and rx.search(blob):
            out.append(d)
            seen.add(d.title)
    return out


def print_diagnosis(*texts: str) -> None:
    """Print what went wrong and what to do, or say plainly that we don't know."""
    found = diagnose(*texts)
    bar = "-" * 72
    print(f"\n{bar}", file=sys.stderr)
    if not found:
        print("No known diagnosis for this failure.\n", file=sys.stderr)
        print("The message above is the primary evidence. If a spool file was "
              "saved, search it for lines containing GIM, IEF, IKJ, ICH or "
              "ABEND -- those carry the cause.\n"
              "Worth adding to the DIAGNOSTICS table in this script once you "
              "know what it was.", file=sys.stderr)
        print(bar, file=sys.stderr)
        return
    for i, d in enumerate(found, 1):
        n = f"{i}. " if len(found) > 1 else ""
        print(f"{n}{d.title.upper()}\n", file=sys.stderr)
        print(f"   Why: {d.cause}\n", file=sys.stderr)
        print(f"   Fix: {d.fix}\n", file=sys.stderr)
    if len(found) > 1:
        print("Multiple matches -- fix the first one; later messages are often "
              "cascade from the same root cause.\n", file=sys.stderr)
    print(bar, file=sys.stderr)


# --------------------------------------------------------------------------
# Self-test
#
# Proves the plumbing -- write member, submit, poll, read return code, fetch
# spool -- using jobs that allocate nothing, delete nothing and reference no
# dataset. IEFBR14 is a program that does nothing and ends RC 00. IDCAMS with
# SET MAXCC=12 ends RC 12 without performing any action. Running these is as
# close to harmless as submitting work to a mainframe gets.
# --------------------------------------------------------------------------

SMOKE_OK = """\
//{jobname} JOB ({acct}),'{prog}',CLASS={cls},MSGCLASS={msg},
//             NOTIFY=&SYSUID,REGION=0M
//*  zsmagent self-test: does nothing, must end RC 00
//STEP1    EXEC PGM=IEFBR14
"""

SMOKE_BAD = """\
//{jobname} JOB ({acct}),'{prog}',CLASS={cls},MSGCLASS={msg},
//             NOTIFY=&SYSUID,REGION=0M
//*  zsmagent self-test: sets a bad return code on purpose, no action taken
//STEP1    EXEC PGM=IDCAMS
//SYSPRINT DD SYSOUT=*
//SYSIN    DD *
  SET MAXCC=12
/*
"""


def run_selftest(runner: "SmpeRunner", spool_dir: Path = Path("spool")) -> int:
    """Submit a passing and a failing job; confirm both are read correctly."""
    if runner.zosmf is None:
        print("no z/OSMF client -- return codes cannot be read. "
              "Set ZSM_PASSWORD and retry.", file=sys.stderr)
        return 2

    v = runner.values
    fields = dict(acct=v.get("ACCT", "ACCT"), prog=v.get("PROGRAMMER", "ZSMAGENT"),
                  cls=v.get("JOBCLASS", "A"), msg=v.get("MSGCLASS", "X"))
    cases = [("SMOKEOK", SMOKE_OK, 0), ("SMOKEBAD", SMOKE_BAD, 12)]
    failures = 0

    print(f"self-test writing to {runner.jcl_pds} -- these jobs touch no datasets\n")
    for member, tmpl, expect in cases:
        body = tmpl.format(jobname=member, **fields)
        written = runner._write_member(member, body)
        if not written.ok:
            print(f"{member:9} could not write member: {written}")
            failures += 1
            continue
        r = runner.session._exec(f"submit \"//'{runner.jcl_pds}({member})'\"")
        try:
            jobname, jobid = job_identity(body, r.raw, member)
        except RuntimeError as exc:
            print(f"{member:9} {exc}")
            failures += 1
            continue
        print(f"{member:9} {jobid}  submitted", end="", flush=True)
        try:
            rc, raw = runner.zosmf.wait_for_rc(
                jobname, jobid, timeout=300,
                on_wait=lambda st: print(f" .. {st.lower()}", end="", flush=True))
        except (TimeoutError, RuntimeError) as exc:
            print(f"\n{'':9} wait failed: {exc}")
            failures += 1
            continue
        verdict = "as expected" if rc == expect else f"EXPECTED RC {expect:02d}"
        print(f" .. {raw}  ({verdict})")
        if rc != expect:
            failures += 1

    if not failures:
        spool_dir.mkdir(parents=True, exist_ok=True)
        print(f"\nboth jobs behaved as expected: the submit -> wait -> read "
              f"path works.\nSpool retrieval is exercised on failures only; "
              f"see {spool_dir}/ after a real run.")
    else:
        print(f"\n{failures} self-test check(s) did not behave as expected -- "
              f"do not run the install sequence yet.")
    return 0 if not failures else 1


# --------------------------------------------------------------------------
# z/OSMF REST client -- the "did it work?" half
#
# Submitting a job returns a ticket, not a result. z/OSMF lets us ask the
# mainframe what happened to that ticket:
#   GET /zosmf/restjobs/jobs/{jobname}/{jobid}
#     -> {"status": "OUTPUT", "retcode": "CC 0000", ...}
# status is INPUT (queued) / ACTIVE (running) / OUTPUT (finished).
# retcode is null until it finishes, then "CC nnnn", or "JCL ERROR" / "ABEND
# Sxxx" when the job did not run normally at all.
# --------------------------------------------------------------------------

_CC_RE = re.compile(r"CC\s+(\d+)")


class JobFailed(RuntimeError):
    """A submitted job finished above its allowed return code."""


def parse_retcode(retcode: Optional[str]) -> Optional[int]:
    """'CC 0004' -> 4. Anything non-numeric (JCL ERROR, ABEND) -> None.

    None means "no clean return code", which is always a failure -- never
    silently treat it as zero.
    """
    if not retcode:
        return None
    m = _CC_RE.search(retcode.upper())
    return int(m.group(1)) if m else None


@dataclass
class ZosmfClient:
    host: str
    user: str
    password: str
    port: int = 443
    verify: bool = True
    _opener: Any = field(default=None, repr=False)

    def _request(self, path: str) -> Any:
        import base64
        import ssl
        import urllib.error
        import urllib.request

        url = f"https://{self.host}:{self.port}{path}"
        token = base64.b64encode(
            f"{self.user}:{self.password}".encode("utf-8")).decode("ascii")
        req = urllib.request.Request(url, headers={
            "Authorization": f"Basic {token}",
            # z/OSMF rejects requests without this header; the value is
            # irrelevant, its presence is what matters.
            "X-CSRF-ZOSMF-HEADER": "zsmagent",
            "Accept": "application/json",
        })
        ctx = ssl.create_default_context()
        if not self.verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
                body = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:300]
            raise RuntimeError(
                f"z/OSMF returned HTTP {exc.code} for {path}: {detail}") from exc
        except ssl.SSLCertVerificationError as exc:
            raise RuntimeError(
                f"z/OSMF TLS certificate could not be verified: {exc}.\n"
                f"If this is an internal test system with a self-signed "
                f"certificate, re-run with --zosmf-insecure (understand that "
                f"this disables certificate checking) or install the site CA."
            ) from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(
                f"could not reach z/OSMF at {url}: {exc.reason}") from exc
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return body

    def ping(self) -> str:
        info = self._request("/zosmf/info")
        if isinstance(info, dict):
            return f"z/OSMF {info.get('zosmf_version', '?')} on {info.get('zos_version', '?')}"
        return "z/OSMF reachable"

    def job_status(self, jobname: str, jobid: str) -> dict[str, Any]:
        data = self._request(f"/zosmf/restjobs/jobs/{jobname}/{jobid}")
        return data if isinstance(data, dict) else {}

    def wait_for_rc(self, jobname: str, jobid: str, timeout: int = 1800,
                    poll: int = 5, on_wait: Optional[Any] = None
                    ) -> tuple[Optional[int], str]:
        """Block until the job leaves the queue; return (rc, raw_retcode).

        rc is None when the job produced no numeric return code at all
        (JCL ERROR, ABEND) -- the caller must treat that as a failure.
        """
        import time
        deadline = time.time() + timeout
        last = ""
        while time.time() < deadline:
            info = self.job_status(jobname, jobid)
            status = str(info.get("status", "")).upper()
            retcode = info.get("retcode")
            if status == "OUTPUT":
                raw = str(retcode) if retcode else "(no return code)"
                return parse_retcode(retcode), raw
            if status != last and on_wait:
                on_wait(status or "?")
                last = status
            time.sleep(poll)
        raise TimeoutError(
            f"{jobname}({jobid}) did not finish within {timeout}s. It may still "
            f"be queued -- check SDSF before resubmitting anything."
        )

    def job_spool(self, jobname: str, jobid: str, limit: int = 4) -> str:
        """Concatenate the job's spool files, for saving when a job fails."""
        files = self._request(f"/zosmf/restjobs/jobs/{jobname}/{jobid}/files")
        if not isinstance(files, list):
            return ""
        chunks = []
        for f in files[:limit]:
            fid = f.get("id")
            ddname = f.get("ddname", f"file{fid}")
            try:
                text = self._request(
                    f"/zosmf/restjobs/jobs/{jobname}/{jobid}/files/{fid}/records")
            except RuntimeError as exc:
                text = f"(could not retrieve: {exc})"
            chunks.append(f"===== {ddname} =====\n{text}")
        return "\n".join(chunks)


# --------------------------------------------------------------------------
# SMP/E pipeline (Step 1 of the lab)
#
# Design rules:
#   * NOTHING generates JCL. Templates are known-good jobs with @PLACEHOLDERS@;
#     this code only fills slots. JCL is column- and quote-sensitive, and slot
#     filling is the only substitution that cannot introduce a syntax error.
#   * Submission is blocked by default (mirrors allow_writes). --dry-run is
#     free and prints exactly what would be written and submitted.
#   * Each job has an RC policy. SMP/E APPLY/ACCEPT legitimately end RC 04
#     with documented warnings; RECEIVE should be clean. Calibrate MAX_RC
#     against your own successful run's output, not guesses.
# --------------------------------------------------------------------------

_PLACEHOLDER_RE = re.compile(r"@([A-Z][A-Z0-9_]*)@")

# `submit` wording varies by system. Seen in the wild:
#   JOB SMOKEOK(JOB01085) SUBMITTED
#   JOB JOB01085 submitted from data set 'CRMBSM1.TEST.JCL(SMOKEOK)'
# Only the JOBnnnnn token is reliably present, so match just that.
_JOBID_RE = re.compile(r"\b(JOB\d{3,})\b", re.IGNORECASE)

# The job NAME is not always echoed back, but we wrote the JCL, so read it
# off the JOB card instead of hoping the message contains it.
_JOBNAME_RE = re.compile(r"^//(\S{1,8})\s+JOB\b", re.MULTILINE)


def job_identity(body: str, submit_output: str, member: str) -> tuple[str, str]:
    """Work out (jobname, jobid) after a submit. Raises if the id is missing."""
    mi = _JOBID_RE.search(submit_output)
    if not mi:
        raise RuntimeError(
            f"submitted {member} but no job ID found in: {submit_output.strip()!r}")
    mn = _JOBNAME_RE.search(body)
    jobname = mn.group(1).upper() if mn else member.upper()
    return jobname, mi.group(1).upper()

@dataclass(frozen=True)
class Step:
    """One submission in the install sequence."""
    member: str
    max_rc: int = 0
    strip_check: bool = False      # resubmit with the CHECK operand removed
    note: str = ""

    @property
    def label(self) -> str:
        return f"{self.member}{' (real)' if self.strip_check else ''}"


# Per Program Directory GI13-0000-00 section 6.1, every job in this sequence is
# documented as "return code of 0 if this job is successful" -- so max_rc is 0
# throughout, not the RC 04 I previously guessed. The one documented exception
# is ACCEPT (6.1.10): accepting PTFs with replacement modules can give RC 04
# from the binder, which the directory says may be ignored. A clean FMID
# install should still be 0, so RC 04 there is surfaced rather than allowed.
_CORE_STEPS: list[Step] = [
    Step("BRSJREC",  note="RECEIVE (PDIR 6.1.5)"),
    Step("BRSJALL",  note="allocate target/dlib libraries (6.1.6)"),
    Step("BRSJALZF", note="allocate + mount target zFS (6.1.7)"),
    Step("BRSJDDD",  note="create DDDEF entries (6.1.8)"),
    # The shipped BRSJAPP/BRSJACC contain the CHECK operand, which REHEARSES
    # the work without doing it. The directory says to run CHECK, review, then
    # remove CHECK and run again. Submitting only the CHECK version would
    # report success while installing nothing.
    Step("BRSJAPP",  note="APPLY CHECK -- rehearsal only (6.1.9)"),
    Step("BRSJAPP",  strip_check=True, note="APPLY for real (6.1.9 step 2)"),
    Step("BRSJACC",  note="ACCEPT CHECK -- rehearsal only (6.1.10)"),
    Step("BRSJACC",  strip_check=True, note="ACCEPT for real (6.1.10)"),
]

# The three CSI/OPTIONS jobs are all marked "(Optional)" in the directory
# (6.1.4.1 - 6.1.4.3) and are needed only when installing into a NEW SMP/E
# environment. They are NOT alternatives to each other, which is what I had
# wrong before: BRSJSMPA makes a GLOBAL CSI, BRSJSMPB makes a TARGET/DLIB CSI,
# BRSJSMPC defines the OPTIONS entry.
SMPE_ENVIRONMENTS: dict[str, list[Step]] = {
    "existing": [],
    "new-shared-global": [
        Step("BRSJSMPB", note="new TARGET/DLIB CSI (6.1.4.2)"),
        Step("BRSJSMPC", note="OPTIONS entry (6.1.4.3)"),
    ],
    "new-dedicated-global": [
        Step("BRSJSMPA", note="new GLOBAL CSI (6.1.4.1)"),
        Step("BRSJSMPB", note="new TARGET/DLIB CSI (6.1.4.2)"),
        Step("BRSJSMPC", note="OPTIONS entry (6.1.4.3)"),
    ],
}


def build_sequence(values: dict[str, str]) -> list[Step]:
    """Resolve SMPEENV into a concrete list of submissions."""
    env = values.get("SMPEENV", "").strip().lower()
    if env not in SMPE_ENVIRONMENTS:
        raise ValueError(
            "values file must set SMPEENV to one of:\n"
            "  existing             -> install into an existing SMP/E environment\n"
            "                          (skips BRSJSMPA/B/C entirely)\n"
            "  new-shared-global    -> new TARGET/DLIB CSI, reuse a GLOBAL CSI\n"
            "  new-dedicated-global -> new GLOBAL CSI as well\n"
            "These jobs are optional per Program Directory 6.1.4; the agent "
            "will not guess which applies to your system."
        )
    return SMPE_ENVIRONMENTS[env] + _CORE_STEPS


_CHECK_RE = re.compile(r"^[ \t]*CHECK[ \t]*(/\*.*?\*/)?[ \t]*$\n?",
                       re.MULTILINE | re.IGNORECASE)


def strip_check_operand(body: str, member: str) -> str:
    """Remove the CHECK operand so APPLY/ACCEPT actually performs the work.

    Refuses rather than guesses: exactly one CHECK line must be removed, and
    the surrounding command must survive intact.
    """
    new, n = _CHECK_RE.subn("", body)
    if n == 0:
        raise TemplateError(
            f"{member}: expected a CHECK operand to remove and found none. "
            f"If this job was already edited to drop CHECK, set strip_check "
            f"to False for it -- do not submit a job whose mode is unclear."
        )
    if n > 1:
        raise TemplateError(
            f"{member}: found {n} CHECK lines; refusing to guess which to remove.")
    if not re.search(r"\b(APPLY|ACCEPT)\b", new, re.IGNORECASE):
        raise TemplateError(f"{member}: APPLY/ACCEPT command lost while removing CHECK.")
    return new


class TemplateError(ValueError):
    """Raised when a template references a value that was not supplied."""


def load_values(path: Path) -> dict[str, str]:
    """Read the tester's one-time values file (KEY=VALUE lines or JSON).

    Keys are upper-cased to match @PLACEHOLDER@ names. '#' starts a comment.
    """
    text = path.read_text(encoding="utf-8")
    stripped = text.lstrip()
    if stripped.startswith("{"):
        data = json.loads(text)
        return {str(k).upper(): str(v) for k, v in data.items()}
    values: dict[str, str] = {}
    for lineno, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError(f"{path}:{lineno}: expected KEY=VALUE, got {line!r}")
        key, _, val = line.partition("=")
        values[key.strip().upper()] = val.strip()
    return values


def tailor(template_text: str, values: dict[str, str], name: str = "") -> str:
    """Fill @PLACEHOLDERS@ in a JCL template. Every placeholder must resolve.

    An unresolved placeholder is an error, never passed through silently --
    a half-tailored job is exactly the "no obvious failure at point of entry"
    problem this exists to prevent.
    """
    missing = sorted({m.group(1) for m in _PLACEHOLDER_RE.finditer(template_text)
                      if m.group(1) not in values})
    if missing:
        raise TemplateError(
            f"{name or 'template'}: no value supplied for: {', '.join(missing)}. "
            f"Add them to the values file."
        )
    out = _PLACEHOLDER_RE.sub(lambda m: values[m.group(1)], template_text)

    tmpl_lines = template_text.splitlines()
    out_lines = out.splitlines()

    # PDS members are fixed 80-byte records. A substituted line longer than
    # that is silently TRUNCATED on write (EDC5003I), so catch it here. This
    # applies to comment lines too -- IBM's banner comments already run to
    # column ~73, so a long value pushes them over.
    over80 = []
    for i, line in enumerate(out_lines):
        if len(line.rstrip("\n")) > 80:
            names = sorted(set(_PLACEHOLDER_RE.findall(tmpl_lines[i]))) \
                if i < len(tmpl_lines) else []
            over80.append((i + 1, len(line), names))
    if over80:
        detail = "; ".join(
            f"line {ln} is {length} chars"
            + (f" (shorten {'/'.join(names)})" if names else "")
            for ln, length, names in over80[:4])
        longest = max(length for _, length, _ in over80)
        raise TemplateError(
            f"{name or 'template'}: {len(over80)} line(s) exceed the 80-byte "
            f"record length after substitution -- {detail}. Longest is "
            f"{longest}, so the value(s) must lose at least {longest - 80} "
            f"character(s)."
        )

    # Column 72 binds JCL *statements*. Comment lines (//*) may run to 80, and
    # the IBM sample jobs use that full width for their banner blocks.
    long_lines = [i for i, l in enumerate(out_lines, 1)
                  if not l.startswith("//*") and len(l.rstrip("\n")) > 71]
    if long_lines:
        raise TemplateError(
            f"{name or 'template'}: substitution pushed statement line(s) "
            f"{long_lines[:5]} past column 71. Shorten the value(s) or fix "
            f"the template's continuation."
        )
    return out


# Values shorter than this are not auto-parametrized: a 1-2 character value
# like CLASS=A would match hundreds of unrelated characters in the file.
MIN_PARAM_LEN = 5


def parametrize(job_text: str, values: dict[str, str]) -> tuple[str, dict[str, int], list[str]]:
    """Turn a real (already-tailored) job into a template.

    Replaces each literal value with its @KEY@ marker, LONGEST VALUE FIRST so
    that CONSUL.BRS320.GA.ZFS is consumed before CONSUL.BRS320.GA and the
    shorter prefix cannot eat the longer one.

    Returns (template_text, {key: occurrences}, [keys skipped as too short]).
    """
    skipped = sorted(k for k, v in values.items() if len(v) < MIN_PARAM_LEN)
    usable = [(k, v) for k, v in values.items() if len(v) >= MIN_PARAM_LEN]
    usable.sort(key=lambda kv: len(kv[1]), reverse=True)

    counts: dict[str, int] = {}
    out = job_text
    for key, val in usable:
        n = out.count(val)
        if n:
            out = out.replace(val, f"@{key}@")
        counts[key] = n
    return out, counts, skipped


def verify_roundtrip(original: str, template_text: str,
                     values: dict[str, str], name: str) -> None:
    """Prove the template + values reproduce the original job exactly.

    This is the whole safety argument for parametrizing automatically: if
    tailoring the generated template does not give back byte-for-byte what
    was downloaded, the template is wrong and must not be used.
    """
    rebuilt = tailor(template_text, values, name)
    if rebuilt != original:
        orig_lines = original.splitlines()
        new_lines = rebuilt.splitlines()
        for i, (a, b) in enumerate(zip(orig_lines, new_lines), 1):
            if a != b:
                raise TemplateError(
                    f"{name}: round-trip mismatch at line {i}\n"
                    f"  original: {a!r}\n  rebuilt : {b!r}"
                )
        raise TemplateError(
            f"{name}: round-trip mismatch in length "
            f"({len(orig_lines)} vs {len(new_lines)} lines)"
        )


def _same_jcl(sent: str, readback: str) -> bool:
    """Compare what we wrote with what came back.

    PDS members are fixed-length records, so every line comes back padded with
    trailing blanks and the file may gain or lose a final newline. Neither of
    those is a real difference; anything else is.
    """
    def norm(text: str) -> list[str]:
        lines = [l.rstrip() for l in text.replace("\r\n", "\n").split("\n")]
        while lines and not lines[-1]:
            lines.pop()
        return lines
    return norm(sent) == norm(readback)


DSN_CHARS = r"[A-Z0-9$#@]{1,8}(?:\.[A-Z0-9$#@]{1,8})*"
_DELETE_RE = re.compile(rf"^\s*DELETE\s+({DSN_CHARS})", re.MULTILINE)
_DEFINE_RE = re.compile(rf"NAME\(\s*({DSN_CHARS})\s*\)", re.IGNORECASE)
_DD_DSN_RE = re.compile(rf"DSN=({DSN_CHARS})", re.IGNORECASE)
_NEW_RE = re.compile(r"DISP=\(\s*NEW", re.IGNORECASE)
_MOUNT_RE = re.compile(r"MOUNTPOINT\('([^']+)'\)|MOUNT\s+FILESYSTEM", re.IGNORECASE)


def plan_effects(text: str) -> dict[str, list[str]]:
    """Best-effort reading of what a tailored job would DO.

    Heuristic, not a JCL interpreter: it reports DELETEs, IDCAMS DEFINEs,
    datasets referenced near a DISP=(NEW, and mount points. Meant to let a
    human see the blast radius before anything is submitted -- read it as a
    warning list, not a guarantee of completeness.
    """
    lines = text.splitlines()
    deletes = sorted(set(_DELETE_RE.findall(text)))
    defines = sorted(set(_DEFINE_RE.findall(text)))

    creates, reads = set(), set()
    for i, line in enumerate(lines):
        for dsn in _DD_DSN_RE.findall(line):
            window = "\n".join(lines[i:i + 4])
            (creates if _NEW_RE.search(window) else reads).add(dsn)

    mounts = sorted({m.group(1) for m in _MOUNT_RE.finditer(text) if m.group(1)})
    return {
        "deletes": deletes,
        "defines": defines,
        "creates": sorted(creates - set(defines)),
        "reads": sorted(reads - creates - set(defines)),
        "mounts": mounts,
    }


def print_plan(runner: "SmpeRunner") -> int:
    """Show the whole sequence's effects without contacting the host."""
    sequence = build_sequence(runner.values)
    destructive: list[tuple[str, str]] = []

    print(f"Install plan: {len(sequence)} jobs, in this order.\n")
    for st in sequence:
        member, max_rc = st.member, st.max_rc
        try:
            body = runner.tailored(member, st.strip_check)
        except (TemplateError, FileNotFoundError) as exc:
            print(f"{st.label}  -- CANNOT TAILOR: {exc}\n")
            continue
        eff = plan_effects(body)
        print(f"--- {st.label}  (max RC {max_rc:02d})"
              f"{'  -- ' + st.note if st.note else ''} ---")
        for label, key in (("DELETES", "deletes"), ("creates (VSAM)", "defines"),
                           ("creates", "creates"), ("mounts", "mounts"),
                           ("reads", "reads")):
            for item in eff[key]:
                print(f"    {label:15} {item}")
                if key == "deletes":
                    destructive.append((member, item))
        print()

    if destructive:
        print("These DELETE statements are the reason preflight exists:")
        for member, dsn in destructive:
            print(f"    {member:9} deletes {dsn}")
        print("\nHarmless on a fresh prefix. On a prefix that is already in use,\n"
              "the SMP/E inventory of what is installed there is discarded.")
    print("\n[plan] nothing was submitted and the host was not contacted.")
    return 0


@dataclass
class SmpeRunner:
    """Tailors BRSJ* templates and (optionally) submits them in sequence."""

    session: ZSMSession
    template_dir: Path
    values: dict[str, str]
    jcl_pds: str                      # e.g. CRMBSM1.BRS320.JCL
    allow_submit: bool = False
    zosmf: Optional[ZosmfClient] = None   # supplies wait_for_rc

    def tailored(self, member: str, strip_check: bool = False) -> str:
        path = self.template_dir / f"{member}.jcl"
        if not path.exists():
            raise FileNotFoundError(
                f"no template {path}. Templates are your OWN known-good jobs "
                f"from the reference run with values swapped for @PLACEHOLDERS@."
            )
        body = tailor(path.read_text(encoding="utf-8"), self.values, member)
        return strip_check_operand(body, member) if strip_check else body

    def dry_run(self, members: Optional[Sequence[str]] = None) -> None:
        """Print every tailored job without touching the host."""
        steps = build_sequence(self.values)
        names = None if members else steps
        todo = ([Step(m) for m in members] if members else steps)
        for st in todo:
            body = self.tailored(st.member, st.strip_check)
            bar = "=" * 70
            print(f"{bar}\n{st.label}  ->  //'{self.jcl_pds}({st.member})'"
                  f"{'   ' + st.note if st.note else ''}\n{bar}")
            print(body.rstrip("\n"))
        print(f"\n[dry run] {len(todo)} submission(s) tailored; nothing was submitted.")

    # -- host operations ---------------------------------------------------

    def _write_member(self, member: str, body: str) -> Result:
        """Write tailored JCL into the PDS member via the SSH session.

        z/OS UNIX has no /dev/stdin, so the content goes to a temp file in the
        shell first, then cp moves it into the dataset. The member is then read
        back and compared: copying between z/OS UNIX and an MVS dataset can
        silently mangle character encoding, and submitting mangled JCL is
        exactly the kind of failure this tool exists to prevent.
        """
        client = self.session._client
        if not client:
            raise RuntimeError("not connected")

        target = f"//'{self.jcl_pds}({member})'"
        # NOT /tmp: it is not guaranteed to exist on z/OS UNIX (absent on
        # TVT8017). $HOME always does, and the shell expands it for us.
        tmp = f"$HOME/.zsmagent.{member}.{os.getpid()}.jcl"
        self.session._audit(f"[write] {target}")

        def sh(cmd: str, stdin_text: Optional[str] = None) -> Result:
            full = f"{self.session.prelude}; {cmd}" if self.session.prelude else cmd
            stdin, stdout, stderr = client.exec_command(full, timeout=60)
            if stdin_text is not None:
                stdin.write(stdin_text)
                stdin.channel.shutdown_write()
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            return parse_result(out, err, stdout.channel.recv_exit_status())

        wrote = sh(f"cat > {tmp}", body)
        if not wrote.ok:
            return wrote

        copied = sh(f"cp {tmp} \"{target}\"; rc=$?; rm -f {tmp}; exit $rc")
        if not copied.ok:
            hint = (f" -- does the PDS {self.jcl_pds} exist? Allocate it "
                    f"(ISPF 3.2, partitioned, FB/80) before running this.")
            copied.description = (copied.description or "cp failed") + hint
            return copied

        readback = sh(f"cat \"{target}\"")
        if not readback.ok:
            return readback
        if not _same_jcl(body, readback.raw):
            return Result(
                ok=False, rc=None,
                description=(
                    f"{member} was written but read back different -- most "
                    f"likely a character-encoding conversion. Do NOT submit it. "
                    f"Inspect the member in ISPF."),
                payload=None, raw=readback.raw)
        return Result(ok=True, rc=0, description=None, payload=None, raw="")

    def submit(self, member: str, strip_check: bool = False) -> tuple[str, str]:
        """Tailor, write, and submit one member. Returns (jobname, jobid)."""
        if not self.allow_submit:
            raise WriteBlocked(
                "job submission is disabled. Run with --dry-run to inspect "
                "the tailored JCL, then pass --allow-submit when ready."
            )
        body = self.tailored(member, strip_check)
        written = self._write_member(member, body)
        if not written.ok:
            print_diagnosis(written.description or "", written.raw, written.stderr)
            raise RuntimeError(f"writing {member} failed: {written}")
        r = self.session._exec(f"submit \"//'{self.jcl_pds}({member})'\"")
        return job_identity(body, r.raw, member)

    def readiness(self) -> int:
        """Report what section 6 needs. Read-only; submits nothing.

        ORDERPFX and TARGETPFX are deliberately separate. In the reference run
        the order sat at CONSUL.BRS320.GA (read-only input to RECEIVE) while the
        install went to CRMBSM1.BRS320. Conflating them makes preflight check
        somebody else's install.
        """
        problems, warnings = 0, 0
        s = self.session
        order = self.values.get("ORDERPFX") or self.values.get("RFPREFIX", "")
        target = self.values.get("TARGETPFX") or self.values.get("RFPREFIX", "")
        pathpfx = self.values.get("PATHPFX", "")

        print("=== identity ===")
        who = s._exec("id")
        print(f"  {who.raw.strip().splitlines()[-1] if who.raw.strip() else '(unknown)'}")
        home = s.home_dir() or ""
        print(f"  home: {home or '(unknown)'}")

        print("\n=== zFS mount authority (BRSJALZF) ===")
        is_root = "uid=0" in who.raw
        under_home = bool(home and pathpfx.startswith(home.rstrip("/")))
        if is_root:
            print("  UID 0 -- unrestricted.")
        elif under_home:
            print(f"  PATHPFX {pathpfx} is inside your own home directory.")
            print("  A user-scoped install of this shape ran RC 00 in the")
            print("  reference run without UID 0 or PFSCTL. Not treated as a")
            print("  blocker -- BRSJALZF's comment applies to system paths.")
        else:
            print(f"  PATHPFX {pathpfx or '(unset)'} is OUTSIDE your home directory.")
            print("  Installing into a system path needs UID 0 or READ on")
            print("  SUPERUSER.FILESYS.PFSCTL (UNIXPRIV). You have neither, so")
            print("  either point PATHPFX under your home, as the reference run")
            print("  did, or ask a RACF administrator to permit you.")
            warnings += 1

        print("\n=== order: input to RECEIVE ===")
        smpmcs = f"{order}.IBM.HBRS320.SMPMCS"
        if s.dataset_exists(smpmcs):
            print(f"  found {smpmcs}")
            print("  RECEIVE reads this; it is not modified.")
        else:
            print(f"  MISSING {smpmcs}")
            print("  Unpack the order first (PDIR 5.4 unterse, then GIMUNZIP 6.1.4).")
            problems += 1

        print("\n=== target: where the install goes ===")
        if target == order:
            print("  TARGETPFX equals ORDERPFX. That is how IBM's samples ship,")
            print("  but the reference run separated them. Set TARGETPFX to your")
            print("  own prefix unless you intend to install over the order.")
            warnings += 1
        for dsn in (f"{target}.CSI", f"{self.values.get('GLOBALPFX', target + '.G')}.CSI",
                    self.values.get("ZFSNAME", f"{target}.ZFS")):
            hit = s.dataset_exists(dsn)
            mark = "EXISTS" if hit else "free  "
            print(f"  {mark}  {dsn}")
            if hit:
                problems += 1
        if problems:
            print("  An existing target means a re-run: BRSJSMPB begins with")
            print("  DELETE, which discards the SMP/E record of what is there.")

        print("\n=== space (PDIR 5.2.3) ===")
        print(f"  ~5680 trks (~380 cyl) on {self.values.get('VOLSER', '(unset)')}")

        print("\n=== ground truth available ===")
        for log in (f"{self.values.get('GLOBALPFX', target + '.G')}.SMPLOG",
                    f"{target}.SMPLOG"):
            if s.dataset_exists(log):
                print(f"  {log} exists -- timestamped record of the previous run.")

        verdict = ("READY" if not problems else f"{problems} BLOCKER(S)")
        extra = f", {warnings} warning(s)" if warnings else ""
        print(f"\n{verdict}{extra} -- nothing was submitted.")
        return 0 if not problems else 1

    def preflight(self) -> list[str]:
        """Return target datasets that ALREADY EXIST.

        This is the guard that matters for an unattended installer. The CSI
        setup jobs open with DELETE ... / SET MAXCC=0 -- correct for a fresh
        install, destructive on a re-run or a prefix collision. A human at a
        3270 screen notices; a script will not unless it is told to look.
        """
        candidates = []
        for key, suffix in (("RFPREFIX", ".CSI"), ("GLOBALPFX", ".CSI"),
                            ("ZFSNAME", "")):
            base = self.values.get(key)
            if base:
                candidates.append(base + suffix)

        found = []
        for dsn in candidates:
            exists = self.session.dataset_exists(dsn)
            if exists is True:
                found.append(dsn)
            elif exists is None:
                print(f"  ? could not determine whether {dsn} exists")
        return found

    def run_sequence(self, force_existing: bool = False,
                     spool_dir: Path = Path("spool"),
                     start_from: Optional[str] = None) -> None:
        """Submit the install sequence, checking each job before the next.

        Without a z/OSMF client there is no way to read return codes, so this
        submits ONE job and stops rather than chaining blind.
        """
        sequence = build_sequence(self.values)

        if start_from:
            names = [st.member for st in sequence]
            if start_from.upper() not in names:
                raise ValueError(
                    f"--from {start_from} is not in the sequence: "
                    + ", ".join(names))
            idx = names.index(start_from.upper())
            skipped = sequence[:idx]
            sequence = sequence[idx:]
            print(f"resuming at {start_from.upper()}; skipping "
                  f"{len(skipped)} already-completed submission(s): "
                  + ", ".join(st.label for st in skipped) + "\n")
            print("Preflight is SKIPPED on a resume -- the earlier jobs are "
                  "expected to have created their datasets.\n")
            force_existing = True

        existing = self.preflight()
        if existing and not force_existing:
            raise RuntimeError(
                "these target datasets already exist:\n  "
                + "\n  ".join(existing)
                + "\n\nThis looks like a re-run or a prefix collision. The CSI "
                  "setup job begins with DELETE, which would discard the SMP/E "
                  "inventory of what is already installed.\nPoint the values "
                  "file at an unused prefix, or pass --force-existing if you "
                  "are certain."
            )

        if self.zosmf is None:
            st = sequence[0]
            jobname, jobid = self.submit(st.member, st.strip_check)
            print(f"submitted {st.label} as {jobid} (max RC {st.max_rc:02d})")
            print("  -> no z/OSMF client configured, so the return code cannot "
                  "be read.\n     Verify in SDSF, then run the next job "
                  "yourself. Stopping here rather than\n     chaining jobs "
                  "whose results are unknown.")
            return

        spool_dir.mkdir(parents=True, exist_ok=True)
        for idx, st in enumerate(sequence):
            member, max_rc = st.member, st.max_rc
            jobname, jobid = self.submit(member, st.strip_check)
            print(f"{st.label:16} {jobid}  submitted", end="", flush=True)
            try:
                rc, raw = self.zosmf.wait_for_rc(
                    jobname, jobid,
                    on_wait=lambda st: print(f" .. {st.lower()}", end="", flush=True))
            except TimeoutError as exc:
                print()
                raise RuntimeError(str(exc)) from exc

            if rc is not None and rc <= max_rc:
                flag = "" if rc == 0 else f"  (warnings, RC {rc:02d} <= {max_rc:02d})"
                print(f" .. done RC {rc:02d}{flag}")
                if rc:
                    self._save_spool(spool_dir, member, jobname, jobid)
                continue

            print(f" .. FAILED ({raw})")
            path = self._save_spool(spool_dir, member, jobname, jobid)
            try:
                print_diagnosis(raw, path.read_text(encoding="utf-8"))
            except OSError:
                print_diagnosis(raw)
            raise JobFailed(
                f"{member} ({jobid}) ended with {raw}; allowed was RC "
                f"{max_rc:02d}.\nSpool saved to {path}\nStopping: the "
                f"remaining {len(sequence) - idx - 1} "
                f"submission(s) would run against a broken install."
            )

        print(f"\nall {len(sequence)} jobs completed within their return codes.")

    def _save_spool(self, spool_dir: Path, member: str,
                    jobname: str, jobid: str) -> Path:
        path = spool_dir / f"{member}-{jobid}.txt"
        try:
            path.write_text(self.zosmf.job_spool(jobname, jobid), encoding="utf-8")
        except Exception as exc:                      # never mask the real error
            path.write_text(f"(spool retrieval failed: {exc})", encoding="utf-8")
        return path


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def session_from_env(allow_writes: bool = False) -> ZSMSession:
    host = os.environ.get("ZSM_HOST")
    user = os.environ.get("ZSM_USER")
    if not host or not user:
        sys.exit("set ZSM_HOST and ZSM_USER (and ZSM_PASSWORD or ZSM_KEYFILE)")
    return ZSMSession(
        host=host,
        user=user,
        password=os.environ.get("ZSM_PASSWORD"),
        keyfile=os.environ.get("ZSM_KEYFILE"),
        allow_writes=allow_writes,
    )


def zosmf_from_env(ns: Any) -> Optional[ZosmfClient]:
    """Build a z/OSMF client if we have a password to authenticate with.

    z/OSMF uses HTTPS basic auth, so an SSH key is not enough here -- the
    tester needs ZSM_PASSWORD set even if SSH itself uses a key.
    """
    password = os.environ.get("ZSM_PASSWORD")
    host = getattr(ns, "zosmf_host", None) or os.environ.get("ZSM_HOST")
    user = os.environ.get("ZSM_USER")
    if not (password and host and user):
        return None
    return ZosmfClient(host=host, user=user, password=password,
                       port=getattr(ns, "zosmf_port", 443),
                       verify=not getattr(ns, "zosmf_insecure", False))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--allow-writes", action="store_true",
                        help="permit mutating commands (off by default)")
    parser.add_argument("--json", action="store_true",
                        help="print the parsed result as JSON")
    parser.add_argument("verb",
                        help="check | zosmf | plan | preflight | selftest | explain | refresh | smpe | parametrize | "
                             + " | ".join(sorted(READ_VERBS)))
    parser.add_argument("args", nargs="*")
    parser.add_argument("--templates", default="templates",
                        help="smpe: directory holding BRSJ*.jcl templates")
    parser.add_argument("--values", default="values.env",
                        help="smpe: KEY=VALUE (or JSON) values file")
    parser.add_argument("--jcl-pds", default=os.environ.get("ZSM_JCL_PDS", ""),
                        help="smpe: target PDS, e.g. CRMBSM1.BRS320.JCL")
    parser.add_argument("--raw", default="raw",
                        help="parametrize: dir of downloaded, already-tailored jobs")
    parser.add_argument("--dry-run", action="store_true",
                        help="smpe: print tailored JCL, submit nothing")
    parser.add_argument("--allow-submit", action="store_true",
                        help="smpe: actually submit jobs (off by default)")
    parser.add_argument("--from", dest="start_from", default=None,
                        help="smpe: resume the sequence at this member")
    parser.add_argument("--force-existing", action="store_true",
                        help="smpe: submit even though target datasets exist")
    parser.add_argument("--zosmf-host", default=os.environ.get("ZSM_ZOSMF_HOST"),
                        help="z/OSMF host (defaults to ZSM_HOST)")
    parser.add_argument("--zosmf-port", type=int,
                        default=int(os.environ.get("ZSM_ZOSMF_PORT", "443")))
    parser.add_argument("--zosmf-insecure", action="store_true",
                        help="skip z/OSMF TLS certificate verification")
    ns = parser.parse_args(argv)

    # -- plan: show what the whole sequence would do, offline ---------------
    if ns.verb == "plan":
        try:
            values = load_values(Path(ns.values))
        except (OSError, ValueError) as exc:
            sys.exit(f"values file problem: {exc}")
        runner = SmpeRunner(session=None, template_dir=Path(ns.templates),  # type: ignore[arg-type]
                            values=values, jcl_pds=ns.jcl_pds or "UNUSED")
        try:
            return print_plan(runner)
        except ValueError as exc:
            sys.exit(f"blocked: {exc}")

    # -- preflight: read-only look at whether targets already exist --------
    if ns.verb == "preflight":
        try:
            values = load_values(Path(ns.values))
        except (OSError, ValueError) as exc:
            sys.exit(f"values file problem: {exc}")
        with session_from_env() as s:
            runner = SmpeRunner(session=s, template_dir=Path(ns.templates),
                                values=values, jcl_pds=ns.jcl_pds or "UNUSED")
            return runner.readiness()

    # -- selftest: exercise submit/wait/read on harmless jobs ---------------
    if ns.verb == "selftest":
        try:
            values = load_values(Path(ns.values))
        except (OSError, ValueError) as exc:
            sys.exit(f"values file problem: {exc}")
        if not ns.jcl_pds:
            sys.exit("--jcl-pds is required (a scratch PDS you own)")
        zosmf = zosmf_from_env(ns)
        with session_from_env() as s:
            runner = SmpeRunner(session=s, template_dir=Path(ns.templates),
                                values=values, jcl_pds=ns.jcl_pds,
                                allow_submit=True, zosmf=zosmf)
            return run_selftest(runner)

    # -- explain: diagnose a saved spool file or pasted message ------------
    if ns.verb == "explain":
        if ns.args:
            blob = ""
            for a in ns.args:
                pth = Path(a)
                blob += (pth.read_text(encoding="utf-8", errors="replace")
                         if pth.exists() else a) + "\n"
        else:
            print("reading failure text from stdin; Ctrl-D when done",
                  file=sys.stderr)
            blob = sys.stdin.read()
        print_diagnosis(blob)
        return 0

    # -- zosmf: prove the return-code path works before relying on it ------
    if ns.verb == "zosmf":
        client = zosmf_from_env(ns)
        if client is None:
            sys.exit("set ZSM_HOST, ZSM_USER and ZSM_PASSWORD "
                     "(z/OSMF needs a password even if SSH uses a key)")
        try:
            print(client.ping())
        except RuntimeError as exc:
            sys.exit(str(exc))
        return 0

    # -- parametrize: turn downloaded jobs into templates ------------------
    if ns.verb == "parametrize":
        try:
            values = load_values(Path(ns.values))
        except (OSError, ValueError) as exc:
            sys.exit(f"values file problem: {exc}")
        src_dir = Path(ns.raw or "raw")
        out_dir = Path(ns.templates)
        out_dir.mkdir(parents=True, exist_ok=True)
        jobs = sorted(src_dir.glob("*.jcl"))
        if not jobs:
            sys.exit(f"no *.jcl files found in {src_dir}/ -- download them first")
        for job in jobs:
            original = job.read_text(encoding="utf-8")
            template_text, counts, skipped = parametrize(original, values)
            try:
                verify_roundtrip(original, template_text, values, job.stem)
            except TemplateError as exc:
                print(f"REJECTED {job.stem}: {exc}", file=sys.stderr)
                continue
            (out_dir / job.name).write_text(template_text, encoding="utf-8")
            hits = ", ".join(f"{k}x{n}" for k, n in sorted(counts.items()) if n)
            misses = sorted(k for k, n in counts.items() if not n)
            print(f"{job.stem:10} -> {out_dir}/{job.name}   [{hits}]")
            if misses:
                print(f"{'':10}    not present in this job: {', '.join(misses)}")
        if skipped:
            print(f"\nNOT auto-replaced (value under {MIN_PARAM_LEN} chars, "
                  f"too risky to match): {', '.join(skipped)}")
            print("Edit those by hand in the template if they vary per site.")
        return 0

    # -- smpe: tailoring is local; only submission needs a session ---------
    if ns.verb == "smpe":
        try:
            values = load_values(Path(ns.values))
        except (OSError, ValueError) as exc:
            sys.exit(f"values file problem: {exc}")
        members = ns.args or None
        if ns.dry_run or not ns.allow_submit:
            runner = SmpeRunner(session=None, template_dir=Path(ns.templates),  # type: ignore[arg-type]
                                values=values, jcl_pds=ns.jcl_pds or "USERID.BRS320.JCL")
            try:
                runner.dry_run(members)
            except (TemplateError, FileNotFoundError, ValueError) as exc:
                sys.exit(f"blocked: {exc}")
            if not ns.dry_run:
                print("\n(submission is off by default; this was a dry run. "
                      "Pass --allow-submit to submit for real.)")
            return 0
        if not ns.jcl_pds:
            sys.exit("--jcl-pds (or ZSM_JCL_PDS) is required to submit")
        zosmf = zosmf_from_env(ns)
        with session_from_env() as s:
            runner = SmpeRunner(session=s, template_dir=Path(ns.templates),
                                values=values, jcl_pds=ns.jcl_pds,
                                allow_submit=True, zosmf=zosmf)
            try:
                runner.run_sequence(force_existing=ns.force_existing,
                                    start_from=ns.start_from)
            except (TemplateError, FileNotFoundError, WriteBlocked,
                    ValueError, JobFailed, RuntimeError) as exc:
                print(f"stopped: {exc}", file=sys.stderr)
                print_diagnosis(str(exc))
                return 1
        return 0

    with session_from_env(allow_writes=ns.allow_writes) as s:
        try:
            if ns.verb == "check":
                result = s.check()
            elif ns.verb == "refresh":
                if not ns.args:
                    sys.exit("refresh needs a RACF class, e.g. refresh RDATALIB")
                result = s.raclist_refresh(ns.args[0])
            else:
                result = s.irrsadmin(ns.verb, *ns.args)
        except (WriteBlocked, UnknownVerb, ValueError) as exc:
            print(f"blocked: {exc}", file=sys.stderr)
            return 2

    if ns.json:
        print(json.dumps({
            "ok": result.ok, "rc": result.rc,
            "description": result.description, "raw": result.raw,
        }, indent=2))
    else:
        print(result)
        if result.raw.strip():
            print(result.raw.rstrip())

    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
