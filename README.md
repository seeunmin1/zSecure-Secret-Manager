# zsmagent

Drives the SMP/E installation of IBM zSecure Secret Manager 3.2.0 (FMID HBRS320)
from your workstation, over SSH into z/OS UNIX, with z/OSMF used to read job
return codes.

It runs the same nine IBM sample jobs (BRSJ*) you would submit by hand in ISPF,
in the order the Program Directory specifies, and stops the moment one of them
returns a code it does not expect.

**It does not replace understanding the install.** Six values in your config are
real decisions about your system. See "The six decisions" below.

---

## What you need before starting

- A Mac or Linux workstation with Python 3.9+
- SSH access to the z/OS system as your own userid
- Your TSO/z/OSMF password (z/OSMF uses it even if SSH uses a key)
- z/OSMF reachable on the system: check `https://<host>/zosmf/` in a browser
- A Shopz order already unpacked on the host (the agent does not download or
  unterse the order; that is Program Directory 5.4 and 6.1.4)
- Roughly 380 cylinders free on the volume you intend to install to
- A PDS you own for scratch JCL, e.g. `<YOURID>.TEST.JCL`, allocated as
  partitioned, FB, LRECL 80

## BEFORE STARTING ANYTHING, ensure you are connected to EUROPE-MEA on your VPN!

Allocate the scratch PDS if you do not have one:

```bash
ssh <YOURID>@<host> "tsocmd \"ALLOCATE DATASET('<YOURID>.TEST.JCL') NEW CATALOG SPACE(5,5) TRACKS DIR(10) RECFM(F,B) LRECL(80) BLKSIZE(0)\""
```

---
### Make sure to Reference the Runbook.md file for exact commands to run

## Setup

```bash
mkdir -p ~/zsm && cd ~/zsm          # put zsmagent.py and the .env files here
pip install paramiko

export ZSM_HOST=<host>
export ZSM_USER=<YOURID>
read -s ZSM_PASSWORD && export ZSM_PASSWORD   # type then Enter
```

`read -s` keeps the password out of your shell history. Check it took with
`echo ${#ZSM_PASSWORD}` prints out length of password.

This step is optional, but saves time by reducing the number of times you need to input your password from nine times to one time during the download step:

```bash
ssh-keygen -t ed25519 -N "" -f ~/.ssh/id_ed25519
ssh-copy-id <YOURID>@<host>
export ZSM_KEYFILE=~/.ssh/id_ed25519
```

Prove both connections work:

```bash
python3 zsmagent.py check     # SSH  -> expect OK
python3 zsmagent.py zosmf     # HTTPS -> expect a version string
```

If `zosmf` fails on the certificate, the host is using an internal CA your
machine does not trust. Check who issued it:

```bash
openssl s_client -connect <host>:443 </dev/null 2>/dev/null | openssl x509 -noout -issuer
```

If it is your organisation's CA, `--zosmf-insecure` will get you past it for a
test run. That flag stops verifying the host's identity. However, the
proper fix is installing the CA bundle on your workstation.

---

## Build your templates (stage 1)

The agent does not ship the IBM sample jobs. You generate templates from the
copy on your own system, so they match your order's service level.

Download the nine jobs from the install library:

```bash
mkdir -p raw templates
for m in BRSJSMPA BRSJSMPB BRSJSMPC BRSJREC BRSJALL BRSJALZF BRSJDDD BRSJAPP BRSJACC; do
  ssh <YOURID>@<host> "cat \"//'<ORDER.PREFIX>.BRSINST($m)'\"" > raw/$m.jcl
done
find raw -name '*.jcl' -size 0        # must print nothing
```

Copy `values.example.env` to `values.env`, then confirm its values actually
appear in your download.

```bash
grep -n "into your\|into the\|into an\|into volume" raw/*.jcl
head -2 raw/BRSJREC.jcl
```

Fix any mismatches in `values.env`, then:

```bash
python3 zsmagent.py parametrize --raw raw --templates templates --values values.env
```

This replaces each literal value with an `@MARKER@` and then verifies the
template plus values rebuilds the original byte-for-byte. Any template that
fails that check is rejected rather than written. The report tells you which
markers landed in which job, anything reported as "not present" in every job
means that value is wrong.

One value must be split by hand. In BRSJREC, the prefix
refers to the *order being read*, everywhere else it is the *install target*:

```bash
sed -i '' 's/@RFPREFIX@/@TARGETPFX@/g' templates/*.jcl
sed -i '' 's/@TARGETPFX@/@ORDERPFX@/g' templates/BRSJREC.jcl
grep -o "@[A-Z]*@" templates/BRSJREC.jcl | sort -u
```

BRSJREC should list `@ORDERPFX@` and `@GLOBALPFX@`, and **not** `@TARGETPFX@`.
(Drop the `''` after `-i` on Linux.)

---

## Configure your install (stage 2)

Copy `values-install.example.env` to `values-install.env` and fill in every
`<ANGLE BRACKET>`. Keep this file separate from `values.env`

---

## Run it

Each step below is safe and tells you something before the next one matters.

```bash
# 1. Read-only readiness report: authority, order present, target free, space
python3 zsmagent.py preflight --values values-install.env

# 2. What every job would create, delete and mount. Never contacts the host.
python3 zsmagent.py plan --templates templates --values values-install.env

# 3. Every job, fully tailored, printed. Submits nothing.
python3 zsmagent.py smpe --dry-run --templates templates --values values-install.env

# 4. Prove submit -> wait -> read return code works, using two throwaway jobs
#    that reference no datasets (IEFBR14, and IDCAMS SET MAXCC=12).
python3 zsmagent.py selftest --jcl-pds <YOURID>.TEST.JCL --values values-install.env --zosmf-insecure

# 5. The real thing: 11 submissions, each checked before the next starts.
mkdir -p $(dirname <PATHPFX>)      # the mount point must exist
python3 zsmagent.py smpe --allow-submit \
  --templates templates --values values-install.env \
  --jcl-pds <YOURID>.TEST.JCL --zosmf-insecure
```

Before step 5, read the `plan` output properly. Every DELETE and create should
name **your** prefix. If you recognise a dataset belonging to an existing
install, stop.

If a job fails, the run stops there, saves that job's spool output under
`spool/`, and refuses to continue. The remaining jobs would run against a
broken install. Fix the cause, then resume without repeating what succeeded:

```bash
python3 zsmagent.py smpe --allow-submit --from BRSJALZF ...
```

### Confirm it installed

```bash
ssh <YOURID>@<host> "df -k | grep -i <TARGETPFX>"
ssh <YOURID>@<host> "ls -R <PATHPFX>usr/lpp/brs/v3r2 | head -30"
ssh <YOURID>@<host> "cat \"//'<TARGETPFX>.SMPLOG'\" | grep GIM22701I"
```

You want the zFS mounted, `zsm-core.jar` / `libbrsscrtc.so` / `librdatalib.so`
present, and `GIM22701I` for both APPLY and ACCEPT.

---

## Six fields to fill out

The agent removes the mechanical work (around 215 value substitutions across
nine jobs), the submissions, and the return-code checking. It does not remove
these, because each needs you to understand what you are choosing:

| Value | Why it is a decision |
|---|---|
| `SMPEENV` | Whether your site has an SMP/E environment to install into, or you are building one. Wrong answer either creates a global zone you did not want or skips one you needed. |
| `ORDERPFX` | Where the order was staged. Comes from whoever ran the unterse/GIMUNZIP. |
| `TARGETPFX` | Must be unused. Reusing a prefix means the CSI setup job's `DELETE` discards the SMP/E record of what is already installed there. |
| `PATHPFX` | Looks like a path, is actually a permissions decision. Under your home directory: no special authority. Under a system path: UID 0 or READ on `SUPERUSER.FILESYS.PFSCTL`. Also keep it short to avoid long values overflow the sample jobs' 80-byte records. |
| `VOLSER` | Needs ~380 cylinders free. Nothing verifies this for you. |
| `TZONE` / `DZONE` | Must be unique on the system. Duplicate zone names cause failures that surface several phases later. |

---

## Safety behaviour

- Mutating `irrsadmin` commands are blocked unless you pass `--allow-writes`
- Job submission is blocked unless you pass `--allow-submit`
- Preflight refuses to submit if the target datasets already exist, unless you
  pass `--force-existing`
- Templates are only written if they provably rebuild the original job
- Members are read back after writing and compared, so a character-encoding
  problem cannot reach JES
- Substitution fails loudly if a value overflows the 80-byte record length or
  pushes a JCL statement past column 71
- APPLY and ACCEPT are submitted twice each: once with `CHECK` (a rehearsal),
  then with `CHECK` removed. Submitting only the shipped job would report
  success while installing nothing
- Every command issued is appended to `~/.zsmagent-audit.log`. These commands
  run under your userid on a shared system and are attributable to you

## Limits

- Does not download, unterse or GIMUNZIP the order (Program Directory 5.4, 6.1.4)
- Does not run `REPORT CROSSZONE` (6.1.11)
- Does not activate the product. SMP/E install alone does not make it
  operational: RACF setup, EzNoSQL configuration and the Vault connection are
  separate (Program Directory 6.2)
- Return-code thresholds are RC 00 for every job, per Program Directory 6.1.
  ACCEPT can legitimately return RC 04 when accepting PTFs with replacement
  modules; that is surfaced rather than ignored
- z/OSMF is required for unattended operation. Without it, the agent submits one
  job and stops rather than chaining jobs whose results it cannot read

## A note on the templates

The BRSJ* jobs are IBM Licensed Materials. Templates you generate with
`parametrize` are derived from them and carry their copyright headers. 
