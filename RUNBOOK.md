# zsmagent — the commands that actually worked

Copy-paste these in order in your terminal.

**Before you start, find-and-replace three things throughout this file:**

| Replace | With | Example |
|---|---|---|
| `CRMBSM1` | your TSO userid | `SMITHJ1` |
| `crmbsm1` | your userid in lowercase | `smithj1` |
| `tvt8017.pok.stglabs.ibm.com` | your host | ask your system programmer |

Everything else: `CONSUL.BRS320.GA`, `T80177`, `BRS320T` leave as-is unless
your system programmer tells you otherwise.

Put `zsmagent.py` in a folder called `zsm` in your home directory before starting.

---

## 1. Set up

```bash
cd ~/zsm
pip install paramiko

export ZSM_HOST=tvt8017.pok.stglabs.ibm.com
export ZSM_USER=CRMBSM1
read -s ZSM_PASSWORD && export ZSM_PASSWORD
```

That last line waits for you: type your password (nothing shows) and press Enter.

```bash
echo ${#ZSM_PASSWORD}
```

Prints the number of characters. If it prints `0`, run the `read -s` line again.

## 2. Test both connections

```bash
python3 zsmagent.py check
python3 zsmagent.py zosmf --zosmf-insecure
```

Expect `OK` and a time from the first, `z/OSMF 30 on 05.30.00` from the second.

Keep `--zosmf-insecure` on every command from here, the mainframe uses an IBM
internal certificate your Mac doesn't trust.

## 3. Set up an SSH key

Saves typing your password nine times in step 5.

```bash
ssh-keygen -t ed25519 -N "" -f ~/.ssh/id_ed25519
ssh-copy-id CRMBSM1@tvt8017.pok.stglabs.ibm.com
```

Asks for your password once.

## 4. Create a scratch dataset

```bash
ssh CRMBSM1@tvt8017.pok.stglabs.ibm.com "tsocmd \"ALLOCATE DATASET('CRMBSM1.TEST.JCL') NEW CATALOG SPACE(5,5) TRACKS DIR(10) RECFM(F,B) LRECL(80) BLKSIZE(0)\""
```

No output means it worked.

## 5. Download the nine IBM jobs

```bash
mkdir -p raw templates

for m in BRSJSMPA BRSJSMPB BRSJSMPC BRSJREC BRSJALL BRSJALZF BRSJDDD BRSJAPP BRSJACC; do
  ssh CRMBSM1@tvt8017.pok.stglabs.ibm.com "cat \"//'CONSUL.BRS320.GA.BRSINST($m)'\"" > raw/$m.jcl
done

ls -l raw/
find raw -name '*.jcl' -size 0
```

All nine need a real size. `find` must print nothing.

## 6. Turn them into templates

```bash
cat > values.env <<'EOF'
SMPEENV=new-dedicated-global
GLOBALPFX=CONSUL.BRS320.GA.G
ZFSNAME=CONSUL.BRS320.GA.ZFS
RFPREFIX=CONSUL.BRS320.GA
PATHPFX=/u/crmbjk1/
VOLSER=CONA40
UNIT=SYSALLDA
TZONE=BRS320T
DZONE=BRS320D
ACCT=ZSECURE
PROGRAMMER=J.KEMPER
JOBCLASS=A
MSGCLASS=X
EOF

python3 zsmagent.py parametrize --raw raw --templates templates --values values.env
```

**Note:** the values above are IBM's shipped defaults, not yours. This step
searches for them and replaces them with markers, so they must stay as they are.
You put your own values in step 7.

If a value shows as "not present in this job" for **every** job, that value is
wrong for your download — check with:

```bash
grep -h "into your\|into the\|into an\|into volume" raw/*.jcl | sort -u
```

Fix `values.env` and rerun. Rerunning is safe.

Then split one marker that means two different things:

```bash
sed -i '' 's/@RFPREFIX@/@TARGETPFX@/g' templates/*.jcl
sed -i '' 's/@TARGETPFX@/@ORDERPFX@/g' templates/BRSJREC.jcl
grep -o "@[A-Z]*@" templates/BRSJREC.jcl | sort -u
```

Must show `@ORDERPFX@`. Must **not** show `@TARGETPFX@` or `@RFPREFIX@`.

## 7. Your install settings

```bash
cat > values-install.env <<'EOF'
SMPEENV=new-dedicated-global
ORDERPFX=CONSUL.BRS320.GA
TARGETPFX=CRMBSM1.BRS321
GLOBALPFX=CRMBSM1.BRS321.G
ZFSNAME=CRMBSM1.BRS321.ZFS
PATHPFX=/home/crmbsm1/t1/
VOLSER=T80177
UNIT=SYSALLDA
TZONE=BRS321T
DZONE=BRS321D
ACCT=ZSECURE
PROGRAMMER=S.MARTINEZ
JOBCLASS=A
MSGCLASS=X
EOF

ssh CRMBSM1@tvt8017.pok.stglabs.ibm.com "mkdir -p /home/crmbsm1/t1 && echo dir-ok"
```

Change `PROGRAMMER` to your name. Keep `PATHPFX` short — `/home/crmbsm1/t1/`
works, anything much longer breaks the 80-character line limit in IBM's jobs.

If someone else already installed using `BRS321` or the zone names `BRS321T` /
`BRS321D`, change the number. Every prefix and zone name must be unused.

## 8. Three checks

```bash
python3 zsmagent.py preflight --values values-install.env
```

Wait for `READY`.

```bash
python3 zsmagent.py plan --templates templates --values values-install.env
```

Every DELETE and create must say `BRS321` (or whatever you chose). If you see a
dataset name you don't recognise, stop.

```bash
python3 zsmagent.py selftest --jcl-pds CRMBSM1.TEST.JCL --values values-install.env --zosmf-insecure
```

Submits two harmless test jobs. Both must say `(as expected)`.

## 9. Install

```bash
python3 zsmagent.py smpe --allow-submit --templates templates --values values-install.env --jcl-pds CRMBSM1.TEST.JCL --zosmf-insecure
```

Takes about 12 minutes. Eleven lines appear, one per job:

```
BRSJSMPA         JOB01123  submitted .. active .. done RC 00
BRSJSMPB         JOB01124  submitted .. active .. done RC 00
BRSJSMPC         JOB01125  submitted .. active .. done RC 00
BRSJREC          JOB01126  submitted .. active .. done RC 00
BRSJALL          JOB01127  submitted .. active .. done RC 00
BRSJALZF         JOB01128  submitted .. active .. done RC 00
BRSJDDD          JOB01129  submitted .. active .. done RC 00
BRSJAPP          JOB01130  submitted .. active .. done RC 00
BRSJAPP (real)   JOB01131  submitted .. active .. done RC 00
BRSJACC          JOB01132  submitted .. active .. done RC 00
BRSJACC (real)   JOB01133  submitted .. active .. done RC 00

all 11 jobs completed within their return codes.
```

**Don't press Ctrl+C while it says `active`.** That's the mainframe working. A
job can take two or three minutes.

`BRSJAPP` and `BRSJACC` each run twice on purpose. IBM ships them in rehearsal
mode, so the agent runs the rehearsal and then the real thing.

## 10. Confirm it installed

```bash
ssh CRMBSM1@tvt8017.pok.stglabs.ibm.com "df -k | grep -i BRS321"
ssh CRMBSM1@tvt8017.pok.stglabs.ibm.com "ls -R /home/crmbsm1/t1/usr/lpp/brs/v3r2 | head -30"
ssh CRMBSM1@tvt8017.pok.stglabs.ibm.com "cat \"//'CRMBSM1.BRS321.SMPLOG'\" | grep GIM22701I"
```

You want the filesystem mounted, then `zsm-core.jar`, `libbrsscrtc.so`,
`librdatalib.so`, `brsscrtp-3.2.0-py3-none-any.whl`, and finally two lines:

```
GIM22701I    APPLY PROCESSING WAS SUCCESSFUL FOR SYSMOD HBRS320.
GIM22701I    ACCEPT PROCESSING WAS SUCCESSFUL FOR SYSMOD HBRS320.
```

That's it — installed.

---

## If a job fails

It stops there, saves the output, and won't continue. Resume from the job that
failed instead of starting over:

```bash
ls spool/
tail -60 spool/BRSJALZF-JOB01128.txt     # use the filename it printed

python3 zsmagent.py smpe --allow-submit --from BRSJALZF --templates templates --values values-install.env --jcl-pds CRMBSM1.TEST.JCL --zosmf-insecure
```

Errors seen in real runs:

| Message | Fix |
|---|---|
| `Truncation of a record occurred` | `PATHPFX` is too long. Shorten it. |
| `cannot open ... for output` | The mount directory doesn't exist — rerun the `mkdir` from step 7. |
| `could not be located` on the PDS | Step 4 didn't run. |
| `ALREADY IN USE` in preflight | `TARGETPFX` is taken. Change the number. |
| `syntax error at column NN` | A value has quotes around it. Remove them. |
| `certificate verify failed` | You forgot `--zosmf-insecure`. |

---

## What this doesn't do

It installs the product. It does **not** make it usable: the RACF setup,
EzNoSQL database, and IBM Vault connection are separate steps after this.

It also doesn't download or unpack the order; that has to already be on the
system at `CONSUL.BRS320.GA`.
