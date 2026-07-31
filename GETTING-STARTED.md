# Installing zSecure Secret Manager with zsmagent — start-to-finish guide

For an IBM employee who has never used z/OS.

You will not need to learn ISPF, JCL, or SMP/E to get through this. You do need
to collect six pieces of information from people who know your system, and you
need to understand roughly what those six things are. This part cannot be
automated, and this guide explains each one.

Total time: about 30 minutes of your own work, to find which systems to use. The install itself runs in about 12 minutes.

---

## z/OS vocabulary you need to operate this agent

| Word | What it means |
|---|---|
| **dataset** | A file. Names look like `SMITH.BRS320.CSI` uppercase, max 44 characters. |
| **PDS** | A dataset that holds multiple members. |
| **member** | One file inside a PDS. Written `SMITH.TEST.JCL(BRSJREC)`. |
| **JCL** | A small text file that tells the mainframe to run something. The nine files this guide installs from are JCL. |
| **job** | A running JCL file. You submit it, it goes in a queue, it runs, it finishes with a number. |
| **RC** | Return code. `RC 00` means success. Anything else requires further inspection. |
| **SMP/E** | The mainframe's package installer. It keeps records of what is installed where. |
| **zFS** | A Unix-style filesystem stored inside a dataset. Part of this product installs into one. |
| **volume** | A physical disk. Has a six-character name like `T80177`. |


---

## Prerequisites: ensure you have the fields you need to fill the agent with

Copy the message below and send it to whoever owns the z/OS test system you will
be using. In IBM that is usually the product team or the system programmer for
the LPAR.

> Hi, I need to run the SMP/E install of zSecure Secret Manager 3.2.0
> (FMID HBRS320) on **\_\_\_\_\_\_\_** as part of onboarding/testing. Could you
> confirm or provide:
>
> 1. **Hostname** of the system, and confirmation my userid can SSH to it
> 2. **My TSO userid and password** (I'll need the password for z/OSMF too)
> 3. Is **z/OSMF** running? I need it to read job return codes. I'll check
>    `https://<host>/zosmf/` responds.
> 4. **Where the Shopz order is already unpacked** I need the dataset prefix,
>    e.g. `SOMETHING.BRS320.GA`, such that
>    `<prefix>.IBM.HBRS320.SMPMCS` exists. I am not downloading or unpacking
>    the order myself.
> 5. A **disk volume** I can install to with about **380 cylinders free**
>    (~5,700 tracks)
> 6. Our **job card conventions** accounting code, job class, message class
> 7. Confirmation that a **second/parallel install** under my own dataset prefix
>    is acceptable on this system
>
> I'll install under my own prefix and mount the filesystem inside my own home
> directory, so I won't need UID 0 or any RACF permissions, and won't touch any
> existing install.

Reference these answers in Part 4 as they come back. **Do not
start Part 5 until you have all of them**

---

## Part 1 — Set up your Device

Open Terminal (Mac: Cmd+Space, type "Terminal", Enter, Windows: Windows key, type "Terminal", Enter).

```bash
mkdir -p ~/zsm
cd ~/zsm
```

Unzip `zsmagent-bundle.zip` and move its contents into `~/zsm`. Check:

```bash
ls
```

You should see `zsmagent.py`, `README.md`, `values.example.env`,
`values-install.example.env`.

Install the paramiko library (Python implementation of the SSH protocol)

```bash
pip install paramiko
```

Confirm the script runs:

```bash
python3 zsmagent.py --help
```

A usage message means you are set. An error mentioning `paramiko` means the
install above did not work, try `pip3 install paramiko`.

---

## Part 2 — Prove you can connect

Set three variables. **Replace the angle brackets with your real values.**

```bash
export ZSM_HOST=<hostname from Part 0>
export ZSM_USER=<YOURID>
read -s ZSM_PASSWORD && export ZSM_PASSWORD
```

That last line looks like it does nothing because it is waiting for your input. Type your
password (nothing appears on screen) and press Enter. Check it registered:

```bash
echo ${#ZSM_PASSWORD}
```

That prints how many characters it captured. If the number matches your
password's length, good. If it prints `0`, run the `read -s` line again.

> These variables last only as long as this Terminal window. If you open a new
> one, set them again.

Now two connection tests:

```bash
python3 zsmagent.py check
```

Expect `OK` followed by a time to confirm the mainframe response. If it asks for
a password or fails, your SSH access is not working yet. Go back to Part 0.

```bash
python3 zsmagent.py zosmf
```

Expect something like `z/OSMF 30 on 05.30.00`.

**If that fails with a certificate error**, your Mac does not trust the
mainframe's certificate. Check who issued it:

```bash
openssl s_client -connect $ZSM_HOST:443 </dev/null 2>/dev/null | openssl x509 -noout -issuer
```

If the issuer is an IBM internal CA, that is expected. Add `--zosmf-insecure` to
every command from here on:

```bash
python3 zsmagent.py zosmf --zosmf-insecure
```

That flag stops checking the mainframe's identity. Fine for an internal test
system over VPN. Not something to put in customer-facing documentation. The
real fix is getting the IBM internal CA installed on your workstation, which is
worth doing eventually.

Set up an SSH key too, so Part 3 does not ask for your password nine times:

```bash
ssh-keygen -t ed25519 -N "" -f ~/.ssh/id_ed25519
ssh-copy-id $ZSM_USER@$ZSM_HOST
```

That asks for your password once. From then on, SSH is automatic.

---

## Part 3 — Create a scratch PDS

The agent needs somewhere on the mainframe to put the JCL it builds. One
command, using the userid from Part 0:

```bash
ssh $ZSM_USER@$ZSM_HOST "tsocmd \"ALLOCATE DATASET('$ZSM_USER.TEST.JCL') NEW CATALOG SPACE(5,5) TRACKS DIR(10) RECFM(F,B) LRECL(80) BLKSIZE(0)\""
```

No output means it worked. If it says the dataset already exists, carry on.

This is a scratch dataset that exists only to hold temporary JCL. You can delete
it when you are finished.

---

## Part 4 — Your values worksheet

Fill this in on paper or in a note before continuing. Every line comes from
Part 0 or is your own choice.

| # | Value | Yours | Where it comes from |
|---|---|---|---|
| 1 | Hostname | | Part 0 answer 1 |
| 2 | Your userid | | Part 0 answer 2 |
| 3 | `ORDERPFX` — where the product comes from | | Part 0 answer 4 |
| 4 | `TARGETPFX` — where it installs to | `<YOURID>.BRS320` | Your choice. Must be unused. |
| 5 | `VOLSER` — which disk | | Part 0 answer 5 |
| 6 | `PATHPFX` — filesystem mount point | `/home/<yourid>/t1/` | Your choice. Keep it short — see below. |
| 7 | `TZONE` / `DZONE` — SMP/E zone names | `BRS320T` / `BRS320D` | Your choice. Must be unique on the system. |
| 8 | `SMPEENV` | `new-dedicated-global` | See below. |
| 9 | Job card: account, class, msgclass | | Part 0 answer 6 |



**`TARGETPFX` must be unused.** The first job in the sequence *deletes* the
SMP/E records at this prefix before creating new ones. On an unused prefix that
is harmless. On a prefix someone else is using, it destroys their record of
what is installed. The agent checks and refuses, but choose carefully anyway.

**`PATHPFX` is a permissions decision disguised as a path.** Put it inside your
own home directory (`/home/yourid/t1/`) and you need no special authority. Point
it at a system directory like `/usr/lpp/...` and the install will fail unless
someone grants you elevated privileges. Also **keep it short**. the IBM sample
jobs have comment lines that already run to near the 80-character limit, and a
long path pushes them over. `/home/yourid/t1/` is safe; `/home/yourid/test321/`
is too long. The agent will tell you by exactly how many characters if so.

**Zone names must be unique on the system.** If someone else already has a zone
called `BRS320T`, pick `BRS32AT` or similar. Ask in Part 0 if unsure.

**`SMPEENV`** has three possible answers:
- `new-dedicated-global` — you are building a completely fresh SMP/E setup of
  your own. **This is almost certainly what you want for a test install.**
- `new-shared-global` — new install area, but reusing an existing shared
  registry
- `existing` — installing into an SMP/E environment that already exists

If you do not know, use `new-dedicated-global` and mention it when you ask
Part 0 question 7.

---

## Part 5 — Build your templates

The agent does not ship IBM's install jobs. You copy them from your own system,
which also means they match your order exactly.

```bash
cd ~/zsm
mkdir -p raw templates
```

Download the nine jobs. **Replace `<ORDERPFX>` with part 4 line 3:**

```bash
for m in BRSJSMPA BRSJSMPB BRSJSMPC BRSJREC BRSJALL BRSJALZF BRSJDDD BRSJAPP BRSJACC; do
  ssh $ZSM_USER@$ZSM_HOST "cat \"//'<ORDERPFX>.BRSINST($m)'\"" > raw/$m.jcl
done
ls -l raw/
find raw -name '*.jcl' -size 0
```

All nine should have a real size. The `find` command should print **nothing** —
anything listed came down empty and needs re-downloading.

Now find out what values are already in those jobs.

```bash
cp values.example.env values.env
head -2 raw/BRSJREC.jcl
grep -h "into your\|into the\|into an\|into volume\|into unit" raw/*.jcl | sort -u
```

The first command shows the job card as shipped. The second lists every value
IBM says you may need to change. Each line looks like
`//* - SOMETHING.PREFIX  into your prefix for zSecure Secret Manager`.

Open `values.env` in an editor and make each entry match what you just saw:

```bash
open -e values.env
```

`values.env` needs the values **as they appear in the downloaded jobs** — not
your own values. That feels backwards, but it is how the next step works: it
searches for those strings and replaces them with markers.

```bash
python3 zsmagent.py parametrize --raw raw --templates templates --values values.env
```

You will get a report per job showing which markers were placed. Read it:

- A value reported as *not present in this job* for **every** job means that
  value in `values.env` is wrong. Fix it and rerun
- Anything reported as `REJECTED` means the template did not reproduce the
  original exactly, and it was not written. Fix the value and rerun.
- Rerunning is safe and repeatable

Finally, one value does two different jobs and must be separated by hand. In
`BRSJREC` the prefix refers to *the product being read in*; everywhere else it
means *where the install goes*:

```bash
sed -i '' 's/@RFPREFIX@/@TARGETPFX@/g' templates/*.jcl
sed -i '' 's/@TARGETPFX@/@ORDERPFX@/g' templates/BRSJREC.jcl
grep -o "@[A-Z]*@" templates/BRSJREC.jcl | sort -u
```

The last command must show `@ORDERPFX@` and must **not** show `@TARGETPFX@` or
`@RFPREFIX@`. If it does, stop and ask for help to avoid pointing
the installer at an empty location.

---

## Part 6 — Write your install config

```bash
cp values-install.example.env values-install.env
open -e values-install.env
```

Replace every `<ANGLE BRACKET>` using your own values. 

Create your mount point directory (worksheet line 6, without the trailing
slash):

```bash
ssh $ZSM_USER@$ZSM_HOST "mkdir -p /home/<yourid>/t1 && echo created"
```

---

## Part 7 — Four safety checks before installing

Run all four. Each takes seconds and none of them installs anything.

```bash
# 1. Readiness: are you authorised, is the order there, is the target free?
python3 zsmagent.py preflight --values values-install.env
```

Wait for **READY**. If it says BLOCKER, read the message to diagnose the
problem.

```bash
# 2. What every job would create, delete, and mount
python3 zsmagent.py plan --templates templates --values values-install.env
```

**Read this properly.** Every DELETE and every create must name *your* prefix.
If you see a dataset name you do not recognise, stop and investigate.

```bash
# 3. Every job, fully filled in, printed to screen
python3 zsmagent.py smpe --dry-run --templates templates --values values-install.env
```

Skim for anything that still looks like a placeholder, or any prefix that is not
yours.

```bash
# 4. Prove the machinery works, using two harmless test jobs
python3 zsmagent.py selftest --jcl-pds $ZSM_USER.TEST.JCL --values values-install.env --zosmf-insecure
```

This submits two jobs that touch no datasets at all: one designed to succeed,
one designed to fail and confirms the agent can tell the difference. Both
should report *as expected*.

---

## Part 8 — Install

```bash
python3 zsmagent.py smpe --allow-submit \
  --templates templates --values values-install.env \
  --jcl-pds $ZSM_USER.TEST.JCL --zosmf-insecure
```

Eleven lines will appear over about ten minutes, one per job:

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

**Do not press Ctrl+C while it says `active`.** That is the mainframe working. A
job can take two or three minutes. If you interrupt after a
submission, the job keeps running on the mainframe and the agent loses track of
it.

`BRSJAPP` appears twice on purpose. IBM's job ships in rehearsal mode, so it is
submitted once as a rehearsal and once for real. Same for `BRSJACC`.

---

## Part 9 — Confirm it installed

```bash
ssh $ZSM_USER@$ZSM_HOST "df -k | grep -i <TARGETPFX>"
ssh $ZSM_USER@$ZSM_HOST "ls -R /home/<yourid>/t1/usr/lpp/brs/v3r2 | head -30"
ssh $ZSM_USER@$ZSM_HOST "cat \"//'<TARGETPFX>.SMPLOG'\" | grep GIM22701I"
```

Look for three things: the filesystem mounted, real product files
(`zsm-core.jar`, `libbrsscrtc.so`, `librdatalib.so`,
`brsscrtp-3.2.0-py3-none-any.whl`), and two `GIM22701I` lines saying APPLY and
ACCEPT were successful.

All three present means the product is installed.

---

## If a job fails

The run stops immediately, saves that job's full output under `spool/`, and
refuses to continue, the remaining jobs would run against a half-built install.

```bash
ls spool/
tail -60 spool/<the file it named>.txt
```

Search that file for `GIM` messages and for `RETURN CODE`. Fix the cause, then
resume from the job that failed rather than starting over:

```bash
python3 zsmagent.py smpe --allow-submit --from BRSJALZF \
  --templates templates --values values-install.env \
  --jcl-pds $ZSM_USER.TEST.JCL --zosmf-insecure
```

Commmon causes:

| Symptom | Cause |
|---|---|
| `Truncation of a record occurred` | A value is too long and overflowed the 80-character line limit. Almost always `PATHPFX`. Shorten it and rerun `smpe --dry-run` first. |
| `cannot open ... for output` | A directory or dataset does not exist. Check the mount point directory and the scratch PDS. |
| Fails on `BRSJALZF` with a permissions error | `PATHPFX` is pointing outside your home directory. |
| `no such file or directory` on the target PDS | The scratch PDS from Part 3 was not created. |
| Fails with a space-related message | The volume from worksheet line 5 does not have room. |
| `syntax error at column NN` | A value contains a character SMP/E does not accept. |

---

## What this does not do

**It installs the product; it does not make it work.** Per the Program
Directory, SMP/E installation alone does not activate zSecure Secret Manager.
The RACF setup, the EzNoSQL database, and connecting to IBM Vault are separate
steps. If your task is "install it," you are done. If your task is "use it,"
that is the next phase.

It also does not download or unpack the Shopz order (that is why Part 0 asks
where it already is), and does not run `REPORT CROSSZONE`.

---

## Cleaning up

The install occupies roughly 380 cylinders. When you no longer need it, ask
whoever owns the system to remove `<TARGETPFX>.*` and unmount the filesystem

The scratch PDS `<YOURID>.TEST.JCL` and the local `~/zsm` folder are yours and
can be deleted freely.
