<div align="center">
<img src="https://raw.githubusercontent.com/alterway/sshportal/master/.assets/bastion.jpg" width="20%">

# sshportal

[![Go Report Card](https://goreportcard.com/badge/moul.io/sshportal)](https://goreportcard.com/report/moul.io/sshportal)
[![License](https://img.shields.io/github/license/alterway/sshportal.svg)](https://github.com/alterway/sshportal/blob/master/LICENSE)
[![GitHub release](https://img.shields.io/github/v/release/alterway/sshportal.svg)](https://github.com/alterway/sshportal/releases)

Jump host/Jump server without the jump, a.k.a Transparent SSH bastion


## IMPORTANT NOTE
**The [original project](https://github.com/moul/sshportal) is no longer being maintained. This fork includes important security fixes, some bugfixes and features but it is on MAINTENANCE mode and only security issues and major bugs will be fixed. You should consider using [Teleport](https://github.com/gravitational/teleport) instead.**

</div>

---

![Flow Diagram](https://raw.githubusercontent.com/alterway/sshportal/master/.assets/flow-diagram.png)

---

<!-- toc -->

- [Installation and usage](#installation)
- [Quick Start](#quick-start)
- [Features and limitations](#features-and-limitations)
- [Backup / Restore](#backup--restore)
- [Built-in shell](#built-in-shell)
- [Healthcheck](#healthcheck)
- [Portal alias (.ssh/config)](#portal-alias-sshconfig)
- [Under the hood](#under-the-hood)
- [Testing](#testing)

<!-- tocstop -->

---

### Installation

Packaged installation (`.deb` & `.rpm`) is privileged as it comes with a hardened systemd service and a SELinux module if you have enfored SELinux on your GNU/Linux distribution.

Get the latest version [here](https://github.com/alterway/sshportal/releases)

**Note :** by default, your package manager will automatically install `sqlite` (recommended dependency)

This installation will install sshportal as a systemd service, configure logrotate to keep 1 year of audit logs and add a systemd timer for session logs management. See [`packaging`](https://github.com/alterway/sshportal/tree/master/packaging).

If mariadb is selected during the install, it will also automatically create the `sshportal` database if it doesn't exist.

<details>
<summary>Show Debian-based distributions instructions</summary>

```bash
apt install ./sshportal_x.x.x_xxx.deb
```
You will be asked if you want to use `mariadb` instead of `sqlite` (default). Make sure to install `mariadb-server` before as the package is not listed as a hard dependency in the [control file](https://github.com/alterway/sshportal/blob/master/.goreleaser.yml#L31).

To install SSHportal with mariadb:

```bash
apt install --no-install-recommends -y mariadb-server
DEBIAN_FRONTEND=noninteractive SSHPORTAL_MARIADB_SETUP=true apt install --no-install-recommends -y mariadb-server ./sshportal_x.x.x_xxx.deb
```

If you want to stick with sqlite, you just have to do this:

```bash
DEBIAN_FRONTEND=noninteractive apt install -y ./sshportal_x.x.x_xxx.deb
```

</details>

<details>
<summary>Show RedHat-based distributions instructions</summary>

Make sure to install `mariadb-server` before if you want to use it as this package is not listed as a hard dependency in the [control file](https://github.com/alterway/sshportal/blob/master/.goreleaser.yml#L31).

There is no debconf in RedHat distribution so if you want an automatic mariadb setup you need to install `sshportal` with :

```bash
dnf install -y --setopt=install_weak_deps=False mariadb-server
SSHPORTAL_MARIADB_SETUP=true dnf install --setopt=install_weak_deps=False ./sshportal_x.x.x_xxx.rpm
```

If you want to stick with sqlite, you just have to do this:

```bash
dnf install -y ./sshportal_x.x.x_xxx.rpm
```

</details>

<details>
<summary>Docker instructions</summary>

An [automated build is setup on the Github registry](https://github.com/alterway/sshportal/pkgs/container/sshportal).

```bash
# Start a server in background
# mount `pwd` to persist the sqlite database file
docker run -p 2222:2222 -d --name=sshportal -v "$(pwd):$(pwd)" -w "$(pwd)" ghcr.io/alterway/sshportal:latest

# check logs (mandatory on first run to get the administrator invite token)
docker logs -f sshportal
```

</details>

---

### Quick start

1) Get the invite token in stdout or `/var/log/sshportal/audit/audit.log` if installed from a package manager :

```bash
2023/09/01 15:03:18 info: system migrated
2023/09/01 15:03:18 info: 'sshportal' user created. Run 'ssh localhost -p 2222 -l invite:6tUguNFYxeOxdx0N' to associate your public key with this account
2023/09/01 15:03:18 info: SSH Server accepting connections on :2222, idle-timout=0s
```

2) Make sure you have a ssh key pair and associate your public key to the bastion

```console
ssh localhost -p 2222 -l invite:xxxxxxx

Welcome sshportal!

Your key is now associated with the user "sshportal@localhost".
```

3) Your first user is the admin. To access to the console, connect like a normal server

```console
ssh sshportal@localhost -p 2222
```


4) Create your first host

```console
config> host create bart@foo.example.org
1
config>
```

5) List hosts

```console
config> host ls
  ID | NAME |           URL           |   KEY   | PASS | GROUPS  | COMMENT
+----+------+-------------------------+---------+------+---------+---------+
   1 | foo  | bart@foo.example.org:22 | default |      | default |
Total: 1 hosts.
config>
```

6) Add the `host` key to the server

```console
config> host ls
  ID | NAME | URL | KEY | GROUPS | UPDATED | CREATED | COMMENT | HOP | LOGGING
-----+------+-----+-----+--------+---------+---------+---------+-----+----------
Total: 0 hosts.
config> key ls
  ID |  NAME   |  TYPE   | LENGTH | HOSTS |   UPDATED    |   CREATED    |       COMMENT
-----+---------+---------+--------+-------+--------------+--------------+-----------------------
   2 | host    | ed25519 |      1 |     0 | 1 minute ago | 1 minute ago | created by sshportal
   1 | default | ed25519 |      1 |     0 | 1 minute ago | 1 minute ago | created by sshportal
```

```console
ssh bart@foo.example.org "$(ssh sshportal@localhost -p 2222 key setup host)"
```

7) Profit

```console
ssh localhost -p 2222 -l foo
bart@foo>
```

8) Invite friends

*This command doesn't create a user on the remote server, it only creates an account in the sshportal database.*

```console
config> user invite bob@example.com
User 2 created.
To associate this account with a key, use the following SSH user: 'invite:NfHK5a84jjJkwzDk'.
```

Demo gif:
![sshportal demo](https://github.com/alterway/sshportal/raw/master/.assets/demo.gif)

---

### Features and limitations

* Single autonomous binary (~20Mb) with no runtime dependencies (except glibc)
* Portable / Cross-platform (regularly tested on linux and OSX/darwin)
* Store data in [Sqlite3](https://www.sqlite.org/) or [MySQL](https://www.mysql.com)
* Stateless -> horizontally scalable when using [MySQL](https://www.mysql.com) as the backend
* Connect to remote host using key or password
* Admin commands can be run directly or in an interactive shell
* Host management
* User management (invite, group, stats)
* Host Key management (create, remove, update, import)
* Automatic remote host key learning
* User Key management (multiple keys per user)
* ACL management (acl + user-groups + host-groups)
* User roles (admin, trusted, standard, ...)
* User invitations (no more "give me your public ssh key please")
* Easy server installation (generate shell command to setup `authorized_keys`)
* Sensitive data encryption
* Session management (see active connections, history, stats, stop)
* Audit log (logging every user action)
* Record TTY Session (with [ttyrec](https://en.wikipedia.org/wiki/Ttyrec) format, use `ttyplay` for replay)
* Tunnels logging
* Host Keys verifications shared across users
* Healthcheck user (replying OK to any user)
* SSH compatibility
  * ipv4 and ipv6 support
  * [`scp`](https://linux.die.net/man/1/scp) support
  * [`rsync`](https://linux.die.net/man/1/rsync) support
  * [`tunneling`](https://www.ssh.com/ssh/tunneling/example) (local forward, remote forward, dynamic forward) support
  * [`sftp`](https://www.ssh.com/ssh/sftp/) support
  * [`ssh-agent`](https://www.ssh.com/ssh/agent) support
  * [`X11 forwarding`](http://en.tldp.org/HOWTO/XDMCP-HOWTO/ssh.html) support
  * Git support (can be used to easily use multiple user keys on GitHub, or access your own firewalled gitlab server)
  * Do not require any SSH client modification or custom `.ssh/config`, works with every tested SSH programming libraries and every tested SSH clients
* SSH to non-SSH proxy
  * [Telnet](https://www.ssh.com/ssh/telnet) support

**(Known) limitations**

* Does not work with [`mosh`](https://mosh.org/)
* It is not possible for a user to access a host with the same name as the user. This is easily circumvented by changing the user name, especially since the most common use cases does not expose it.
* It is not possible to access a host named `healthcheck` as this is a built-in command.

---

### Backup / Restore

sshportal embeds built-in backup/restore methods which basically import/export JSON objects:

```sh
# Backup
ssh portal config backup  > sshportal.bkp

# Restore
ssh portal config restore < sshportal.bkp
```

This method is particularly useful as it should be resistant against future DB schema changes (expected during development phase).

I suggest you to be careful during this development phase, and use an additional backup method, for example:

```sh
# sqlite dump
sqlite3 sshportal.db .dump > sshportal.sql.bkp

# or just the immortal cp
cp sshportal.db sshportal.db.bkp
```

---

### Built-in shell

`sshportal` embeds a configuration CLI.

By default, the configuration user is the user starting the server for the first time. It fallbacks to `root`.

Each command can be run directly by using this syntax: `ssh root@portal.example.org <command> [args]`:

```
ssh root@portal.example.org host inspect toto
```

You can enter in interactive mode using this syntax: `ssh root@portal.example.org`

![sshportal overview](https://raw.github.com/alterway/sshportal/master/.assets/overview.png)
---

See [Documentation](https://github.com/alterway/sshportal/wiki/Documentation) for the list of shell commands.

---

### Healthcheck

By default, `sshportal` will return `OK` to anyone sshing using the `healthcheck` user without checking for authentication.

```console
$ ssh healthcheck@localhost -p 2222
OK
```

the `healtcheck` user can be changed using the `healthcheck-user` option.

---

Alternatively, you can run the built-in healthcheck helper (requiring no ssh client nor ssh key):

Usage: `sshportal healthcheck [--addr=host:port] [--wait] [--quiet]`

```console
$ sshportal healthcheck --addr=localhost:2222; echo $?
0
```

---

Wait for sshportal to be healthy, then connect

```console
$ sshportal healthcheck --wait && ssh sshportal -l root
config>
```

---

### Portal alias (.ssh/config)

Edit your `~/.ssh/config` file (create it first if needed)

```ini
Host portal
  User      root       # or 'sshportal' if you use the packaged binary
  User      root       # or 'sshportal' if you use the packaged sshportal
  Port      2222       # portal port
  HostName  127.0.0.1  # portal hostname
```

```bash
# you can now run a shell using this:
ssh portal
# instead of this:
ssh localhost -p 2222 -l root

# or connect to hosts using this:
ssh hostname@portal
# instead of this:
ssh localhost -p 2222 -l hostname
```

---

## Scaling

`sshportal` is stateless but relies on a database to store configuration and logs.

By default, `sshportal` uses a local [sqlite](https://www.sqlite.org/) database which isn't scalable by design.

You can run multiple instances of `sshportal` sharing the same [MySQL](https://www.mysql.com) database, using `sshportal --db-conn=user:pass@host/dbname?parseTime=true --db-driver=mysql`.

![sshportal cluster with MySQL backend](https://raw.github.com/alterway/sshportal/master/.assets/cluster-mysql.png)

See [examples/mysql](http://github.com/alterway/sshportal/tree/master/examples/mysql).

---

### Under the hood

* Docker first (used in dev, tests, by the CI and in production)
* Backed by (see [dep graph](https://godoc.org/github.com/alterway/sshportal?import-graph&hide=2)):
  * SSH
    * https://github.com/gliderlabs/ssh: SSH server made easy (well-designed golang library to build SSH servers)
    * https://godoc.org/golang.org/x/crypto/ssh: both client and server SSH protocol and helpers
  * Database
    * https://github.com/jinzhu/gorm/: SQL orm
    * https://github.com/go-gormigrate/gormigrate: Database migration system
  * Built-in shell
    * https://github.com/olekukonko/tablewriter: Ascii tables
    * https://github.com/asaskevich/govalidator: Valide user inputs
    * https://github.com/dustin/go-humanize: Human-friendly representation of technical data (time ago, bytes, ...)
    * https://github.com/mgutz/ansi: Terminal color helpers
    * https://github.com/urfave/cli: CLI flag parsing with subcommands support

![sshportal data model](https://raw.github.com/alterway/sshportal/master/.assets/sql-schema.png)

---

### Testing

[Install golangci-lint](https://golangci-lint.run/usage/install/#local-installation) and run this in project root:
```
golangci-lint run
```

Perform integration tests
```
cd ./examples/integration && make
```

Perform unit tests
```
go test
```
---
