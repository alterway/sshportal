#!/bin/sh -e

mkdir -p /etc/systemd/system/sshportal.service.d/

# Only do this on new install or during upgrade if no DB configuration found
if [ -f /tmp/sshportal_mariadb ] &&
	{ [ -z "$2" ] || [ ! -f /etc/systemd/system/sshportal.service.d/custom.conf ]; }; then
	SOCKET="$(mysqladmin variables | grep ".sock " | awk '{print $4}')"
	readonly SOCKET

tee /etc/systemd/system/sshportal.service.d/custom.conf >/dev/null 2>&1 << END
[Service]
StateDirectory=
Environment=SSHPORTAL_DB_DRIVER=mysql
Environment=SSHPORTAL_DATABASE_URL=sshportal@unix($SOCKET)/sshportal?charset=utf8&parseTime=true&loc=Local
END
	rm -f /tmp/sshportal_mariadb
elif [ -z "$2" ] || [ ! -f /etc/systemd/system/sshportal.service.d/custom.conf ]; then

tee /etc/systemd/system/sshportal.service.d/custom.conf >/dev/null 2>&1 << END
[Service]
Environment=SSHPORTAL_DB_DRIVER=sqlite3
Environment=SSHPORTAL_DATABASE_URL=/var/lib/sshportal/sshportal.db?_fk=1
END

fi

[ -n "$2" ] && sed -i 's/sshportal\.db$/sshportal.db?_fk=1/' /etc/systemd/system/sshportal.service.d/custom.conf

if command -v selinuxenabled >/dev/null 2>&1; then
	semodule -i /usr/share/selinux/packages/sshportal.pp
	restorecon -F -R /usr/bin/sshportal
fi

mkdir -p /var/log/sshportal/audit
systemctl daemon-reload

# LogsDirectory, StateDirectory are created by systemd
if command -v selinuxenabled >/dev/null 2>&1; then
	systemctl enable --now sshportal >/dev/null 2>&1 # this will fail because of SELinux on first install
	restorecon -F -R /var/log/sshportal
	[ -d /var/lib/sshportal ] && restorecon -F -R /var/lib/sshportal
fi

systemctl enable --now sshportal
systemctl enable --now sshportal_clean_session_logs.timer

systemctl restart sshportal
systemctl restart sshportal_clean_session_logs.timer
