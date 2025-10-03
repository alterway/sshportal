#!/bin/sh -e

mkdir -p ~/.ssh
cp /integration/client_test_rsa ~/.ssh/id_rsa
chmod -R 700 ~/.ssh
cat >~/.ssh/config <<EOF
Host sshportal
    Port 2222
    HostName sshportal

Host testserver
    Port 2222
    HostName testserver

Host *
    StrictHostKeyChecking no
    ControlMaster auto
    SendEnv TEST_*

EOF

set -x

until nc -z sshportal 2222; do echo "Waiting for sshportal to be up..."; sleep 2; done

# login
ssh sshportal -l invite:integration

# hostgroup/usergroup/acl
ssh sshportal -l root hostgroup create
ssh sshportal -l root hostgroup create --name=hg1
ssh sshportal -l root hostgroup create --name=hg2 --comment=test
ssh sshportal -l root hostgroup inspect hg1 hg2
ssh sshportal -l root hostgroup ls

ssh sshportal -l root usergroup create
ssh sshportal -l root usergroup create --name=ug1
ssh sshportal -l root usergroup create --name=ug2 --comment=test
ssh sshportal -l root usergroup inspect ug1 ug2
ssh sshportal -l root usergroup ls

ssh sshportal -l root acl create --ug=ug1 --ug=ug2 --hg=hg1 --hg=hg2 --comment=test --action=allow --weight=42
ssh sshportal -l root acl inspect 2
ssh sshportal -l root acl ls

# basic host create
ssh sshportal -l root host create bob@example.org:1234
ssh sshportal -l root host create test42
ssh sshportal -l root host create --name=testtest --comment=test --password=test test@test.test
ssh sshportal -l root host create --group=hg1 --group=hg2 hostwithgroups.org
ssh sshportal -l root host inspect example test42 testtest hostwithgroups
ssh sshportal -l root host update --assign-group=hg1 test42
ssh sshportal -l root host update --unassign-group=hg1 test42
ssh sshportal -l root host update --assign-group=hg1 test42
ssh sshportal -l root host update --assign-group=hg2 --unassign-group=hg2 test42
ssh sshportal -l root host ls

# backup/restore
ssh sshportal -l root config backup --indent --ignore-events > backup-1
ssh sshportal -l root config restore --confirm < backup-1
ssh sshportal -l root config backup --indent --ignore-events  > backup-2
(
    cat backup-1 | grep -v '"date":' | grep -v 'tedAt":' > backup-1.clean
    cat backup-2 | grep -v '"date":' | grep -v 'tedAt":' > backup-2.clean
    set -xe
    diff backup-1.clean backup-2.clean
)

# if [ "$CIRCLECI" = "true" ]; then
echo "Strage behavior with cross-container communication on Github CI, skipping some tests..."
# else
#     # bastion
#     ssh sshportal -l root host create --name=testserver toto@testserver:2222
#     out="$(ssh sshportal -l testserver echo hello | head -n 1)"
#     test "$out" = '{"User":"toto","Environ":null,"Command":["echo","hello"]}'

#     out="$(TEST_A=1 TEST_B=2 TEST_C=3 TEST_D=4 TEST_E=5 TEST_F=6 TEST_G=7 TEST_H=8 TEST_I=9 ssh sshportal -l testserver echo hello | head -n 1)"
#     test "$out" = '{"User":"toto","Environ":["TEST_A=1","TEST_B=2","TEST_C=3","TEST_D=4","TEST_E=5","TEST_F=6","TEST_G=7","TEST_H=8","TEST_I=9"],"Command":["echo","hello"]}'
# fi

# TODO: test more cases (forwards, scp, sftp, interactive, pty, stdin, exit code, ...)