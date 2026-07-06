# Lab VMs

This file lists the controlled lab targets used for Account Discovery Tool testing.

Do not save lab passwords in this file. Enter passwords manually at runtime or store them only in a local `.env` file that is excluded from Git.

## RHEL / Linux Lab

```bash
RHEL_TEST_HOST=192.168.7.130
RHEL_TEST_USERNAME=root
RHEL_TEST_PASSWORD=
```

Seeded test areas:

- Linux local accounts
- MySQL on port `3306`
- MongoDB on port `27017`

Database admin connection placeholders:

```bash
MYSQL_TEST_HOST=192.168.7.130
MYSQL_TEST_PORT=3306
MYSQL_TEST_USERNAME=root
MYSQL_TEST_PASSWORD=

MONGO_TEST_HOST=192.168.7.130
MONGO_TEST_PORT=27017
MONGO_TEST_USERNAME=adpct_admin
MONGO_TEST_PASSWORD=
MONGO_TEST_AUTH_DB=admin
```

## Windows Lab

```bash
WIN11_TEST_HOST=192.168.7.131
WIN11_TEST_USERNAME=demo\\administrator
WIN11_TEST_PASSWORD=

WIN_SERVER_TEST_HOST=192.168.101.115
WIN_SERVER_TEST_USERNAME=Demo\\Administrator
WIN_SERVER_TEST_PASSWORD=
```

Seeded test areas:

- Windows local accounts
- Local Administrators membership
- Remote Desktop Users membership
- Windows service account
- Scheduled task account

Windows Server target:

- `192.168.101.115`
- Use the password supplied manually at runtime only. Do not commit it to this file.

## Safety

The lab seeding scripts only allow these targets by default:

- `192.168.7.130`
- `192.168.7.131`
- `192.168.101.115`

To run against any other explicitly approved non-production target, set:

```bash
ALLOW_NON_LAB_TARGET=true
```

Use that override only for temporary lab validation.
