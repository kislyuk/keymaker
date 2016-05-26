from __future__ import absolute_import, division, print_function, unicode_literals

from io import open

import os
import sys
import json
import time
import logging
import subprocess
import pwd
import hashlib
import codecs
import grp
from collections import namedtuple

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

import boto3
from botocore.exceptions import ClientError

class ARN(namedtuple("ARN", "partition service region account resource")):
    def __str__(self):
        return ":".join(["arn"] + list(self))

ARN.__new__.__defaults__ = ("aws", "", "", "", "")

def parse_arn(arn):
    return ARN(*arn.split(":", 5)[1:])

def configure(args):
    print("Will configure", args)

def get_authorized_keys(args):
    iam = boto3.client("iam")
    try:
        for key_desc in iam.list_ssh_public_keys(UserName=args.user)["SSHPublicKeys"]:
            key = iam.get_ssh_public_key(UserName=args.user, SSHPublicKeyId=key_desc["SSHPublicKeyId"], Encoding="SSH")
            if key["SSHPublicKey"]["Status"] == "Active":
                print(key["SSHPublicKey"]["SSHPublicKeyBody"])
    except Exception as e:
        err_exit("Error while retrieving IAM SSH keys for {u}: {e}".format(u=args.user, e=str(e)), code=os.errno.EINVAL)

def from_bytes(data, big_endian=False):
    """Used on Python 2 to handle int.from_bytes"""
    if isinstance(data, str):
        data = bytearray(data)
    if big_endian:
        data = reversed(data)
    num = 0
    for offset, byte in enumerate(data):
        num += byte << (offset * 8)
    return num

def aws_to_unix_id(aws_key_id):
    """Converts a AWS Key ID into a UID"""
    USING_PYTHON2 = True if sys.version_info < (3, 0) else False
    if USING_PYTHON2:
        return 2000 + int(
            from_bytes(hashlib.sha256(aws_key_id.encode()).digest()[-2:]) // 2)
    else:
        return 2000 + (
            int.from_bytes(hashlib.sha256(aws_key_id.encode()).digest()[-2:],
            byteorder=sys.byteorder) // 2)


def get_uid(args):
    iam = boto3.resource("iam")
    try:
        user_id = iam.User(args.user).user_id
        uid = aws_to_unix_id(user_id)
        print(uid)
    except Exception as e:
        err_exit("Error while retrieving UID for {u}: {e}".format(u=args.user, e=str(e)), code=os.errno.EINVAL)

def get_groups(args):
    iam_linux_group_prefix = "keymaker_"
    iam = boto3.resource("iam")
    try:
        for group in iam.User(args.user).groups.all():
            if group.name.startswith(iam_linux_group_prefix):
                gid = aws_to_unix_id(group.group_id)
                print(group.name[len(iam_linux_group_prefix):])
    except Exception as e:
        err_exit("Error while retrieving UID for {u}: {e}".format(u=args.user, e=str(e)), code=os.errno.EINVAL)

def install(args):
    user = args.user or "keymaker"
    try:
        pwd.getpwnam(user)
    except KeyError:
        subprocess.check_call(["useradd", user,
                               "--comment", "Keymaker SSH key daemon",
                               "--shell", "/usr/sbin/nologin"])

    authorized_keys_script_path = "/usr/sbin/keymaker-get-public-keys"
    with open(authorized_keys_script_path, "w") as fh:
        print("#!/bin/bash -e", file=fh)
        print('keymaker get_authorized_keys "$@"', file=fh)
    subprocess.check_call(["chown", "root", authorized_keys_script_path])
    subprocess.check_call(["chmod", "go-w", authorized_keys_script_path])
    subprocess.check_call(["chmod", "a+x", authorized_keys_script_path])

    with open("/etc/ssh/sshd_config") as fh:
        sshd_config_lines = fh.read().splitlines()
    remove_lines = ["ChallengeResponseAuthentication no"]
    add_lines = ["AuthorizedKeysCommand " + authorized_keys_script_path,
                 "AuthorizedKeysCommandUser " + user,
                 "ChallengeResponseAuthentication yes",
                 "AuthenticationMethods publickey keyboard-interactive:pam,publickey"]
    sshd_config_lines = [l for l in sshd_config_lines if l not in remove_lines]
    sshd_config_lines += [l for l in add_lines if l not in sshd_config_lines]
    with open("/etc/ssh/sshd_config", "w") as fh:
        for line in sshd_config_lines:
            print(line, file=fh)

    # TODO: print explanation if errors occur
    subprocess.check_call(["sshd", "-t"])

    pam_config_line = "auth requisite pam_exec.so stdout /usr/local/bin/keymaker-create-account-for-iam-user"
    with open("/etc/pam.d/sshd") as fh:
        pam_config_lines = fh.read().splitlines()
    if pam_config_line not in pam_config_lines:
        pam_config_lines.insert(1, pam_config_line)
    with open("/etc/pam.d/sshd", "w") as fh:
        for line in pam_config_lines:
            print(line, file=fh)

    with open("/etc/cron.d/keymaker-group-sync", "w") as fh:
        print("* * * * * root /usr/local/bin/keymaker sync_groups", file=fh)

def err_exit(msg, code=3):
    print(msg, file=sys.stderr)
    exit(code)

def load_ssh_public_key(filename):
    with open(filename) as fh:
        key = fh.read()
        if "PRIVATE KEY" in key:
            logger.info("Extracting public key from private key {}".format(filename))
            key = subprocess.check_output(["ssh-keygen", "-y", "-f", filename]).decode()
    return key

def select_ssh_public_key(identity=None):
    if identity:
        if not os.path.exists(identity):
            err_exit("Path {} does not exist".format(identity))
        return load_ssh_public_key(identity)
    else:
        try:
            keys = subprocess.check_output(["ssh-add", "-L"]).decode("utf-8").splitlines()
            if len(keys) > 1:
                exit('Multiple keys reported by ssh-add. Please specify a key filename with --identity or unload keys with "ssh-add -D", then load the one you want with "ssh-add ~/.ssh/id_rsa" or similar.')
            return keys[0]
        except subprocess.CalledProcessError:
            default_path = os.path.expanduser("~/.ssh/id_rsa.pub")
            if os.path.exists(default_path):
                logger.warning('Using {} as your SSH key. If this is not what you want, specify one with --identity or load it with ssh-add'.format(default_path))
                return load_ssh_public_key(default_path)
            exit('No keys reported by ssh-add, and no key found in default path. Please run ssh-keygen to generate a new key, or load the one you want with "ssh-add ~/.ssh/id_rsa" or similar.')

def upload_key(args):
    ssh_public_key = select_ssh_public_key(args.identity)
    iam = boto3.resource("iam")
    if args.user:
        user = iam.User(args.user)
    else:
        user = iam.CurrentUser().user
    try:
        user.meta.client.upload_ssh_public_key(UserName=user.name, SSHPublicKeyBody=ssh_public_key)
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") == "LimitExceeded":
            logger.error('The current IAM user has filled their public SSH key quota. Delete keys with "keymaker list_keys" and "keymaker delete_key".')
        raise

def list_keys(args):
    iam = boto3.resource("iam")
    if args.user:
        user = iam.User(args.user)
    else:
        user = iam.CurrentUser().user
    for key in iam.meta.client.list_ssh_public_keys(UserName=user.name)["SSHPublicKeys"]:
        print(key)

def update_key(args, status):
    iam = boto3.resource("iam")
    if args.user:
        user = iam.User(args.user)
    else:
        user = iam.CurrentUser().user
    return iam.meta.client.update_ssh_public_key(UserName=user.name, SSHPublicKeyId=args.ssh_public_key_id, Status=status)

def disable_key(args):
    print(update_key(args, status="Inactive"))

def enable_key(args):
    print(update_key(args, status="Active"))

def delete_key(args):
    iam = boto3.resource("iam")
    if args.user:
        user = iam.User(args.user)
    else:
        user = iam.CurrentUser().user
    print(iam.meta.client.delete_ssh_public_key(UserName=user.name, SSHPublicKeyId=args.ssh_public_key_id))

def sync_groups(args):
    from pwd import getpwnam
    iam = boto3.resource("iam")
    for group in iam.groups.filter(PathPrefix="/keymaker/"):
        if not group.name.startswith("keymaker-"):
            continue
        logger.info("Syncing IAM group %s", group.name)
        unix_group_name = group.name[len("keymaker-"):]
        try:
            unix_group = grp.getgrnam(unix_group_name)
        except KeyError:
            logger.info("Provisioning group %s from IAM", unix_group_name)
            subprocess.check_call(["groupadd", "--gid", str(aws_to_unix_id(group.group_id)), unix_group_name])
            unix_group = grp.getgrnam(unix_group_name)
        user_names_in_iam_group = [user.name for user in group.users.all()]
        for user in user_names_in_iam_group:
            try:
                uid = pwd.getpwnam(user.name)
                if uid < 2000:
                    raise ValueError(uid)
            except Exception:
                logger.error("User %s is not provisioned or not managed by keymaker, skipping", user)
                continue
            if user.name not in unix_group.gr_mem:
                logger.info("Adding user %s to group %s", user.name, unix_group_name)
                subprocess.check_call(["usermod", "--append", "--groups", unix_group_name, user.name])
        for unix_user_name in unix_group.gr_mem:
            if unix_user_name not in user_names_in_iam_group:
                subprocess.check_call(["gpasswd", "--delete", user.name, unix_group_name])
