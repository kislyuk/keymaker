from __future__ import absolute_import, division, print_function, unicode_literals

from io import open

import os
import sys
import json
import re
import time
import logging
import subprocess
import pwd
import hashlib
import codecs
import grp
import shlex
from collections import namedtuple

import boto3
from botocore.exceptions import ClientError

from .iam.policies import trust_policy_template, keymaker_instance_role_policy, keymaker_instance_assume_role_statement

USING_PYTHON2 = True if sys.version_info < (3, 0) else False

logger = logging.getLogger(__name__)

class ARN(namedtuple("ARN", "partition service region account resource")):
    def __str__(self):
        return ":".join(["arn"] + list(self))


ARN.__new__.__defaults__ = ("aws", "", "", "", "")

default_iam_linux_group_prefix = "keymaker_"
default_iam_linux_user_suffix = ""

def parse_arn(arn):
    return ARN(*arn.split(":", 5)[1:])

def ensure_iam_role(iam, role_name, trust_principal, keymaker_config=None):
    trust_policy = json.loads(json.dumps(trust_policy_template))
    trust_policy["Statement"][0]["Principal"] = trust_principal
    description = ", ".join("=".join(i) for i in keymaker_config.items()) if keymaker_config else ""
    for role in iam.roles.all():
        if role.name == role_name:
            logger.info("Using existing IAM role %s", role)
            break
    else:
        logger.info("Creating IAM role %s", role_name)
        role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    role_config = parse_keymaker_config(role.description)
    if keymaker_config is not None and role_config != keymaker_config:
        description = ", ".join("=".join(i) for i in keymaker_config.items()) if keymaker_config else ""
        logger.info('Updating IAM role description to "%s"', description)
        iam.meta.client.update_role_description(RoleName=role.name, Description=description)
    iam.meta.client.update_assume_role_policy(RoleName=role.name, PolicyDocument=json.dumps(trust_policy))
    return role

def ensure_iam_policy(iam, policy_name, policy, description):
    for p in iam.policies.all():
        if p.policy_name == policy_name:
            logger.info("Using existing IAM policy %s", p)
            if p.default_version.document != policy:
                logger.info("Updating IAM policy %s", p)
                p.create_version(PolicyDocument=json.dumps(policy), SetAsDefault=True)
            return p
    else:
        logger.info("Creating IAM policy %s", policy_name)
        return iam.create_policy(PolicyName=policy_name, PolicyDocument=json.dumps(policy), Description=description)

def configure(args):
    iam = boto3.resource("iam")
    sts = boto3.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    logger.info("Configuring Keymaker in account %s", account_id)

    keymaker_config = {}
    if args.require_iam_group:
        keymaker_config.update(keymaker_require_iam_group=args.require_iam_group)
    keymaker_policy_description = ("Used by EC2 instances running Keymaker (https://github.com/kislyuk/keymaker) to "
                                   "access user SSH public keys stored in IAM user accounts.")
    keymaker_policy = ensure_iam_policy(iam, args.instance_iam_policy, keymaker_instance_role_policy,
                                        description=keymaker_policy_description)
    if args.instance_iam_role.startswith("arn:") and parse_arn(args.instance_iam_role).account != account_id:
        keymaker_config.update(keymaker_id_resolver_account=account_id,
                               keymaker_id_resolver_iam_role=args.id_resolver_iam_role)
        logger.info("Assuming role in profile %s", args.cross_account_profile)
        iam = boto3.Session(profile_name=args.cross_account_profile).resource("iam")
    elif args.cross_account_profile:
        logger.warn("Instance IAM role is in current account; argument --cross-account-profile has no effect")

    instance_role_name = args.instance_iam_role
    if args.instance_iam_role.startswith("arn:"):
        instance_role_name = parse_arn(instance_role_name).resource.split("/", 1)[1]
    instance_role = ensure_iam_role(iam, instance_role_name, trust_principal={"Service": "ec2.amazonaws.com"},
                                    keymaker_config=keymaker_config)
    if args.instance_iam_role.startswith("arn:") and parse_arn(args.instance_iam_role).account != account_id:
        id_resolver_role = ensure_iam_role(boto3.resource("iam"), args.id_resolver_iam_role,
                                           trust_principal={"AWS": args.instance_iam_role})
        id_resolver_role.attach_policy(PolicyArn=keymaker_policy.arn)

        keymaker_instance_assume_role_statement["Resource"] = id_resolver_role.arn
        keymaker_instance_role_policy["Statement"].append(keymaker_instance_assume_role_statement)
        keymaker_policy = ensure_iam_policy(iam, args.instance_iam_policy, keymaker_instance_role_policy,
                                            description=keymaker_policy_description)
    logger.info("Attaching IAM policy %s to IAM role %s", keymaker_policy, instance_role)
    instance_role.attach_policy(PolicyArn=keymaker_policy.arn)

def parse_keymaker_config(iam_role_description):
    config = {}
    for role_desc_word in re.split("[\s\,]+", iam_role_description or ""):
        if role_desc_word.startswith("keymaker_") and role_desc_word.count("=") == 1:
            config.update([shlex.split(role_desc_word)[0].split("=")])
    return config

def get_assume_role_session(sts, role_arn):
    credentials = sts.assume_role(RoleArn=str(role_arn), RoleSessionName=__name__)["Credentials"]
    return boto3.Session(aws_access_key_id=credentials["AccessKeyId"],
                         aws_secret_access_key=credentials["SecretAccessKey"],
                         aws_session_token=credentials["SessionToken"])

def get_authorized_keys(args):
    session = boto3.Session()
    iam = session.client("iam")
    sts = session.client("sts")
    config = {}
    try:
        role_arn = parse_arn(sts.get_caller_identity()["Arn"])
        _, role_name, instance_id = role_arn.resource.split("/", 2)
        config = parse_keymaker_config(iam.get_role(RoleName=role_name)["Role"]["Description"])
        args.user += config.get('keymaker_linux_user_suffix', default_iam_linux_user_suffix)
    except Exception as e:
        logger.info("No IAM role based configuration found")
    if "keymaker_id_resolver_account" in config:
        id_resolver_role_arn = ARN(service="iam", account=config["keymaker_id_resolver_account"],
                                   resource="role/" + config["keymaker_id_resolver_iam_role"])
        iam = get_assume_role_session(sts, id_resolver_role_arn).client("iam")
    if "keymaker_require_iam_group" in config:
        groups = []
        for page in iam.get_paginator('list_groups_for_user').paginate(UserName=args.user):
            groups.extend([group["GroupName"] for group in page["Groups"]])
        if config["keymaker_require_iam_group"] not in groups:
            err_exit("User {u} is not in group {g}".format(u=args.user, g=config["keymaker_require_iam_group"]))
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
    uid_bytes = hashlib.sha256(aws_key_id.encode()).digest()[-2:]
    if USING_PYTHON2:
        return 2000 + int(from_bytes(uid_bytes) // 2)
    else:
        return 2000 + (int.from_bytes(uid_bytes, byteorder=sys.byteorder) // 2)

def get_uid(args):
    session = boto3.Session()
    iam_caller = session.client("iam")
    sts = session.client("sts")
    config = {}

    try:
        role_arn = parse_arn(sts.get_caller_identity()["Arn"])
        _, role_name, instance_id = role_arn.resource.split("/", 2)
        config = parse_keymaker_config(iam_caller.get_role(RoleName=role_name)["Role"]["Description"])
    except Exception as e:
        logger.info("No IAM role based configuration found")

    if "keymaker_id_resolver_account" in config:
        id_resolver_role_arn = ARN(service="iam", account=config["keymaker_id_resolver_account"],
                                   resource="role/" + config["keymaker_id_resolver_iam_role"])
        iam_resource = get_assume_role_session(sts, id_resolver_role_arn).resource("iam")

    else:
        iam_resource = boto3.resource("iam")

    args.user += config.get('keymaker_linux_user_suffix', default_iam_linux_user_suffix)
    try:
        user_id = iam_resource.User(args.user).user_id
        uid = aws_to_unix_id(user_id)
        print(uid)
    except Exception as e:
        err_exit("Error while retrieving UID for {u}: {e}".format(u=args.user, e=str(e)), code=os.errno.EINVAL)

def get_groups(args):
    session = boto3.Session()
    iam_caller = session.client("iam")
    sts = session.client("sts")
    config = {}
    try:
        role_arn = parse_arn(sts.get_caller_identity()["Arn"])
        _, role_name, instance_id = role_arn.resource.split("/", 2)
        config = parse_keymaker_config(iam_caller.get_role(RoleName=role_name)["Role"]["Description"])
    except Exception as e:
        logger.info("No IAM role based configuration found")
    if "keymaker_id_resolver_account" in config:
        id_resolver_role_arn = ARN(service="iam", account=config["keymaker_id_resolver_account"],
                                   resource="role/" + config["keymaker_id_resolver_iam_role"])
        iam_resource = get_assume_role_session(sts, id_resolver_role_arn).resource("iam")

    else:
        iam_resource = boto3.resource("iam")

    iam_linux_group_prefix = config.get('keymaker_linux_group_prefix', default_iam_linux_group_prefix)
    args.user += config.get('keymaker_linux_user_suffix', default_iam_linux_user_suffix)
    try:
        for group in iam_resource.User(args.user).groups.all():
            if group.name.startswith(iam_linux_group_prefix):
                gid = aws_to_unix_id(group.group_id)  # noqa
                print(group.name[len(iam_linux_group_prefix):])
    except Exception as e:
        msg = "in get groups Error while retrieving UID for {u}: {e}"
        err_exit(msg.format(u=args.user, e=str(e)), code=os.errno.EINVAL)

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

    pam_config_line = "auth optional pam_exec.so stdout /usr/local/bin/keymaker-create-account-for-iam-user"
    with open("/etc/pam.d/sshd") as fh:
        pam_config_lines = fh.read().splitlines()
    if pam_config_line not in pam_config_lines:
        pam_config_lines.insert(1, pam_config_line)
    with open("/etc/pam.d/sshd", "w") as fh:
        for line in pam_config_lines:
            print(line, file=fh)

    with open("/etc/cron.d/keymaker-group-sync", "w") as fh:
        print("*/5 * * * * root /usr/local/bin/keymaker sync_groups", file=fh)

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
                exit(('Multiple keys reported by ssh-add. Please specify a key filename with --identity or unload keys '
                      'with "ssh-add -D", then load the one you want with "ssh-add ~/.ssh/id_rsa" or similar.'))
            return keys[0]
        except subprocess.CalledProcessError:
            default_path = os.path.expanduser("~/.ssh/id_rsa.pub")
            if os.path.exists(default_path):
                msg = 'Using {} as your SSH key. If this is not what you want, specify one with --identity or load it with ssh-add'  # noqa
                logger.warning(msg.format(default_path))
                return load_ssh_public_key(default_path)
            exit(('No keys reported by ssh-add, and no key found in default path. Please run ssh-keygen to generate a '
                  'new key, or load the one you want with "ssh-add ~/.ssh/id_rsa" or similar.'))

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
            logger.error('The current IAM user has filled their public SSH key quota. Delete keys with "keymaker list_keys" and "keymaker delete_key".')  # noqa
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
    return iam.meta.client.update_ssh_public_key(UserName=user.name,
                                                 SSHPublicKeyId=args.ssh_public_key_id,
                                                 Status=status)

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

def is_managed(unix_username):
    try:
        uid = pwd.getpwnam(unix_username).pw_uid
        if uid < 2000:
            raise ValueError(uid)
    except Exception:
        return False
    return True

def sync_groups(args):
    from pwd import getpwnam

    session = boto3.Session()
    iam_caller = session.client("iam")
    sts = session.client("sts")
    config = {}
    try:
        role_arn = parse_arn(sts.get_caller_identity()["Arn"])
        _, role_name, instance_id = role_arn.resource.split("/", 2)
        config = parse_keymaker_config(iam_caller.get_role(RoleName=role_name)["Role"]["Description"])
    except Exception as e:
        logger.warn(str(e))
    if "keymaker_id_resolver_account" in config:
        id_resolver_role_arn = ARN(service="iam", account=config["keymaker_id_resolver_account"],
                                   resource="role/" + config["keymaker_id_resolver_iam_role"])
        iam_resource = get_assume_role_session(sts, id_resolver_role_arn).resource("iam")

    else:
        iam_resource = boto3.resource("iam")

    iam_linux_group_prefix = config.get('keymaker_linux_group_prefix', default_iam_linux_group_prefix)
    iam_linux_user_suffix = config.get('keymaker_linux_user_suffix', default_iam_linux_user_suffix)

    for group in iam_resource.groups.all():
        if not group.name.startswith(iam_linux_group_prefix):
            continue
        logger.info("Syncing IAM group %s", group.name)
        unix_group_name = group.name[len(iam_linux_group_prefix):]
        try:
            unix_group = grp.getgrnam(unix_group_name)
        except KeyError:
            logger.info("Provisioning group %s from IAM", unix_group_name)
            subprocess.check_call(["groupadd", "--gid", str(aws_to_unix_id(group.group_id)), unix_group_name])
            unix_group = grp.getgrnam(unix_group_name)
        user_names_in_iam_group = [user.name[:-len(iam_linux_user_suffix)]
                                   for user in group.users.all()
                                   if user.name.endswith(iam_linux_user_suffix)]
        for user in user_names_in_iam_group:
            user_names_in_iam_group = []
        for user in user_names_in_iam_group:
            if not is_managed(user):
                logger.warn("User %s is not provisioned or not managed by keymaker, skipping", user)
                continue
            if user not in unix_group.gr_mem:
                logger.info("Adding user %s to group %s", user, unix_group_name)
                subprocess.check_call(["usermod", "--append", "--groups", unix_group_name, user])
        for unix_user_name in filter(is_managed, unix_group.gr_mem):
            if unix_user_name not in user_names_in_iam_group:
                logger.info("Removing user %s from group %s", unix_user_name, unix_group_name)
                subprocess.check_call(["gpasswd", "--delete", unix_user_name, unix_group_name])
