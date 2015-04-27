import os, sys, json, time, logging

import boto3
from botocore.exceptions import ClientError

cloudtrail = boto3.client("cloudtrail")

logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logging.getLogger("botocore.vendored.requests").setLevel(logging.DEBUG)

iam=boto3.resource("iam")
s3=boto3.resource("s3")
#cloudtrail = boto3.client("cloudtrail")
#sqs=boto3.resource("sqs")
#sqs_client=boto3.client("sqs")

#response = client.create_trail(Name=__name__, S3BucketName=__name__)

"""

> keymaker
Using AWS key: <KEY ID>
Account ID: <ID>
Checking if key has admin privileges... GREEN(OK)
Your account is not configured for use with Keymaker. Exiting.
Your account is not configured for use with Keymaker. Configure now? [y/n] Please answer yes or no.
Configuring account.
Creating S3 bucket "..."... GREEN(OK)
Setting permissions... GREEN(OK)
Done! Next steps:

* Install Keymaker on your hosts with BOLD(keymaker install).
* Upload user SSH credentials with BOLD(keymaker upload).

> keymaker install
> keymaker upload

supervisor run
- ensure bucket/perms

See http://docs.aws.amazon.com/AmazonS3/latest/dev/example-policies-s3.html
{
   "Version":"2012-10-17",
   "Statement":[
      {
         "Effect":"Allow",
         "Action":[
            "s3:PutObject",
            "s3:GetObject",
            "s3:GetObjectVersion",
            "s3:DeleteObject",
            "s3:DeleteObjectVersion"
         ],
         "Resource":"arn:aws:s3:::examplebucket/${aws:username}/*"
      }
   ]
}

- ensure specified or current user has corresponding IAM user
- set bucket policies

client run
- "keymaker upload [--user u] [--public-key id.pub]"
- ensure bucket/perms
- ensure specified or current user has corresponding IAM user
- upload specified or current user pubkey
- set uid (Q: how to make this transactional?)
- Q: How to sync groups?

daemon run
- check bucket/perms or quit
- list all IAM users who have network access to this instance and are in the ssh group
- for each IAM user:
  - create if necessary
  - copy pubkeys to authorized
  - for any pubkey in authorized not in IAM: disable it
  - if userdata contains deny password access option, deny password access?
- for each local user with no IAM user:
  - if in range, issue warning
  - if userdata contains force option, disable user

- write cloudtrail log whenever adding or deleting user/group
- installing daemon via userdata/cloud-init
"""

from collections import namedtuple

class ARN(namedtuple("ARN", "partition service region account resource")):
    def __str__(self):
        return ":".join(["arn"] + list(self))

ARN.__new__.__defaults__ = ("aws", "", "", "", "")

def parse_arn(arn):
    return ARN(*arn.split(":", 5)[1:])

def get_bucket():
    account_id = parse_arn(iam.CurrentUser().arn).account
    bucket = s3.Bucket("{name}-{account}".format(name=__name__, account=account_id))
    bucket.create()
    bucket.wait_until_exists()

    response = cloudtrail.create_trail(Name=__name__, S3BucketName=bucket.name)

    return bucket

def get_group(name="ssh"):
    ssh_group = iam.Group(name)
    try:
        ssh_group.create()
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") != "EntityAlreadyExists":
            raise
    return ssh_group

def build_policy_doc(bucket, prefix="/*", perms="r"):
    actions = []
    if "r" in perms:
        actions.extend(["s3:ListBucket", "s3:GetObject"])
    if "w" in perms:
        actions.extend(["s3:PutObject", "s3:DeleteObject"])
    doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": actions,
                "Resource": [str(ARN(service="s3", resource=bucket.name)),
                             str(ARN(service="s3", resource=bucket.name + prefix))]
            }
        ]
    }
    return json.dumps(doc)

def set_permissions(bucket):
    ssh_admin_group = get_group(name="ssh_admin")
    ssh_admin_group.create_policy(PolicyName="keymaker-ssh-admin",
                                  PolicyDocument=build_policy_doc(bucket, perms="rw"))
    ssh_admin_group.add_user(UserName=iam.CurrentUser().user_name)

    ssh_group = get_group()
    ssh_group.create_policy(PolicyName="keymaker-ssh-group",
                            PolicyDocument=build_policy_doc(bucket, perms="r"))
    for user in iam.users.all():
        ssh_group.add_user(UserName=user.name)
        user.create_policy(PolicyName="keymaker-ssh-user",
                           PolicyDocument=build_policy_doc(bucket, perms="w", prefix="/users/" + user.name))

    # TODO: delete all other policies concerning this bucket - must be done by enumerating all policies for all users/groups?

"""
def set_notifications(bucket):
    queue = sqs_client.create_queue(QueueName="keymaker"

    config = {
        'QueueConfiguration': {
            'Id': STRING,
        'Event': STRING,
        'Events': [
            STRING,
            ...
        ],
        'Queue': STRING
    },
    'CloudFunctionConfiguration': {
        'Id': STRING,
        'Event': STRING,
        'Events': [
            STRING,
            ...
        ],
        'CloudFunction': STRING,
        'InvocationRole': STRING
    }
}
    bn = bucket.Notification().put(config, md5)
"""

def upload_public_key(bucket, user, key_name, key_body):
    return bucket.put_object(Key="/users/{user}/{key}".format(user=user, key=key_name),
                             Body=key_body)

def download_public_key(bucket, user, key_name, key_body):
    return bucket.Object("/users/{user}/{key}".format(user=user, key=key_name)).get()

"""
from datetime import datetime
from dateutil.tz import tzutc
def watch(bucket, interval=5):
    last_checked_at = datetime.fromtimestamp(0, tzutc())
    while True:
        t = datetime.now(tzutc())
        print("Checking", bucket)
        for obj in bucket.objects.filter(Prefix="/"):
            if obj.last_modified > last_checked_at:
                print("Processing", obj)

        last_checked_at = t
        time.sleep(interval)
"""

def install():
    # Check sshd version
    # Create keymaker user, no shell
    # Install /usr/sbin/keymaker-get-public-keys from code literal, set permissions
    # If /etc/ssh/sshd_config already contains AuthorizedKeysCommand, AuthorizedKeysCommandUser:
    # - if values equal, log OK
    # - else log instructions: "Please remove the following directives from /etc/ssh/sshd_config:"
    try:
        pass
        # Back up /etc/ssh/sshd_config
        # Add:
        #AuthorizedKeysCommand /usr/sbin/keymaker-get-public-keys
        #AuthorizedKeysCommandUser keymaker
        # Run sshd -t, set OK
    except:
        pass
        # If not OK: revert to backup copy

#    for i in range(2000):
#        bucket.put_object(Key="/user/penguin/key{}".format(i), Body="foo")

#set_notifications(bucket)
#ec2=boto3.resource('ec2')

# To userdata -> cloud-init: pip3 install keymaker; keymaker install
