# Contains draft code for S3-based policy data synchronization.
# This code is UNUSED and likely to be deleted in a future release.

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
