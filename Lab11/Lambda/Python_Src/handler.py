# Don't forget, you have to upload this as a zip file. 

import json
import os
import boto3
import uuid
import datetime

secrets = boto3.client("secretsmanager")

def get_db_secret(secret_arn: str) -> dict:
    resp = secrets.get_secret_value(SecretId=secret_arn)
    return json.loads(resp["SecretString"])

def lambda_handler(event, context):
    # 1) Parse input
    body = json.loads(event.get("body") or "{}")
    actor = body.get("actor", "unknown")
    action = body.get("action", "unknown")
    resource = body.get("resource", "unknown")
    note = body.get("note", "")

    # 2) Metadata
    event_id = str(uuid.uuid4())
    ts = datetime.datetime.utcnow().isoformat() + "Z"
    request_id = getattr(context, "aws_request_id", "no-request-id")
    source_ip = (event.get("requestContext", {})
                    .get("http", {})
                    .get("sourceIp", "unknown"))

    # 3) Fetch DB creds from Secrets Manager
    secret_arn = os.environ["DB_SECRET_ARN"]
    db = get_db_secret(secret_arn)

    # 4) Connect to RDS and insert row
    # NOTE: Use psycopg2 for Postgres OR pymysql for MySQL.
    # We will wire this up in the next step (layer/package + SQL).
    #
    # Example insert:
    # INSERT INTO audit_events(id, ts, actor, action, resource, note, source_ip, request_id)
    # VALUES (%s,%s,%s,%s,%s,%s,%s,%s)

    # Placeholder so it runs before we add driver:
    # (Next step we'll add actual DB connection code.)
    return {
        "statusCode": 200,
        "headers": {"content-type": "application/json"},
        "body": json.dumps({
            "ok": True,
            "event_id": event_id,
            "ts": ts,
            "request_id": request_id,
            "actor": actor,
            "action": action,
            "resource": resource
        })
    }