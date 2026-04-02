import json
import os

from monitoring_engine.runner.run_pipeline import run_pipeline
from monitoring_engine.storage.dynamodb_store import save_incidents


def lambda_handler(event, context):
    incidents = run_pipeline()

    normalized = []
    for inc in incidents:
        if isinstance(inc, dict):
            normalized.append(inc)

    table_name = os.environ["DYNAMODB_TABLE"]
    save_incidents(normalized, table_name)

    return {
        "statusCode": 200,
        "body": json.dumps(
            {
                "message": "pipeline executed",
                "incident_count": len(normalized),
            },
            ensure_ascii=False,
        ),
    }