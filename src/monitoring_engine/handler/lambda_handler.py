from __future__ import annotations

import json
import os

from monitoring_engine.runner.run_pipeline import run_pipeline
from monitoring_engine.storage.dynamodb_store import save_incidents


def lambda_handler(event, context):
    incidents = run_pipeline()

    table_name = os.environ.get("DYNAMODB_TABLE", "Backdoor-Incidents")
    save_incidents(incidents, table_name)

    return {
        "statusCode": 200,
        "body": json.dumps(
            {
                "message": "pipeline executed",
                "incident_count": len(incidents),
            },
            ensure_ascii=False,
        ),
    }