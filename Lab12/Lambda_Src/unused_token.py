from datetime import datetime, timedelta
import boto3
import json

def lambda_handler(event, context):
    dynamodb = boto3.resource("dynamodb")
    table = dynamodb.Table("waf-correlation-findings")

    response = table.scan()

    alerts = []

    for item in response["Items"]:

        if item["used"] is False:

            issued = datetime.fromisoformat(item["issued_at"])

            if datetime.utcnow() - issued > timedelta(minutes=2):

                message = f"ALERT: Token unused for user {item['username']}"
                print(message)
                alerts.append(message)

    # if alerts:
    #     prompt = "\n".join(alerts)

    #     bedrock = boto3.client("bedrock-runtime")

    #     bedrock_response = bedrock.invoke_model(
    #         modelId="anthropic.claude-v2",
    #         body=json.dumps({
    #             "prompt": f"\n\nHuman: Summarize these security alerts:\n{prompt}\n\nAssistant:",
    #             "max_tokens_to_sample": 300
    #         })
    #     )

    #     result = json.loads(bedrock_response["body"].read())
    #     print(result)

    return {
        "statusCode": 200,
        "body": json.dumps("Token scan completed")
    }

    bedrock = boto3.client("bedrock-runtime")
    
    response = bedrock.invoke_model(
        modelId="anthropic.claude-v4.6",
        body=json.dumps({
            "prompt": prompt,
            "max_tokens_to_sample": 300
        })
    )