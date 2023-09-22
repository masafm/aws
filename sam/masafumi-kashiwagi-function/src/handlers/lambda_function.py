import json
import boto3

def lambda_handler(event, context):
    #sqs = boto3.client('sqs')
    #url = 'https://sqs.ap-northeast-1.amazonaws.com/601427279990/masafumi-kashiwagi-sqs'
    #response = sqs.send_message(
    #    QueueUrl=url,
    #    DelaySeconds=0,
    #    MessageBody=(
    #        json.dumps({'message':'test'})
    #    )
    #)
    print("event="+str(event))
    print("context="+str(context))
    return {
        'statusCode': 200,
        'body': json.dumps('Hello from Lambda!')
    }
