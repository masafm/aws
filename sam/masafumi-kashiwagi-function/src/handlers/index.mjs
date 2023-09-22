import { SendMessageCommand, SQSClient } from "@aws-sdk/client-sqs";
const client = new SQSClient({});

//const my_func = require("test"); //for *.js
import { my_func } from "test/index.mjs";

export const handler = async (event) => {
  console.log(my_func());
  const command = new SendMessageCommand({
    QueueUrl: process.env.SQS_QUEUE_URL,
    DelaySeconds: 10,
    MessageAttributes: {},
    MessageBody:
      "Test",
  });
  const sqs_response = await client.send(command);
  console.log(sqs_response);
  console.log("DEBUG: "+JSON.stringify(event))
  const response = {
    statusCode: 200,
    body: JSON.stringify('Hello from Lambda!'),
  };
  return response;
};
