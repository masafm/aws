# Datadog Serverless Macro
How to deploy
```
aws cloudformation create-stack --stack-name datadog-serverless-macro-masafumi-kashiwagi --template-body file://v0.8.0.yaml --capabilities CAPABILITY_AUTO_EXPAND CAPABILITY_IAM
```
How to update
```
aws cloudformation update-stack --stack-name datadog-serverless-macro-masafumi-kashiwagi --template-body file://v0.8.0.yaml --capabilities CAPABILITY_AUTO_EXPAND CAPABILITY_IAM
```
