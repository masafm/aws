# Datadog Serverless Macro
How to deploy
```
aws cloudformation create-stack --stack-name datadog-serverless-macro-masafumi-kashiwagi --template-body file://v0.8.0.yaml --capabilities CAPABILITY_AUTO_EXPAND CAPABILITY_IAM --parameters ParameterKey=FunctionName,ParameterValue=DatadogServerlessMacroLambdaMasafumiKashiwagi
```
or
```
aws cloudformation create-stack \
  --stack-name datadog-serverless-macro-masafumi-kashiwagi \
  --template-url https://datadog-cloudformation-template.s3.amazonaws.com/aws/serverless-macro/latest.yml \
  --capabilities CAPABILITY_AUTO_EXPAND CAPABILITY_IAM \
  --parameters ParameterKey=FunctionName,ParameterValue=DatadogServerlessMacroLambdaMasafumiKashiwagi
```
How to update
```
aws cloudformation update-stack --stack-name datadog-serverless-macro-masafumi-kashiwagi --template-body file://v0.8.0.yaml --capabilities CAPABILITY_AUTO_EXPAND CAPABILITY_IAM --parameters ParameterKey=FunctionName,ParameterValue=DatadogServerlessMacroLambdaMasafumiKashiwagi
```
