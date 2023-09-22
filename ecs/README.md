# ecs
commands
```
# EC2 ECSの場合はUIからクラスター作る方が簡単
# aws ecs create-cluster --cluster-name masafumi-kashiwagi-ecs-cluster
aws ecs register-task-definition --cli-input-json "$(sed -e s/{DD_API_KEY}/${DD_API_KEY}/ -e s/{AWS_ACCOUNT_ID}/123456789123/ datadog-agent-ecs-fargate.json)"
# aws ecs create-service --cluster masafumi-kashiwagi-ecs-cluster --task-definition masafumi-kashiwagi-ecs-fargate --enable-execute-command --service-name my-service --desired-count 1
# UIからサービス作る方が簡単
aws ecs update-service --cluster masafumi-kashiwagi-ecs-cluster --service my-service --enable-execute-command
# execute-commandするには､一回Taskストップしてつくりなおすひつようあり 
```
