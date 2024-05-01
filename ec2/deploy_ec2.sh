#!/bin/bash
set -e

# Retrieve the region
region=${REGION:-"ap-northeast-1"}
# Retrieve the username
user_name=$(aws --region ${region} sts get-caller-identity --query 'Arn' --output text | rev | cut -d/ -f1 | rev | sed -e 's/@.*//')
        
# Retrieve my public IP address
my_ip=$(curl -s https://checkip.amazonaws.com)

# Specify the AMI ID and instance type
ami_id=${AMI_ID:-"ami-0adb3635eb20f395b"}
ami_info=$(aws --region ${region} ec2 describe-images --image-ids "$ami_id" --query 'Images[*].{Platform:Platform,Name:Name}' --output json)

# Determine the OS using the Platform attribute
if echo "$ami_info" | grep -q '"Platform": "windows"'; then
  ami_platform="windows"
  echo "The AMI ID $ami_id is a Windows image."
elif echo "$ami_info" | grep -iq 'linux'; then
  ami_platform="linux"
  echo "The AMI ID $ami_id is a Linux image."
else
  ami_platform="other"
  echo "The OS of AMI ID $ami_id could not be determined or it is not a standard Linux or Windows image."
fi

# Get SSH key pair name
if [[ -n $SSH_KEY ]];then
    ssh_key=$SSH_KEY
else
    default_name=$user_name
    if [[ $ami_platform != windows ]];then
        aws --region $region ec2 describe-key-pairs --query 'KeyPairs[*].KeyName' --output text | tr '\t' '\n' | sort -f
        echo ""
        echo "Please find your SSH key pair name from above list"
        echo -n "Enter your ssh key name [$default_name]: "
        read ssh_key
    fi
    ssh_key=${ssh_key:-$default_name}
fi
timestamp=$(date +%s)

# Set the instance name based on the username
instance_name="${user_name}-${ami_platform}-${timestamp}"

# Create a security group
subnet_id=${SUBNET_ID:-"subnet-099904a6ad96204d6"}
vpc_id=$(aws --region ${region} ec2 describe-subnets --subnet-ids $subnet_id --query 'Subnets[*].VpcId' --output text)
SG_CREATE=$(echo $SG_CREATE | tr '[:upper:]' '[:lower:]')
if [[ -n $SG_CREATE ]] && [[ "${SG_CREATE}" != "false" ]]; then
    sg_id=$(aws --region ${region} ec2 create-security-group --group-name "$instance_name" --description "Security group for SSH and RDP access" --query 'GroupId' --vpc-id "$vpc_id" --output text)
    # Allow SSH access (port 22)
    aws --region ${region} ec2 authorize-security-group-ingress --group-id $sg_id --protocol tcp --port 22 --cidr ${my_ip}/32
    # Allow RDP access (port 3389)
    aws --region ${region} ec2 authorize-security-group-ingress --group-id $sg_id --protocol tcp --port 3389 --cidr ${my_ip}/32
    # Allow ICMP
    aws --region ${region} ec2 authorize-security-group-ingress --group-id $sg_id --protocol icmp --port -1 --cidr ${my_ip}/32
elif [[ -n $SG_ID ]]; then
    sg_id=$SG_ID
else
    sg_id=$(aws --region ${region} ec2 describe-security-groups --filters Name=vpc-id,Values=${vpc_id} Name=group-name,Values='default' --query 'SecurityGroups[0].GroupId' --output text)
fi

hostname="$(echo $instance_name | sed -e 's/\./-/g')"

if [[ $ami_platform != windows ]]; then
    user_data=$(cat <<EOF
#!/bin/bash
echo "ubuntu:Datadog/4u" | sudo chpasswd
sudo sh -c "echo \"$hostname\" >/etc/hostname"
sudo sh -c "hostname \"$hostname\""
EOF
)
elif [[ $ami_platform == windows ]]; then
    user_data=$(cat <<EOF
<powershell>
EOF
)
fi

if [[ -n $DD_VERSION ]];then
    # Remove begining 7.
    dd_version=${DD_VERSION/#7./}
    dd_version=DD_AGENT_MINOR_VERSION=$dd_version
fi
if [[ -n $DD_API_KEY ]] && [[ $ami_platform != windows ]]; then
    echo "Datadog Agent for linux will be installed"
    user_data+=$(cat <<EOF

# Install Datadog Agent
DD_API_KEY=${DD_API_KEY} DD_SITE=\"${DD_SITE:-datadoghq.com}\" bash -c \"\$(curl -L https://s3.amazonaws.com/dd-agent/scripts/install_script_agent7.sh)\""
EOF
)
elif [[ $ami_platform == windows ]]; then
    if [[ -n $DD_API_KEY ]]; then
        echo "Datadog Agent for windows will be installed"
        user_data+=$(cat <<EOF

# Add Datadog Agent/bin to PATH
\$newPath = "C:\Program Files\Datadog\Datadog Agent\bin"
\$currentPath = [System.Environment]::GetEnvironmentVariable("PATH", "Machine")
\$newPath = \$currentPath + ";" + \$newPath
[System.Environment]::SetEnvironmentVariable("PATH", \$newPath, "Machine")

# Install Datadog Agent
${DD_VERSION:+"\$version = \"$DD_VERSION\""}

\$file = "datadog-agent-7-latest.amd64.msi"
if (Test-Path \$file) {
    Remove-Item -Path \$file
}

if (\$version) {
    \$file = "ddagent-cli-\$version.msi"
}

if (-not (Test-Path \$file)) {
    Write-Host "Downloading \$file"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri https://s3.amazonaws.com/ddagent-windows-stable/\$file -OutFile \$file
    Write-Host "Download finished"
}
\$now = (Get-Date).ToString("yyyyMMddHHmmss")
Start-Process -Wait msiexec -ArgumentList "/qn /log C:/\$file.\$now.log /i \$file DDAGENTUSER_NAME=.\\ddagentuser DDAGENTUSER_PASSWORD=ji7689sGHKJUH@ APIKEY=${DD_API_KEY}"
</powershell>
EOF
)
    else
        user_data+=$(cat <<EOF
</powershell>
EOF
)
    fi
fi

instance_type=${INSTANCE_TYPE:-"c5.xlarge"}
# Deploy instance from AMI
instance_id=$(aws --region ${region} ec2 run-instances --image-id $ami_id --instance-type ${instance_type} --security-group-ids $sg_id --subnet-id $subnet_id --key-name "$ssh_key" --count 1 --query 'Instances[0].InstanceId' --output text --user-data "$user_data")

# Set Name tag of instance
aws --region ${region} ec2 create-tags --resources $instance_id --tags Key=Name,Value=$instance_name

# Output the instance name
echo "---------------------------------"
echo "Instance name: ${instance_name}"
echo "Instance ID: ${instance_id}"
echo "VPC ID: ${vpc_id}"
echo "Subnet ID: ${subnet_id}"
echo "Security Group ID: ${sg_id}"
echo "AMI ID: ${ami_id}"
echo "AMI Platform: $ami_platform"
echo "Public IP: $(aws --region $region ec2 describe-instances --instance-ids "${instance_id}" --query 'Reservations[*].Instances[*].PublicIpAddress' --output text 2>/dev/null)"
echo "Private IP: $(aws --region $region ec2 describe-instances --instance-ids "${instance_id}" --query 'Reservations[*].Instances[*].PrivateIpAddress' --output text 2>/dev/null)"
if [[ $ami_platform != windows ]]; then
    echo "User Name: ubuntu or ec2-user"
    echo "RDP Password: Datadog/4u"
elif [[ $ami_platform == windows ]]; then
    echo "User Name: Administrator"
    echo "RDP Password: Check AWS console"
fi
sleep 1
aws_url="https://${region}.console.aws.amazon.com/ec2/home?region=${region}#InstanceDetails:instanceId=${instance_id}"
echo $aws_url
open $aws_url

# Comment for avoiding unknown error
