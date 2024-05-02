#!/bin/bash
set -e

function create_rdp_file {
    rdp_addr=$1
    rdp_user_name=$2
    rdp_file=$3
    cat <<EOF >$rdp_file
smart sizing:i:1
armpath:s:
enablerdsaadauth:i:0
targetisaadjoined:i:0
hubdiscoverygeourl:s:
redirected video capture encoding quality:i:0
camerastoredirect:s:
gatewaybrokeringtype:i:0
use redirection server name:i:0
alternate shell:s:
disable themes:i:0
geo:s:
disable cursor setting:i:1
remoteapplicationname:s:
resourceprovider:s:
disable menu anims:i:1
remoteapplicationcmdline:s:
promptcredentialonce:i:0
gatewaycertificatelogonauthority:s:
audiocapturemode:i:0
prompt for credentials on client:i:0
allowed security protocols:s:*
gatewayhostname:s:
remoteapplicationprogram:s:
gatewayusagemethod:i:2
screen mode id:i:1
use multimon:i:0
authentication level:i:2
desktopwidth:i:0
desktopheight:i:0
redirectsmartcards:i:1
redirectclipboard:i:1
forcehidpioptimizations:i:1
drivestoredirect:s:
loadbalanceinfo:s:
networkautodetect:i:1
enablecredsspsupport:i:1
redirectprinters:i:1
autoreconnection enabled:i:1
session bpp:i:32
administrative session:i:0
audiomode:i:0
bandwidthautodetect:i:1
authoring tool:s:
connection type:i:7
remoteapplicationmode:i:0
disable full window drag:i:0
gatewayusername:s:
dynamic resolution:i:1
shell working directory:s:
wvd endpoint pool:s:
remoteapplicationappid:s:
allow font smoothing:i:1
connect to console:i:0
disable wallpaper:i:0
gatewayaccesstoken:s:
auto connect:i:1
full address:s:${rdp_addr}
username:s:${rdp_user_name}
EOF
}

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
    items=$(aws --region $region ec2 describe-key-pairs --query 'KeyPairs[*].KeyName' --output text | tr '\t' '\n' | sort -f)
    default_name_exist=$(echo "$items" | grep "^$default_name$" || true)
    if [[ -n $default_name_exist ]]; then
        items=$(echo "$items" | grep -v "^$default_name$" | sort)
        ssh_key=$(echo -e "$default_name\n$items" | fzf --header "Select your SSH key name")
    else
        ssh_key=$(echo -e "$items" | fzf --header "Select your SSH key name")
    fi
fi

timestamp=$(date +%Y%m%d%H%M%S)

# Set the instance name based on the username
instance_name="${user_name}-${ami_platform}-${timestamp}"

# Create a security group
if [[ $user_name == masafumi.kashiwagi ]];then
    subnet_id=${SUBNET_ID:-"subnet-099904a6ad96204d6"}
else
    subnet_id=${SUBNET_ID:-"subnet-8a85c0a2"}
fi
vpc_id=$(aws --region ${region} ec2 describe-subnets --subnet-ids $subnet_id --query 'Subnets[*].VpcId' --output text)
if [[ -z $SG_CREATE ]];then
    echo -n "Create new security group? [y/N]: "
    sg_create_def=no
    read sg_create
    sg_create=${sg_create:-$sg_create_def}
elif [[ -n $SG_CREATE ]] && [[ "${SG_CREATE,,}" == "f"* ]]; then
    sg_create=no
elif [[ -n $SG_CREATE ]] && [[ "${SG_CREATE,,}" == "t"* ]]; then
    sg_create=yes
fi
if [[ "${sg_create,,}" == "y"* ]]; then
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
    ami_info=$(aws ec2 describe-images --image-ids $ami_id --region $region --query 'Images[*].Description' --output text | tr '[:upper:]' '[:lower:]' | tr -d '[:punct:]' | tr -d '[:space:]')
    echo "AMI Description: $ami_info"
    if [[ $ami_info == *"amazonlinux"* ]]; then
        default_user="ec2-user"
    elif [[ $ami_info == *"ubuntu"* ]]; then
        default_user="ubuntu"
    elif [[ $ami_info == *"rhel"* ]]; then
        default_user="ec2-user"
    elif [[ $ami_info == *"centos"* ]]; then
        default_user="centos"
    elif [[ $ami_info == *"fedora"* ]]; then
        default_user="fedora"
    elif [[ $ami_info == *"debian"* ]]; then
        default_user="admin"
    elif [[ $ami_info == *"suse"* ]]; then
        default_user="ec2-user"
    else
        default_user="unknown"
    fi
    echo "Default user for AMI $ami_id is likely: $default_user"
    user_data=$(cat <<EOF
#!/bin/bash -x
echo "$default_user:Datadog/4u" | sudo chpasswd
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

dd_versions=$(curl -L https://ddagent-windows-stable.s3.amazonaws.com/installers_v2.json 2>/dev/null | python3 -c "import sys, json, re; print('\n'.join([re.sub(r'-\d+$', '', key) for key in json.load(sys.stdin)['datadog-agent'].keys()]))" | sort -r | grep -e '^7\.')
if [[ -n $DD_VERSION ]];then
    # Remove begining 7.
    dd_version=$DD_VERSION
    dd_minor_version=${dd_version/#7./}
    dd_minor_version=DD_AGENT_MINOR_VERSION=$dd_minor_version
    dd_version_exists=$(echo "$dd_versions" | grep $dd_version || true)
    if [[ -z $dd_version_exists ]];then
        echo "Invalid Datadog Agent version: $DD_VERSION"
        echo "$dd_versions" | grep -e '7\..*-'
        exit 1
    fi
else
    dd_version=$(echo "$dd_versions" | fzf --header "Datadog Agent version")
    dd_minor_version=${dd_version/#7./}
    dd_minor_version=DD_AGENT_MINOR_VERSION=$dd_minor_version
fi

if [[ -n $DD_API_KEY ]];then
    dd_api_key=$DD_API_KEY
else
    echo -n "Enter Datadog API key: "
    read dd_api_key
    if [[ -z $dd_api_key ]];then
        echo "API key is required!"
        exit 1
    fi
fi

if [[ $ami_platform != windows ]]; then
    echo "Datadog Agent for linux will be installed"
    user_data+=$(cat <<EOF

# Install Datadog Agent
DD_API_KEY=${dd_api_key} DD_SITE="${DD_SITE:-datadoghq.com}" ${dd_minor_version} bash -c "\$(curl -L https://s3.amazonaws.com/dd-agent/scripts/install_script_agent7.sh)"
# end
EOF
)
elif [[ $ami_platform == windows ]]; then
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
Start-Process -Wait msiexec -ArgumentList "/qn /log C:/\$file.\$now.log /i \$file DDAGENTUSER_NAME=.\\ddagentuser DDAGENTUSER_PASSWORD=ji7689sGHKJUH@ APIKEY=${dd_api_key}"
</powershell>
EOF
)
else
    user_data+=$(cat <<EOF
</powershell>
EOF
)
fi

# Get root volume
volume_dev_name=$(aws ec2 describe-images --image-ids $ami_id --region $region --query 'Images[0].BlockDeviceMappings[0].DeviceName' --output text)
volume_size=${VOLUME_SIZE:-"100"}

instance_type=${INSTANCE_TYPE:-"c5.xlarge"}
# Deploy instance from AMI
instance_id=$(aws --region ${region} ec2 run-instances --image-id $ami_id --instance-type ${instance_type} --security-group-ids $sg_id --subnet-id $subnet_id --key-name "$ssh_key" --count 1 --block-device-mappings "DeviceName=${volume_dev_name},Ebs={VolumeSize=${volume_size},VolumeType=gp3,DeleteOnTermination=true}" --query 'Instances[0].InstanceId' --output text --user-data "$user_data")

# Set Name tag of instance
aws --region ${region} ec2 create-tags --resources $instance_id --tags Key=Name,Value=$instance_name

# Output the instance name
echo "---------------------------------"
echo "Datadog Agent version: ${dd_version}"
echo "Instance name: ${instance_name}"
echo "Instance ID: ${instance_id}"
echo "VPC ID: ${vpc_id}"
echo "Subnet ID: ${subnet_id}"
echo "Security Group ID: ${sg_id}"
echo "AMI ID: ${ami_id}"
echo "AMI Platform: $ami_platform"
public_ip=$(aws --region $region ec2 describe-instances --instance-ids "${instance_id}" --query 'Reservations[*].Instances[*].PublicIpAddress' --output text 2>/dev/null)
private_ip=$(aws --region $region ec2 describe-instances --instance-ids "${instance_id}" --query 'Reservations[*].Instances[*].PrivateIpAddress' --output text 2>/dev/null)
echo "Public IP: $public_ip"
echo "Private IP: $private_ip"
if [[ $ami_platform != windows ]]; then
    echo "User Name: $default_user"
    echo "Password: Datadog/4u"
elif [[ $ami_platform == windows ]]; then
    echo "User Name: Administrator"
    temp_file=$(mktemp)
    op item get "AWS ap-northeast-1" --fields "RSA PRIVATE KEY" | sed -e 's/"//g' >$temp_file
    password=""
    max_attempts=40
    for ((i=1; i<=max_attempts; i++)); do
        password=$(aws ec2 get-password-data --instance-id "${instance_id}" --priv-launch-key "$temp_file" --query 'PasswordData' --output text)
        # Show progress bar
        percent=$((i * 100 / max_attempts))
        bar=$(printf '%*s' $((i*40/max_attempts)) '' | tr ' ' '#')
        printf "\rWait for password generation: [%-50s] %d%%" "$bar" "$percent"
        if [[ -n $password ]]; then
            # Clear the progress bar by printing spaces and move cursor up
            printf "\r%-120s\r"
            # Optional: Move cursor up to overwrite the progress line
            echo -ne "\033[1A"  # Move cursor up one line
            break
        fi
        sleep 3
    done
    printf "\rPassword: "
    echo "${password}"
    echo -n "${password}" | pbcopy
    rm -f "$temp_file"
fi

aws_url="https://${region}.console.aws.amazon.com/ec2/home?region=${region}#InstanceDetails:instanceId=${instance_id}"
echo -n "Open $aws_url ? [y/N]: "
read open_url
open_url=${open_url:-"no"}
if [[ "${open_url,,}" == "y"* ]]; then
    open $aws_url
fi

if [[ $ami_platform != windows ]]; then
    echo -n "SSH to private IP(${private_ip}) ? [y/N]: "
    read ssh_yes_no
    ssh_yes_no=${ssh_yes_no:-"no"}
    if [[ "${ssh_yes_no,,}" == "y"* ]]; then
        echo "Exec: ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ${default_user}@${private_ip}"
        booted=""
        while [[ -z $booted ]];do
            echo "Wait for booting"
            sleep 1
            booted=$(echo test | nc $private_ip 22 || true)
        done
        ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ${default_user}@${private_ip}
    fi
    if [[ "${ssh_yes_no,,}" == "y"* ]]; then
        exit 0
    fi
    echo -n "SSH to public IP(${public_ip}) ? [y/N]: "
    read ssh_yes_no
    ssh_yes_no=${ssh_yes_no:-"no"}
    if [[ "${ssh_yes_no,,}" == "y"* ]]; then
        echo "Exec: ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ${default_user}@${public_ip}"
        while [[ -z $booted ]];do
            echo "Wait for booting"
            sleep 1
            booted=$(echo test | nc $public_ip 22 || true)
        done
        ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ${default_user}@${public_ip}
    fi
elif [[ $ami_platform == windows ]]; then
    echo -n "Open RDP to private IP(${private_ip})? [y/N]: "
    read rdp_yes_no
    rdp_yes_no=${rdp_yes_no:-"no"}
    if [[ "${rdp_yes_no,,}" == "y"* ]]; then
        rdp_file=~/Downloads/${hostname}-${private_ip}.rdp
        create_rdp_file "$private_ip" "Administrator" "$rdp_file"
        open $rdp_file
    fi    
    echo -n "Open RDP to public IP(${public_ip})? [y/N]: "
    read rdp_yes_no
    rdp_yes_no=${rdp_yes_no:-"no"}
    if [[ "${rdp_yes_no,,}" == "y"* ]]; then
        rdp_file=~/Downloads/${hostname}-${public_ip}.rdp
        create_rdp_file "$public_ip" "Administrator" "$rdp_file"
        open $rdp_file
    fi
fi
# Comment for avoiding unknown error
