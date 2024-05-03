#!/bin/bash
set -e

function create_rdp_file {
    local rdp_addr=$1
    local rdp_user_name=$2
    local rdp_file=$3
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
    echo "$rdp_file created" 1>&2
}

# Determine the OS using the Platform attribute
function determine_os_platform {
    local ami_info=$(aws --region ${REGION} ec2 describe-images --image-ids "$AMI_ID" --output json)
    if echo "$ami_info" | grep -iq 'windows'; then
        echo "windows"
    elif echo "$ami_info" | grep -iq 'linux'; then
        echo "linux"
    else
        echo "other"
fi
}

function get_current_aws_user {
    aws --region ${REGION} sts get-caller-identity --query 'Arn' --output text | rev | cut -d/ -f1 | rev | sed -e 's/@.*//'
}

function get_ssh_key {
    # Get SSH key pair name
    if [[ -n $SSH_KEY ]];then
        echo $SSH_KEY
    else
        local default_name=$user_name
        local items=$(aws --region $REGION ec2 describe-key-pairs --query 'KeyPairs[*].KeyName' --output text | tr '\t' '\n' | sort -f)
        local default_name_exist=$(echo "$items" | grep "^$default_name$" || true)
        if [[ -n $default_name_exist ]]; then
            items=$(echo "$items" | grep -v "^$default_name$" | sort)
            echo $(echo -e "$default_name\n$items" | fzf --height 30 --header "Select your SSH key name")
        else
            echo $(echo -e "$items" | fzf --height 30 --header "Select your SSH key name")
    fi
fi
}

function get_vpc_id {
    local subnet_id=$1
    echo $(aws --region ${REGION} ec2 describe-subnets --subnet-ids $subnet_id --query 'Subnets[*].VpcId' --output text)
}

function create_security_group {
    local subnet_id=$1
    local vpc_id=$(get_vpc_id $subnet_id)
    # Create a security group
    local sg_id=$(aws --region ${REGION} ec2 create-security-group --group-name "$instance_name" --description "Security group for SSH and RDP access" --query 'GroupId' --vpc-id "$vpc_id" --output text)
    # Allow SSH access (port 22)
    aws --region ${REGION} ec2 authorize-security-group-ingress --group-id $sg_id --protocol tcp --port 22 --cidr ${my_ip}/32 1>&2
    # Allow RDP access (port 3389)
    aws --region ${REGION} ec2 authorize-security-group-ingress --group-id $sg_id --protocol tcp --port 3389 --cidr ${my_ip}/32 1>&2
    # Allow ICMP
    aws --region ${REGION} ec2 authorize-security-group-ingress --group-id $sg_id --protocol icmp --port -1 --cidr ${my_ip}/32 1>&2
    echo $sg_id
}

function get_default_security_group {
    local subnet_id=$1
    local vpc_id=$(get_vpc_id $subnet_id)
    echo $(aws --region ${REGION} ec2 describe-security-groups --filters Name=vpc-id,Values=${vpc_id} Name=group-name,Values='default' --query 'SecurityGroups[0].GroupId' --output text)
}

function get_ami_description {
    echo $(aws ec2 describe-images --image-ids $AMI_ID --region $REGION --query 'Images[*].Description' --output text)
}

function get_linux_default_user {
    ami_info=$(aws ec2 describe-images --image-ids $AMI_ID --region $REGION --query 'Images[*].Description' --output text | tr '[:upper:]' '[:lower:]' | tr -d '[:punct:]' | tr -d '[:space:]')
    if [[ $ami_info == *"amazonlinux"* ]]; then
        echo "ec2-user"
    elif [[ $ami_info == *"ubuntu"* ]]; then
        echo "ubuntu"
    elif [[ $ami_info == *"rhel"* ]]; then
        echo "ec2-user"
    elif [[ $ami_info == *"centos"* ]]; then
        echo "centos"
    elif [[ $ami_info == *"fedora"* ]]; then
        echo "fedora"
    elif [[ $ami_info == *"debian"* ]]; then
        echo "admin"
    elif [[ $ami_info == *"suse"* ]]; then
        echo "ec2-user"
    else
        echo ""
    fi
}

function get_dd_version {
    local dd_versions=$(curl -L https://ddagent-windows-stable.s3.amazonaws.com/installers_v2.json 2>/dev/null | python3 -c "import sys, json, re; print('\n'.join([re.sub(r'-\d+$', '', key) for key in json.load(sys.stdin)['datadog-agent'].keys()]))" | sort -r | grep -e '^7\.')
    if [[ -n $DD_VERSION ]];then
        local dd_version_exists=$(echo "$dd_versions" | grep -e "^${DD_VERSION}\$" || true)
        if [[ -n $dd_version_exists ]];then
            echo $DD_VERSION
        else
            echo "Invalid Datadog Agent version: $DD_VERSION" 1>&2
            echo $(echo "$dd_versions" | fzf --height 30 --header "${DD_VERSION} specified is invalid. Select Datadog Agent version")
        fi
    else
        echo $(echo "$dd_versions" | fzf --height 30 --header "Select Datadog Agent version")
    fi
}

function create_linux_user_data {
    local dd_version_linux=$1
    local dd_api_key=$2
    cat <<EOF
#!/bin/bash -x
echo "$default_user:Datadog/4u" | sudo chpasswd
sudo sh -c "echo \"$hostname\" >/etc/hostname"
sudo sh -c "hostname \"$hostname\""
sudo sh -c "echo '---------------------------------------------------------------------------'>>/etc/motd"
sudo sh -c "echo 'Run \033[1;31mtail -f /var/log/cloud-init-output.log\033[0m for Datadog Agent install status' >> /etc/motd"
sudo sh -c "echo '---------------------------------------------------------------------------'>>/etc/motd"
# Install Datadog Agent
DD_API_KEY=${dd_api_key} DD_SITE="${DD_SITE:-datadoghq.com}" ${dd_version_linux} bash -c "\$(curl -L https://s3.amazonaws.com/dd-agent/scripts/install_script_agent7.sh)"
# end
EOF
}

function create_windows_user_data {
    # Generate random passowrd
    local dd_agentuser_pass="$(openssl rand -base64 12 | tr -cd '[:alnum:]' | cut -c -15)@"
    echo "DDAGENTUSER_PASSWORD is ${dd_agentuser_pass}"
    local dd_version=$1
    cat <<EOF
<powershell>
# Add Datadog Agent/bin to PATH
\$newPath = "C:\Program Files\Datadog\Datadog Agent\bin"
\$currentPath = [System.Environment]::GetEnvironmentVariable("PATH", "Machine")
\$newPath = \$currentPath + ";" + \$newPath
[System.Environment]::SetEnvironmentVariable("PATH", \$newPath, "Machine")

# Install Datadog Agent
${dd_version:+"\$version = \"$dd_version\""}

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
Start-Process -Wait msiexec -ArgumentList "/qn /log C:/\$file.\$now.log /i \$file DDAGENTUSER_NAME=.\\ddagentuser DDAGENTUSER_PASSWORD=${dd_agentuser_pass} SITE=${DD_SITE:-datadoghq.com} APIKEY=${dd_api_key}"
</powershell>
EOF
}

function get_dd_api_key {
    if [[ -n $DD_API_KEY ]];then
        echo $DD_API_KEY
    else
        echo -n "Enter Datadog API key: " 1>&2
        local dd_api_key
        read dd_api_key
        if [[ -z $dd_api_key ]];then
            echo "API key is required!" 1>&2
            exit 1
        else
            echo $dd_api_key
        fi
    fi
}

function deploy_ec2_instance {
    local ssh_key_name=$1
    local sg_id=$2
    # Get root volume device name
    local volume_dev_name=$(aws ec2 describe-images --image-ids $AMI_ID --region $REGION --query 'Images[0].BlockDeviceMappings[0].DeviceName' --output text)
    # Get root volume size
    local volume_dev_size=$(aws ec2 describe-images --image-ids $AMI_ID --region $REGION --query 'Images[0].BlockDeviceMappings[0].Ebs.VolumeSize' --output text)
    if [[ $VOLUME_SIZE -gt $volume_dev_size ]];then
        local update_volume=--block-device-mappings "DeviceName=${volume_dev_name},Ebs={VolumeSize=${VOLUME_SIZE},VolumeType=gp3,DeleteOnTermination=true}"
    fi
    # Deploy instance from AMI
    local instance_id=$(aws --region ${REGION} ec2 run-instances --image-id $AMI_ID --instance-type ${INSTANCE_TYPE} --security-group-ids $sg_id --subnet-id $subnet_id --key-name "$ssh_key_name" --count 1 ${update_volume} --query 'Instances[0].InstanceId' --output text --user-data "$user_data")
    # Set Name tag of instance
    aws --region ${REGION} ec2 create-tags --resources $instance_id --tags Key=Name,Value=$instance_name
    echo $instance_id
}

function get_public_ip {
    local instance_id=$1
    echo $(aws --region $REGION ec2 describe-instances --instance-ids "${instance_id}" --query 'Reservations[*].Instances[*].PublicIpAddress' --output text 2>/dev/null)
}

function get_private_ip {
    local instance_id=$1
    echo $(aws --region $REGION ec2 describe-instances --instance-ids "${instance_id}" --query 'Reservations[*].Instances[*].PrivateIpAddress' --output text 2>/dev/null)
}

function get_windows_password {
    local instance_id=$1
    local secret_file=$2
    local password=""
    local max_attempts=40
    for ((i=1; i<=max_attempts; i++)); do
        local password=$(aws ec2 get-password-data --instance-id "${instance_id}" --priv-launch-key "$secret_file" --query 'PasswordData' --output text)
        # Show progress bar
        local percent=$((i * 100 / max_attempts))
        local bar_len=50
        local bar=$(printf '%*s' $((i*bar_len/max_attempts)) '' | tr ' ' '#')
        printf "\rWait for password generation: [%-${bar_len}s] %d%%" "$bar" "$percent" 1>&2
        if [[ -n $password ]]; then
            break
        fi
        sleep 3
    done
    sleep 3
    # Clear the progress bar by printing spaces and move cursor up
    printf "\r%-120s\r" 1>&2
    echo $password
}

function get_secret_file {
    local ssh_key_name=$1
    local secret_file
    # Check for locally saved pem files
    secret_files=$(find ~ -maxdepth 3 -type f -name "${ssh_key_name}.pem")
    if [[ $(wc -l <<<$secret_files) -gt 1 ]];then
        secret_file=$(fzf --height 10 --header "Select your pem file for ${ssh_key_name}" <<<$secret_files)
    else
        secret_file=$secret_files
    fi
    if [[ -z $secret_file ]] && command -v op &> /dev/null;then
        secret_file=$(mktemp)
        item_title=$(op item list --vault="Private" --format=json | python3 -c "import sys, json; print('\n'.join([item['title'] for item in json.load(sys.stdin)]))" | fzf --height 30 --header "Select your 1Password item for ${ssh_key_name} ssh key pair")
        op item get "$item_title" --fields "RSA PRIVATE KEY" | sed -e 's/"//g' >$secret_file
    fi
    echo $secret_file
}

function open_aws_console_page {
    local open_url
    local aws_url="https://${REGION}.console.aws.amazon.com/ec2/home?region=${REGION}#InstanceDetails:instanceId=${instance_id}"
    echo -n "Open $aws_url ? [y/N]: " 1>&2
    read open_url
    open_url=${open_url:-"no"}
    if [[ "${open_url,,}" == "y"* ]]; then
        open $aws_url
    fi
}

function ssh_to_host {
    local username=$1
    local addr=$2
    local ssh_key_name=$3
    local secret=$(get_secret_file "$ssh_key_name")
    local ssh_opts=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null)
    local ssh_cmd=(ssh "${ssh_opts[@]}" "${username}@${addr}")

    if [[ -n $secret ]]; then
        ssh_cmd+=(-i "$secret")
    fi

    echo "Exec: ${ssh_cmd[*]}" 1>&2
    local ssh_avail=""
    local max_attempts=40
    for ((i=1; i<=max_attempts; i++)); do
        ssh_avail=$(echo test | nc -G2 $addr 22 || true)
        # Show progress bar
        local percent=$((i * 100 / max_attempts))
        local bar_len=50
        local bar=$(printf '%*s' $((i*bar_len/max_attempts)) '' | tr ' ' '#')
        printf "\rWait for ssh availability: [%-${bar_len}s] %d%%" "$bar" "$percent" 1>&2
        if [[ -n $ssh_avail ]]; then
            break
        fi
        sleep 1
    done
    sleep 3
    # Clear the progress bar by printing spaces and move cursor up
    printf "\r%-120s\r" 1>&2
    "${ssh_cmd[@]}"
}

function main {
    # Install fzf command if not installed
    if ! command -v fzf &> /dev/null ;then
        echo "fzf command is required. Installing it."
        brew update && brew install fzf
    fi
    
    # Global variables
    ## AWS region
    REGION=${REGION:-"ap-northeast-1"}
    ## Amazon machine image ID
    AMI_ID=${AMI_ID:-"ami-0485f90cce0eb4c17"}
    ## Volume size of root volume
    VOLUME_SIZE=${VOLUME_SIZE:-"100"}
    ## Instance Type
    INSTANCE_TYPE=${INSTANCE_TYPE:-"c5.xlarge"}
    
    # Retrieve the username
    local user_name=$(get_current_aws_user)
    # Retrieve my public IP address
    local my_ip=$(curl -s https://checkip.amazonaws.com)
    local ami_platform=$(determine_os_platform $AMI_ID)
    echo "The AMI ID $AMI_ID platform is ${ami_platform}."
    local ssh_key_name=$(get_ssh_key)
    local timestamp=$(date +%Y%m%d-%H%M%S)
    # Set the instance name based on the username
    local instance_name="${user_name}-${ami_platform}-${timestamp}"

    local subnet_id
    if [[ $user_name == masafumi.kashiwagi ]];then
        subnet_id=${SUBNET_ID:-"subnet-099904a6ad96204d6"}
    else
        subnet_id=${SUBNET_ID:-"subnet-8a85c0a2"}
    fi

    # SG_CREATE default is false/no
    if [[ -z $SG_CREATE ]];then
        echo -n "Create new security group? If not create, default security group will be used. [y/N]: "
        read SG_CREATE
        SG_CREATE=${SG_CREATE:-"false"}
    fi
    local sg_id
    if [[ -n $SG_ID ]];then
        sg_id=$SG_ID
    elif [[ "${SG_CREATE,,}" == "t"* ]] || [[ "${SG_CREATE,,}" == "y"* ]]; then
        # If user wanto to create a new security group
        sg_id=$(create_security_group $subnet_id)
    else
        sg_id=$(get_default_security_group $subnet_id)
    fi

    local dd_version=$(get_dd_version)
    local dd_version_linux=${dd_version/#7./}
    dd_version_linux="DD_AGENT_MINOR_VERSION=$dd_version_linux"
    local dd_api_key=$(get_dd_api_key)
    local hostname="$(echo $instance_name | sed -e 's/\./-/g')"

    # Create uesr data script
    local user_data
    if [[ $ami_platform != windows ]]; then
        echo "Datadog Agent for linux will be installed"
        # Check default user name for linux instance
        local default_user=$(get_linux_default_user $AMI_ID)
        if [[ -n $default_user ]];then
            echo "Default user for AMI $AMI_ID is likely: $default_user"
        else
            echo "Default user for AMI $AMI_ID not found!"
            echo "Please check below AWS page"
            echo "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/managing-users.html#ami-default-user-names"
            exit 1
        fi
        user_data=$(create_linux_user_data $dd_version_linux $dd_api_key)
    elif [[ $ami_platform == windows ]]; then
        echo "Datadog Agent for windows will be installed"
        user_data=$(create_windows_user_data $dd_version)
    fi

    # Deploy Instance
    local instance_id=$(deploy_ec2_instance "$ssh_key_name" "$sg_id")

    # Output the instance name
    echo "---------------------------------"
    echo "Datadog Agent version: ${dd_version}"
    echo "Instance name: ${instance_name}"
    echo "Instance ID: ${instance_id}"
    echo "VPC ID: $(get_vpc_id $subnet_id)"
    echo "Subnet ID: ${subnet_id}"
    echo "Security Group ID: ${sg_id}"
    echo "AMI ID: ${AMI_ID}"
    echo "AMI Description: $(get_ami_description)"
    echo "AMI Platform: $ami_platform"
    local public_ip=$(get_public_ip $instance_id)
    local private_ip=$(get_private_ip $instance_id)
    echo "Public IP: $public_ip"
    echo "Private IP: $private_ip"

    if [[ $ami_platform != windows ]]; then
        echo "User Name: $default_user"
        echo "Password: Datadog/4u"
    elif [[ $ami_platform == windows ]]; then
        echo "User Name: Administrator"
        local secret_file=$(get_secret_file "$ssh_key_name")
        echo "pem file for Windows password decryption: $secret_file"
        local password=$(get_windows_password $instance_id "$secret_file")
        printf "Password: "
        echo "${password}"
        echo -n "${password}" | pbcopy
    fi

    open_aws_console_page

    if [[ $ami_platform != windows ]]; then
        echo -n "SSH to private IP(${private_ip}) ? [y/N]: "
        local do_ssh
        read do_ssh
        do_ssh=${do_ssh:-"no"}
        if [[ "${do_ssh,,}" == "y"* ]]; then
            ssh_to_host $default_user $private_ip "$ssh_key_name"
            exit 0
        fi
        echo -n "SSH to public IP(${public_ip}) ? [y/N]: "
        read do_ssh
        do_ssh=${do_ssh:-"no"}
        if [[ "${do_ssh,,}" == "y"* ]]; then
            ssh_to_host $default_user $public_ip "$ssh_key_name"
        fi
    elif [[ $ami_platform == windows ]]; then
        echo -n "Open RDP to private IP(${private_ip})? [y/N]: "
        local do_rdp rdp_file
        read do_rdp
        do_rdp=${do_rdp:-"no"}
        if [[ "${do_rdp,,}" == "y"* ]]; then
            rdp_file=~/Downloads/${hostname}-${private_ip}.rdp
            create_rdp_file "$private_ip" "Administrator" "$rdp_file"
            open $rdp_file
        fi    
        echo -n "Open RDP to public IP(${public_ip})? [y/N]: "
        read do_rdp
        do_rdp=${do_rdp:-"no"}
        if [[ "${do_rdp,,}" == "y"* ]]; then
            rdp_file=~/Downloads/${hostname}-${public_ip}.rdp
            create_rdp_file "$public_ip" "Administrator" "$rdp_file"
            open $rdp_file
        fi
    fi
}

main
# Comment for avoiding unknown error
