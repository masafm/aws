#!/bin/bash
set -e         # Stop script when error happened
set -o nounset # Don't accept undefined variables

function select_region() {
    # Try to get the default region from AWS CLI configuration
    local default_region=$(aws configure get region 2>/dev/null)
    
    if [[ -z "$default_region" ]]; then
        echo "No default region is configured." >&2
    else
        echo "Default region detected: $default_region" >&2
    fi

    # Get available regions dynamically using AWS CLI
    local regions=$(aws ec2 describe-regions --query "Regions[?OptInStatus=='opt-in-not-required'].[RegionName,OptInStatus]" --output text)
    echo "Fetching available AWS regions..." >&2

    # Format fetched regions for display
    local region_info=""
    local default_region_info=""
    while read -r line; do
        local region_name=$(echo $line | awk '{print $1}')
        local description=""

        # Assign descriptions based on region names
        case $region_name in
            ap-northeast-1) description="Tokyo" ;;
            ap-northeast-2) description="Seoul" ;;
            ap-southeast-1) description="Singapore" ;;
            ap-southeast-2) description="Sydney" ;;
            ap-northeast-3) description="Osaka" ;;
            us-east-1) description="N. Virginia" ;;
            us-west-1) description="N. California" ;;
            eu-west-1) description="Ireland" ;;
            eu-central-1) description="Frankfurt" ;;
            *)
                description="Other region"
                ;;
        esac

        # Append the default region to the top of the list if it exists
        if [[ "$region_name" == "$default_region" ]]; then
            default_region_info="$region_name ($description) - Default\n"
        else
            region_info+="$region_name ($description)\n"
        fi
    done <<< "$regions"

    # Use fzf to select a region, placing the default region at the top if it exists
    local selected_region=$(echo -e "$default_region_info$region_info" | fzf --height 20 --header "Select AWS Region" | awk '{print $1}')
    echo $selected_region
}

function fetch_public_subnet_security_group_ids() {
    local region="${REGION}"

    # Get the default VPC ID
    local default_vpc_id=$(aws ec2 describe-vpcs --region "$region" --filters "Name=is-default,Values=true" --query "Vpcs[0].VpcId" --output text 2>&1)
    echo "Default VPC ID: $default_vpc_id" >&2

    # Validate if default VPC ID was found
    if [[ $default_vpc_id == "None" || -z $default_vpc_id ]]; then
        echo "No default VPC found." >&2
        return 1
    fi

    # Find subnets in the default VPC where Auto-assign public IPv4 is enabled
    local subnet_ids=($(aws ec2 describe-subnets --region "$region" --filters "Name=vpc-id,Values=$default_vpc_id" "Name=map-public-ip-on-launch,Values=true" --query "Subnets[*].SubnetId" --output text 2>&1))

    # Check if any subnet IDs were found
    if [[ ${#subnet_ids[@]} -eq 0 ]]; then
        echo "No subnets with auto-assign public IPv4 found in the default VPC." >&2
        return 1
    fi

    echo "Subnet IDs with auto-assign public IPv4: ${subnet_ids[*]}" >&2

    # Shuffle subnet IDs and process each one
    local shuffled_ids=($(shuf -e "${subnet_ids[@]}"))
    for subnet_id in "${shuffled_ids[@]}"; do
        local is_public=$(aws ec2 describe-subnets --region "$region" --subnet-ids "$subnet_id" --query 'Subnets[].MapPublicIpOnLaunch' --output text 2>&1)
        if [[ "${is_public,,}" == "true" ]]; then
            echo "$subnet_id"
            break
        fi
    done
}

function search_amis() {
    local preferred_ami_id="$1"
    local ami_info=""
    local all_amis=""
    local amis filter os temp_file

    # Create a temporary directory to store output files
    local temp_dir=$(mktemp -d)
    
    # Get the AWS account ID of the current user
    local owner_id=$(aws --region ${REGION} sts get-caller-identity --query "Account" --output text)

    # Check if a preferred AMI ID is provided and valid
    if [[ -n "$preferred_ami_id" ]]; then
        ami_info=$(aws --region ${REGION} ec2 describe-images --image-ids "$preferred_ami_id" --query "Images[*].[ImageId,Name,Description]" --output text)
        if [[ -n "$ami_info" ]]; then
            echo "Fetching details for preferred AMI ID: $preferred_ami_id..." >&2
            # Prepend preferred AMI info
            echo "$ami_info" > "$temp_dir/preferred_ami"
        fi
    fi

    declare -A os_filters=(
        ["Ubuntu"]="Name=owner-id,Values=099720109477 Name=name,Values=ubuntu/images/hvm-ssd/ubuntu-*-amd64-server-* Name=architecture,Values=x86_64"
        ["RHEL"]="Name=owner-id,Values=309956199498 Name=name,Values=RHEL-* Name=architecture,Values=x86_64"
        ["AmazonLinux"]="Name=owner-id,Values=137112412989 Name=name,Values=amzn2-ami-hvm-2.0.*-gp2 Name=architecture,Values=x86_64"
        ["Windows"]="Name=owner-id,Values=801119661308 Name=name,Values=Windows_Server-*-*-Full-Base-* Name=architecture,Values=x86_64"
        ["SUSE"]="Name=owner-id,Values=013907871322 Name=name,Values=suse-sles-15-sp1-v*-hvm-ssd-x86_64 Name=architecture,Values=x86_64"
        ["Debian"]="Name=owner-id,Values=379101102735 Name=name,Values=debian-10-amd64-hvm-* Name=architecture,Values=x86_64"
    )

    # Fetch official AMIs in background
    for os in "${!os_filters[@]}"; do
        filter="${os_filters[$os]}"
        temp_file="$temp_dir/$os"
        echo "Fetching AMI information for $os..." >&2
        (aws --region ${REGION} ec2 describe-images --filters $filter --query "Images[*].[ImageId,Name,Description]" --output text > "$temp_file") &
    done

    # Fetch user-defined AMIs
    temp_file="$temp_dir/user_defined_amis"
    echo "Fetching user-defined AMIs..." >&2
    (aws --region ${REGION} ec2 describe-images --owners "$owner_id" --query "Images[*].[ImageId,Name,Description]" --output text > "$temp_file") &

    # Wait for all background processes to complete
    wait

    # Merge all results
    for file in $(ls "$temp_dir"); do
        cat "$temp_dir/$file" >> "$temp_dir/all_amis"
    done

    # Display the AMIs in fzf, with the preferred AMI (if any) at the top
    cat "$temp_dir/all_amis" | awk -F '\t' '{printf "%-20s %-50s %-80s\n", $1, $2, $3}' | fzf --header "Select an AMI" | cut -f1 -d' '

    # Clean up
    rm -r "$temp_dir"
}


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
    if [[ -n $SSH_KEY_PAIR_NAME ]];then
        echo $SSH_KEY_PAIR_NAME
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

function ensure_security_group {
    local subnet_id=$1
    local vpc_id=$(get_vpc_id $subnet_id)
    local sg_name="${user_name}-${subnet_id}"
    
    # Check if the security group already exists
    local sg_id=$(aws --region ${REGION} ec2 describe-security-groups \
                   --filters Name=vpc-id,Values="$vpc_id" Name=group-name,Values="$sg_name" \
                   --query 'SecurityGroups[0].GroupId' --output text)
    
    # If security group does not exist, create it
    if [[ $sg_id == "None" ]]; then
        echo "Creating new security group..." >&2
        sg_id=$(aws --region ${REGION} ec2 create-security-group \
                      --group-name "$sg_name" --description "Security group for SSH and RDP access" \
                      --vpc-id "$vpc_id" --query 'GroupId' --output text)
    else
        echo "Security group $sg_name already exists with ID $sg_id." >&2
    fi
    
    # Update rules: Ensure SSH, RDP and ICMP are allowed (idempotent operations)
    echo "Updating security group rules..." >&2
    aws --region ${REGION} ec2 authorize-security-group-ingress --group-id $sg_id --protocol tcp --port 22 --cidr ${my_ip}/32 --output text >/dev/null
    aws --region ${REGION} ec2 authorize-security-group-ingress --group-id $sg_id --protocol tcp --port 3389 --cidr ${my_ip}/32 --output text >/dev/null
    aws --region ${REGION} ec2 authorize-security-group-ingress --group-id $sg_id --protocol icmp --port -1 --cidr ${my_ip}/32 --output text >/dev/null

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
    elif [[ $ami_info == *"redhat"* ]]; then
        echo "ec2-user"
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
    local dd_versions=$(curl -L https://ddagent-windows-stable.s3.amazonaws.com/installers_v2.json 2>/dev/null | python3 -c "import sys, json, re; print('\n'.join([re.sub(r'-\d+$', '', key) for key in json.load(sys.stdin)['datadog-agent'].keys()]))" | sort -r | grep -e '^[6-7]\.')
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
    local dd_version_major=$1
    local dd_version_minor="DD_AGENT_MINOR_VERSION=${2}"
    local dd_api_key=$3
    cat <<EOF
#!/bin/bash -x
echo "$default_user:Datadog/4u" | sudo chpasswd
sudo sh -c "echo \"$hostname\" >/etc/hostname"
sudo sh -c "hostname \"$hostname\""
sudo sh -c "echo '---------------------------------------------------------------------------'>>/etc/motd"
sudo sh -c "echo 'Run tail -f /var/log/cloud-init-output.log for Datadog Agent install status' >> /etc/motd"
sudo sh -c "echo '---------------------------------------------------------------------------'>>/etc/motd"
# Install Datadog Agent
DD_API_KEY=${dd_api_key} DD_SITE="${DD_SITE:-datadoghq.com}" ${dd_version_minor} bash -c "\$(curl -L https://s3.amazonaws.com/dd-agent/scripts/install_script_agent${dd_version_major}.sh)"
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
    local update_volume=""
    if [[ $VOLUME_SIZE -gt $volume_dev_size ]];then
        update_volume="--block-device-mappings [{\"DeviceName\":\"$volume_dev_name\",\"Ebs\":{\"VolumeSize\":$VOLUME_SIZE,\"VolumeType\":\"gp3\",\"DeleteOnTermination\":true}}]"
    fi
    # Deploy instance from AMI
    local instance_id=$(aws --region ${REGION} ec2 run-instances --image-id $AMI_ID --instance-type ${INSTANCE_TYPE} --security-group-ids $sg_id --subnet-id $SUBNET_ID --key-name "$ssh_key_name" --count 1 ${update_volume} --query 'Instances[0].InstanceId' --output text --user-data "$user_data")
    # Set Name tag of instance
    aws --region ${REGION} ec2 create-tags --resources $instance_id --tags Key=Name,Value="$instance_name"
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

function get_secret_local_file {
    local ssh_key_name=$1
    local secret_file
    # Check for locally saved pem files
    secret_files=$(find ~ -maxdepth 3 -type f -name "${ssh_key_name}.pem")
    if [[ $(wc -l <<<$secret_files) -gt 1 ]];then
        secret_file=$(fzf --height 10 --header "Select your pem file for ${ssh_key_name}" <<<$secret_files)
    else
        secret_file=$secret_files
    fi
    echo $secret_file
}

function get_secret_1password {
    local ssh_key_name=$1
    local secret_file
    if command -v op &> /dev/null;then
        secret_file=$(mktemp)
        local keys=("private key")
        if [[ -n $(echo $LANG | grep -i ja_JP) ]];then
            keys=("秘密鍵" "${keys[@]}")
        fi
        item_title=$(op item list --vault="Private" --format=json | python3 -c "import sys, json; print('\n'.join([item['title'] for item in json.load(sys.stdin)]))" | fzf --height 30 --header "Select your 1Password item for ${ssh_key_name} ssh key pair")
        for i in "${keys[@]}"; do
            op item get "$item_title" --fields "${i}" | sed -e 's/"//g' -e 's/BEGIN PRIVATE KEY/BEGIN RSA PRIVATE KEY/' -e 's/END PRIVATE KEY/END RSA PRIVATE KEY/' >$secret_file
            if [[ -n $(cat $secret_file) ]];then
                break
            fi
        done
    fi
    echo $secret_file
}

function get_secret_file_path {
    local ssh_key_name=$1
    local secret_file=$(get_secret_local_file "$ssh_key_name")
    if [[ -z $secret_file ]];then
        secret_file=$(get_secret_1password "$ssh_key_name")
    fi
    echo $secret_file
}

function is_ssh_available {
    is_tcp_port_available 22 "$@"
}

function is_rdp_available {
    is_tcp_port_available 3389 "$@"
}

function is_tcp_port_available {
    local tcp_port=$1
    shift
    local addr_array=("$@")
    local port_avail=""
    local max_attempts=40
    for ((i=1; i<=max_attempts; i++)); do
        for addr in "${addr_array[@]}"; do
            port_avail=$(nc -z -G2 $addr $tcp_port 2>&1 | grep -i succeeded || true)
            # Show progress bar
            local percent=$((i * 100 / max_attempts))
            local bar_len=50
            local bar=$(printf '%*s' $((i*bar_len/max_attempts)) '' | tr ' ' '#')
            printf "\rWait for TCP port $tcp_port availability: [%-${bar_len}s] %d%%" "$bar" "$percent" 1>&2
            if [[ -n $port_avail ]]; then
                echo $addr
                break
            fi
        done
        if [[ -n $port_avail ]]; then
            break
        fi
        sleep 1
    done
    # Clear the progress bar by printing spaces and move cursor up
    printf "\r%-120s\r" 1>&2
}

function get_instance_name {
    local default_instance_name=$1
    echo -n "Enter instance name [${default_instance_name}]: " 1>&2
    local name
    read name
    if [[ -z $name ]];then
        echo $default_instance_name
    else
        echo $name | sed -e 's/[&;|*^<>$?!\\'\'\"'"]//g'
    fi
}

function main {
    # Install fzf command if not installed
    if ! command -v fzf &> /dev/null ;then
        echo "fzf command is required. Installing it."
        brew update && brew install fzf
    fi

    # Reading default env variables
    if [ -f ~/.deploy_ec2.env ]; then
        source ~/.deploy_ec2.env
    fi
    
    # Global variables
    set +o nounset # Accept undefined variables
    ## AWS region
    REGION=${REGION:-$(select_region)}
    ## Amazon machine image ID
    AMI_ID=${AMI_ID:-$(search_amis "$AMI_ID")}
    ## Volume size of root volume
    VOLUME_SIZE=${VOLUME_SIZE:-"100"}
    ## Instance Type
    INSTANCE_TYPE=${INSTANCE_TYPE:-"c5.xlarge"}
    ## Subnet ID
    SUBNET_ID=${SUBNET_ID:-$(fetch_public_subnet_security_group_ids)}
    ## Security group ID
    SG_ID=${SG_ID:-""}
    ## Name of AWS ssh key pair
    SSH_KEY_PAIR_NAME=${SSH_KEY_PAIR_NAME:-""}
    ## Datadog Agent version
    DD_VERSION=${DD_VERSION:-""}
    ## Create new security group or update existing new security group(default: true)
    SG_CREATE=${SG_CREATE:-"true"}
    set -o nounset # Don't accept undefined variables
    
    # Retrieve the username
    local user_name=$(get_current_aws_user)
    # Retrieve my public IP address
    local my_ip=$(curl -s https://checkip.amazonaws.com)
    local ami_platform=$(determine_os_platform $AMI_ID)
    echo "The AMI ID $AMI_ID platform is ${ami_platform}."
    local ssh_key_name=$(get_ssh_key)
    local timestamp=$(date +%Y%m%d-%H%M%S)
    # Set the instance name based on the username
    local instance_name=$(get_instance_name "${user_name}-${ami_platform}-${timestamp}")

    local sg_id
    if [[ -n $SG_ID ]];then
        sg_id=$SG_ID
    elif [[ "${SG_CREATE,,}" == "t"* ]] || [[ "${SG_CREATE,,}" == "y"* ]]; then
        # If user wanto to create a new security group
        sg_id=$(ensure_security_group $SUBNET_ID)
    else
        sg_id=$(get_default_security_group $SUBNET_ID)
    fi

    local dd_version=$(get_dd_version)
    local dd_version_minor=$(echo $dd_version | sed -e 's/[0-9]*\.//')
    local dd_version_major=$(echo $dd_version | sed -e 's/\.[0-9.]*//')
    local dd_api_key=$(get_dd_api_key)
    local hostname="$(echo "$instance_name" | sed -e 's/\./-/g')"

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
        user_data=$(create_linux_user_data $dd_version_major $dd_version_minor $dd_api_key)
    elif [[ $ami_platform == windows ]]; then
        echo "Datadog Agent for windows will be installed"
        user_data=$(create_windows_user_data $dd_version)
    fi

    # Deploy Instance
    local instance_id=$(deploy_ec2_instance "$ssh_key_name" "$sg_id")

    # Output the instance information
    echo "---------------------------------"
    echo "Datadog Agent version: ${dd_version}"
    echo "Instance name: ${instance_name}"
    echo "Instance ID: ${instance_id}"
    echo "VPC ID: $(get_vpc_id $SUBNET_ID)"
    echo "Subnet ID: ${SUBNET_ID}"
    echo "Security Group ID: ${sg_id}"
    echo "AMI ID: ${AMI_ID}"
    echo "AMI Description: $(get_ami_description)"
    echo "AMI Platform: $ami_platform"
    local private_ip=$(get_private_ip $instance_id)
    local public_ip=$(get_public_ip $instance_id)
    [[ -n $private_ip ]] && echo "Private IP: $private_ip"
    [[ -n $public_ip ]] && echo "Public IP: $public_ip"
    if [[ $ami_platform != windows ]]; then
        echo "User Name: $default_user"
        echo "Password: Datadog/4u"
    elif [[ $ami_platform == windows ]]; then
        echo "User Name: Administrator"
        local secret_file=$(get_secret_file_path "$ssh_key_name")
        echo "pem file for Windows password decryption: $secret_file"
        local password=$(get_windows_password $instance_id "$secret_file")
        printf "Password: "
        echo "${password}"
        echo -n "${password}" | pbcopy
    fi
    echo "URL: https://${REGION}.console.aws.amazon.com/ec2/home?region=${REGION}#InstanceDetails:instanceId=${instance_id}"
    echo "---------------------------------"
    
    local addr_array=("$private_ip" "$public_ip")
    if [[ $ami_platform != windows ]]; then
        local addr=$(is_ssh_available "${addr_array[@]}")
        echo "SSH to $addr is available now"
        local ssh_opts=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null)
        local ssh_cmd=(ssh "${ssh_opts[@]}" "${default_user}@${addr}")
        local secret=$(get_secret_local_file "$ssh_key_name")
        if [[ -n $secret ]]; then
            ssh_cmd+=(-i \"$secret\")
        fi
        local cmd="${ssh_cmd[@]}"
        echo "Command is in clip board: $cmd"
        echo -n $cmd | pbcopy
    elif [[ $ami_platform == windows ]]; then
        local addr=$(is_rdp_available "${addr_array[@]}")
        echo "RDP to $addr is available now"
        local rdp_file=~/Downloads/${hostname}-${addr}.rdp
        create_rdp_file "$addr" "Administrator" "$rdp_file"
        open ~/Downloads
    fi
}

main
# Comment for avoiding unknown error
