#!/bin/bash
# Stop script when error and undefined variables used
set -eu

function _show_fzf {
    title=$1;shift
    full_screen=$1;shift
    
    # Expected maximum height
    local max_height=20
    
    # Save standard input to a variable and count the number of lines
    local input=$(cat)
    local line_count=$(echo "$input" | wc -l)
    
    # Calculate the actual height (the smaller of max_height or line_count)
    local actual_height=$(( line_count < max_height ? line_count : max_height ))
    # Add number of fzf header and footer
    actual_height=$(( actual_height + 3 ))

    echo -e "\033[0;33m${title}\033[0m" >&2
    # Execute fzf with the calculated height
    full_screen=$(echo "$full_screen" | tr '[:upper:]' '[:lower:]')
    if [[ -z $full_screen ]] || [[ "${full_screen}" == "f"* ]] || [[ "${full_screen}" == "n"* ]];then
        opt_height="--height $actual_height"
    fi
    local selected_line=$(echo "$input" | fzf $opt_height --header "$title")
    if [[ -z $selected_line ]];then
        return 1
    fi
    echo -e "$selected_line"
    echo -e "  Choice: \033[0;32m${selected_line}\033[0m" >&2
}

function select_region {
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
            ap-northeast-3) description="Osaka" ;;
            ap-southeast-1) description="Singapore" ;;
            ap-southeast-2) description="Sydney" ;;
            ap-south-1) description="Mumbai" ;;
            eu-north-1) description="Stockholm" ;;
            eu-west-1) description="Ireland" ;;
            eu-west-2) description="London" ;;
            eu-west-3) description="Paris" ;;
            eu-central-1) description="Frankfurt" ;;
            us-east-1) description="N. Virginia" ;;
            us-east-2) description="Ohio" ;;
            us-west-1) description="N. California" ;;
            us-west-2) description="Oregon" ;;
            ca-central-1) description="Central Canada" ;;
            sa-east-1) description="São Paulo" ;;
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
    local selected_region=$(echo -e "$default_region_info$region_info" | _show_fzf "Select AWS Region" "false" | awk '{print $1}')
    if [[ -z $selected_region ]];then
        return 1
    fi
    echo $selected_region
}

function fetch_public_subnet_ids {
    # Get the default VPC ID
    local default_vpc_id=$(aws ec2 describe-vpcs --filters "Name=is-default,Values=true" --query "Vpcs[0].VpcId" --output text 2>&1)
    echo "Default VPC ID: $default_vpc_id" >&2

    # Validate if default VPC ID was found
    if [[ $default_vpc_id == "None" || -z $default_vpc_id ]]; then
        echo "No default VPC found." >&2
        return 1
    fi

    # Find subnets in the default VPC where Auto-assign public IPv4 is enabled
    local subnet_ids=($(aws ec2 describe-subnets --filters "Name=vpc-id,Values=$default_vpc_id" "Name=map-public-ip-on-launch,Values=true" --query "Subnets[*].SubnetId" --output text 2>&1))

    # Check if any subnet IDs were found
    if [[ ${#subnet_ids[@]} -eq 0 ]]; then
        echo "No subnets with auto-assign public IPv4 found in the default VPC." >&2
        return 1
    fi

    echo "Subnet IDs with auto-assign public IPv4: ${subnet_ids[*]}" >&2

    # Shuffle subnet IDs and process each one
    #local shuffled_ids=($(shuf -e "${subnet_ids[@]}"))
    for subnet_id in "${subnet_ids[@]}"; do
        local is_public=$(aws ec2 describe-subnets --subnet-ids "$subnet_id" --query 'Subnets[].MapPublicIpOnLaunch' --output text 2>&1)
        is_public=$(echo "$is_public" | tr '[:upper:]' '[:lower:]')
        if [[ "${is_public}" == "t"* ]]; then
            echo "Using subnet: $subnet_id" >&2
            echo "$subnet_id"
            break
        fi
    done
}

function is_cache_valid {
    local cache_file=$1;shift
    # Check if cache file exists
    [[ -f "$cache_file" ]] || return 1  
    # Get last modified time of the cache file
    local last_modified=$(stat -c %Y "$cache_file" 2>/dev/null)
    if [[ -z $last_modified ]];then
        last_modified=$(stat -f '%m' "$cache_file" 2>/dev/null)
    fi
    # Get current time
    local current_time=$(date +%s)
    # Calculate elapsed time since last modified
    local elapsed_time=$((current_time - last_modified))
    # Set maximum age of cache
    local max_age=${AMI_LIST_CACHE_EXPIRE}
    # Return true if the elapsed time is less than the max age
    [[ $elapsed_time -lt $max_age ]]
}

function search_amis {
    local preferred_ami_id="$1";shift
    local ami_info=""
    local all_amis=""
    local temp_file
    local cache_dir="$HOME/.cache/deploy_ec2/amis"
    local cache_file="$cache_dir/amazon_amis-${REGION}"

    # Creating cache dir
    mkdir -p "$cache_dir"
    
    # Create a temporary directory to store output files
    local temp_dir=$(mktemp -d)
    
    # Get the AWS account ID of the current user
    local owner_id=$(aws sts get-caller-identity --query "Account" --output text)

    # Check if a preferred AMI ID is provided and valid
    if [[ -n "$preferred_ami_id" ]]; then
        ami_info=$(aws ec2 describe-images --image-ids "$preferred_ami_id" --query "Images[*].[ImageId,Name,Description]" --output text)
        if [[ -n "$ami_info" ]]; then
            echo "Fetching details for preferred AMI ID: $preferred_ami_id..." >&2
            # Prepend preferred AMI info
            echo "$ami_info" > "$temp_dir/preferred_ami"
        fi
    fi

    # Fetch AMI information for each owner ID
    local amis_file_path
    if is_cache_valid "$cache_file" && [[ "${NO_CACHE}" == "f"* || "${NO_CACHE}" == "n"* ]]; then
        amis_file_path="$cache_file"
        echo "Using cache file for Amazon AMI..." >&2        
    else
        amis_file_path="$temp_dir/amazon_amis"
        echo "Fetching AMI information from Amazon..." >&2
        temp_file="$temp_dir/amazon_amis"
        (aws ec2 describe-images --owners amazon --filters Name=is-public,Values=true Name=architecture,Values=x86_64 --query "Images[*].[ImageId,Name,Description]" --output text > "$temp_file") &
    fi
    
    # Fetch user-defined AMIs
    touch "$temp_dir/user_defined_amis"
    if [[ "${INCLUDE_USER_DEF_AMIS}" == "t"* ]] || [[ "${INCLUDE_USER_DEF_AMIS}" == "y"* ]]; then
        temp_file="$temp_dir/user_defined_amis"
        echo "Fetching user-defined AMIs..." >&2
        (aws ec2 describe-images --owners "$owner_id" --query "Images[*].[ImageId,Name,Description]" --output text > "$temp_file") &
    fi
    
    # Wait for all background processes to complete
    wait
    
    # Check if "$temp_dir/amazon_amis" exists and has a size greater than zero
    if [ -f "$temp_dir/amazon_amis" ] && [ -s "$temp_dir/amazon_amis" ]; then
        echo "Chashing AMIs list from Amazon..." >&2
        cp -f "$temp_dir/amazon_amis" "$cache_file"
    else
        echo "File does not exist or is empty. No action taken." >&2
    fi
    
    # Display the AMIs in fzf, with the preferred AMI (if any) at the top
    cat "$temp_dir/user_defined_amis" "$cache_file" | sort -k2 | awk -F '\t' '{printf "%-20s %-50s %-80s\n", $1, $2, $3}' | _show_fzf "Select an AMI" "true" | cut -f1 -d' '
    
    # Clean up
    rm -r "$temp_dir"
}

function create_rdp_file {
    local rdp_addr=$1;shift
    local rdp_user_name=$1;shift
    local rdp_file=$1;shift
    cat <<EOF >"$rdp_file"
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
    local ami_info=$(aws ec2 describe-images --image-ids "$AMI_ID" --output json)
    if echo "$ami_info" | grep -iq 'windows'; then
        echo "windows"
    elif echo "$ami_info" | grep -iq 'linux'; then
        echo "linux"
    else
        echo "other"
fi
}

function get_current_aws_user {
    aws sts get-caller-identity --query 'Arn' --output text | rev | cut -d/ -f1 | rev | sed -e 's/@.*//'
}

function get_ssh_key {
    local user_name=$1;shift
    # Get SSH key pair name
    if [[ -n $SSH_KEY_PAIR_NAME ]];then
        echo $SSH_KEY_PAIR_NAME
    else
        local default_name=$user_name
        local items=$(aws ec2 describe-key-pairs --query 'KeyPairs[*].KeyName' --output text | tr '\t' '\n' | sort -f)
        local default_name_exist=$(echo "$items" | grep "^$default_name$" || true)
        if [[ -n $default_name_exist ]]; then
            items=$(echo "$items" | grep -v "^$default_name$" | sort)
            echo $(echo -e "$default_name\n$items" | _show_fzf "Select your SSH key name" "false")
        else
            echo $(echo -e "$items" | _show_fzf "Select your SSH key name" "false")
        fi
    fi
}

function get_vpc_id {
    local subnet_id=$1;shift
    echo $(aws ec2 describe-subnets --subnet-ids $subnet_id --query 'Subnets[*].VpcId' --output text)
}

function ensure_security_group {
    local subnet_id=$1;shift
    local user_name=$1;shift
    # Retrieve VPC ID from Subnet ID
    local vpc_id=$(get_vpc_id $subnet_id)
    local sg_name="${user_name}-${vpc_id}"
    # Retrieve my public IP address
    local my_ip=$(curl -s https://checkip.amazonaws.com)

    # Check if the security group already exists
    local sg_id=$(aws ec2 describe-security-groups \
                   --filters Name=vpc-id,Values="$vpc_id" Name=group-name,Values="$sg_name" \
                   --query 'SecurityGroups[0].GroupId' --output text)
    
    # If security group does not exist, create it
    if [[ $sg_id == "None" ]]; then
        echo "Creating new security group..." >&2
        sg_id=$(aws ec2 create-security-group \
                      --group-name "$sg_name" --description "Security group for SSH and RDP access" \
                      --vpc-id "$vpc_id" --query 'GroupId' --output text)
    else
        echo "Security group $sg_name already exists with ID $sg_id." >&2
    fi
    
    # Update rules: Ensure SSH, RDP and ICMP are allowed (idempotent operations)
    echo "Updating security group rules..." >&2
    aws ec2 authorize-security-group-ingress --group-id $sg_id --protocol tcp --port 22 --cidr ${my_ip}/32 --output text 2>&1 >/dev/null | grep -vi "already exists" | sed '/^$/d'
    aws ec2 authorize-security-group-ingress --group-id $sg_id --protocol tcp --port 3389 --cidr ${my_ip}/32 --output text 2>&1 >/dev/null | grep -vi "already exists" | sed '/^$/d'
    aws ec2 authorize-security-group-ingress --group-id $sg_id --protocol icmp --port -1 --cidr ${my_ip}/32 --output text 2>&1 >/dev/null | grep -vi "already exists" | sed '/^$/d'

    echo $sg_id
}

function get_default_security_group {
    local subnet_id=$1;shift
    local vpc_id=$(get_vpc_id $subnet_id)
    echo $(aws ec2 describe-security-groups --filters Name=vpc-id,Values=${vpc_id} Name=group-name,Values='default' --query 'SecurityGroups[0].GroupId' --output text)
}

function get_ami_description {
    echo $(aws ec2 describe-images --image-ids $AMI_ID --query 'Images[*].Description' --output text)
}

function _get_linux_default_user {
    local ami_info=$(aws ec2 describe-images --image-ids $AMI_ID --query 'Images[*].Description' --output text | tr '[:upper:]' '[:lower:]' | tr -d '[:punct:]' | tr -d '[:space:]')
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

function _get_windows_default_user {
    local ami_info=$(aws ec2 describe-images --image-ids $AMI_ID --query 'Images[*].Description' --output text | tr '[:upper:]' '[:lower:]' | tr -d '[:punct:]' | tr -d '[:space:]')
    if [[ $ami_info == *"finnish"* ]]; then
        echo "Järjestelmänvalvoja"
    elif [[ $ami_info == *"french"* ]]; then
        echo "Administrateur"
    elif [[ $ami_info == *"hungarian"* ]]; then
        echo "Rendszergazda"
    elif [[ $ami_info == *"portuguese"* ]]; then
        echo "Administrador"
    elif [[ $ami_info == *"russian"* ]]; then
        echo "Администратор"
    elif [[ $ami_info == *"spanish"* ]]; then
        echo "Administrador"
    elif [[ $ami_info == *"swedish"* ]]; then
        echo "Administratör"
    else
        echo "Administrator"
    fi
}

function get_host_default_user {
    ami_platform=$1;shift
    if [[ $ami_platform == windows ]]; then
        _get_windows_default_user
    elif [[ $ami_platform == linux ]]; then
        _get_linux_default_user
    fi
}

function get_dd_version {
    local dd_versions_url="https://ddagent-windows-stable.s3.amazonaws.com/installers_v2.json"
    local dd_versions=$(curl -L $dd_versions_url 2>/dev/null | \
                            python3 -c "import sys, json, re; \
                            print('\n'.join([re.sub(r'-\d+$', '', key) for key in json.load(sys.stdin)['datadog-agent'].keys()]))" | \
                            sort -r | \
                            grep -e '^[6-7]\.')
    if [[ -n $DATADOG_VERSION ]];then
        local dd_version_exists=$(echo "$dd_versions" | grep -e "^${DATADOG_VERSION}\$" || true)
        if [[ -n $dd_version_exists ]];then
            echo $DATADOG_VERSION
            return
        else
            echo -e "\033[0;31mInvalid Datadog Agent version: $DATADOG_VERSION\033[0m" 1>&2
        fi
    fi
    echo $(echo "$dd_versions" | _show_fzf "Select Datadog Agent version" "false")
}

function create_linux_user_data {
    local dd_version_major=$1;shift
    local dd_version_minor="DD_AGENT_MINOR_VERSION="$1;shift
    local hostname=$1;shift
    local username=$1;shift
    local password=$1;shift
    cat <<EOF
#!/bin/bash -x
echo "$username:$password" | sudo chpasswd
sudo sh -c "echo \"$hostname\" >/etc/hostname"
sudo sh -c "hostname \"$hostname\""
sudo sh -c "echo '---------------------------------------------------------------------------'>>/etc/motd"
sudo sh -c "echo 'Run tail -f /var/log/cloud-init-output.log for user script log' >> /etc/motd"
sudo sh -c "echo '---------------------------------------------------------------------------'>>/etc/motd"
EOF
    if [[ -n "$DD_API_KEY" ]];then
        cat <<EOF        
# Install Datadog Agent
DD_API_KEY=${DD_API_KEY} DD_SITE="${DD_SITE:-datadoghq.com}" ${dd_version_minor} bash -c "\$(curl -L https://s3.amazonaws.com/dd-agent/scripts/install_script_agent${dd_version_major}.sh)"
EOF
    fi
}

function generate_random_password {
    # Generate random passowrd
    echo "$(openssl rand -base64 24 | tr -cd '[:alnum:]' | cut -c -31)@"
}

function create_windows_user_data {
    local dd_version=$1;shift
    local dd_agentuser_pass="$(generate_random_password)"
    echo "DDAGENTUSER_PASSWORD is ${dd_agentuser_pass}"
    cat <<EOF
<powershell>
# Create Initial setup running.txt on desktop
\$desktopPath = [Environment]::GetFolderPath("Desktop")
# Specify the full path for the new file
\$filePath = Join-Path -Path \$desktopPath -ChildPath "Initial setup running.txt"
New-Item -Path \$filePath -ItemType File

# Make shortcut on desktop for checking launch logs
# Target directory for the shortcut
\$targetPath = "C:\\ProgramData\\Amazon\\EC2Launch\\log"
# Location to save the shortcut (user's desktop)
\$desktopPath = [Environment]::GetFolderPath("Desktop")
\$shortcutPath = Join-Path -Path \$desktopPath -ChildPath "Launch Logs.lnk"
# Create a WScript.Shell object
\$shell = New-Object -ComObject WScript.Shell
# Create the shortcut
\$shortcut = \$shell.CreateShortcut(\$shortcutPath)
\$shortcut.TargetPath = \$targetPath
\$shortcut.Save()
# Release the COM object
[System.Runtime.InteropServices.Marshal]::ReleaseComObject(\$shell) | Out-Null
EOF
    if [[ -n "$DD_API_KEY" ]];then
        cat <<EOF
# Install Datadog Agent
Write-Host "Start installing Datadog Agent"
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
Start-Process -Wait msiexec -ArgumentList "/qn /log C:/\$file.\$now.log /i \$file DDAGENTUSER_NAME=.\\ddagentuser DDAGENTUSER_PASSWORD=${dd_agentuser_pass} SITE=${DD_SITE:-datadoghq.com} APIKEY=${DD_API_KEY}"
Write-Host "Datadog Agent has been installed successfully."

# Add Datadog Agent/bin to PATH
Write-Host "Start adding Datadog Agent/bin to PATH"
\$newPath = "C:\Program Files\Datadog\Datadog Agent\bin"
\$currentPath = [System.Environment]::GetEnvironmentVariable("PATH", "Machine")
\$newPath = \$currentPath + ";" + \$newPath
[System.Environment]::SetEnvironmentVariable("PATH", \$newPath, "Machine")
Write-Host "End adding Datadog Agent/bin to PATH"

# Make shortcut on desktop for Datadog Agent conf and logs dir
# Target directory for the shortcut
\$targetPath = "C:\\ProgramData\\Datadog"
# Location to save the shortcut (user's desktop)
\$desktopPath = [Environment]::GetFolderPath("Desktop")
\$shortcutPath = Join-Path -Path \$desktopPath -ChildPath "Datadog Agent conf.lnk"
# Create a WScript.Shell object
\$shell = New-Object -ComObject WScript.Shell
# Create the shortcut
\$shortcut = \$shell.CreateShortcut(\$shortcutPath)
\$shortcut.TargetPath = \$targetPath
\$shortcut.Save()
# Release the COM object
[System.Runtime.InteropServices.Marshal]::ReleaseComObject(\$shell) | Out-Null
EOF
    fi
    cat <<EOF
# Set the registry key to show file extensions in Windows Explorer
Write-Host "Seting the registry key to show file extensions in Windows Explorer."
\$registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
\$registryKey = "HideFileExt"
\$registryValue = 0  # Set to 0 to show extensions
# Check if the registry key already exists
if (Test-Path -Path \$registryPath) {
    # Set the value to show file extensions
    Set-ItemProperty -Path \$registryPath -Name \$registryKey -Value \$registryValue
    Write-Host "File extensions will now be displayed in Windows Explorer."
} else {
    Write-Host "The registry path does not exist. Check the path and try again."
}
Write-Host "Finished adding the registry key to show file extensions in Windows Explorer."
# Restart Windows Explorer to apply the change
Stop-Process -Name explorer -Force
Start-Process explorer

# Install Notepad++
Write-Host "Start installing Notepad++"
# URL for the Notepad++ installer
\$installerUrl = "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.6.5/npp.8.6.5.Installer.x64.exe"
# Local path for downloading the installer
\$localPath = "\$env:TEMP\npp_installer.exe"
# Download the installer
Invoke-WebRequest -Uri \$installerUrl -OutFile \$localPath
# Execute the installer (silent installation)
Start-Process -FilePath \$localPath -Args '/S' -NoNewWindow -Wait
# Delete the installer file
Remove-Item -Path \$localPath -Force
Write-Host "Notepad++ has been installed successfully."

# Create Initial setup finished.txt on desktop
\$desktopPath = [Environment]::GetFolderPath("Desktop")
# Specify the full path for the new file
\$filePath = Join-Path -Path \$desktopPath -ChildPath "Initial setup finished.txt"
New-Item -Path \$filePath -ItemType File

# Delete Initial setup running.txt on desktop
\$desktopPath = [Environment]::GetFolderPath("Desktop")
# Specify the full path for the file to be deleted
\$filePath = Join-Path -Path \$desktopPath -ChildPath "Initial setup running.txt"
Remove-Item -Path \$filePath -Force

Write-Host "User data script completed!"
</powershell>
EOF
}

function deploy_ec2_instance {
    local instance_name=$1;shift
    local ssh_key_name=$1;shift
    local sg_id=$1;shift
    # Get root volume device name
    local volume_dev_name=$(aws ec2 describe-images --image-ids $AMI_ID --query 'Images[0].BlockDeviceMappings[0].DeviceName' --output text)
    # Get root volume size
    local volume_dev_size=$(aws ec2 describe-images --image-ids $AMI_ID --query 'Images[0].BlockDeviceMappings[0].Ebs.VolumeSize' --output text)
    local update_volume=""
    if [[ $VOLUME_SIZE -gt $volume_dev_size ]];then
        update_volume="--block-device-mappings [{\"DeviceName\":\"$volume_dev_name\",\"Ebs\":{\"VolumeSize\":$VOLUME_SIZE,\"VolumeType\":\"gp3\",\"DeleteOnTermination\":true}}]"
    fi
    # Deploy instance from AMI
    local instance_id=$(aws ec2 run-instances --image-id $AMI_ID --instance-type ${INSTANCE_TYPE} --security-group-ids $sg_id --subnet-id $SUBNET_ID --key-name "$ssh_key_name" --count 1 ${update_volume} --query 'Instances[0].InstanceId' --output text --user-data "$user_data")
    # Set Name tag of instance
    aws ec2 create-tags --resources $instance_id --tags Key=Name,Value="$instance_name"
    echo $instance_id
}

function get_public_ip {
    local instance_id=$1;shift
    echo $(aws ec2 describe-instances --instance-ids "${instance_id}" --query 'Reservations[*].Instances[*].PublicIpAddress' --output text 2>/dev/null)
}

function get_private_ip {
    local instance_id=$1;shift
    echo $(aws ec2 describe-instances --instance-ids "${instance_id}" --query 'Reservations[*].Instances[*].PrivateIpAddress' --output text 2>/dev/null)
}

function get_windows_password {
    local instance_id=$1;shift
    local secret_file=$1;shift
    local password=""
    local max_attempts=100
    echo "Password generation for windows takes up to 4 minutes. Please be patient." 1>&2
    for ((i=1; i<=max_attempts; i++)); do
        local password=$(aws ec2 get-password-data --instance-id "${instance_id}" --priv-launch-key "$secret_file" --query 'PasswordData' --output text)
        # Show progress bar
        local percent=$((i * 100 / max_attempts))
        local bar_len=50
        local bar=$(printf '%*s' $((i*bar_len/max_attempts)) '' | tr ' ' '#')
        printf "\rWaiting for password generation: [%-${bar_len}s] %d%%" "$bar" "$percent" 1>&2
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
    local ssh_key_name=$1; shift
    local secret_file
    local secret_files=()

    while IFS= read -r -d '' file; do
        secret_files+=("$file")
    done < <(find ~ -maxdepth 3 -type f -name "*${ssh_key_name}*.pem" -print0)

    if [[ "${#secret_files[@]}" -gt 1 ]]; then
        secret_file=$(printf "%s\n" "${secret_files[@]}" | _show_fzf "Select your PEM file for ${ssh_key_name}" "false")
    elif [[ "${#secret_files[@]}" == 1 ]]; then
        secret_file=${secret_files[0]}
    else
        secret_file=""
    fi
    echo $secret_file
}

function _get_secret_1password {
    local ssh_key_name=$1;shift
    local secret_file
    if command -v op &> /dev/null;then
        local secret_file=$(mktemp)
        local keys=("private key")
        keys=("秘密鍵" "${keys[@]}")
        local item_list=$(op item list --vault="Private" --format=json | python3 -c "import sys, json; print('\n'.join([item['title'] for item in json.load(sys.stdin)]))")
        for i in "$ssh_key_name" "${REGION}";do
            local item_list_new=$(echo "$item_list" | grep -v "$i")
            local item_list_grep=$(echo "$item_list" | grep "$i")
            if [[ -n $item_list_grep ]];then
                item_list=$(echo -e "${item_list_grep}\n${item_list_new}")
            fi
        done
        local item_title=$(echo "$item_list" | _show_fzf "Select your 1Password item for ${ssh_key_name} ssh key pair" "false")
        if [[ -z $item_title ]];then
            return 1
        fi
        for i in "${keys[@]}"; do
            op item get "$item_title" --fields "${i}" --reveal | \
                sed -e 's/"//g' \
                    -e 's/BEGIN PRIVATE KEY/BEGIN RSA PRIVATE KEY/' \
                    -e 's/END PRIVATE KEY/END RSA PRIVATE KEY/' \
                    -e '/^[[:space:]]*$/d' >$secret_file 2>/dev/null
            if [[ -n $(grep "BEGIN OPENSSH PRIVATE KEY" "$secret_file") ]];then
                ssh-keygen -p -f "$secret_file" -m PEM -N "" >/dev/null 2>&1
            fi
            if [[ -n $(cat $secret_file) ]];then
                break
            fi
        done
    fi
    echo $secret_file
}

function get_secret_file_path {
    local ssh_key_name=$1;shift
    local secret_file=$(get_secret_local_file "$ssh_key_name")
    if [[ -z $secret_file ]];then
        secret_file=$(_get_secret_1password "$ssh_key_name")
    fi
    echo $secret_file
}

function is_ssh_available {
    is_tcp_port_available 22 "$@"
    local sleep_sec=15
    echo "Waiting $sleep_sec more sec for user script run" >&2
    sleep $sleep_sec
}

function is_rdp_available {
    is_tcp_port_available 3389 "$@"
}

function is_tcp_port_available {
    local tcp_port=$1;shift
    local addr_array=("$@");shift $#
    local port_avail=""
    local max_attempts=60
    for ((i=1; i<=max_attempts; i++)); do
        for addr in "${addr_array[@]}"; do
            port_avail=$(nc -z -G2 $addr $tcp_port 2>&1 | grep -i succeeded || true)
            # Show progress bar
            local percent=$((i * 100 / max_attempts))
            local bar_len=50
            local bar=$(printf '%*s' $((i*bar_len/max_attempts)) '' | tr ' ' '#')
            printf "\rWaiting for TCP port $tcp_port availability: [%-${bar_len}s] %d%%" "$bar" "$percent" 1>&2
            if [[ -n $port_avail ]]; then
                echo $addr
                break
            fi
            sleep 1
        done
        if [[ -n $port_avail ]]; then
            break
        fi
    done
    # Clear the progress bar by printing spaces and move cursor up
    printf "\r%-120s\r" 1>&2
}

function get_instance_name {
    local default_instance_name=$1;shift
    echo -n "Enter instance name [${default_instance_name}]: " 1>&2
    local name
    read name
    if [[ -z $name ]];then
        echo $default_instance_name
    else
        echo $name | sed -e 's/[&;|*^<>$?!\\'\'\"'"]//g'
    fi
}

# main function
# All variables in uppercase are global variables, and variables starting with an underscore are local variables.
#
# Exit if aws command is not working
if ! aws sts get-caller-identity >/dev/null 2>&1;then
    echo "AWS command is not working. Exiting..."
    exit 1
fi
# Install fzf command if not installed
if ! command -v fzf &> /dev/null ;then
    echo "fzf command is required. Installing it."
    brew update && brew install fzf
fi
# Install op command if not installed
if ! command -v op &> /dev/null ;then
    echo "op command is required. Installing it."
    brew update && brew install 1password-cli
fi

# Reading default env variables
_env_file=~/.deploy_ec2.env
if [ -f $_env_file ]; then
    echo -e "\033[33mReading default env variables from $_env_file. Your command line env variables may be ignored.\033[0m"
    source $_env_file
fi

# Global variables
set +o nounset # Accept undefined variables
## Disable any kind of caching
NO_CACHE=${NO_CACHE:-"false"}
## AWS region
REGION=${REGION:-$(select_region)};[[ -z $REGION ]] && exit 1
AWS_REGION=$REGION
## Datadog API key
DD_API_KEY=${DD_API_KEY:-""}
## Amazon AMI cache list expire second
AMI_LIST_CACHE_EXPIRE=${AMI_LIST_CACHE_EXPIRE:-$((24 * 3600 * 30))}
## Amazon machine image ID
AMI_ID=${AMI_ID:-$(search_amis)};[[ -z $AMI_ID ]] && exit 1
## Volume size of root volume
VOLUME_SIZE=${VOLUME_SIZE:-"100"}
## Instance Type
INSTANCE_TYPE=${INSTANCE_TYPE:-"t2.large"}
## Subnet ID
SUBNET_ID=${SUBNET_ID:-$(fetch_public_subnet_ids)}
## Security group ID
SG_ID=${SG_ID:-""}
## Name of AWS ssh key pair
SSH_KEY_PAIR_NAME=${SSH_KEY_PAIR_NAME:-""}
## Datadog Agent version
DATADOG_VERSION=${DATADOG_VERSION:-""}
## Create new security group or update existing new security group(default: true)
SG_CREATE=${SG_CREATE:-"true"}
## Include user-defined AMIs?
INCLUDE_USER_DEF_AMIS=${INCLUDE_USER_DEF_AMIS:-"false"}
## Password for linux will be Datadog/4u if this is ture/yes
RANDOM_LINUX_PASSWORD=${RANDOM_LINUX_PASSWORD:-"true"}
set -o nounset # Don't accept undefined variables

# Retrieve the username
_user_name=$(get_current_aws_user)
_ami_platform=$(determine_os_platform)
echo "The AMI ID $AMI_ID platform is ${_ami_platform}."
_ssh_key_name=$(get_ssh_key "$_user_name");[[ -z $_ssh_key_name ]] && exit 1
_datetime=$(date +%Y%m%d-%H%M%S)
# Set the instance name based on the username
_instance_name=$(get_instance_name "${_user_name}-${_ami_platform}-${_datetime}")

if [[ -n $SG_ID ]];then
    _sg_id=$SG_ID
elif [[ "${SG_CREATE}" == "t"* ]] || [[ "${SG_CREATE}" == "y"* ]]; then
    # If user wanto to create a new security group
    _sg_id=$(ensure_security_group "$SUBNET_ID" "$_user_name")
else
    _sg_id=$(get_default_security_group "$SUBNET_ID")
fi

_dd_version=""
_dd_version_minor=""
_dd_version_major=""
if [[ -n "$DD_API_KEY" ]];then
    _dd_version=$(get_dd_version);[[ -z $_dd_version ]] && exit 1
    _dd_version_minor=$(echo $_dd_version | sed -e 's/[0-9]*\.//')
    _dd_version_major=$(echo $_dd_version | sed -e 's/\.[0-9.]*//')
    echo "Datadog Agent $_dd_version for $_ami_platform will be installed"
fi
_hostname="$(echo "$_instance_name" | sed -e 's/\./-/g')"
_host_username=$(get_host_default_user "$_ami_platform")

## Validate host user name
if [[ -n $_host_username ]];then
    echo "Default user for AMI $AMI_ID is likely: $_host_username"
else
    echo "Default user for AMI $AMI_ID not found!"
    echo "Please check below AWS page"
    echo "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/managing-users.html#ami-default-user-names"
    exit 1
fi

# Create uesr data script
if [[ $_ami_platform != windows ]]; then
    # Check default user name for linux instance
    if [[ "${RANDOM_LINUX_PASSWORD}" == "t"* ]] || [[ "${RANDOM_LINUX_PASSWORD}" == "y"* ]]; then
        _host_password=$(generate_random_password)
    else
        _host_password="Datadog/4u"
    fi
    user_data=$(create_linux_user_data "$_dd_version_major" "$_dd_version_minor" "$_hostname" "$_host_username" "$_host_password")
elif [[ $_ami_platform == windows ]]; then
    user_data=$(create_windows_user_data "$_dd_version")
fi

# Deploy Instance
instance_id=$(deploy_ec2_instance "$_instance_name" "$_ssh_key_name" "$_sg_id")

# Ctrl-c will stop witing for windows password generation
set +e; trap 'echo -e "\nCtrl-C is pressed. Instance ${instance_id} already created.."' SIGINT
# Wait for windows password generation, but can be skipped by ctrl-c.
if [[ $_ami_platform == windows ]]; then
    secret_file=$(get_secret_file_path "$_ssh_key_name");[[ -z $secret_file ]] && exit 1
    echo "PEM file for Windows password decryption: $secret_file"
    echo "You can skip waiting by ctrl-c"
    _host_password=$(get_windows_password $instance_id "$secret_file")
fi
set -e; trap - SIGINT # Ctrl-c will stop the script after this

# Output the instance information
echo "---------------------------------"
[[ -n "$DD_API_KEY" ]] && echo "Datadog Agent version: ${_dd_version}"
echo "Instance name: ${_instance_name}"
echo "Instance Type: ${INSTANCE_TYPE}"
echo "Instance ID: ${instance_id}"
echo "VPC ID: $(get_vpc_id $SUBNET_ID)"
echo "Subnet ID: ${SUBNET_ID}"
echo "Security Group ID: ${_sg_id}"
echo "AMI ID: ${AMI_ID}"
echo "AMI Description: $(get_ami_description)"
echo "AMI Platform: $_ami_platform"
_host_private_ip=$(get_private_ip $instance_id)
_host_public_ip=$(get_public_ip $instance_id)
[[ -n $_host_private_ip ]] && echo "Private IP: $_host_private_ip"
[[ -n $_host_public_ip ]] && echo "Public IP: $_host_public_ip"
echo "User Name: $_host_username"
echo "Password: ${_host_password}"
# Copy password to clipboard
echo -n "${_host_password}" | pbcopy
echo "URL: https://${REGION}.console.aws.amazon.com/ec2/home?region=${REGION}#InstanceDetails:instanceId=${instance_id}"
echo "---------------------------------"

_addr_array=("$_host_private_ip" "$_host_public_ip")
if [[ $_ami_platform != windows ]]; then
    trap 'echo -n ""' SIGINT; set +e
    _addr=$(is_ssh_available "${_addr_array[@]}")
    trap - SIGINT; set -e
    echo "SSH to $_addr is available now"
    _ssh_opts=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null)
    _ssh_cmd=(ssh "${_ssh_opts[@]}" "${_host_username}@${_addr}")
    _secret_file=$(get_secret_local_file "$_ssh_key_name")
    if [[ -n $_secret_file ]]; then
        _ssh_cmd+=(-i \"$_secret_file\")
    fi
    _cmd="${_ssh_cmd[@]}"
    echo "Command is in clipboard: $_cmd"
    echo -n $_cmd | pbcopy
elif [[ $_ami_platform == windows ]]; then
    trap 'echo ""' SIGINT; set +e
    _addr=$(is_rdp_available "${_addr_array[@]}")
    trap - SIGINT; set -e
    if [[ -z $_addr ]];then
        exit 1
    fi
    echo "RDP to $_addr is available now"
    _rdp_file=~/Downloads/${_hostname}-${_addr}.rdp
    create_rdp_file "$_addr" "$_host_username" "$_rdp_file"
    open ~/Downloads
fi

# Comment for avoiding unknown error
