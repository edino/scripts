import os
import subprocess
from datetime import datetime
import time

# Get the timezone abbreviation (e.g., EDT, EST, etc.)
timezone_abbr = time.tzname[0] if time.localtime().tm_isdst == 0 else time.tzname[1]

# Function to generate timestamp
def get_timestamp():
    current_time = time.localtime()
    return f"{current_time.tm_year}-{current_time.tm_mon:02d}-{current_time.tm_mday:02d}_at_{current_time.tm_hour:02d}:{current_time.tm_min:02d}:{current_time.tm_sec:02d}_{timezone_abbr}"

def log_command(command, description, log_file):
    timestamp = get_timestamp()
    with open(log_file, 'a') as f:
        f.write(f"[{timestamp}] {description}\n")
        f.write(f"[{timestamp}] Running: {command}\n")
        try:
            result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            f.write(result.stdout)  # Write command output to file
            f.write(f"[{timestamp}] Finished: {command}\n\n")
        except subprocess.CalledProcessError as e:
            f.write(f"[{timestamp}] Error running command: {e}\n\n")
			
# Function to check free space at /var
def check_var_space():
    df_output = subprocess.run(["df", "-kh", "/var"], capture_output=True, text=True).stdout.strip()
    print(f"Disk space at /var:\n{df_output}")
    # Parsing the output to get the percentage of available space
    df_lines = df_output.split("\n")
    if len(df_lines) > 1:
        # Splitting the second line by whitespace and getting the percentage value
        available_percentage = int(df_lines[1].split()[4].replace("%", ""))
        return available_percentage < 70
    return False

ls -lah /var/*_Master-* && ls -lah /var/tam_healthcheck_*

# Main function
def main():
    try:
        nvram_output = subprocess.run(["nvram", "get", "#li.serial"], capture_output=True, text=True).stdout.strip()
        log_file = f"/var/tam_healthcheck_{nvram_output}-{get_timestamp()}.log"
        print(f"Executing commands and saving output to {log_file} ...")

        # Check free space at /var before proceeding with the script
        if not check_var_space():
            print("Insufficient free space at /var. Exiting.")
            return

        # Commands to be executed
        log_command("date", "Display current date and time", log_file)
        log_command("uptime", "Show system uptime and load", log_file)
        log_command("nvram get '#'li.serial", "Get the serial number of the device", log_file)
        log_command("df -kh", "Show disk space usage", log_file)
        log_command("grep 'cpu cores' /proc/cpuinfo | wc -l", "Count the number of CPU cores", log_file)
        log_command("cat /proc/scsi/scsi", "Display SCSI devices", log_file)
        log_command("hdparm -i /dev/sda", "Show information about the hard drive /dev/sda", log_file)
        log_command("fdisk -l", "List disk partitions", log_file)
        log_command("dmidecode -s system-version", "Show the system version", log_file)
        log_command("showfw", "Show firmware information", log_file)
        log_command("csc custom status", "Show the status of custom CSC (Customizable Service Code) settings", log_file)
        log_command("service -S | sort -f", "List all services sorted alphabetically", log_file)
        log_command("central-register --status", "Show status of central registration", log_file)
        log_command("central-connect --check_status", "Check central connect status", log_file)
        log_command("nsgenc status; echo $?", "Show NSGenc status", log_file)
        log_command("psql -U nobody -d signature -p 5434 -tAc 'select * from public.tblup2dateinfo;'", "Show up-to-date information from a PostgreSQL database", log_file)
        log_command("ifconfig", "List information about all network interfaces", log_file)
        log_command("tcpdump -D", "List available network interfaces for packet capture", log_file)
        log_command("listif -s", "List network interfaces with statistics", log_file)
        log_command("netstat -i", "List network interfaces and their statistics", log_file)
        log_command("psql -U nobody -d corporate -Xc 'select * from tblipaddress;'", "Show IP addresses from a PostgreSQL database assigned to the Interfaces", log_file)
        log_command("psql -U nobody -d corporate -Xc 'select ruleid,name from tblfirewallrule where logginglevel=-1 and isenable=1;'", "Show Firewall Rules Turned ON without Logging Enabled", log_file)
        log_command("psql -U nobody -d corporate -Xc 'select * from tblatpconfiguration;'", "Show Advanced Threat protection Status (ATP/Sophos X-OPS) Log = Log and Drop = Log and Drop", log_file)
        log_command("psql -U nobody -d corporate -Xc 'select * from tblactive_threat_response'", "Show MDR threat feeds Status", log_file)
        log_command("psql -U nobody -d corporate -Xc 'select * from tblconfiguration;' | grep -E 'ARP_POISONING'", "Display Status for ARP Poising Protection (Configure/Network/Neighbors (ARP-NDP)/Log possible neighbor poisoning attempts)", log_file)
        log_command("psql -U nobody -d corporate -Xc 'select * from tblconfiguration;' | grep -E 'pua_detection'", "Display Status for PUA Detection (Protect/Web/General Settings/Protection/Malware and content scanning/Block potentially unwanted applications)", log_file)
        log_command("psql -U nobody -d corporate -Xc 'select * from tbloutboundallowedhost where id=1'", "Your device is configured as an open relay server. (Protect/Email/Relay Settings/Host Based Relay/Allow relay from hosts/networks) is set as ANY.", log_file)
        log_command("psql -U nobody -d corporate -Xc 'select * from tblclientservices' | grep -E 'LogoutAdminSess|LogoutAdminSess|blocklocaladmin|blockremoteadmin|remoteadminattempts|remoteadminseconds|remoteadminminutes'", "Display information about Login security (System/Administration/Admin and User Settings/Login security)", log_file)
	log_command('psql -U nobody -d corporate -Xc "SELECT a.localaclid, a.zoneid, a.localserviceid, b.servicename, b.isenabled, c.zonename FROM tbllocalzoneacl a JOIN (SELECT * FROM tbllocalservice WHERE isenabled='Y') b ON a.localserviceid = b.localserviceid JOIN tblnetworkzone c ON a.zoneid = c.zoneid WHERE (a.localserviceid = 4 OR a.localserviceid = 2) AND a.zoneid = 2;"', "HTTPS and SSH turned on WAN zone", log_file)
        log_command("ip route show table all", "Show the routing table", log_file)
        log_command("ip route get 8.8.8.8", "Get route information for the IP address 8.8.8.8", log_file)
        log_command("nslookup eu2.apu.sophos.com", "Perform a DNS lookup for eu2.apu.sophos.com", log_file)
        log_command("ls -lah /var/cores/", "List core files in /var/cores/", log_file)
        log_command("ls -lah /var/crashkernel/", "List core files in /var/crashkernel/", log_file)
        log_command('cish -c "system firewall-acceleration show"', "Show Status for Firewall Acceleration", log_file)
        log_command('cish -c "system ipsec-acceleration show"', "Show Status for IPSec Acceleration", log_file)
        log_command('cish -c "show advanced-firewall"', "Show Status for Advanced Firewall Options", log_file)
        log_command('cish -c "system system_modules show"', "Show Status for System Modules pptp, h323, tftp, irc, sip, dns", log_file)
        log_command('cish -c "system auto-reboot-on-hang show"', "Show Status for Auto reboot system when kernel gets into a hang state is enabled", log_file)
        log_command('cish -c "show service-param"', "Show Status for Web Filtering Configurations for MTA, SMTP and Web HTTPS", log_file)
        log_command('cish -c "system diagnostics show version-info"', "System Check Information Details", log_file)
        log_command('cish -c "show ips-settings"', "System Check Information Details", log_file)
        log_command('cish -c "system ha show details"', "High Availability Check Information Details", log_file)
        log_command("curl -s https://raw.githubusercontent.com/sivel/speedtest-cli/master/speedtest.py | python -", "Run a speed test using speedtest-cli", log_file)
        log_command('smartctl -a /dev/sda |grep "Device Model";smartctl -a /dev/sda | grep "Firmware Version"', "Disk Model and Firmware Details", log_file)
        log_command('smartctl -a /dev/sdb |grep "Device Model";smartctl -a /dev/sdb | grep "Firmware Version"', "Disk Model and Firmware Details", log_file)
        log_command('grep -i "exception Emask .* SAct .* SErr .* action .*\|Unrecovered read error\|I/O error" /var/tslog/syslog.log*', "Check for Disk Errors", log_file)
        log_command('grep -i "DRDY ERR" /var/tslog/syslog.log*', "Check for Disk Errors", log_file)
        log_command('grep -i "drdy\|i/o\|segfault" /var/tslog/syslog.log*', "Check for Disk Errors", log_file)
        log_command('grep -i "media error" /var/tslog/syslog.log*', "Check for Disk Errors - This Particular error supports a straight RMA if the timestamp is recent and appliance has valid warranty", log_file)
        log_command('grep -i "call trace" /var/tslog/syslog.log*', "Check for Kernel Crash Errors", log_file)
        log_command('tar -czvf /var/log_Master-$(nvram get "#li.serial")-$(date +"%Y-%m-%d_at_%T_%Z").tar.gz /var/tslog/*.log* /var/tslog/*.gz* | ls -lah /var/log_Master*', "Compress Appliance Logs to be collected", log_file)
        log_command('tar -czvf /var/kdump_Master-$(nvram get "#li.serial")-$(date +"%Y-%m-%d_at_%T_%Z").tar.gz /var/crashkernel/* | ls -lah /var/kdump_Master*', "Compress Crash Kernel Dumps to be collected", log_file)
        log_command('tar -czvf /var/core_dump_Master-$(nvram get "#li.serial")-$(date +"%Y-%m-%d_at_%T_%Z").tar.gz /var/cores/* | ls -lah /var/core_dump_Master*', "Compress Core Dumps to be collected", log_file)
        

    except Exception as e:
        print(f"Error: {e}")

# Check if running as root
if os.geteuid() != 0:
    print("This script must be run as root")
    exit(1)

try:
    # Call main function
    main()
except KeyboardInterrupt:
    print("Script execution was manually interrupted by the user.")
    exit(1)
