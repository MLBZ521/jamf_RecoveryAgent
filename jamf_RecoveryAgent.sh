#!/bin/bash

###################################################################################################
# Script Name:  jamf_RecoveryAgent.sh
# By:  Zack Thompson / Created:  2/14/2019
# Version:  1.4.0b / Updated:  5/30/2019 / By:  ZT
#
# Description:  This script checks the Jamf management framework, and if in an undesirable state, attempts to repair and/or re-enrolls the device into Jamf.
#
# Inspired by several other projects and discussions on JamfNation:
#    Rich Trouton/(derflounder)'s CasperCheck
#       - https://github.com/rtrouton/CasperCheck
#    Several Jamf projects:
#       - https://github.com/jamf/autoenroll
#       - https://github.com/jamf/JSSBinarySelfHeal
#    And all the sites and threads I've read regarding Jamf managed state recovery methods
#
###################################################################################################

echo "*****  jamf_RecoveryAgent process:  START  *****"

##################################################
# Script Parameters

# Install or uninstall the agent
action="${4}"
# Enter the Jamf Pro Server FQDN
jamfURL="${6}" # "jps.company.com"
# verifySSLCert Key
expected_verifySSLCert="${7}" # "always"
# JPS Root CA Certificate Common Name
jpsRootCA="${8}" # "Organization's JSS Built-in Certificate Authority"
# JPS Root CA Certificate SHA-1 Hash
jpsRootCASHA1="${9}" # "3FE77342FC69A07EEEA0C014AAC5BDBC6AE6FCFB"
# Invitation ID
invitationID="${10}" # "239475012374912374023478123402092374091"
# Custom Trigger for Test Policy
testTrigger="${11}" # "checkJRA"

##################################################

case $action in

    "Install" )
        echo "** Installing the Jamf Recovery Agent **"

        /bin/cat > "/etc/periodic/weekly/100.jra" <<'EOF'
#!/bin/bash

echo ""
echo "Running the Jamf Recovery Agent..."

##################################################
# Define Variables
EOF

        # Insert code
        echo "jamfURL=\"${jamfURL}\"" >> "/etc/periodic/weekly/100.jra"
        echo "expected_verifySSLCert=\"${expected_verifySSLCert}\"" >> "/etc/periodic/weekly/100.jra"
        echo "jpsRootCA=\"${jpsRootCA}\"" >> "/etc/periodic/weekly/100.jra"
        echo "jpsRootCASHA1=\"${jpsRootCASHA1}\"" >> "/etc/periodic/weekly/100.jra"
        echo "invitationID=\"${invitationID}\"" >> "/etc/periodic/weekly/100.jra"
        echo "testTrigger=\"${testTrigger}\"" >> "/etc/periodic/weekly/100.jra"

        /bin/cat >> "/etc/periodic/weekly/100.jra" <<'EOF'

##################################################
# Only modify the below variables if needed.

# Enter the port number of your Jamf Pro Server; this is usually 8443 -- change if needed.
jamfPort="8443"
# Set the GUID for the MDM Enrollment Profile.
mdmEnrollmentProfileID="00000000-0000-0000-A000-4A414D460003"
# Jamf Pro Server
jpsURL="https://${jamfURL}:${jamfPort}/"
# Set the location to write logging information for later viewing.
logFile="/var/log/jamf_RecoveryAgent.log"
# Set location of local recovery files.
recoveryFiles="/private/var/jra"
# Location of the Jamf Binary.
jamfBinary="/usr/local/jamf/bin/jamf"
# Location of Jamf Keychain
jamfKeychain="/Library/Application Support/JAMF/JAMF.keychain"
# Set the number of jamf manage attempts.
maxManageAttempts=1
manageAttempts=0

# Check the version of the profiles utiliy.
profilesCMDVersion=$( /usr/bin/profiles version | /usr/bin/awk -F 'version: ' '{print $2}' | /usr/bin/xargs )
if [[ $profilesCMDVersion == "6.01" ]]; then
    profilesCMD="list"
else
    profilesCMD="-P"
fi

##################################################
# Helper Functions

# This function writes to the defined log.
writeToLog() {
    timeStamp=$( /bin/date +%Y-%m-%d\ %H:%M:%S )
    message="${1}"
    echo "${timeStamp}:  ${message}" >> "${logFile}"
}

# This is a helper function to interact with the JRA plist.
defaultsJRA() {
    case $1 in
        "read" )
            /usr/bin/defaults read "${recoveryFiles}/jra.plist" "${2}" 2> /dev/null
        ;;
        "write" )
            /usr/bin/defaults write "${recoveryFiles}/jra.plist" "${2}" "${3}" 2> /dev/null
        ;;
        "delete" )
            /usr/bin/defaults delete "${recoveryFiles}/jra.plist" "${2}" 2> /dev/null
        ;;
    esac
}

# This function handles the exit process of the script.
exitProcess() {
    writeToLog "Result: ${1}"
    defaultsJRA write last_Result "${1}"
    writeToLog "*****  jamf_RecoveryAgent Process:  COMPLETE  *****"
    echo "Jamf Recovery Agent Result: ${1}..."
    exit $2
}

repairPerformed() {
    timeStamp=$( /bin/date +%Y-%m-%d\ %H:%M:%S )
    previousTotal=$( defaultsJRA read "${1}" )

    if [[ $? == 0 ]]; then
        newTotal=$((previousTotal + 1))
    else
        newTotal=1
    fi

    writeToLog "A { ${1} } repair was performed for the ${newTotal} time."
    defaultsJRA write "${1}" $newTotal
    defaultsJRA write repair_performed "Performed:  ${1} (${newTotal})${2}"
    defaultsJRA write repair_date "${timeStamp}"
}

##################################################
# Logic Functions

# Verifies that the Jamf binary can successfully communicate with the Jamf Pro Server; returns result.
checkBinaryConnection() {
    writeToLog "Testing if the Jamf Binary can communicate with the JPS..."
    binaryCommunication=$( "${jamfBinary}" checkJSSConnection > /dev/null; echo $? )

    if [[ "$binaryCommunication" -eq 0 ]]; then
        writeToLog "  -> Success"
    else
        writeToLog "  -> Failed"
        exitProcess "Binary cannot communicate with JPS" 3
    fi
}

# Checking the permissions on the Jamf binary; returns result.
checkBinaryPermissions() {
    writeToLog "Verifying the Jamf Binary permissions..."
    currentPermissions=$( /usr/bin/stat -f "%OLp" "${jamfBinary}" )
    currentOwner=$( /usr/bin/stat -f "%Su:%Sg" "${jamfBinary}" )

    # Verifying Permissions
    if [[ $currentPermissions == "555" && $currentOwner == "root:wheel" ]]; then
        writeToLog "  -> Valid"
    else
        writeToLog "  -> WARNING:  Improper permissions found!"
        writeToLog "    -> Currently they are:  ${currentPermissions} ${currentOwner}"
        writeToLog "      -> Setting proper permissions..."
        /usr/bin/chflags noschg "${jamfBinary}"
        /usr/bin/chflags nouchg "${jamfBinary}"
        /usr/sbin/chown root:wheel "${jamfBinary}"
        /bin/chmod 555 "${jamfBinary}"
        repairPerformed "Reset Binary Permissions"
    fi
}

# Restore the Jamf Binary.
restoreJamfBinary() {
    writeToLog "  -> NOTICE:  Restoring the Jamf Binary!"

    # Check if the Recovery Binary exists and restore it if not.
    if [[ ! -e "${recoveryFiles}/jamf" ]]; then
        writeToLog "  -> WARNING:  Unable to locate the Jamf Binary in the Recovery Files!"
        writeToLog "    -> Downloading binary from the JPS..."
        curlReturn="$(/usr/bin/curl --silent --show-error --fail --write-out "statusCode:%{http_code}" --output "${recoveryFiles}/jamf" --request GET "${jpsURL}bin/jamf")"
        curlCode=$(echo "$curlReturn" | /usr/bin/awk -F statusCode: '{print $2}')
    	if [[ $curlCode != "200" ]]; then
            writeToLog "  -> ERROR:  Failed to restore the Jamf Binary!"
            exitProcess "Missing Recovery Jamf Binary" 4
	    fi
    fi

    # Create the directory structure and ensure the proper permisssions are set.
    /bin/mkdir -p /usr/local/jamf/bin /usr/local/bin
    /bin/cp -f "${recoveryFiles}/jamf"  "${jamfBinary}"
    /bin/ln -s "${jamfBinary}" /usr/local/bin
    checkBinaryPermissions
    repairPerformed "Restored Binary"
}

# Running a manual policy trigger to check jamf binary functionality; returns result.
checkValidationPolicy () {
    writeToLog "Testing if device can run a Policy..."
    checkPolicy=$( "${jamfBinary}" policy -event $testTrigger )
    checkPolicyResults=$( echo "${checkPolicy}" | /usr/bin/grep "Policy Execution Successful!" )

    if [[ -n "${checkPolicyResults}" ]]; then
        writeToLog "  -> Success"
    else
        writeToLog "  -> WARNING:  Unable to execute Policy!"
        manage " / Failed Validation Policy"

        # After attempting to recover, try executing again.
        checkValidationPolicy
    fi
}

# Creates the config and runs the `jamf manage` command.
manage() {
    if [[ $maxManageAttempts -gt $manageAttempts ]]; then
        writeToLog "  -> NOTICE: Enabling the Management Framework"

        # Create the /Library/Preferences/com.jamfsoftware.jamf plist if it doesn't exist and set the proper values
        "${jamfBinary}" createConf -url "${jpsURL}" -verifySSLCert "${expected_verifySSLCert}"

        "${jamfBinary}" manage #? -forceMdmEnrollment
        repairPerformed "jamf manage" " / ${1}"
        manageAttempts=$(( manageAttempts + 1 ))

    elif [[ $maxManageAttempts -eq $manageAttempts ]]; then
        reenroll "${1}"
        manageAttempts=$(( manageAttempts + 1 ))
    else
        exitProcess "Unable to repair" 5
    fi
}

# Reenrolls with an enrollment Invitation ID.
reenroll() {
    writeToLog "  -> NOTICE: Reenrolling into Jamf"
    "${jamfBinary}" enroll -invitation "${invitationID}" -noRecon -noPolicy -reenroll -archiveDeviceCertificate
     repairPerformed "jamf enroll" " / ${1}"
}

# Run the 'jamf removeMdmProfile' command.
removeMdmProfile() {
    writeToLog "  -> WARNING: Removing the MDM Profile!"
    "${jamfBinary}" removeMdmProfile
}

# Run the 'jamf removeFramework' command.
removeFramework() {
    writeToLog "  -> WARNING: Removing the Management Framework!"
    "${jamfBinary}" removeFramework #? -keepMDM
}

##################################################
# Bits staged...

writeToLog "*****  jamf_RecoveryAgent Process:  START  *****"

# Verify client is not currently enrolling.
while true
jamfEnrollStatus=$( /bin/ps aux | /usr/bin/grep -E "[j]amf enroll|[j]amf update" | /usr/bin/wc -l )
do
    if [ "${jamfEnrollStatus}" -gt 0 ]; then
        writeToLog "Conflicting prcoess is running; waiting..."
        /bin/sleep 5
    else
        break
    fi
done

# Check for a valid IP address and can connect to the "outside world"; returns result.
writeToLog "Checking for an active network interface..."
defaultInterfaceID=$( /sbin/route get default | /usr/bin/awk -F 'interface: ' '{print $2}' | /usr/bin/xargs )
linkStatus=$( /sbin/ifconfig "${defaultInterfaceID}" | /usr/bin/awk -F 'status: ' '{print $2}' | /usr/bin/xargs )

if [[ "${linkStatus}" == "active" ]]; then
    writeToLog "  -> Active interface:  ${defaultInterfaceID}"
else
    writeToLog "  -> Notice:  Device is offline"
    exitProcess "Device is offline" 1
fi

# Verifies that the Jamf Pro Servers' Tomcat service is responding via its assigned port; returns result.
writeToLog "Testing if the Jamf web service available..."
webService=$( /usr/bin/nc -z -w 5 $jamfURL $jamfPort > /dev/null 2>&1; echo $? )

if [ "${webService}" -eq 0 ]; then
    writeToLog "  -> Success"
else
    writeToLog "  -> Failed"
    exitProcess "JPS Web Service Unavailable" 2
fi

# Verify the Binary exists first.
writeToLog "Verifying the Jamf Binary exists..."

if [[ -e "${jamfBinary}" ]]; then
    writeToLog "  -> True"
    checkBinaryPermissions
else
    writeToLog "  -> WARNING:  Unable to locate the Jamf Binary!"
    restoreJamfBinary
fi

# Does the Jamf Application Support folder exists?
if [[ ! -e "/Library/Application Support/JAMF" ]]; then
    writeToLog "  -> WARNING:  The Jamf Application Support folder is missing!"
    reenroll " / Missing Application Support"
fi

# Does the JAMF.keychain exists?
writeToLog "Verifying the Jamf Keychain exists..."

if [[ -e "${jamfKeychain}" ]]; then
    writeToLog "  -> True"
elif [[ -e "${recoveryFiles}/JAMF.keychain" ]]; then
    writeToLog "  -> WARNING:  Jamf Keychain is missing!"
    /bin/cp -f "${recoveryFiles}/JAMF.keychain"  "${jamfKeychain}"
    repairPerformed "Restored Jamf Keychain"
else
    writeToLog "  -> WARNING:  Unable to locate the Jamf Keychain!"
    reenroll "Missing Jamf Keychain"
fi

# Checking the permissions on the Jamf Keychain; returns result.
writeToLog "Verifying the Jamf Keychain permissions..."
currentPermissions=$( /usr/bin/stat -f "%OLp" "${jamfKeychain}" )
currentOwner=$( /usr/bin/stat -f "%Su:%Sg" "${jamfKeychain}" )

# Verifying Permissions
if [[ $currentPermissions == "600" && $currentOwner == "root:admin" ]]; then
    writeToLog "  -> Valid"
else
    writeToLog "  -> WARNING:  Improper permissions found!"
    writeToLog "    -> Currently they are:  ${currentPermissions} ${currentOwner}"
    writeToLog "      -> Setting proper permissions..."
    /usr/bin/chflags noschg "${jamfKeychain}"
    /usr/bin/chflags nouchg "${jamfKeychain}"
    /usr/sbin/chown root:admin "${jamfKeychain}"
    /bin/chmod 600 "${jamfKeychain}"
    repairPerformed "Reset Keychain Permissions"
fi

# Does the Jamf Software configuration exist and is it configured as expected?
writeToLog "Checking local configuration..."
if [[ -e "/Library/Preferences/com.jamfsoftware.jamf.plist" ]]; then
    jss_url=$( /usr/bin/defaults read "/Library/Preferences/com.jamfsoftware.jamf" jss_url )

    if [[ "${jss_url}" == "${jpsURL}" ]]; then
        writeToLog "  -> Valid"
        checkBinaryConnection
    else
        writeToLog "  -> WARNING:  Unexpected JPS URL Specified!"
        /usr/bin/defaults write "/Library/Preferences/com.jamfsoftware.jamf" "${jpsURL}"
        repairPerformed "Set JPS Server"
    fi
else
    writeToLog "  -> WARNING:  Jamf configuration is missing!"
    "${jamfBinary}" createConf -url "${jpsURL}" -verifySSLCert "${expected_verifySSLCert}"
    repairPerformed "Restored Jamf Config"
fi

# Does system contain the JPS Root CA?
writeToLog "Checking if the JPS Root CA is installed..."
jpsRootCAPresent=$( /usr/bin/security find-certificate -Z -c "${jpsRootCA}" | /usr/bin/awk -F 'SHA-1 hash: ' '{print $2}' | /usr/bin/xargs )

if [[ "${jpsRootCAPresent}" == "${jpsRootCASHA1}" ]]; then
    writeToLog "  -> True"
else
    writeToLog "  -> WARNING:  Root CA is missing!"
    "${jamfBinary}" trustJSS
    repairPerformed "jamf trustJSS"
fi

# Does system contain the MDM Enrollment Profile?
writeToLog "Checking if the MDM Profile is installed..."
mdmProfilePresent=$( /usr/bin/profiles $profilesCMD | /usr/bin/grep "${mdmEnrollmentProfileID}" )

if [[ "${mdmProfilePresent}" != "" ]]; then
            writeToLog "  -> True"
    else
        writeToLog "  -> WARNING:  MDM Profile is missing!"
        manage " / Missing MDM Profile"
fi

# Run the checkValidationPolicy Function
checkValidationPolicy

# Update local recovery files.
writeToLog "Updating the Recovery Files..."
jamfBinaryVersion=$( "${jamfBinary}" version | /usr/bin/awk -F 'version=' '{print $2}' | /usr/bin/xargs )

if [[ -e "${recoveryFiles}/jamf" ]]; then
    jamfRecoveryBinaryVersion=$( "${recoveryFiles}/jamf" version | /usr/bin/awk -F 'version=' '{print $2}' | /usr/bin/xargs )

    # Compares the current version and updates if there is a newer binary available.
    if [[ "${jamfBinaryVersion}" == "${jamfRecoveryBinaryVersion}" ]]; then
        writeToLog "  -> Current"
    else
        writeToLog "  -> Updating recovery Jamf Binary"
        /bin/cp -f "${jamfBinary}" "${recoveryFiles}"
        defaultsJRA write latest_JamfBinaryVersion "${jamfBinaryVersion}"
    fi
else
    /bin/mkdir -p "${recoveryFiles}"
    writeToLog "  -> Creating a recovery Jamf Binary"
    /bin/cp -f "${jamfBinary}" "${recoveryFiles}"
    defaultsJRA write latest_JamfBinaryVersion "${jamfBinaryVersion}"
fi

# Backup the Jamf Keychain and server configuration.
/bin/cp -f "${jamfKeychain}" "${recoveryFiles}"

exitProcess "Enabled" 0
EOF

        # Verify the files exist...
        if [[ -e "/etc/periodic/weekly/100.jra" ]]; then
            echo "Setting permissions on the script..."
            /usr/sbin/chown root:wheel "/etc/periodic/weekly/100.jra"
            /bin/chmod 755 "/etc/periodic/weekly/100.jra"
        else
            echo "Jamf Recovery Agent not found!"
            echo "*****  jamf_RecoveryAgent process:  FAILED  *****"
            exit 1
        fi

    ;;

    "Uninstall" )
        echo "Uninstalling the Jamf Recovery Agent..."
        /bin/rm -f "/etc/periodic/weekly/100.jra"
    ;;

    "UninstallOld" )
        launchDaemonLabel="edu.asu.RecoveryAgent"
        launchDaemonLocation="/Library/LaunchDaemons/${launchDaemonLabel}.plist"
        osVersion=$( /usr/bin/sw_vers -productVersion | /usr/bin/awk -F '.' '{print $2}' )

        removeJRFiles() {
            echo "Removing files..."
            /bin/rm -f "${launchDaemonLocation}"
            /bin/rm -rf "${recoveryFiles}"
        }

        echo "Uninstalling the old Jamf Recovery Agent..."
        # Check if the LaunchDaemon is running.
        # Determine proper launchctl syntax based on OS Version.
        if [[ $osVersion -ge 11 ]]; then
            exitCode1=$( /bin/launchctl print system/$launchDaemonLabel > /dev/null 2>&1; echo $? )

            if [[ $exitCode1 == 0 ]]; then
                echo "Stopping the JRA LaunchDaemon..."
                /bin/launchctl bootout system/$launchDaemonLabel
                removeJRFiles
            fi

        elif [[ $osVersion -le 10 ]]; then
            exitCode1=$( /bin/launchctl list $launchDaemonLabel > /dev/null 2>&1; echo $? )

            if [[ $exitCode1 == 0 ]]; then
                echo "Stopping the JRA LaunchDaemon..."
                /bin/launchctl unload "${launchDaemonLocation}"
                removeJRFiles
            fi
        fi
    ;;
esac

echo "*****  jamf_RecoveryAgent process:  COMPLETE  *****"
exit 0