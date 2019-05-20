#!/bin/bash

###################################################################################################
# Script Name:  jamf_RecoveryAgent.sh
# By:  Zack Thompson / Created:  2/14/2019
# Version:  1.4.0 / Updated:  5/20/2019 / By:  ZT
#
# Description:  This script checks the Jaßmf management framework, and if in an undesirable state, attempts to repair and/or re-enrolls the device into Jamf.
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

##################################################
# Define Variables

# Enter the FQDN of your Jamf Pro Server.
jamfURL="jps.company.com"
# Enter the port number of your Jamf Pro Server; this is usually 8443 -- change if needed.
jamfPort="8443"
# Expected value for the verifySSLCert key
expected_verifySSLCert="always"
# Set the GUID for the MDM Enrollment Profile.
mdmEnrollmentProfileID="00000000-0000-0000-A000-0A498DBD6646"
# Set the name of the JPS Root CA certificate.
jpsRootCA="Organization's JSS Built-in Certificate Authority"
# Set the SHA-1 hash of the JPS Root CA certificate.
jpsRootCASHA1="3FE77342FC69A07EEEA0C014AAC5BDBC6AE6FCFB"
# Set the Invintation ID.
invitationID="239475012374912374023478123402092374091"
# Set the custom trigger used to test Policies.
testTrigger="checkJRA"
# Set a custom plist domain.
plistdomain="com.github.mlbz521"

##################################################
# The below variables do not need to be modified.

# Jamf Pro Server
jpsURL="https://${jamfURL}:${jamfPort}/"
# Set the location to write logging information for later viewing.
logFile="/var/log/jamf_RecoveryAgent.log"
# Set location of local recovery files.
recoveryFiles="/private/var/jra"
# Get location of the Jamf Binary.
jamfBinary="/usr/local/jamf/bin/jamf"
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
defaultsCMD() {
    case $1 in
        "read" )
            /usr/bin/defaults read "${recoveryFiles}/${plistdomain}.jra.plist" "${2}" 2> /dev/null
        ;;
        "write" )
            /usr/bin/defaults write "${recoveryFiles}/${plistdomain}.jra.plist" "${2}" "${3}" 2> /dev/null
        ;;
        "delete" )
            /usr/bin/defaults delete "${recoveryFiles}/${plistdomain}.jra.plist" "${2}" 2> /dev/null
        ;;
    esac
}

# This function handles the exit process of the script.
exitProcess() {
    writeToLog "Result: ${1}"
    defaultsCMD write last_Result "${1}"
    writeToLog "*****  jamf_RecoveryAgent Process:  COMPLETE  *****"
    exit $2
}

repairPerformed() {
    timeStamp=$( /bin/date +%Y-%m-%d\ %H:%M:%S )
    previousTotal=$( defaultsCMD read "${1}" )

    if [[ $? == 0 ]]; then
        newTotal=$((previousTotal + 1))
    else
        newTotal=1
    fi

    writeToLog "A { ${1} } repair was performed for the ${newTotal} time."
    defaultsCMD write "${1}" $newTotal
    defaultsCMD write repair_performed "Performed:  ${1} (${newTotal})${2}"
    defaultsCMD write repair_date "${timeStamp}"
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
         writeToLog "  -> Proper permissions set"
    else
        writeToLog "  -> WARNING:  Improper permissions found!"
        writeToLog "    -> Currently they are:  ${currentPermissions} ${currentOwner}"
        writeToLog "      -> Setting proper permissions..."
        /usr/bin/chflags noschg "${jamfBinary}"
        /usr/bin/chflags nouchg "${jamfBinary}"
        /usr/sbin/chown root:wheel "${jamfBinary}"
        /bin/chmod 555 "${jamfBinary}"
        repairPerformed "Reset Permissions"
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
writeToLog "Testing if the device has an active network interface..."
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
writeToLog "Testing the Jamf Binary..."

if [[ -e "${jamfBinary}" ]]; then
    checkBinaryPermissions
else
    writeToLog "  -> WARNING:  Unable to locate the Jamf Binary!"
    restoreJamfBinary
fi

# Check the 'health' of the Jamf Management Framework.
writeToLog "Checking the health of the management framework..."

# Does the Jamf Application Support folder exists?
if [[ ! -e "/Library/Application Support/JAMF" ]]; then
    writeToLog "  -> WARNING:  The Jamf Application Support folder is missing!"
    reenroll " / Missing Application Support"
fi

# Does the JAMF.keychain exists?
writeToLog "Checking if the Jamf Keychain exists..."

if [[ -e "/Library/Application Support/JAMF/JAMF.keychain" ]]; then
    writeToLog "  -> True"
elif [[ -e "${recoveryFiles}/JAMF.keychain" ]]; then
    writeToLog "  -> WARNING:  Jamf Keychain is missing!"
    /bin/cp -f "${recoveryFiles}/JAMF.keychain"  "/Library/Application Support/JAMF/JAMF.keychain"
    repairPerformed "Restored Jamf Keychain"
else
    writeToLog "  -> WARNING:  Unable to locate the Jamf Keychain!"
    reenroll "Missing Jamf Keychain"
fi

# Does the Jamf Software configuration exist and is it configured as expected?
writeToLog "Checking the Jamf Configuration..."
if [[ -e "/Library/Preferences/com.jamfsoftware.jamf.plist" ]]; then
    jss_url=$( /usr/bin/defaults read "/Library/Preferences/com.jamfsoftware.jamf" jss_url )
    
    if [[ "${jss_url}" == "${jpsURL}" ]]; then
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

if [[ -e "${recoveryFiles}/jamf" ]]; then
    jamfBinaryVersion=$( "${jamfBinary}" version | /usr/bin/awk -F 'version=' '{print $2}' | /usr/bin/xargs )
    jamfRecoveryBinaryVersion=$( "${recoveryFiles}/jamf" version | /usr/bin/awk -F 'version=' '{print $2}' | /usr/bin/xargs )

    # Compares the current version and updates if there is a newer binary available.
    if [[ "${jamfBinaryVersion}" == "${jamfRecoveryBinaryVersion}" ]]; then
        writeToLog "  -> Current"
    else
        writeToLog "  -> Updating recovery Jamf Binary"
        /bin/cp -f "${jamfBinary}" "${recoveryFiles}"
        defaultsCMD write latest_JamfBinaryVersion "${jamfBinaryVersion}"
    fi
else
    writeToLog "  -> Creating a recovery Jamf Binary"
    /bin/cp -f "${jamfBinary}" "${recoveryFiles}"
    defaultsCMD write latest_JamfBinaryVersion "${jamfBinaryVersion}"
fi

# Backup the Jamf Keychain and server configuration.
/bin/cp -f "/Library/Application Support/JAMF/JAMF.keychain" "${recoveryFiles}"

exitProcess "Enabled" 0