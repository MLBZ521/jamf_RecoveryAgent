#!/bin/bash

###################################################################################################
# Script Name:  jamf_ea_JamfRecoveryAgent.sh
# By:  Zack Thompson / Created:  2/20/2019
# Version:  1.1.1 / Updated:  4/26/2019 / By:  ZT
#
# Description:  A Jamf Extension Attribute to get the last reported status of the JRA.
#
###################################################################################################

# Set location of local recovery files.
recoveryFiles="/private/var/jra"
# Set a custom plist domain.
plistdomain="com.github.mlbz521"

# This is a helper function to interact with the JRA plist.
defaultsCMD() {
    case $1 in
        "read" )
            /usr/bin/defaults read "${recoveryFiles}/${plistdomain}.jra.plist" $2 2> /dev/null
        ;;
        "write" )
            /usr/bin/defaults write "${recoveryFiles}/${plistdomain}.jra.plist" $2 "${3}" 2> /dev/null
        ;;
        "delete" )
            /usr/bin/defaults delete "${recoveryFiles}/${plistdomain}.jra.plist" $2 2> /dev/null
        ;;
    esac
}

if [[ -e "${recoveryFiles}/${plistdomain}.jra.plist" ]]; then
    result=$( defaultsCMD read repair_performed )

    if [[ $? == 0 ]]; then
        defaultsCMD delete repair_performed
    	echo "<result>${result}</result>"
    else
        result=$( defaultsCMD read last_Result )

        if [[ $? == 0 ]]; then
            echo "<result>${result}</result>"
        else
            echo "<result>Not Reported</result>"
        fi
    fi
else
	echo "<result>Not Configured</result>"
fi

exit 0