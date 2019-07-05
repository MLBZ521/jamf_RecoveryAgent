#!/bin/bash

###################################################################################################
# Script Name:  jamf_ea_JamfRecoveryAgent.sh
# By:  Zack Thompson / Created:  2/20/2019
# Version:  1.2.0 / Updated:  5/30/2019 / By:  ZT
#
# Description:  A Jamf Extension Attribute to get the last reported status of the JRA.
#
###################################################################################################

# Set location of the JRA Plist.
jraPlist="/private/var/jra/jra.plist"

# This is a helper function to interact with the JRA plist.
defaultsCMD() {
    case $1 in
        "read" )
            /usr/bin/defaults read "${jraPlist}" $2 2> /dev/null
        ;;
        "write" )
            /usr/bin/defaults write "${jraPlist}" $2 "${3}" 2> /dev/null
        ;;
        "delete" )
            /usr/bin/defaults delete "${jraPlist}" $2 2> /dev/null
        ;;
    esac
}

if [[ -e "${jraPlist}" ]]; then
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