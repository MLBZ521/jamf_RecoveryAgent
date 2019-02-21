#!/bin/bash

###################################################################################################
# Script Name:  jamf_ea_JamfRecoveryAgent.sh
# By:  Zack Thompson / Created:  2/20/2019
# Version:  1.1.0 / Updated:  2/21/2019 / By:  ZT
#
# Description:  A Jamf Extension Attribute to get the last reported status of the JRA.
#
###################################################################################################

# Set location of local recovery files.
recoveryFiles="/private/var/jra"
# Set a custom plist domain.
plistdomain="com.github.mlbz521"

if [[ -e "${recoveryFiles}/${plistdomain}.jra.plist" ]]; then
    result=$( /usr/bin/defaults read "${recoveryFiles}/${plistdomain}.jra.plist" repair_performed )

    if [[ $? == 0 ]]; then
        /usr/bin/defaults delete "${recoveryFiles}/${plistdomain}.jra.plist" repair_performed
    	echo "<result>${result}</result>"
    else
        result=$( /usr/bin/defaults read "${recoveryFiles}/${plistdomain}.jra.plist" last_Result )

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