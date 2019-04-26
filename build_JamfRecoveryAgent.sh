#!/bin/bash

###################################################################################################
# Script Name:  build_JamfRecoveryAgent.sh
# By:  Zack Thompson / Created:  2/20/2019
# Version:  1.1.0 / Updated:  4/25/2019 / By:  ZT
#
# Description:  Builds the "setup" script for the JRA.
#
###################################################################################################

# Set working directory
cwd=$( /usr/bin/dirname "${0}" )
jraScript=$( /bin/ls "${cwd}" | /usr/bin/grep "jamf_RecoveryAgent.sh" )
launchDaemon=$( /bin/ls "${cwd}" | /usr/bin/grep -E ".*RecoveryAgent.plist" | /usr/bin/sed 's/.plist//g' )

# Insert code
/bin/cat > "${cwd}/setup_JamfRecoveryAgent.sh" <<'EOFbuild'
#!/bin/bash

###################################################################################################
# Script Name:  setup_JamfRecoveryAgent.sh
# By:  Zack Thompson / Created:  2/20/2019
# Version:  1.1.0 / Updated:  4/25/2019 / By:  ZT
#
# Description:  This script installs or uninstalls the JRA.
#
###################################################################################################

echo "*****  setup_JamfRecoveryAgent process:  START  *****"

##################################################
# Define Variables

action="${4}"
stageLocation="/private/var/jra"
scriptLocation="${stageLocation}/jamf_RecoveryAgent.sh"
EOFbuild

# Insert code
echo "launchDaemonLabel=\"${launchDaemon}\"" >> "${cwd}/setup_JamfRecoveryAgent.sh"

# Insert code
/bin/cat >> "${cwd}/setup_JamfRecoveryAgent.sh" <<'EOFbuild'
launchDaemonLocation="/Library/LaunchDaemons/${launchDaemonLabel}.plist"
osVersion=$(/usr/bin/sw_vers -productVersion | /usr/bin/awk -F '.' '{print $2}')

##################################################
# Bit staged...

case $action in

    "Install" )
        echo "** Installing the Jamf Recovery Agent **"

		# Create the script...
		echo "Creating the Script..."
		/bin/mkdir -p "${stageLocation}"

		/bin/cat > "${scriptLocation}" <<'EOF'
EOFbuild

# Insert code
/bin/cat "${cwd}/${jraScript}" >> "${cwd}/setup_JamfRecoveryAgent.sh"

# Insert code
/bin/cat >> "${cwd}/setup_JamfRecoveryAgent.sh" <<'EOFbuild'

EOF


		# Create the Launch Daemon...
		echo "Creating the LaunchDaemon..."

		/bin/cat > "${launchDaemonLocation}" <<EOF
EOFbuild

# Insert code
/bin/cat "${cwd}/${launchDaemon}.plist" >> "${cwd}/setup_JamfRecoveryAgent.sh"

# Insert code
/bin/cat >> "${cwd}/setup_JamfRecoveryAgent.sh" <<'EOFbuild'

EOF

		# Verify the files exist...
		if [[ -e "${scriptLocation}" && -e "${launchDaemonLocation}" ]]; then

			echo "Setting permissions on the script..."
			/bin/chmod 744 "${scriptLocation}"

			# Check if the LaunchDaemon is running, if so restart it in case a change was made to the plist file.
			# Determine proper launchctl syntax based on OS Version.
			if [[ $osVersion -ge 11 ]]; then
				exitCode=$( /bin/launchctl print system/$launchDaemonLabel > /dev/null 2>&1; echo $? )

				if [[ $exitCode == 0 ]]; then
					echo "LaunchDaemon is currently started; stopping now..."
					/bin/launchctl bootout system/$launchDaemonLabel
				fi

				echo "Loading LaunchDaemon..."
				/bin/launchctl bootstrap system "${launchDaemonLocation}"
				/bin/launchctl enable system/$launchDaemonLabel

			elif [[ $osVersion -le 10 ]]; then
				exitCode=$(/bin/launchctl list $launchDaemonLabel > /dev/null 2>&1; echo $? )

				if [[ $exitCode == 0 ]]; then
					echo "LaunchDaemon is currently started; stopping now..."
					/bin/launchctl unload "${launchDaemonLocation}"
				fi

				echo "Loading LaunchDaemon..."
				/bin/launchctl load "${launchDaemonLocation}"
			fi

			echo "*****  setup_JamfRecoveryAgent process:  COMPLETE  *****"
		else
			echo "*****  setup_JamfRecoveryAgent process:  FAILED  *****"
			exit 1
		fi
	;;

    "Uninstall" )
        echo "Uninstalling the Jamf Recovery Agent..."
        # Check if the LaunchDaemon is running.
        # Determine proper launchctl syntax based on OS Version.
        if [[ $osVersion -ge 11 ]]; then
            exitCode=$( /bin/launchctl print system/$launchDaemonLabel > /dev/null 2>&1; echo $? )

            if [[ $exitCode == 0 ]]; then
                echo "Stopping the JRA LaunchDaemon..."
                /bin/launchctl bootout system/$launchDaemonLabel
            fi
        elif [[ $osVersion -le 10 ]]; then
            exitCode=$(/bin/launchctl list $launchDaemonLabel > /dev/null 2>&1; echo $? )

            if [[ $exitCode == 0 ]]; then
                echo "Stopping the JRA LaunchDaemon..."
                /bin/launchctl unload "${launchDaemonLocation}"
            fi
        fi

        echo "Removing files..."
        /bin/rm -f "${launchDaemonLocation}"
        /bin/rm -rf "${stageLocation}"
    ;;

esac

exit 0
EOFbuild

exit 0