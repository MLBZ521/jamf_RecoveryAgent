jamf_RecoveryAgent
======

A LaunchDaemon that monitors the health of the Jamf Management Framework.

**New:**  Added support to remove the JRA for situations where the device needs to be legitimately unmanaged and will not be wiped.  `setup_JamfRecoveryAgent.sh` expects either `Install` or `Uninstall` passed via Script Parameter 1.

## Overview

Essentially this workflow checks the Jamf management framework, and if in an undesirable state, attempts to repair and/or re-enrolls the device into Jamf.

Inspired by several other projects and discussions:
  * Rich Trouton/(derflounder)'s CasperCheck
    * https://github.com/rtrouton/CasperCheck
  * Several Jamf projects:
    * https://github.com/jamf/autoenroll
    * https://github.com/jamf/JSSBinarySelfHeal
  * And all the sites and threads I've read regarding Jamf managed state recovery methods

I started to work on this project quite a while ago, but stopped after the release of the "Re-enrollment Settings" introduced in Casper v9.9x.  This change affected device record by, optionally, erasing specific content, and flushing policy logs.  So, having a process to "heal" or "re-enroll" a device, not only could trigger enrollment policies, but erase information that could be accurate and which you may not want erased.

Then Apple introduced the concept of "User Approved" MDM enrollment.  So, re-enrolling a device through a non-User Approved method, changes the status of the device in Jamf.  

Which leads me to the difference between this project and similar projects.  My main desire is to *not* re-enroll a device that has an issue, but as a last resort, attempt a re-enroll.  This process will attempt to resolve any issues, before attempting a non-User Approved enrollment.  I figured a non-User Approved enrollment is better than no enrollment at all.

Obviously this process is not fool proof, a smart user can remove it.

Another difference is I prefer, whenever possible, to deploy things of this nature, via a script only and not a package.  In my environment, scripts are hosted in the Jamf Pro Database, so a distribution point does not need to be accessible by the client if they're off network.  This is actually no longer needed in my environment, but I still feel it is more efficient.


## Details

So what *does* this project do?  It creates a copy of the files and information needed to repair the management framework without needing to re-enroll (if possible).

It backs up the following files:
  * Jamf Binary
    * And will check for, and backup a newer binary version, after upgrade
  * JAMF.keychain

And from `/Library/Preferences/com.jamfsoftware.jamf.plist` records:
  * jss_url
  * verifySSLCert

With this information, a device can have the Jamf Management Framework and it's connection to the Jamf Pro Server restored.  It will also resolve other common issues that can cause issues to the Management Framework.

A LaunchDaemon is configured to run every seven days or upon a change to the following locations:
  * /usr/local/bin/jamf
  * /usr/local/jamf/bin/jamf

The process logs all details to the following log:  `/var/log/jamf_RecoveryAgent.log`.  See the [Example Files](../master/Example%20Files) folder for samples.

The workflow is configured to only attempt to reinstate the Management Framework once and then a re-enroll once per run (this is configurable) so as not to have an endless loop occurring.

An Extension Attribute is available to report on the status of the JRA as well.


## Workflow

This flowchart goes through the steps the JRA goes through to test the state of the Management Framework on a device.

<img src="https://github.com/MLBZ521/jamf_RecoveryAgent/blob/master/images/flowchart.png"/>

## Setup

#### To utilize this process, you need to do the following: 
  * Add script and Extension Attribute to the JPS
  * Create two policies
  * Customize a few files

##### Customize:
  * Edit the variables needed in the script
    * `jamf_RecoveryAgent.sh`
  * Edit the plist domain as desired and match the Label value as well.
    * `com.github.mlbz521.RecoveryAgent.plist`
  * Run the `build_JamfRecoveryAgent.sh` script which will create the script
    * `setup_JamfRecoveryAgent.sh`

##### Upload:
  * Add the following files into Jamf:
    * `setup_JamfRecoveryAgent.sh`
    * `jamf_ea_JamfRecoveryAgent.sh`

##### Policies:
  * Policy 1
    * Purpose:  Installs the Jamf Recovery Agent
    * Event:
      * Recurring Check-in
      * Enrollment
    * Frequency:  Once Per Computer
    * Scope:
      * Target:  All Computers
    * Scripts Payload
      * Add the `setup_JamfRecoveryAgent.sh` Script
        * Script Parameter 1:  [ Install | Uninstall ]
  * Policy 2
    * Purpose:  Validation Policy that is called by a Custom Trigger
    * Event:
      * Custom:  `checkJRA`
    * Frequency:  Ongoing
    * Scope:
      * Target:  All Computers
    * Files and Processes Payload
      * Run command:  `echo "Policy Execution Successful!"`
