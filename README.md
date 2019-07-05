jamf_RecoveryAgent
======

A process that monitors the health of the Jamf Management Framework.


**Change Log:**  
  * `jamf_RecoveryAgent.sh`
    * v1.1.0 = Added support to report a repair action was taken
    * v1.2.0 = Added logic to track how many repairs are performed for each repair action
    * v1.3.0 = Added additional verbosity to identify which step triggered a manage and reenroll repair action (This would be recorded in the plist for the EA to report); Checking if an update to the Jamf binary is being performed and waiting for that to complete before running
    * v1.4.0 = Switched to using periodic to control when to run the jra instead of a launchdaemon; didn't want to specify when exactly to run the jra as I didn't want all devices running it at the same time.  Peridoic will now control when to run the jra.

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

Which leads me to the difference between this project and similar projects.  My main desire is to *not* re-enroll a device that has an issue; a re-enroll is attempted as a last resort repair.  This process will attempt to resolve any issues, before attempting a non-User Approved enrollment.  I figured a non-User Approved enrollment is better than no enrollment at all.

Obviously this process is not fool proof, a smart user can remove it.

Another difference is I prefer, whenever possible, to deploy things of this nature, via a script only and not a package.  In my environment, scripts are hosted in the Jamf Pro Database, so a distribution point does not need to be accessible by the client if they're off network.  This is actually no longer needed in my environment, but I still feel it is more efficient.


## Details

So what *does* this project do?  It creates a copy of the files and information needed to repair the management framework without needing to re-enroll (if possible).

It creates backups of the following files:
  * Jamf Binary
    * And will check for, and backup a newer binary version, after upgrade
  * JAMF.keychain

With this information, a device can have the Jamf Management Framework and it's connection to the Jamf Pro Server restored.  It will also resolve other common symptoms that can cause issues to the Management Framework.

By default, this script will install itself into the weekly periodic folder, which as it's name suggests, will run the health check weekly when periodic runs.  If you wanted to run it daily or monthly, simply change "daily" to the desired term, throughout the script.

The process logs all details to the following log:  `/var/log/jamf_RecoveryAgent.log`.  See the [Example Files](../master/Example%20Files) folder for samples.

The workflow is configured to only attempt to reinstate the Management Framework once and then a re-enroll once per run (this is configurable) so as not to have an endless loop occurring.

An Extension Attribute is available to report on the status of the JRA as well.

The logic will record several pieces of information to a plist, which is located here:  `/private/var/jra/jra.plist`.  All repair attempts and how many times each repair has been performed is also tracked.  The EA will check if a repair was performed and report what was performed and how many times it was performed, otherwise, it will report that the local JRA is simply `Enabled`.


## Workflow

This flowchart goes through the steps the JRA goes through to test the state of the Management Framework on a device.

<img src="https://github.com/MLBZ521/jamf_RecoveryAgent/blob/master/images/flowchart.png"/>

## Setup

#### To utilize this process, you need to do the following: 
  * Add script and Extension Attribute to the JPS
  * Create two policies

##### Upload:
  * Add the following files into Jamf:
    * `setup_JamfRecoveryAgent.sh`
    * `jamf_ea_JamfRecoveryAgent.sh`

##### Policies:
  * Policy 1
    * Purpose:  Installs the Jamf Recovery Agent
      * Configure the Event, Frequency, and Scope however you normally deploy to your devices
    * Event:
      * Recurring Check-in
      * Enrollment
    * Frequency:  Once Per Computer
    * Scope:
      * Target:  All Computers
    * Scripts Payload
      * Add the `jamf_RecoveryAgent.sh` Script and set the Script Parameters
        * Script Parameter 1:  Install or uninstall the agent
          * [ `Install` | `Uninstall` ]
        * Script Parameter 2:  Enter the Jamf Pro Server FQDN
          * `jps.company.com`
        * Script Parameter 2:  verifySSLCert Key
          * `always`
        * Script Parameter 2:  JPS Root CA Certificate Common Name
          * `Organization's JSS Built-in Certificate Authority`
        * Script Parameter 2:  JPS Root CA Certificate SHA-1 Hash
          * `3FE77342FC69A07EEEA0C014AAC5BDBC6AE6FCFB`
        * Script Parameter 2:  Invitation ID
          * `239475012374912374023478123402092374091`
        * Script Parameter 2:  Custom Trigger for Test Policy
          * `checkJRA`
  * Policy 2
    * Purpose:  Validation Policy that is called by a Custom Trigger
    * Event:
      * Custom:  `checkJRA`
    * Frequency:  Ongoing
    * Scope:
      * Target:  All Computers
    * Files and Processes Payload
      * Run command:  `echo 'Policy Execution Successful!'`
