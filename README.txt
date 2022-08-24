###########
#
# Sync Users
# BladeLogic, Inc.
# Tim Fessenden, October 28, 2004
#
# Updated:	Bill Robinson, May 1, 2006
#		-Removed need for Vbs script, runs all in 1 script using dsquery, dsget
#		-Removed ACL Push
# Updated:	Bill Robinson, June 1, 2006
#		-Made the UPN and Logon domain variables
# Updated:      Bill Robinson Dec 19, 2006
#               -Made the ldap query a variable, other clean ups
# Updated: 	Bill Robinson Jan 10, 2007
#		-Properly handle blank lines in the roles.txt file
#		-Fixed incorrect results while creating users and roles
# Updated: 	Bill Robinson Mar 13, 2007
#		-Added check of target server - script exits if not available
#		-Allowed comments in the roles.txt file
# Updated: 	Bill Robinson Jul 13, 2007
#		-Modified to run on Unix or Windows
# Updated: 	2.9 Bill Robinson Aug 31, 2007
#		-Fixed control character issue in user names
# Updated:	2.9.1 Bill Robinson Sep 06, 2007
#		-Added default acl template to roles
# Updated:	2.9.2 Frank Lamprea Jan 25, 2008
#		-Added enable/disable for RBAC users
		-Properly handle failed/empty LDAP queries
		-Added additional error checking to "Prune Users"
		-Changed default acl template to roles only when role is newly created
# Updated:	2.9.3 Frank Lamprea Jan 30, 2008
		-Removed setting of default acl template (not needed)
		-Fixed path to use kinit in default install (/usr/nsh/br/java/bin/kinit)
		-Converted script to use NSH/BLCLI performance commands
		-As of 2.9.3 script is no longer compatibe with pre-7.4.x releases.
# Updated:	2.9.4 Frank Lamprea Feb 5, 2008
		-Added LDAP_SYNC property (boolean) requirement to "User" Class. This property
		 acts as a filter optionally skipping a user if the flag is set to false.
# Updated:	2.9.5 Frank Lamprea June 1, 2008
		-Added additional Error Checking	
# Updated:	3.0.0 Frank Lamprea March 30,2009
		-Added support for 7.5 user account segmentation
#
###
# 
# NSH Execution: Type 1 script (runscript)
#
# PARAMETERS:
#     - Path to file containing roles to sync
#     - Flag to decide whether to prune users from the roles
#     - Flag to decide whether to prune users from RBAC
#     - Flag to decide whether to disable users in RBAC (not implemented)
###
#
# This script uses the blcli to perform a one-way sync (pull) from a user store
# (typically Active Directory) into RBAC. It is to be used in conjunction
# with BladeLogic's Kerberos implementation to provide single sign-on
# capability to end users. Specifically, after querying the user store for
# user and role information, it performs the following actions:
#    - Creates new users in RBAC
#    - Creates new Roles in RBAC
#    - Adds users to RBAC roles
#    - Removes users from RBAC roles (optional)
#    - Removes users from RBAC all together (optional)
#    - Disabled users in RBAC (optional)
#
###
#
# ASSUMPTIONS:
#    - Usernames do not have spaces in their names
#    - The User you are running this script in is in both the RBACAdmins and BLAdmins roles
#    - The BladeLogic RBAC Administrator must setup newly created Roles with the proper ACL templates, Authorizations, etc
#    - The commandline dsquery and dsget or ldapsearch tools are available on the system
#    - the users are returned in the format "username" and you know the domain/realm the accounts exist in - eg @SUB.DOMAIN.COM
#    - At least ONE user must exist in a domain group
#    - you have installed the included custom command xml files in the proper location
#    - MAKE SURE THE SYSTEM TIME IS IN SYNC between all systems.
	 - "User" Class has a property LDAP_SYNC (Boolean type) with a default of TRUE.
############

The roles.txt file is of the format:
RBAC Role+LDAP Query+Logon Domain

RBAC Role is the Role in RBAC you want to populate.
LDAP Query is the full query command you need to run - this could be an ldapsearch or dsquery for example
Logon Domain is the user's logon domain to AD

Note that '+' is the delimeter.

Currently the script looks for the AD/LDAP query in the roles.txt file.
Your query may have to included text parsing to filter out any non-group related information.  
The roles.txt file included includes a few examples.

On Linux you must have the openldap-clients and cyrus-sasl-gssapi RPMS installed.

On Linux and Solaris we utilize kinit to get an authenticated ticket from AD for the same user the Application Server 
uses for the AD integration specified in the product docs.  The ldapsearch command is then required to use GSSAPI
authentication to bind to the directory for query execution.

