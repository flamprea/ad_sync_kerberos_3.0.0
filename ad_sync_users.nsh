#!/bin/nsh

# v3.0.0
###
# Some variables used in the script
###
PRUNE_USERS=false
PRUNE_ROLES=false
DISABLE_USERS=false
DEBUG=false

######
# If host platform is a Window machine, use NUL
######
HOST_OS=$(uname -s)

if [ "$HOST_OS" = "WindowsNT" ]
then
	DEV_NULL="NUL"
else
	DEV_NULL="/dev/null"
fi


print_usage()
{
    echo "Usage: sync_users.nsh [-u <true|false>] [-r <true|false>] [-f file] [-d <true|false>]"
    echo "       -f file       Path to file containing roles to sync. "
    echo
    echo "       -u true|false Prune users option. Decides whether or not to"
    echo "                     delete users from RBAC that are not specified"
    echo "                     in the user store.  THIS REMOVES THE USER FROM RBAC." 
    echo 
    echo "        -e true|false Disable users options.  Disables users that are not"
    echo "                     listed in the user store."
    echo 
    echo "       Note that -e and -u are mutually exclusive"
    echo
    echo "       -r true|false Prune roles option. Decides whether or not to"
    echo "                     remove users from roles that are not specified"
    echo "                     in the user store groups."
    echo
    echo "       -k Non-nsh path to the keytab file "
    echo 
    echo "       -p Non-nsh path to the krb5.conf file"
    echo
    echo "       -d true|false Print extra messages for debugging."
    echo 
    echo "       -s <service principal> For unix, pass the spn for the LDAP GSSAPI authentication"
    echo
    echo "       -?            Print this usage."

    exit 1
}


write_title()
{
    # Creates a title and a variable-length line based on the length 
    # of the title. Used to create uniform sub-headings in the script.

    # Disabling variable-length based line since it creates a few huge headings
	# for long query strings.
	#length=`echo "$1" | wc -c | cut -c1-8`
	border=""

    echo $1
    #for ((i=1; i < $length; i++))
	for ((i=1; i < 36; i++))
    do
        border=$border$2
    done

    echo $border
}

# Set the DEBUG variable to 1 to print out all debug statements
print_debug()
{
	if [ "${DEBUG}" = "true" ]
		then
		echo " "
		echo "DEBUG: $@"
	fi
}

print_error()
{
	echo " "
	echo "ERROR: $@"
	echo "ERROR: Exiting..."
	blcli_destroy
	exit 1
}

print_warn()
{
	echo " "
	echo "WARNING: $@"
}

print_info()
{
	echo " "
	echo "INFO: $@"
}

check_errs()
{
  # Function. Parameter 1 is the return code
  # Para. 2 is text to display on failure.
  if [ "${1}" -ne "0" ]; then
    echo "ERROR # ${1} : ${2}"
    # as a bonus, make our script exit with the right error code.
    exit ${1}
  fi
}

create_user()
{
    # When we create users from this script, we assume that they should only
    # connect via the Kerberos protocol. So we do 2 things to assure security:
    # 1. We obfuscate the password (see gen_password function)
    # 2. We disable the user for SRP connectivity by passing "false".
    #
    # NOTE: The createUser call we're using is a hidden command that is not
    #       available in the documentation as of the 6.2 GA.

    gen_password

    print_debug "blcli_execute RBACUser createUser $1 <password> false"

    print_info "Creating user $1..."

    blcli_execute RBACUser createUser "$1" "$PASSWORD" "AD User" true
	check_errs $? "BLCLI ERROR"
	blcli_storeenv USER_KEY
    if ! ( echo "${USER_KEY}" | grep "DBKey" > $DEV_NULL 2>&1 )
    then
        print_error "Failed to add $1: $USER_KEY"
        return 1
    fi
	
	print_info "Enabling user $1 for AD-Kerberos Authentication"
	print_debug "blcli_execute RBACUser setAdkAuthenticationEnabled $1 true"
	blcli_execute RBACUser setAdkAuthenticationEnabled "$1" true
	check_errs $? "BLCLI ERROR"
	
	print_info "Disabling user $1 for SRP Authentication"
	print_debug "blcli_execute RBACUser setSrpAuthenticationEnabled $1 false"
	blcli_execute RBACUser setSrpAuthenticationEnabled "$1" false
	check_errs $? "BLCLI ERROR"

    print_info "Created User $1"

    return 0
}

create_role()
{

    print_debug "blcli_execute RBACRole createRolePS $1 "AD Role" 8 root ADMIN_ACCOUNT"

    print_info "Creating Role $1..."

    blcli_execute RBACRole createRolePS $1 "AD Role" 8 root ADMIN_ACCOUNT
	check_errs $? "BLCLI ERROR"
	blcli_storeenv ROLE_KEY
    if ! ( echo "${ROLE_KEY}" | grep "DBKey" > $DEV_NULL 2>&1 )
    then
        print_error "Failed to add $1: $RESULT"
        return 1
    fi

    print_info "Created Role $1"

    return 0
}

gen_password()
{
    # Even though we're not using the passwords in the RBAC system,
    # we must supply one when we'create the user. In the current system,
    # there is no global option to stop users from authenticating via
    # SRP, assuming they know the password. Until this is resolved, the
    # best workaround is to obfuscate the password using a random generation
    # algorithm.

    # There are a variety of ways to do this, but since we're running this
    # through NSH, we're limited in what zsh offers.

    PASSWORD=`echo $RANDOM | md5sum | cut -f1 -d" "`
}


query_users_for_role()
{
    # The way in which users are queried by role will vary
    # significantly depending on where they're being pulled from.
   QUERY="${1}"
   print_debug "${QUERY}"

   if [ "$HOST_OS" = "WindowsNT" ]
        then
	USERS_IN_LDAP_GROUP=`nexec -e cmd /c "${QUERY}"`
	print_debug "Processing: $USERS_IN_LDAP_GROUP"
   else
	#get the Kerberos Ticket
	print_debug "nexec -e sh -c KRB5_CONFIG=${KRB5_FILE};export KRB5_CONFIG;/usr/nsh/br/java/bin/kinit -k -t ${KEYTAB} ${SPN} 1>&2;${QUERY}"
	USERS_IN_LDAP_GROUP=`nexec -e sh -c "KRB5_CONFIG=${KRB5_FILE};export KRB5_CONFIG;/usr/nsh/br/java/bin/kinit -k -t ${KEYTAB} ${SPN} 1>&2;${QUERY}"`
	check_errs $? "NEXEC ERROR"
	print_debug "USERS_IN_LDAP_GROUP = $USERS_IN_LDAP_GROUP"		
   fi
 
   if [ "${USERS_IN_LDAP_GROUP}x" = "x" ]
	then
	# query failed or is empty quit
	print_warn "LDAP query failed or is empty. Discarding Results"	
	return 1
   else
	# add the UPN suffix
    USERS_IN_LDAP_GROUP=`for ITEM in ${USERS_IN_LDAP_GROUP}; do echo ${ITEM}${UPN}; done`
	print_debug "USERS_IN_LDAP_GROUP = $USERS_IN_LDAP_GROUP"
	
	# Not sure why, but this was truncating the results - Frank Lamprea
	#USERS_IN_LDAP_GROUP=`echo ${USERS_IN_LDAP_GROUP} | sed "s/@.*@/@/g"`
	#print_debug "USERS_IN_LDAP_GROUP = $USERS_IN_LDAP_GROUP"
	
   fi

   print_debug "USERS_IN_LDAP_GROUP = ${USERS_IN_LDAP_GROUP}"

}


add_user_to_role()
{

    print_debug "blcli_execute RBACUser createUser addRole $1 $2"

    print_info "Adding $1 to $2..."
    blcli_execute RBACUser addRole "$1" "$2"
	check_errs $? "BLCLI ERROR"
	blcli_storeenv VOID
    print_info "Added $1 to $2"
    return 0
}


###
# Check input arguments.
###

if [ $# -eq 0 ]
   then
   print_usage
fi

while [ $# -gt 0 ]
do
    case "$1" in
     -u)
	shift
	if [ "${1}" = "true" ]
		then
	      PRUNE_USERS=true
	else
		PRUNE_USERS=false
	fi
        ;;

    -r)
	shift
	if [ "${1}" = "true" ]
		then
		PRUNE_ROLES=true
	else
		PRUNE_ROLES=false
	fi
        ;;

    -f)
        shift
        if [ $# -eq 0 ]
       	then
	      print_info "Path to roles files required after -f option"
	      print_usage
	else
            ROLES_FILE="${1}"            
        fi
        ;;

    -d)
	shift
	if [ "${1}" = "true" ]
		then
		DEBUG=true
	else
		DEBUG=false
	fi
        ;;

    -e)
	shift
	if [ "${1}" = "true" ]
		then
		DISABLE_USERS=true
	else
		DISABLE_USERS=false
	fi
        ;;
    -s)
        shift
        if [ $# -eq 0 ]
       	then
	      print_info "Service Principal name for LDAP GSSAPI authentication"
	      print_usage
	else        
	      SPN="${1}"
        fi
        ;;
    -p)
        shift
        if [ $# -eq 0 ]
       	then
	      print_info "Krb5.conf file path not defined for LDAP GSSAPI authentication"
	      print_usage
	else        
	      KRB5_FILE="${1}"
              [ ! -f ${KRB5_FILE} ] && print_error "Invalid file defined for krb5.conf"
        fi
        ;;
    -k)
        shift
        if [ $# -eq 0 ]
       	then
	      print_info "Keytab file not defined for LDAP GSSAPI authentication"
	      print_usage
	else        
	      KEYTAB="${1}"
	      [ ! -f ${KEYTAB} ] && print_error "Invalid file defined for keytab"
        fi
        ;;
    -\?)
        print_usage
        ;;
    *)
        print_usage
        ;;
    esac

    shift

done


###
# Print Header Information
###
echo "##################################"
echo "# Directory Sync Script"
echo "# BladeLogic, Inc."
echo "# `date`"
echo "##################################"
echo

write_title "Running Script:" "-"

if [ "${ROLES_FILE}x" = "x" ]
then
    print_error "No roles file defined."
else
    print_info "Using roles found in $ROLES_FILE."
fi


if [ "$PRUNE_ROLES" = "false" ]
	then
		print_debug "You have chosen not to prune users from roles."
	else
		print_debug "You have chose to prune users from roles."
	fi

if [ "$PRUNE_USERS" = "false" ]
	then
		print_debug "You have chosen not to prune users from RBAC."
	else
		print_debug "You have chosen to prune users from RBAC."
	fi

if [ "$DISABLE_USERS" = "false" ]
	then
		print_debug "You have chosen not to disable users in RBAC."
	else
		print_debug "You have chosen to disable users in RBAC."
	fi

if [ "$DISABLE_USERS" = "$PRUNE_USERS" ] && [ "$PRUNE_USERS" = "true" ]
	then
		print_error "PRUNE_USERS (-u) and DISABLE USERS (-e) cannot both be true)"
fi

if [ "${SPN}x" = "x" ] && [ "$HOST_OS" != "WindowsNT" ] && [ "${KRB5_FILE}x" = "x" ] && [ "${KEYTAB}x" = "x" ]
then
    print_error "You are missing the SPN, keytab or krb5.conf file.  These are required for ${HOST_OS}"
else
    print_info "Using SPN: ${SPN}, keytab: ${KEYTAB}, krb5.conf: ${KRB5_FILE}"
fi

###
# Validate that the roles file exists. Print its
# output, minus the comments, if it does.
###
if [ ! -f "$ROLES_FILE" ]
	then
    	print_error "Unable to access $ROLES_FILE.  Exiting..."
fi

# Validate that the LDAP_SYNC property exists....
print_debug "blcli_execute PropertyClass isPropertyDefined Class://SystemObject/User LDAP_SYNC"
blcli_execute PropertyClass isPropertyDefined "Class://SystemObject/User" "LDAP_SYNC"
check_errs $? "BLCLI ERROR"
blcli_storeenv RESULT

if [ "$RESULT" = "false" ]
	then
	print_error "LDAP_SYNC property is not defined in the User Class"
fi

print_debug "You have chosen to output debug messages."

#######################################
# MAIN PROCESSING
#
# Syncing is a multi-step process:
# 1. Get list of roles to sync (currently from external file). The file
#    should contain one line for each role to sync. Each line should
#    will have two comma-delimited values. The first value is the name of
#    the RBAC role and the second value is the name of the LDAP role.
#    Example:
#    
#    some_rbac_role,some_ldap_role
#    some_other_rbac_role,some_other_ldap_role
#
#    If the script doesn't find a value for the LDAP role, it will assume
#    that the LDAP role is the same name as the RBAC role.
#
# 2. For each ldap role, get the list of users from the user store. This
#    vary for each customer implementation and, thus, has been externalized
#    to another script.
#
# 3. For each user in the ldap role, add it to RBAC (if it isn't found)
#    and then add it to the role (again, if it isn't found in the role).
#
# 4. Prune the rbac roles of users that should no longer exist in them.
#    This is optional depending on whether the user specified the -r flag.
#
# 5. Prune the list of users in RBAC. This is optional depending on whether
#    the user specified the -u flag.
#
#######################################
# Initialize BLCLI
print_info "Initialize BLCLI"
print_debug "blcli_disconnect"
blcli_disconnect
check_errs $? "BLCLI ERROR"
print_debug "blcli_init"
blcli_init
check_errs $? "BLCLI ERROR"
print_debug "blcli_setoption roleName RBACAdmins"
blcli_setoption roleName RBACAdmins
check_errs $? "BLCLI ERROR"
print_debug "blcli_connect"
blcli_connect
check_errs $? "BLCLI ERROR"

agentinfo ${HOST} >${DEV_NULL} 2>&1
if [ $? != 0 ]
	then
	print_error "Host ${HOST} is not available, exiting"
	exit 1
fi

LINE_COUNT=`grep -v -e "^$" -e "^#" "${ROLES_FILE}" | wc -l | awk '{print $1}' 2>$DEV_NULL`
COUNT=1
while [ $COUNT -le $LINE_COUNT ]
do
    # Initialize
    INDEX=0
    SYNCED_AT_LEAST_ONE=false
    PRUNED_AT_LEAST_ONE=false

    line=`grep -v -e "^$" -e "^#" "${ROLES_FILE}" | head -$COUNT | tail -1`
    RBAC_ROLE=`echo $line | awk -F'+' '{print $1}'`
    LDAP_QUERY=`echo $line | awk -F'+' '{print $2}'`
    UPN=`echo $line | awk -F'+' '{print $3}'`
    COUNT=`expr $COUNT + 1`
    print_debug "RBAC_ROLE is $RBAC_ROLE"
    print_debug "LDAP_QUERY is \"$LDAP_QUERY\""
    print_debug "UPN is $UPN"


    if [ "${RBAC_ROLE}x" = "x" ] || [ "${LDAP_QUERY}x" = "x" ]
    then
	print_error "Set the RBAC Role and/or LDAP Query"
    fi    

    # Check to see if the RBAC_ROLE exists
    print_debug "blcli_execute RBACRole isRoleExistsPS $RBAC_ROLE"
	blcli_execute RBACRole isRoleExistsPS "$RBAC_ROLE"
	check_errs $? "BLCLI ERROR"
	blcli_storeenv ROLE_EXISTS
   
    if [ "$ROLE_EXISTS" = "false" ]
    	then
        # Role doesn't exist, so we're creating it. 
        create_role $RBAC_ROLE
		# Set the Default Acl Template for the role
		#print_debug "blcli_execute RBACRole setDefaultAclTemplateByName $RBAC_ROLE Recommmended Default ACL Template"
		#blcli_execute RBACRole setDefaultAclTemplateByName "$RBAC_ROLE" "Recommmended Default ACL Template"
		#blcli_storeenv ROLE_KEY
    fi
    
	write_title "Syncing Role $RBAC_ROLE (Query=\"$LDAP_QUERY\"):" "#"

    # First we get the users for role out of the user store
    query_users_for_role "${LDAP_QUERY}"
	
	# If the query recorded an error or returned empty discard the results 
	# and move on to the next query. This avoids emptying out the entire group
	# accidentally.
	if [ $? -ne 0 ]
		then
		print_debug "Continue:Break Loop"
		continue
	fi

    ALL_LDAP_USERS="$USERS_IN_LDAP_GROUP $ALL_LDAP_USERS"
    # Next we iterate through the users that were returned from LDAP
    # and check whether or not each user already exists in RBAC.
    # If it doesn't, create it and add it to the role.
    # If the user does exist, check to see if it also exists
    # in the role and add it to the role if it doesn't. Then
	# ensure the user's account in RBAC is enabled.
    for LDAP_USER in ${USERS_IN_LDAP_GROUP} 
    	do
        let "INDEX += 1"
        LDAP_USER=`echo ${LDAP_USER} | tr -d '[:cntrl:]'`
        print_debug "LDAP_USER is $LDAP_USER"
        print_debug "blcli_execute RBACUser isUserExists $LDAP_USER"
        blcli_execute RBACUser isUserExists "$LDAP_USER"
		check_errs $? "BLCLI ERROR"
		blcli_storeenv USER_EXISTS
        print_debug "$LDAP_USER exists in RBAC: $USER_EXISTS"

        if [ "$USER_EXISTS" = "false" ]
        	then
                # User doesn't exist, so we're creating it. Also set flag so that
                # we know at least one sync occurred in the role (for reporting
                # purposes later).
                SYNCED_AT_LEAST_ONE="true"

                create_user $LDAP_USER
                if [ $? -eq 0 ]
                	then
                    	# Add user to the role.
                    	add_user_to_role "$LDAP_USER" "$RBAC_ROLE"
                fi
        else
                # User already exists. Check the role.
                blcli_execute RBACUser belongsToRole "$LDAP_USER" "$RBAC_ROLE"
				check_errs $? "BLCLI ERROR"
				blcli_storeenv USER_EXISTS_IN_ROLE
                if [ "$USER_EXISTS_IN_ROLE" = "false" ]
        	        then
                	# Add user to the role.
                    	add_user_to_role "$LDAP_USER" "$RBAC_ROLE"
                    	SYNCED_AT_LEAST_ONE="true"					
								
                fi
				
				# Ensure the user is enabled & Grab the user's LDAP_SYNC property
				print_debug "blcli_execute RBACUser getFullyResolvedPropertyValue $LDAP_USER LDAP_SYNC"
				blcli_execute RBACUser getFullyResolvedPropertyValue "$LDAP_USER" "LDAP_SYNC"
				check_errs $? "BLCLI ERROR"
				blcli_storeenv RESULT
								
				if [ "$RESULT" = "false" ]               
					then
					print_info "User $LDAP_USER is reserved. Skipping..."				
				elif [ "$LDAP_USER" = "BLAdmin" ] || [ "$LDAP_USER" = "RBACAdmin" ]
					then
					print_info "User $LDAP_USER is reserved. Skipping..."
				else
					print_info "Enabling $LDAP_USER in RBAC..."
					print_debug "blcli_execute RBACUser enable $LDAP_USER"
					blcli_execute RBACUser enable "$LDAP_USER"
					check_errs $? "BLCLI ERROR"
					blcli_storeenv RESULT
					print_info "Enabled $LDAP_USER in RBAC: $RESULT"
					
					print_info "Enabling user $1 for AD-Kerberos Authentication"
					print_debug "blcli_execute RBACUser setAdkAuthenticationEnabled $1 true"
					blcli_execute RBACUser setAdkAuthenticationEnabled "$1" true
					check_errs $? "BLCLI ERROR"
					blcli_storeenv RESULT
					print_info "Enabled ADK Access for $LDAP_USER in RBAC: $RESULT"
					
					print_info "Disabling user $1 for SRP Authentication"
					print_debug "blcli_execute RBACUser setSrpAuthenticationEnabled $1 false"
					blcli_execute RBACUser setSrpAuthenticationEnabled "$1" false
					check_errs $? "BLCLI ERROR"
					blcli_storeenv RESULT
					print_info "Disabled SRP Access for $LDAP_USER in RBAC: $RESULT"
					
				fi
								
        fi
    done


    if [ $INDEX = 0 ]
    	then
        print_info "Either no users were found within the LDAP for $LDAP_ROLE or the group doesn't exist."
    elif [ "$SYNCED_AT_LEAST_ONE" = "false" ]
        then
        print_info "Role ${RBAC_ROLE} was already in sync, so no additional actions were needed."
    fi
    
    #######################################
    # PRUNE ROLES
    #
    # Next we prune the role of unwanted users (if the user chose to do so).
    # We do this by iterating through the list of users in the RBAC role and
    # the list of users in the LDAP role and removing the extra ones.
    if [ "$PRUNE_ROLES" = "true" ]
    then
    	write_title "Pruning Users from Role: $RBAC_ROLE" "-"
		print_debug "blcli_execute RBACUser getAllUserNamesByRole $RBAC_ROLE"
        blcli_execute RBACUser getAllUserNamesByRole "$RBAC_ROLE"
		check_errs $? "BLCLI ERROR"
		blcli_storeenv USERS_IN_RBAC_ROLE

        # Iterate through list of users in the RBAC role.
        for RBAC_USER in ${USERS_IN_RBAC_ROLE}
		do
		    RBAC_USER=`echo ${RBAC_USER} | tr -d '[:cntrl:]'`
                MATCH_FOUND=false
        
		# "BLAdmin" and "RBACAdmin" are reserved users, so skip them & Grab the user's LDAP_SYNC property
		print_debug "blcli_execute RBACUser getFullyResolvedPropertyValue $RBAC_USER LDAP_SYNC"
		blcli_execute RBACUser getFullyResolvedPropertyValue "$RBAC_USER" "LDAP_SYNC"
		check_errs $? "BLCLI ERROR"
		blcli_storeenv RESULT
				
		if [ "$RESULT" = "false" ]               
			then
			MATCH_FOUND=true 
		elif [ "$RBAC_USER" = "BLAdmin" ] || [ "$RBAC_USER" = "RBACAdmin" ]
			then
			MATCH_FOUND=true 
		else
                    # Iterate through list of users returned from LDAP.
                	for LDAP_USER in ${USERS_IN_LDAP_GROUP} 
                		do
					LDAP_USER=`echo ${LDAP_USER} | tr -d '[:cntrl:]'`
                    		# Check for a match. If there is one, set a variable and exit the loop.
                    		if [ "$RBAC_USER" = "$LDAP_USER" ]
                    			then
                        		print_debug "$RBAC_USER=$LDAP_USER. Found a match."
                        		MATCH_FOUND=true
								break
                    		fi
                	done
              	 fi

                 # If no match was found, remove the user from the role.
                 if [ "$MATCH_FOUND" = "false" ]
	             	then
        	       	PRUNED_AT_LEAST_ONE="true"
					print_debug "blcli_execute RBACUser removeRole $RBAC_USER $RBAC_ROLE"
	
                 	print_info "Removing $RBAC_USER from $RBAC_ROLE..."
                    	blcli_execute RBACUser removeRole "$RBAC_USER" "$RBAC_ROLE"
						check_errs $? "BLCLI ERROR"
						blcli_storeenv RESULT
                    	print_info "Removed $RBAC_USER from $RBAC_ROLE"
                 fi
        done

        if [ "$PRUNED_AT_LEAST_ONE" = "false" ]
        	then
                print_info "No extra users were found in the role, so no pruning was needed."
        fi
    fi

done 
# End Main Loop

#######################################
# PRUNE USERS
#
# Now we prune RBAC of unwanted users (again, if the user chose to do so by
# specifying the -u flag). We do this by iterating through a global list of users
# in RBAC and a global list of user returned by the calls to LDAP that we made
# earlier in this script. If we find any extra users in the RBAC list, we delete
# them from RBAC. We do this last since we want to be sure that we've iterated
# through all of the LDAP roles to get the global list) before figuring out which
# users are no longer needed.
# The same logic is used to disable users, but a different command runs to disable the user.


if [ "$PRUNE_USERS" = "true" ] || [ "$DISABLE_USERS" = "true" ]
    then
    # Initialize
    DELETED_AT_LEAST_ONE="false"

    write_title "Pruning Users from RBAC:" "#"
    print_debug "blcli_execute RBACUser getAllUserNames"
  
    blcli_execute RBACUser getAllUserNames
	check_errs $? "BLCLI ERROR"
	blcli_storeenv ALL_RBAC_USERS
    ALL_LDAP_USERS=$ALL_LDAP_USERS
    print_debug "ALL LDAP USERS:"
    print_debug "$ALL_LDAP_USERS"
    print_debug "ALL RBAC USERS:"
    print_debug "$ALL_RBAC_USERS"
	
	# If no LDAP queries returned records continuing would effectively wipe out
	# the entire RBAC user structure.
	if [ "${ALL_LDAP_USERS}x" = "x" ]
		then
		print_error "All LDAP Queries returned NULL"
	fi	

    # Iterate through the users in RBAC.
    for RBAC_USER in ${ALL_RBAC_USERS}
    	do
	  RBAC_USER=`echo ${RBAC_USER} | tr -d '[:cntrl:]'`
        print_debug "RBAC_USER=$RBAC_USER"
        MATCH_FOUND=false

        # "BLAdmin" and "RBACAdmin" are reserved users, so skip them.
		# Grab the user's LDAP_SYNC property
		print_debug "blcli_execute RBACUser getFullyResolvedPropertyValue $RBAC_USER LDAP_SYNC"
		blcli_execute RBACUser getFullyResolvedPropertyValue "$RBAC_USER" "LDAP_SYNC"
		check_errs $? "BLCLI ERROR"
		blcli_storeenv RESULT
				
		if [ "$RESULT" = "false" ]               
			then
			MATCH_FOUND=true 
		elif [ "$RBAC_USER" = "BLAdmin" ] || [ "$RBAC_USER" = "RBACAdmin" ]
			then
			MATCH_FOUND=true 
		else        
		# Iterate through the users we got from LDAP.
        	for LDAP_USER in ${ALL_LDAP_USERS}
        		do
			    LDAP_USER=`echo ${LDAP_USER} | tr -d '[:cntrl:]'`
	                print_debug "LDAP_USER=$LDAP_USER"
	                # Check for a match. If there is one, set a variable and exit the loop.
              		if [ "$RBAC_USER" = "$LDAP_USER" ]
                		then
                    		print_debug $RBAC_USER=$LDAP_USER. Found a match.
                    		MATCH_FOUND=true
                    		break
                	fi
       		done
        fi
        
        # If no match was found, delete or disable the user.
        if [ "$MATCH_FOUND" = "false" ]
        	then
                # Set a variable for future reporting and then delete the user from RBAC.
                DELETED_AT_LEAST_ONE=true
		
			if [ "${DISABLE_USERS}" = "true" ]
				then
			        print_debug "blcli_execute RBACUser disable $RBAC_USER"
		                print_info "Disabling $RBAC_USER from RBAC..."
		                blcli_execute RBACUser disable "$RBAC_USER"
						check_errs $? "BLCLI ERROR"
						blcli_storeenv RESULT
						print_info "Disabled $RBAC_USER from RBAC: $RESULT."			

			elif [ "${PRUNE_USERS}" = "true" ]
				then
			        print_debug "blcli_execute RBACUser deleteUser $RBAC_USER"
		                print_info "Deleting $RBAC_USER from RBAC..."
		                blcli_execute RBACUser deleteUser "$RBAC_USER"
						check_errs $? "BLCLI ERROR"
						blcli_storeenv RESULT
	        	        print_info "Deleted $RBAC_USER from RBAC: $RESULT."
			fi

        fi

    done

        if [ "$DELETED_AT_LEAST_ONE" = "false" ]
    		then
        	print_info "No extra users were found in RBAC, so no deletion was needed."
    	fi
fi

echo "Script Complete."

print_debug "blcli_destroy"
blcli_destroy
check_errs $? "BLCLI ERROR"

exit 0
