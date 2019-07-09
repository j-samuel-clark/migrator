#!/bin/zsh


# Create a password for the migrator user. Make sure to update both scripts.
migratorUserPassword=""


log="/var/log/alectrona.log"
preferences="/Library/Preferences/com.alectrona.scripts.migratorTool"


function writelog () {
	DATE=$(date +%Y-%m-%d\ %H:%M:%S)
	/bin/echo "${1}"
	/bin/echo "$DATE" " $1" >> "$log"
}

function exitHandler () {
	writelog "Finalizer exiting with $?"
	rm $preferences.plist
	# only delete the migrator user if we have successfully made the
	dscl . list /Users/$username && sysadminctl -deleteUser migrator -adminUser "$username" -adminPassword "$password" > $log 2>&1
	killall loginwindow
	launchctl unload -w /Library/LaunchDaemons/com.alectrona.scripts.migratorTool.plist
}

trap exitHandler EXIT

writelog "Starting Finalizer..."


loggedInUser=$(defaults read $preferences loggedInUser)
username=$(defaults read $preferences username)
password=$(defaults read $preferences password)

[[ $loggedInUser != "" ]] || exit 1
[[ $username != "" ]] || exit 2
[[ $password != "" ]] || exit 3

writelog "Got username: $username, loggedInUser: $loggedInUser"

/usr/bin/dscl . create "/Users/$username" IsHidden 1 >> "$log" 2>&1

# Log out user - needs system events authorization
/bin/launchctl bootout gui/$(id -u "$loggedInUser") 2>&1

sleep 5


writelog "deleting existing user if s/he exists"

# Delete $username if s/he exists (and home folder)
dscl . list "/Users/$username" && { sysadminctl -deleteUser $username -adminUser "migrator" -adminPassword "migrationisfun" > $log 2>&1 || exit 4 }

sleep 10

writelog "Moving files"
# Move files into place
mv /Users/migratorTool-$username /Users/$username > $log 2>&1 || exit 6

# Fix permissions
chmod -R -N "/Users/$username" > $log 2>&1 || exit 7
chflags -R nouchg "/Users/$username" > $log 2>&1 || exit 8

writelog "Creating new user account."
# Create $username account
sysadminctl -addUser $username -fullName "$username" -password "$password" -home "/Users/$username" -admin -adminUser "migrator" -adminPassword "migrationisfun" > $log 2>&1 || exit 6

chown -R "$username":staff "/Users/$username" > $log 2>&1 # allowing non-zero exit code, certain library items fail but don't seem to matter


exit 0
