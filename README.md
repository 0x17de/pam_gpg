# pam_gpg
PAM module for authentication against e.g. g10 smartcards via gpg.

![Pin entry example](http://www.icetruck.de/0/pics/pinentry.png)

**Use this at your own risk.** Please verify&validate the source before usage.

Not yet implemented: Per user basis - currently you can log into every user by using the smartcard.

## Setup:
- GPG-PublicKeys for login have to be exported to */etc/authorized_pubkey.gpg*.
- The library pam_gpg.so must be copied to /lib/security.
- Edit */etc/pam.d/system-auth*, add the following before the *pam_unix.so line*.
```
auth		[success=1 default=ignore]	pam_gpg.so
```
