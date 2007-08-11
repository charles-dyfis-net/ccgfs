
CC Network Filesystem (ccgfs)
A transport-agnostic filesystem


ccgfs is a transport-agnostic filesystem. Common transport modes are
"pull" and "push", the latter of which makes it possible to export a
filesystem located in a LAN to a DMZ host without needing to allow
connections from the DMZ as would be the case with the pull model.
Any transport can be used, e.g. ssh for encryption.


Most, if not all, networked filesystems use a pull model, where a
client sends a mount request to a server. (Because the push model
reverses roles, the terms "mount endpoint" and "storage endpoint"
will be used to avoid confusion.) So in the pull model, a mount
endpoint opens a connection to the storage endpoint. This however is
a problem when you want a host in a DMZ network to access data that
is located in the inner LAN, because you would need to allow
connections from the DMZ to the LAN on the firewall, which is
contrary to the principle of a DMZ.

One could move the storage unit into the DMZ itself, but that may
create interoperability problems with LAN clients, e.g. with SMB
clients using NBT broadcast. Or you do not want to move it to the
DMZ, because it is your only workhorse in the LAN. To solve this
issue without moving the storage unit into the DMZ itself, a
filesystem that can be pushed is needed. (Since connections from LAN
to DMZ are always allowed.) Classical networked filesystems do not
seem to be able to do that.

Actually, this is only a transport issue. Classical (pull-based)
networked filesystems could be made transport-agnostic, but I figured
it would take more time to code. The requirements are:

	 * must support ACLs/xattrs
	 * should support quotas if possible
	 * connection must be encryptable if desired
	 * implementation should be simple
	 * and perhaps modularized
	(* it should not take too long to implement push-based
	   operation for it)

I figured that neither SSHFS (SFTP) nor NFS fulfilled all of these,
so ccgfs came to life.
