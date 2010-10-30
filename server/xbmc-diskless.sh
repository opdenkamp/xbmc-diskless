#!/bin/bash
#
#  Copyright (c) 2010 Lars Op den Kamp
#
#  Author: Lars Op den Kamp <lars@opdenkamp.eu>
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License as
#  published by the Free Software Foundation; either version 2 of the
#  License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, you can find it on the World Wide
#  Web at http://www.gnu.org/copyleft/gpl.html, or write to the Free
#  Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#


###############################################################################
##      Configuration
###############################################################################

set -e

SCRIPT=`basename $0`

# file locations, can be overriden by the config files
APTADDREPOS="/usr/bin/add-apt-repository"
APTGET="/usr/bin/apt-get"
APTKEY="/usr/bin/apt-key"
AWK="/usr/bin/awk"
CAT="/bin/cat"
CHMOD="/bin/chmod"
CHOWN="/bin/chown"
CHROOT="/usr/sbin/chroot"
CP="/bin/cp"
DEBOOTSTRAP="/usr/sbin/debootstrap"
DPKGSCANPACKAGES="/usr/bin/dpkg-scanpackages"
EXPORTFS="/usr/sbin/exportfs"
FIND="/usr/bin/find"
GREP="/bin/grep"
GZIP="/bin/gzip"
HEAD="/usr/bin/head"
IFCONFIG="/sbin/ifconfig"
ID="/usr/bin/id"
INETD="/usr/sbin/inetd"
INETD_INIT="/etc/init.d/openbsd-inetd"
MKDIR="/bin/mkdir"
MKSQUASHFS="/usr/bin/mksquashfs"
MOUNT="/bin/mount"
MOUNTD="/usr/sbin/rpc.mountd"
MV="/bin/mv"
NETSTAT="/bin/netstat"
PASSWD="/usr/bin/passwd"
PIDOF="/bin/pidof"
PORTMAP="portmap"
RM="/bin/rm"
SED="/bin/sed"
STATD="rpc.statd"
SORT="/usr/bin/sort"
TAIL="/usr/bin/tail"
TFTPD="/usr/sbin/in.tftpd"
UMOUNT="/bin/umount"
WC="/usr/bin/wc"
WGET="/usr/bin/wget"
XARGS="/usr/bin/xargs"
ZCAT="/bin/zcat"

# check if we are running as root or debootstrap won't work
if [ ! `$ID -u` -eq 0 ]; then
	echo "This program must be run as user 'root'.

use \"sudo $0\" to execute this program as root."
	exit 1
fi

# some global variables
export DEBIAN_FRONTEND=noninteractive
export DEBIAN_PRIORITY=critical
APT_FLAGS="--allow-unauthenticated"
VERBOSE=1
unset LAST_DIALOG
unset LAST_DIALOG_PID

# start as "xbmc-diskless.sh X" to use Xdialog. completely untested
if [ "x$1" = "xX" ]; then
	DIALOG=${DIALOG=/usr/bin/Xdialog}
else
	DIALOG=${DIALOG=/usr/bin/dialog}
fi

# verbose apt or not
if [ ! "x${VERBOSE}" = "x1" ]; then
	APT_FLAGS+=" -qq"
fi

# load the default config if it exists
if [ -f "/etc/default/xbmc-diskless-server.conf" ]; then
	echo "Loading the default configuration"
	source /etc/default/xbmc-diskless-server.conf
fi

# load the config if it exists
if [ -f "/etc/xbmc-diskless-server.conf" ]; then
	echo "Loading configuration"
	source /etc/xbmc-diskless-server.conf
fi

# check the configuration
if [ -z "${base_dir}" ]; then
	echo "base_dir is not set. Check you configuration."
	exit 1
fi

# set the default target_dir if it's not set
if [ -z "${target_dir}" ]; then
	target_dir="${base_dir}/target"
fi

# set the default image_dir if it's not set
if [ -z "${image_dir}" ]; then
	image_dir="${base_dir}/images"
fi

# set the default tftp_dir if it's not set
if [ -z "${tftp_dir}" ]; then
	tftp_dir="/var/lib/tftpboot"
fi

# set the default image_name if it's not set
if [ -z "${image_name}" ]; then
	image_name="xbmc.img"
fi

# set the default log_file if it's not set
if [ -z "${log_file}" ]; then
	log_file="/var/log/xbmc-diskless.log"
fi

# set the default overlay_dir if it's not set
if [ -z "${overlay_dir}" ]; then
	overlay_dir="${base_dir}/overlay"
fi

###############################################################################
##      Trap signals
###############################################################################

function cancel_call
{
	cleanup_temp
	show_dlg_menu
}

function cleanup_temp
{
	if [ ! -z "$LAST_DIALOG" ]; then
		try_exec $RM -f $LAST_DIALOG
		unset LAST_DIALOG
	fi
}

function exec_signal
{
	if [ -f $log_file ]; then
		last_log_lines=`tail -n 10 $log_file`
	else
		last_log_line="No log file found at '${log_file}'"
	fi

	dialog_error "Action interrupted!\n
\n
Last action was: ${last_log_message}\n
\n
The last log messages are:\n
${last_log_lines}"

	umount_virtual

	echo "exited because a signal was received. you might want to check your log in '${log_file}'"
	exit 1
}

###############################################################################
##      Logging
###############################################################################

function log_message
{
	last_log_message="$@"
	echo "$@" >> $log_file
}

###############################################################################
##      Image creation
###############################################################################

## Try to execute a command and add a log message if it failed
function try_exec
{
	trap "exec_signal" 0 1 2 5 15

	$@ &>> $log_file

	trap - 0 1 2 5 15

	EXEC_RETURN="$?"

	if [ ! $EXEC_RETURN -eq 0 ]; then
		log_message "error executing '$@'"
		dialog_error "error executing '$@'"
		return 1
	else
		return 0
	fi
}

## Creates the destination directory
function create_destination
{
	if [ ! -d "${target_dir}" ]; then
		log_message "creating target directory '${target_dir}'"
		try_exec $MKDIR -p $target_dir

		return $EXEC_RETURN
	else
		log_message "target directory '${target_dir}' already exists"
		return 1
	fi
}

## Removes the destination directory
function remove_target
{
	if [ -d "${target_dir}" ]; then
		log_message "making sure that virtual directories are not mounted"
		umount_virtual
		if [ ! $? -eq 0 ]; then
			log_message "cancel!"
			return 1
		fi

		log_message "removing target directory '${target_dir}'"
		try_exec $RM -rf --one-file-system $target_dir

		if [ ! $? -eq 0 ]; then
			return $EXEC_RETURN
		elif [ -d $target_dir ]; then
			log_error "Failed to remove '${target_dir}'"
			return 1
		else
			return 0
		fi
	else
		return 0
	fi
}

## Create the target directory
function create_target
{
	if [ -d "${target_dir}" ]; then
		log_message "target directory '${target_dir}' exists"
		return 1
	else
		create_destination
		return $?
	fi
}

## Run debootstrap on the target directory but download only
function debootstrap_target_download
{
	# debootstrap destination
	log_message "running debootstrap --download-only on '${target_dir}'"
	try_exec $DEBOOTSTRAP --download-only --include=python-software-properties,language-pack-en,plymouth-label ${ubuntu_dist} ${target_dir} ${ubuntu_mirror}
	if [ ! $? -eq 0 ]; then
		return $EXEC_RETURN
	fi
}

## Run debootstrap on the target directory
function debootstrap_target
{
	# debootstrap destination
	log_message "running debootstrap on '${target_dir}'"
	try_exec $DEBOOTSTRAP --include=python-software-properties,language-pack-en,plymouth-label ${ubuntu_dist} ${target_dir} ${ubuntu_mirror}
	if [ ! $? -eq 0 ]; then
		return $EXEC_RETURN
	fi

	## don't allow daemons to restart during the installation
	$CAT << EOF > ${target_dir}/usr/sbin/policy-rc.d
#!/bin/sh
exit 101
EOF

	try_exec $CHMOD +x ${target_dir}/usr/sbin/policy-rc.d
	if [ ! $? -eq 0 ]; then
		return $EXEC_RETURN
	fi

	return 0
}

## Create the default fstab
function create_fstab
{
	log_message "creating fstab"
	$CAT << EOF > ${target_dir}/etc/fstab
# /etc/fstab: static file system information.
#
# Use 'blkid -o value -s UUID' to print the universally unique identifier
# for a device; this may be used with UUID= as a more robust way to name
# devices that works even if disks are added and removed. See fstab(5).
#
# <file system> <mount point>   <type>  <options>       <dump>  <pass>
proc            /proc           proc    nodev,noexec,nosuid 0       0
EOF

	return 0
}

## Check whether a path is mounted
function is_mounted
{
	if $GREP -qs "$1" /proc/mounts ; then
		log_message "$1 is mounted"
		return 1
	else
		log_message "$1 is not mounted"
		return 0
	fi
}

## Mount /proc /dev /sys and /dev/pts in the target
function mount_virtual
{
	mount_exec "/dev" "${target_dir}/dev" "-o bind" && \
	mount_exec "none" "${target_dir}/proc" "-t proc"  && \
	mount_exec "none" "${target_dir}/sys" "-t sysfs" && \
	mount_exec "none" "${target_dir}/dev/pts" "-t devpts"

	return $?
}

## Unmount a path
function umount_exec
{
	path="$1"

	if $GREP -qs "$path" /proc/mounts ; then
		log_message "umount '${path}'"

		try_exec $UMOUNT "${path}" &>${log_file}
		if [ ! $? -eq 0 ]; then
			log_message "'${path}' could not be umounted"
			return $EXEC_RETURN
		fi
	else
		log_message "${path} is not mounted"
	fi

	return 0
}

## Mount a path
function mount_exec
{
	source="$1"
	path="$2"
	options="$3"

	if $GREP -qs "$path" /proc/mounts ; then
		log_message "${path} is already mounted"
	else
		log_message "mount ${options} '${source}' '${path}'"

		try_exec $MOUNT ${options} ${source} ${path} &>${log_file}
		if [ ! $? -eq 0 ]; then
			log_message "'${path}' could not be mounted"
			return $EXEC_RETURN
		fi
	fi

	return 0
}

## Unmount the virtual filesystems in the target
function umount_virtual
{
	umount_exec "${target_dir}/sys" && \
	umount_exec "${target_dir}/proc"  && \
	umount_exec "${target_dir}/dev/pts" && \
	umount_exec "${target_dir}/dev"

	return $?
}

## Create and update the apt sources
function update_apt_sources
{
	# set the default apt sources
	log_message "creating default apt sources"

	log_message "adding 'deb ${ubuntu_mirror} ${ubuntu_dist} universe multiverse restricted'"
	$CHROOT ${target_dir} $APTADDREPOS "deb ${ubuntu_mirror} ${ubuntu_dist} universe multiverse restricted"
	if [ ! $? -eq 0 ]; then
		log_error "failed to add apt source: deb ${ubuntu_mirror}"
		return 1
	fi

	# add the default mirror
	log_message "adding 'deb-src ${ubuntu_mirror} ${ubuntu_dist} main universe multiverse restricted'"
	$CHROOT ${target_dir} $APTADDREPOS "deb-src ${ubuntu_mirror} ${ubuntu_dist} main universe multiverse restricted"
	if [ ! $? -eq 0 ]; then
		log_error "failed to add apt source: deb-src ${ubuntu_mirror}"
		return 1
	fi

	# add the second mirror if it's set
	if [ ! -z ${ubuntu_mirror2} ]; then
		log_message "adding 'deb ${ubuntu_mirror2} ${ubuntu_dist} main universe multiverse restricted'"
		$CHROOT ${target_dir} $APTADDREPOS "deb ${ubuntu_mirror2} ${ubuntu_dist} main universe multiverse restricted"
		if [ ! $? -eq 0 ]; then
			log_error "failed to add apt source: 'deb ${ubuntu_mirror2}'"
			return 1
		fi

		log_message "adding 'deb-src ${ubuntu_mirror2} ${ubuntu_dist} main universe multiverse restricted'"
		$CHROOT ${target_dir} $APTADDREPOS "deb-src ${ubuntu_mirror2} ${ubuntu_dist} main universe multiverse restricted"
		if [ ! $? -eq 0 ]; then
			log_error "failed to add apt source: 'deb-src ${ubuntu_mirror2}'"
			return 1
		fi
	fi

	# add the xbmc-diskless ppa
	log_message "adding 'ppa:lars-opdenkamp/xbmc-diskless'"
	try_exec $CHROOT ${target_dir} $APTADDREPOS "ppa:lars-opdenkamp/xbmc-diskless"
	if [ ! $? -eq 0 ]; then
		log_error "failed to add apt source: 'ppa:lars-opdenkamp/xbmc-diskless'"
		return $EXEC_RETURN
	fi

	# add-apt-repository still exits with 0 if gpg can't get the key, so we'll do an extra check
	log_message "making sure we got our launchpad key"
	try_exec $CHROOT ${target_dir} $APTKEY adv --keyserver keyserver.ubuntu.com --recv-key 200B0F29E1326DA781F163333A4CAE5D0DB24E15
	if [ ! $? -eq 0 ]; then
		log_error "failed to add get the xbmc-diskless launchpad key"
		return $EXEC_RETURN
	fi

	# add the custom ppa if it's set
	if [ ! -z "${ppa_source}" ]; then
		log_message "adding '${ppa_source}'"
		try_exec $CHROOT ${target_dir} $APTADDREPOS "$ppa_source"
		if [ ! $? -eq 0 ]; then
			log_error "failed to add apt source: '${ppa_source}'"
			return $EXEC_RETURN
		fi
	fi

	# add custom packages
	add_custom_packages

	# update sources
	log_message "updating apt sources"
	try_exec $CHROOT ${target_dir} $APTGET ${APT_FLAGS} update
	if [ ! $? -eq 0 ]; then
		log_error "failed to update apt sources"
		return $EXEC_RETURN
	fi

	return 0
}

## copy the packages from $base_dir/packages to the target
function add_custom_packages
{
	log_message "adding packages from '${base_dir}/packages'"
	$CHROOT ${target_dir} $APTADDREPOS "deb file:/ packages/"

	try_exec $CP -r ${base_dir}/packages ${target_dir}/.
	try_exec $CHOWN -R root:root ${target_dir}/packages

	# there isn't any plymouth theme in a ubuntu repository yet as far as I can see
	$WGET -q -nc -t 3 --directory-prefix="${target_dir}/packages" http://excyle.nl/plymouth-theme-xbmc-logo.deb

	cd ${target_dir}
	$DPKGSCANPACKAGES packages | $GZIP > ${target_dir}/packages/Packages.gz

	return 0
}

## remove the custom packages from the target
function remove_custom_packages
{
	log_message "removing /packages"
	try_exec $RM -rf ${target_dir}/packages

	$CAT ${target_dir}/etc/apt/sources.list | $GREP -v "file:" > /tmp/sources.list.tmp
	$MV /tmp/sources.list.tmp ${target_dir}/etc/apt/sources.list

	return 0
}

## run dist-upgrade on the target
function upgrade_system
{
	log_message "upgrading system"
	try_exec $CHROOT ${target_dir} $APTGET ${APT_FLAGS} -y dist-upgrade

	if [ ! $? -eq 0 ]; then
		log_error "failed to upgrade the system"
	fi

	return $EXEC_RETURN
}

## make sure the kernel and initramfs are installed
function install_kernel
{
	log_message "installing kernel"
	echo "do_initrd = Yes" >> ${target_dir}/etc/kernel-img.conf
	try_exec $CHROOT ${target_dir} $APTGET ${APT_FLAGS} -y install linux-image-generic linux-headers-generic

	if [ ! $? -eq 0 ]; then
		log_error "failed to install the kernel"
	fi

	return $EXEC_RETURN
}

## download xbmc and deps
function download_xbmc
{
	log_message "downloading diskless xbmc"

	try_exec $CHROOT ${target_dir} $APTGET -d ${APT_FLAGS} -y install xbmc-diskless-client

	if [ ! $? -eq 0 ]; then
		log_error "failed to download diskless xbmc"
		return $EXEC_RETURN
	fi
}

## install xbmc
function install_xbmc
{
	log_message "installing diskless xbmc"

	touch ${target_dir}/tmp/.xbmc
	try_exec $CHROOT ${target_dir} $APTGET ${APT_FLAGS} -y install xbmc-diskless-client

	if [ ! $? -eq 0 ]; then
		log_error "failed to install diskless xbmc"
		return $EXEC_RETURN
	fi

	$CAT << EOF | $CHROOT ${target_dir} $PASSWD xbmc > /dev/null 2>/dev/null
${client_password}
${client_password}
EOF

	return 0
}

## install misc packages / do misc config
function install_misc
{	
	log_message "starting ssh at boot"
	try_exec $CHROOT ${target_dir} update-rc.d ssh defaults >/dev/null

	if [ ! $? -eq 0 ]; then
		return $EXEC_RETURN
	fi

	# set the default hostname to "xbmc-diskless"
	log_message "setting hostname to 'xbmc-diskless'"
	echo "xbmc-diskless" > ${target_dir}/etc/hostname

	if [ ! -z "${extra_packages}" ]; then
		# don't use -y on extra packages
		try_exec $CHROOT ${target_dir} $APTGET ${APT_FLAGS} install $extra_packages
		if [ ! $? -eq 0 ]; then
			log_error "failed to install the extra packages: ${extra_packages}"
			return $EXEC_RETURN
		fi
	fi

	return 0
}

## install the bootsplash
function install_bootsplash
{
	log_message "installing splash screen"
	try_exec $CHROOT ${target_dir} $APTGET ${APT_FLAGS} -y install plymouth-theme-xbmc-logo

	if [ ! $? -eq 0 ]; then
		log_error "failed to install the splash screen"
	fi

	return $EXEC_RETURN
}

## copy /root/.ssh/id_rsa.pub to the target's authorized_keys2 if it exists
function copy_host_key
{
	# copy this user's public key to the new host
	if [ ! -f ~/.ssh/id_rsa.pub ]; then
	        log_message "no ssh public key found, not installing authorized key"
	else
		log_message "adding id_rsa.pub to the new host\'s authorized_keys2"
		try_exec $MKDIR -p ${target_dir}/root/.ssh
		try_exec $CP ~/.ssh/id_rsa.pub ${target_dir}/root/.ssh/authorized_keys2
	fi
}

###############################################################################
##      Provisioning
###############################################################################

## update the provisioning archives
function update_provision
{
	$FIND -L ${base_dir}/provision/* -maxdepth 0 -type d -exec /usr/share/xbmc-diskless/provision.sh {} ${overlay_dir} \;

	return $?
}

###############################################################################
##      Create squashfs
###############################################################################

## cleanup the target
function pack_cleanup
{
	log_message "cleaning target"
	try_exec $CHROOT ${target_dir} $APTGET clean
	try_exec $CHROOT ${target_dir} $APTGET -y autoremove
	try_exec $RM -rf ${target_dir}/root/.bash_history \
		${target_dir}/tmp/* \
		${target_dir}/usr/sbin/policy-rc.d \
		${target_dir}/tmp/.xbmc

	remove_custom_packages

	try_exec $CHROOT ${target_dir} $APTGET update

	return 0
}

## create a new squashfs image
function pack
{
	## create the squashfs image
	log_message "creating image"

	umount_virtual

	try_exec $RM -f ${image_dir}/${image_name}-new
	try_exec $MKDIR -p ${image_dir} 2>/dev/null
	$MKSQUASHFS ${target_dir} ${image_dir}/${image_name}-new -e cdrom -no-progress -no-recovery -noappend &> ${log_file}
	try_exec $CHMOD 0644 ${image_dir}/${image_name}-new

	return $EXEC_RETURN
}

###############################################################################
##      Install image, kernel and initrd
###############################################################################

## install the squashfs image and copy the kernel and initramfs to the tftp dir
function install_image
{
	log_message "installing image"

	## copy kernel and initramfs
	$FIND ${base_dir}/target/boot -name initrd.img-\* | $SORT | $TAIL -n1 | $XARGS /usr/share/xbmc-diskless/copy_image.sh ${tftp_dir}/initrd.img

	if [ ! $? -eq 0 ]; then
		log_message "unable to copy the initrd"
		return 1
	elif [ ! -f ${tftp_dir}/initrd.img ]; then
		log_error "the initrd wasn't found on '${tftp_dir}/initrd.img'"
		return 1
	fi

	$FIND ${base_dir}/target/boot -name vmlinuz-\* | $SORT | $TAIL -n1 | $XARGS /usr/share/xbmc-diskless/copy_image.sh ${tftp_dir}/vmlinuz

	if [ ! $? -eq 0 ]; then
		log_error "unable to copy the kernel"
		return 1
	elif [ ! -f ${tftp_dir}/vmlinuz ]; then
		log_error "the kernel wasn't found on '${tftp_dir}/vmlinuz'"
		return 1
	fi

	## make squashfs image available via nbd
	if [ -f "${base_dir}/images/${image_name}-new" ]; then
		try_exec $MV ${base_dir}/images/${image_name}-new ${base_dir}/images/${image_name}
		return $?
	elif [ ! -f "${base_dir}/images/${image_name}" ]; then
		return 1
	fi

	if [ ! -f "${tftp_dir}/pxelinux.0" ]; then
		## copy the client's pxelinux.0 to the tftpdir
		try_exec $CP -a ${target_dir}/usr/lib/syslinux/pxelinux.0 ${tftp_dir}/pxelinux.0
		if [ ! $? -eq 0 ]; then
			log_error "unable to copy pxelinux.0"
			return $EXEC_RETURN
		fi
	fi

	if [ ! -d "${tftp_dir}/pxelinux.cfg" ]; then
		try_exec $MKDIR -p ${tftp_dir}/pxelinux.cfg

		$CAT <<EOF > ${tftp_dir}/pxelinux.cfg/default
DEFAULT vmlinuz ro initrd=initrd.img nbdroot=${host_ip} nbdport=2000 xbmcdir=nfs=${host_ip}:${overlay_dir} xbmc=autostart quiet splash
EOF
	fi

	return 0
}

## update the inetd configuration
function install_inetd
{
	installed=`$GREP -v "^#" /etc/inetd.conf | $GREP "\${image_name}" | $WC -m`

	if [ "$installed" -eq 0 ]; then
		log_message "adding nbdrootd to /etc/inetd.conf"
		echo "2000	stream	tcp	nowait	nobody	/usr/sbin/tcpd /usr/sbin/nbdrootd ${image_dir}/${image_name}" >> /etc/inetd.conf
		log_message "restarting inetd"
		try_exec $INETD_INIT restart
	else
		log_message "nbdrootd already present in /etc/inetd.conf"
	fi

	return 0
}

## update the overlay configuration (nfs)
function install_overlay
{
	installed=`$GREP -v '^#' /etc/exports | $GREP "\${overlay_dir}" | $WC -m`

	if [ ! -d "${overlay_dir}" ]; then
		try_exec $MKDIR -p $overlay_dir

		if [ ! $? -eq 0 ]; then
			log_message "unable to create ${overlay_dir}"
			return $EXEC_RETURN
		fi
	fi

	if [ "${installed}" -eq 0 ]; then
		log_message "adding ${overlay_dir} to /etc/exports"
		echo "${overlay_dir}/ ${client_iprange}(rw,no_root_squash,async,no_subtree_check)" >> /etc/exports
		log_message "re-exporting /etc/exports"
		try_exec $EXPORTFS -r

		return $EXEC_RETURN
	else
		log_message "${overlay_dir} already present in /etc/exports"
	fi

	return 0
}

###############################################################################
##      Dialog helpers
###############################################################################

## get the default dialog parameters
function dialog_default
{
	dlg_title=""
	dlg_message=""
	dlg_height=10
	dlg_width=80
}

## gauge dialog
function dialog_gauge
{
	log_message "show dialog_gauge '${dlg_cur_action}'"

	$CAT <<EOF | $DIALOG --title "${dlg_title}" --gauge "Please wait" \
		$dlg_height $dlg_width 0
XXX
${dlg_cur_gauge}
${dlg_cur_action}:
XXX
EOF
	LAST_DIALOG_PID=$!
}

## a message dialog
function dialog_message
{
	log_message "show dialog_message '${dlg_message}'"

	trap "cancel_call" 0 1 2 5 15
	$DIALOG --title "${dlg_title}" --msgbox "${dlg_message}" \
		${dlg_height} ${dlg_width}

	trap - 0 1 2 5 15
}

## a yes/no dialog
function dialog_yesno
{
	log_message "show dialog_yesno '${dlg_message}'"

	trap "cancel_call" 0 1 2 5 15
	_RET=0

	$DIALOG --title "${dlg_title}" --clear --defaultno --yesno "${dlg_message}" \
		 ${dlg_height} ${dlg_width}

	trap - 0 1 2 5 15

	_RET=$?

	case ${_RET} in
	0)
		# yes
		_RET=1
		return 0
	;;
	1)
		# no
		_RET=0
		return 0
	;;
	*)
		# anything else
		return 1
	;;
	esac
}

## a question dialog
function dialog_question
{
	log_message "show dialog_question '${dlg_message}'"

	trap "cancel_call" 0 1 2 5 15
	_RET=""

	cleanup_temp
	LAST_DIALOG=`LAST_DIALOG 2>/dev/null` || LAST_DIALOG=/tmp/xdg$$

	$DIALOG --title "${dlg_title}" --clear \
		--inputbox "${dlg_message}" ${dlg_height} ${dlg_width} 2> $LAST_DIALOG

	trap - 0 1 2 5 15

	retval=$?
	case $retval in
	0)
		_RET=`$CAT $LAST_DIALOG`
		return 0
	;;
	*)
		return 1
	;;
	esac
}

## a password dialog
function dialog_password_int
{
	log_message "show dialog_password_int '${dlg_message}'"

	trap "cancel_call" 0 1 2 5 15
	_PWD=""

	cleanup_temp
	LAST_DIALOG=`LAST_DIALOG 2>/dev/null` || LAST_DIALOG=/tmp/xdg$$

	$DIALOG --title "${dlg_title}" --clear --insecure \
		--passwordbox "${dlg_message}" ${dlg_height} ${dlg_width} 2> $LAST_DIALOG

	trap - 0 1 2 5 15

	retval=$?
	case $retval in
	0)
		_PWD=`$CAT $LAST_DIALOG`
		return 0
	;;
	*)
		return 1
	;;
	esac
}

## a password dialog
function dialog_password
{
	log_message "show dialog_password '${dlg_message}'"

	_RET=""
	orig_message="${dlg_message}"

	dialog_password_int

	if [ $? -eq 1 ]; then
                return 1
	else
		if [ `echo "$_PWD" | $WC -m` -lt 4 ]; then
			dialog_error "The password is too short. Please use at least 3 characters"

			dialog_password

			return $?
		else
			password1="$_PWD"
			dlg_message="Enter the same password again."

			dialog_password_int

			if [ $? -eq 1 ]; then
				return 1
			else
				password2="$_PWD"

				if [ "x$password1" == "x$password2" ]; then
					_RET="$password1"
					return 0
				else
					dialog_error "The passwords don't match. Please try again."

					dlg_message="$orig_message"
					dialog_password

					return $?
				fi
			fi
		fi
 	fi
}

## error dialog
function dialog_error
{
	log_message "show dialog_error '$1'"

	if [ ! -z "$LAST_DIALOG_PID" ]; then
		kill $LAST_DIALOG_PID &>/dev/null
		unset LAST_DIALOG_PID
	fi

	trap "cancel_call" 0 1 2 5 15
	$DIALOG --title "${dlg_title}" --msgbox "$1" \
		${dlg_height} ${dlg_width}
	trap - 0 1 2 5 15
}

###############################################################################
##      Menu items
###############################################################################

## the help file
function menu_item_help
{
	log_message "show menu_item_help"

	dialog_default
	dlg_width=84
	dlg_height=30
	dlg_title="XBMC Diskless server"
	dlg_message=`$ZCAT /usr/share/doc/xbmc-diskless-server/README.gz`

	trap "cancel_call" 0 1 2 5 15
	$DIALOG --title "${dlg_title}" --msgbox "${dlg_message}" \
		${dlg_height} ${dlg_width}

	trap - 0 1 2 5 15
}

## the main menu
function show_dlg_menu
{
	log_message "show show_dlg_menu"

	exiting="0"

	while [ $exiting -eq 0 ]; do
		trap "cleanup_temp" 0 1 2 5 15
		cleanup_temp
		LAST_DIALOG=`LAST_DIALOG 2>/dev/null` || LAST_DIALOG=/tmp/xdg$$

		$DIALOG --clear --title "XBMC Diskless Server" \
			--menu "Choose an option:" 20 51 10 \
			"create" "Create a new image" \
			"pack" "Compress a new image" \
			"install" "Install a new image" \
			"provision" "Create the provisioning files" \
			"help" "Show help" \
			"exit" "Exit this tool" 2> $LAST_DIALOG

		trap - 0 1 2 5 15

		retval=$?

		choice=`$CAT $LAST_DIALOG`

		case $retval in
		0)
			dlg_menu_choice "$choice"

			if [ $? -eq 1 ]; then
				dialog_error "The last action did not complete succesfully. You might want to check the log file in ${log_file}"
			fi
		;;
		1)
			exiting="1"
		;;
		255)
			exiting="1"
		;;
		esac
	done

	clean_and_exit
}

## handle a choice in the main menu
function dlg_menu_choice
{
	log_message "show dlg_menu_choice '$1'"

	case $1 in
	create)
		menu_item_create
		return $?
	;;
	pack)
		menu_item_pack
		return $?
	;;
	install)
		menu_item_install
		return $?
	;;
	provision)
		update_provision
		return $?
	;;
	help)
		menu_item_help
		return $?
	;;
	*)
		return 1
	;;
	esac
}

## pack a new image
function menu_item_pack
{
	log_message "show menu_item_pack"

	if [ ! -d "${target_dir}" ]; then
		dialog_error "Cannot find the source in '${target_dir}'. Please create a new image first"
		return 1
	fi

	dialog_default
	dlg_title="Creating a compressed image"
	dlg_cur_action="Cleaning the target"
	dlg_cur_gauge=0
	dialog_gauge
	pack_cleanup
	
	dlg_cur_action="Compressing the target"
	dlg_cur_gauge=25
	dialog_gauge
	pack

	if [ ! $? -eq 0 ]; then
		dialog_error "An error occured while trying to compress the image. A detailed log can be found in '${log_file}'."
		return 1
	else
		dialog_error "The compressed image has been created succesfully. You can continue to install the image."
		return 0
	fi
}

## install the new image
function menu_item_install
{
	log_message "show menu_item_install"

	if [ ! -f "${image_dir}/${image_name}-new" && ! -f "${image_dir}/${image_name}" ]; then
		dialog_error "Cannot find the compressed image. Please create a new image first"
		return 1
	fi

	dialog_default
	dlg_title="Installing a new image"
	dlg_message="Please make sure all your clients are shut down before installing a new image or your clients will crash!\n
\n
Press OK when all your clients are shut down to continue."
	dialog_message

	dlg_cur_action="Moving squashfs image and kernel"
	dlg_cur_gauge=0
	dialog_gauge
	install_image

	if [ ! $? -eq 0 ]; then
		dialog_error "An error occured while trying to install the image. A detailed log can be found in '${log_file}'."
		return 1
	fi
	
	dlg_cur_action="Updating /etc/inetd.conf"
	dlg_cur_gauge=50
	dialog_gauge
	install_inetd
	
	if [ ! $? -eq 0 ]; then
		dialog_error "An error occured while trying to update /etc/inetd.conf. A detailed log can be found in '${log_file}'."
		return 1
	fi
	
	dlg_cur_action="Updating overlay configuration"
	dlg_cur_gauge=75
	dialog_gauge
	install_overlay
	
	if [ ! $? -eq 0 ]; then
		dialog_error "An error occured while trying to update the overlay configuration. A detailed log can be found in '${log_file}'."
		return 1
	fi
	
	dlg_message="The new image has been installed succesfully. You can boot your clients again, or you can update your provisioning files before booting them."
	dialog_message
	return 0
}

## create a new target
function menu_item_create
{
	log_message "show menu_item_create"

	### intro
	dialog_default
	dlg_width=80
	dlg_height=14

	dlg_title="Create a new image - step 1/7"
	dlg_message="This will create a new image, used for booting your clients over the network.\n
The image contains a minimal Ubuntu installation with XBMC Live installed.\n
\n
Your current images will not be changed until the final step, which will ask for your confirmation. You can press 'Cancel' at any time."

	dialog_message

	item_create_2
	return $?
}

###############################################################################
##      Target creation gui
###############################################################################

## crate a new target, step 2
function item_create_2
{
	log_message "show item_create_2"

	### distribution
	dlg_title="Create a new image - step 2/7"
	dlg_message="Please enter the Ubuntu distribution to use on your clients. If nothing is entered, '$ubuntu_dist' will be used.\n
\n
Please note that only 'lucid' is tested."

	dialog_question

	if [ $? -eq 1 ]; then
		return 1
	else
		if [ -z "$_RET" ]; then
			dlg_message="Using the default distribution: '$ubuntu_dist'"
			dialog_message
		else
			ubuntu_dist="$_RET"
		fi

		item_create_3
		return $?
	fi
}

## crate a new target, step 3
function item_create_3
{
	log_message "show item_create_3"

	### ppa
	LAST_DIALOG=`LAST_DIALOG 2>/dev/null` || LAST_DIALOG=/tmp/xdg$$

	$DIALOG --clear --title "Create a new image - step 3/7" \
		--menu "Select the PPA you want to use:" 20 51 10 \
		"none"  "No PPA" \
		"teamxbmc" "Team XBMC official PPA" \
		"opdenkamp"  "XBMC Dharma with PVR" \
		"henningpingel" "Henning Pingel's PPA" \
		"gregor-fuis" "Gregor Fuis' PPA" \
		"custom" "Enter a custom PPA" 2> $LAST_DIALOG

	retval=$?

	if [ $retval -eq 0 ]; then
		choice=`$CAT $LAST_DIALOG`

		case $choice in
		none)
			ppa_source=""
			item_create_4
			return $?
		;;
		team-xbmc)
			ppa_source="ppa:team-xbmc/ppa"
			item_create_4
			return $?
		;;
		opdenkamp)
			ppa_source="ppa:lars-opdenkamp/xbmc-pvr"
			item_create_4
			return $?
		;;
		henningpingel)
			ppa_source="ppa:henningpingel/xbmc"
			item_create_4
			return $?
		;;
		gregor-fuis)
			ppa_source="ppa:gregor-fuis/xbmc-pvr"
			item_create_4
			return $?
		;;
		custom)
			item_create_3_custom
			return $?
		;;
		esac
	else
		return 1
	fi
}

## crate a new target, step 3 - custom ppa
function item_create_3_custom
{
	log_message "show item_create_3_custom"

	### custom ppa
	dlg_title="Create a new image - step 3/7"
	dlg_message="Please enter the PPA you want to use. Leave it empty if you don't want to use any PPA.\n
Example: ppa:lars-opdenkamp/xbmc-diskless"
	dialog_question

	if [ $? -eq 1 ]; then
		return 1
	elif [ -z "$_RET" ]; then
		dlg_message="Not using any PPA"
		ppa_source=""
		dialog_message

		item_create_4
	else
		ppa_source="$_RET"

		item_create_4
		return $?
	fi
}

## crate a new target, step 4
function item_create_4
{
	log_message "show item_create_4"

	### extra packages
	dlg_title="Create a new image - step 4/7"
	dlg_message="Enter any extra packages you want to have installed"
	dialog_question

	if [ $? -eq 1 ]; then
		return 1
	else
		extra_packages="$_RET"

		item_create_5
		return $?
	fi
}

## crate a new target, step 5
function item_create_5
{
	log_message "show item_create_4"

	### password
	dlg_title="Create a new image - step 5/7"
	dlg_message="Enter the password for the user 'xbmc'"
	dialog_password

	if [ $? -eq 1 ]; then
		return 1
	else
		client_password="$_RET"

		item_create_6
		return $?
	fi
}

## crate a new target, step 6
function item_create_6
{
	log_message "show item_create_6"

	### verify
	dlg_title="Create a new image - step 6/7"
	dlg_message="Is this information correct?\n
Ubuntu distribution:     $ubuntu_dist\n
PPA source:              $ppa_source\n
Extra packages:          $extra_packages\n
Password:                [hidden]\n
\n
If you press 'yes', a new image will be created. It will not be installed yet."
	dialog_yesno

	if [ $? -eq 1 ]; then
		return 1
	else
		if [ $_RET -eq 0 ]; then
			return 1
		else
			# start creating
			item_create_7
			return $?
		fi
	fi
}

## crate a new target, step 7
function item_create_7
{
	log_message "show item_create_7"

	### create new image
	dlg_title="Create a new image - step 7/7"

	dlg_cur_action="Removing old files"
	dlg_cur_gauge=0
	dialog_gauge
	remove_target
	if [ ! $? -eq 0 ]; then
		dialog_error "An error occured while trying to remove '${target_dir}'."
		return 1
	fi

	dlg_cur_gauge=5
	dlg_cur_action="Creating target"
	dialog_gauge
	create_target
	if [ ! $? -eq 0 ]; then
		dialog_error "An error occured while trying to create '${target_dir}'."
		return 1
	fi

	dlg_cur_gauge=5
	dlg_cur_action="Downloading basic Ubuntu installation (this will take a while)"
	dialog_gauge
	debootstrap_target_download
	if [ ! $? -eq 0 ]; then
		dialog_error "An error occured while trying to run debootstrap."
		return 1
	fi

	dlg_cur_gauge=25
	dlg_cur_action="Creating basic Ubuntu installation (this will take a while)"
	dialog_gauge
	debootstrap_target
	if [ ! $? -eq 0 ]; then
		dialog_error "An error occured while trying to run debootstrap."
		return 1
	fi

	dlg_cur_gauge=40
	dlg_cur_action="Mounting virtual directories"
	dialog_gauge
	mount_virtual
	if [ ! $? -eq 0 ]; then
		dialog_error "An error occured while trying to mount virtual directories."
		return 1
	fi

	dlg_cur_gauge=40
	dlg_cur_action="Updating apt sources"
	dialog_gauge
	update_apt_sources
	if [ ! $? -eq 0 ]; then
		dialog_error "An error occured while trying to update the APT sources."
		return 1
	fi

	dlg_cur_gauge=45
	dlg_cur_action="Upgrading installation"
	dialog_gauge
	upgrade_system
	if [ ! $? -eq 0 ]; then
		dialog_error "An error occured while trying to upgrade the installation."
		return 1
	fi

	dlg_cur_gauge=50
	dlg_cur_action="Downloading XBMC"
	dialog_gauge
	download_xbmc
	if [ ! $? -eq 0 ]; then
		dialog_error "An error occured while trying to download XBMC."
		return 1
	fi

	dlg_cur_gauge=70
	dlg_cur_action="Installing XBMC"
	dialog_gauge
	install_xbmc
	if [ ! $? -eq 0 ]; then
		dialog_error "An error occured while trying to install XBMC."
		return 1
	fi

	dlg_cur_gauge=90
	dlg_cur_action="Installing bootsplash"
	dialog_gauge
	install_bootsplash
	if [ ! $? -eq 0 ]; then
		dialog_error "An error occured while trying to install the bootsplash image."
		return 1
	fi

	dlg_cur_gauge=95
	dlg_cur_action="Installing misc. packages"
	dialog_gauge
	install_misc
	if [ ! $? -eq 0 ]; then
		dialog_error "An error occured while trying to install the misc. packages."
		return 1
	fi

	dlg_cur_gauge=100
	dlg_cur_action="Installing the kernel"
	dialog_gauge
	install_kernel
	if [ ! $? -eq 0 ]; then
		dialog_error "An error occured while trying to install the kernel."
		return 1
	fi

	dlg_cur_gauge=100
	dlg_cur_action="Finishing the installation"
	dialog_gauge
	copy_host_key && umount_virtual
	if [ ! $? -eq 0 ]; then
		dialog_error "An error occured while trying to finish the installation."
		return 1
	fi

	dlg_message="New image created succesfully in '${target_dir}'. If you are satisfied with it, continue to 'pack' the image. This will create a compressed squashfs image of the installation."
	dialog_message
}

## remove the temporary files and exit
function clean_and_exit
{
	cleanup_temp
	clear
	exit 0
}

###############################################################################
##      Configuration checks
###############################################################################

function check_image_present
{
	echo -n "image present:            "
	if [ ! -f "${base_dir}/images/${image_name}" ]; then
		echo "NO - create an installation image first"
		return 1
	else
		echo "yes"
		return 0
	fi

	echo -n "nbd (2000) listening:     "
	tmp=`$NETSTAT -lan | $GREP 2000 | $GREP LISTEN | $WC -m`
	if [ $tmp -eq 0 ]; then
		echo "NO - clients will not boot"
		errors=1
	else
		echo "yes"
	fi
}

function check_inetd_running
{
	errors=0

	echo -n "inetd running:            "
	tmp=`$PIDOF $INETD | $WC -m`
	if [ $tmp -eq 0 ]; then
		echo "NO - clients will not boot"
		errors=1
	else
		echo "yes"
	fi

	return $errors
}

function check_tftpd_running
{
	errors=0

	echo -n "tftpd running:            "
	tmp=`$PIDOF $TFTPD | $WC -m`
	if [ $tmp -eq 0 ]; then
		echo "NO - clients will not boot"
		errors=1
	else
		echo "yes"
	fi

	echo -n "tftpd (69) listening:     "
	tmp=`$NETSTAT -lan | $GREP 69 | $GREP udp | $WC -m`
	if [ $tmp -eq 0 ]; then
		echo "NO - clients will not boot"
		errors=1
	else
		echo "yes"
	fi

	return $errors
}

function check_nfs_running
{
	errors=0

	echo -n "nfsd running:             "
	tmp=`$PIDOF nfsd | $WC -m`
	if [ $tmp -eq 0 ]; then
		echo "NO - clients will not be able to persist data"
		errors=1
	else
		echo "yes"
	fi

	echo -n "mountd running:           "
	tmp=`$PIDOF $MOUNTD | $WC -m`
	if [ $tmp -eq 0 ]; then
		echo "NO - clients will not be able to persist data"
		errors=1
	else
		echo "yes"
	fi

	echo -n "statd running:            "
	tmp=`$PIDOF $STATD | $WC -m`
	if [ $tmp -eq 0 ]; then
		echo "NO - clients will not be able to persist data"
		errors=1
	else
		echo "yes"
	fi

	echo -n "portmap running:          "
	tmp=`$PIDOF $PORTMAP | $WC -m`
	if [ $tmp -eq 0 ]; then
		echo "NO - clients will not be able to persist data"
		errors=1
	else
		echo "yes"
	fi

	echo -n "/etc/exports has overlay: "
	tmp=`$GREP -v '^#' /etc/exports | $GREP "\${overlay_dir}" | $WC -m`
	if [ $tmp -eq 0 ]; then
		echo "NO - clients will not be able to persist data"
		errors=1
	else
		echo "yes"
	fi

	echo -n "portmap (111) listening:  "
	tmp=`$NETSTAT -lan | $GREP 111 | $GREP LISTEN | $WC -m`
	if [ $tmp -eq 0 ]; then
		echo "NO - clients will not be able to persist data"
		errors=1
	else
		echo "yes"
	fi

	echo -n "nfs (2049) listening:     "
	tmp=`$NETSTAT -lan | $GREP 2049 | $GREP LISTEN | $WC -m`
	if [ $tmp -eq 0 ]; then
		echo "NO - clients will not be able to persist data"
		errors=1
	else
		echo "yes"
	fi

	return $errors
}

function check_config
{
	errors=0

	echo "Checking your configuration:"

	check_image_present
	if [ $? -eq 1 ]; then
		errors=1
	fi

	check_inetd_running
	if [ $? -eq 1 ]; then
		errors=1
	fi

	check_tftpd_running
	if [ $? -eq 1 ]; then
		errors=1
	fi

	check_nfs_running
	if [ $? -eq 1 ]; then
		errors=1
	fi

	if [ $errors -eq 1 ]; then
		echo ""
		echo "Error were detected!"
	fi

	return $errors
}

if [ "x$1" = "xcheck" ]; then
	check_config
else
	# set the default client_iprange if it's not set
	host_ip=`$IFCONFIG | $GREP "inet addr" | $AWK '{print $2}' | $SED 's/addr://' | $GREP -v "127.0.0.1" | $HEAD -n1`
	log_message "detected IP: $host_ip"

	host_mask=`$IFCONFIG | $GREP "inet addr" | $AWK '{print $4}' | $SED 's/Mask://' | $GREP -v "255.0.0.0" | $HEAD -n1`
	log_message "detected hostmask: $host_mask"

	if [ -z "${client_iprange}" ]; then
		client_iprange="${host_ip}/${host_mask}"
	fi

	## run the main menu
	show_dlg_menu
fi

exit $?
