#!/bin/bash
# vim: set noet :

set -eu

################################################################################
# Default Variables
################################################################################

# Root File System Mount Point
# Values: String
# shellcheck disable=SC2086
: ${WORKDIR:='/tmp/rootfs'}

# Destination Directory
# Values: String
# shellcheck disable=SC2086
: ${DESTDIR:="$(cd "$(dirname "$0")"; pwd)/release"}

# Release Codename
# Value:
#   - xenial
#   - bionic
# shellcheck disable=SC2086
: ${RELEASE:='bionic'}

# Kernel Package
# Values:
#   - generic
#   - generic-hwe
#   - signed-generic
#   - signed-generic-hwe
#   - virtual
#   - virtual-hwe
# shellcheck disable=SC2086
: ${KERNEL:='generic'}

# Package Selection
# Values:
#   - minimal
#   - standard
#   - server
#   - cloud
# shellcheck disable=SC2086
: ${PROFILE:='cloud'}

# Cloud-Init Datasources
# Values:
#   - NoCloud
#   - None
# shellcheck disable=SC2086
: ${DATASOURCES:='NoCloud, None'}

# Apt Repository - Official
# Values: String
# shellcheck disable=SC2086
: ${MIRROR_UBUNTU:='http://archive.ubuntu.com/ubuntu'}

# Apt Repository URL - Canonical Partner
# Values: String
# shellcheck disable=SC2086
: ${MIRROR_UBUNTU_PARTNER:='http://archive.canonical.com'}

# Proxy - No Proxy List
# Values: String
# shellcheck disable=SC2086
: ${NO_PROXY:=''}

# Proxy - FTP Proxy
# Values: String
# shellcheck disable=SC2086
: ${FTP_PROXY:=''}

# Proxy - HTTP Proxy
# Values: String
# shellcheck disable=SC2086
: ${HTTP_PROXY:=''}

# Proxy - HTTPS Proxy
# Values: String
# shellcheck disable=SC2086
: ${HTTPS_PROXY:=''}

# Proxy - Apt Proxy Host
# Values: String
# shellcheck disable=SC2086
: ${APT_PROXY_HOST:=''}

# Proxy - Apt Proxy Port
# Values: String
# shellcheck disable=SC2086
: ${APT_PROXY_PORT:=''}

################################################################################
# Available Environment
################################################################################

# Release
declare -a AVAILABLE_RELEASE=(
	'xenial'
	'bionic'
)

# Kernel
declare -a AVAILABLE_KERNEL=(
	'generic'
	'generic-hwe'
	'signed-generic'
	'signed-generic-hwe'
	'virtual'
	'virtual-hwe'
)

# Profile
declare -a AVAILABLE_PROFILE=(
	'minimal'
	'standard'
	'server'
	'cloud'
)

################################################################################
# Check Environment
################################################################################

# Array Util
containsElement () {
	local e match="$1"
	shift
	for e; do [[ "$e" == "$match" ]] && return 0; done
	return 1
}

# Release
containsElement "${RELEASE}" "${AVAILABLE_RELEASE[@]}"
RETVAL=$?
if [ "${RETVAL}" != 0 ]; then
	echo "RELEASE: ${AVAILABLE_RELEASE[*]}"
	exit 1
fi

# Kernel
containsElement "${KERNEL}" "${AVAILABLE_KERNEL[@]}"
RETVAL=$?
if [ "${RETVAL}" != 0 ]; then
	echo "KERNEL: ${AVAILABLE_KERNEL[*]}"
	exit 1
fi

# Profile
containsElement "${PROFILE}" "${AVAILABLE_PROFILE[@]}"
RETVAL=$?
if [ "${RETVAL}" != 0 ]; then
	echo "PROFILE: ${AVAILABLE_PROFILE[*]}"
	exit 1
fi

################################################################################
# Normalization Environment
################################################################################

# Select Kernel Package
case "${RELEASE}-${KERNEL}" in
	* ) ;;
esac

################################################################################
# Require Environment
################################################################################

# Get Release Version
case "${RELEASE}" in
	'xenial' )
		# shellcheck disable=SC2034
		RELEASE_MAJOR='16'
		# shellcheck disable=SC2034
		RELEASE_MINOR='04'
	;;
	'bionic' )
		# shellcheck disable=SC2034
		RELEASE_MAJOR='18'
		# shellcheck disable=SC2034
		RELEASE_MINOR='04'
	;;
esac

# Download Files Directory
CACHEDIR="$(cd "$(dirname "$0")"; pwd)/.cache"

# Destination Directory
DESTDIR="${DESTDIR}/${RELEASE}/${KERNEL}/${PROFILE}"

# Debootstrap Command
DEBOOTSTRAP_COMMAND="debootstrap"

# Debootstrap Variant
DEBOOTSTRAP_VARIANT="--variant=minbase"

# Debootstrap Components
DEBOOTSTRAP_COMPONENTS="--components=main,restricted,universe,multiverse"

# Debootstrap Include Packages
DEBOOTSTRAP_INCLUDES="--include=gnupg,eatmydata"

# Debootstrap Environment
declare -a DEBOOTSTRAP_ENVIRONMENT=()

# Check APT Proxy
if [ "x${APT_PROXY_HOST}" != "x" ] && [ "x${APT_PROXY_PORT}" != "x" ]; then
	# HTTP Proxy Environment
	DEBOOTSTRAP_ENVIRONMENT=("${DEBOOTSTRAP_ENVIRONMENT[*]}" "http_proxy=http://${APT_PROXY_HOST}:${APT_PROXY_PORT}")

	# HTTPS Proxy Environment
	DEBOOTSTRAP_ENVIRONMENT=("${DEBOOTSTRAP_ENVIRONMENT[*]}" "https_proxy=http://${APT_PROXY_HOST}:${APT_PROXY_PORT}")
fi

# Check Debootstrap Environment
if [ ${#DEBOOTSTRAP_ENVIRONMENT[*]} -gt 0 ]; then
	# Debootstrap Override Command
	DEBOOTSTRAP_COMMAND="env ${DEBOOTSTRAP_ENVIRONMENT[*]} ${DEBOOTSTRAP_COMMAND}"
fi

# Select Kernel Image Package
case "${RELEASE}-${KERNEL}" in
	"xenial-generic"            ) KERNEL_IMAGE_PACKAGE="linux-image-generic" ;;
	"bionic-generic"            ) KERNEL_IMAGE_PACKAGE="linux-image-generic" ;;
	"xenial-generic-hwe"        ) KERNEL_IMAGE_PACKAGE="linux-image-generic-hwe-16.04" ;;
	"bionic-generic-hwe"        ) KERNEL_IMAGE_PACKAGE="linux-image-generic-hwe-18.04" ;;
	"xenial-signed-generic"     ) KERNEL_IMAGE_PACKAGE="linux-signed-image-generic" ;;
	"bionic-signed-generic"     ) KERNEL_IMAGE_PACKAGE="linux-signed-image-generic" ;;
	"xenial-signed-generic-hwe" ) KERNEL_IMAGE_PACKAGE="linux-signed-image-generic-hwe-16.04" ;;
	"bionic-signed-generic-hwe" ) KERNEL_IMAGE_PACKAGE="linux-signed-image-generic-hwe-18.04" ;;
	"xenial-virtual"            ) KERNEL_IMAGE_PACKAGE="linux-image-virtual" ;;
	"bionic-virtual"            ) KERNEL_IMAGE_PACKAGE="linux-image-virtual" ;;
	"xenial-virtual-hwe"        ) KERNEL_IMAGE_PACKAGE="linux-image-virtual-hwe-16.04" ;;
	"bionic-virtual-hwe"        ) KERNEL_IMAGE_PACKAGE="linux-image-virtual-hwe-18.04" ;;
esac

# Select Kernel Header Package
case "${RELEASE}-${KERNEL}" in
	"xenial-generic"            ) KERNEL_HEADER_PACKAGE="linux-headers-generic" ;;
	"bionic-generic"            ) KERNEL_HEADER_PACKAGE="linux-headers-generic" ;;
	"xenial-generic-hwe"        ) KERNEL_HEADER_PACKAGE="linux-headers-generic-hwe-16.04" ;;
	"bionic-generic-hwe"        ) KERNEL_HEADER_PACKAGE="linux-headers-generic-hwe-18.04" ;;
	"xenial-signed-generic"     ) KERNEL_HEADER_PACKAGE="linux-headers-generic" ;;
	"bionic-signed-generic"     ) KERNEL_HEADER_PACKAGE="linux-headers-generic" ;;
	"xenial-signed-generic-hwe" ) KERNEL_HEADER_PACKAGE="linux-headers-generic-hwe-16.04" ;;
	"bionic-signed-generic-hwe" ) KERNEL_HEADER_PACKAGE="linux-headers-generic-hwe-18.04" ;;
	"xenial-virtual"            ) KERNEL_HEADER_PACKAGE="linux-headers-virtual" ;;
	"bionic-virtual"            ) KERNEL_HEADER_PACKAGE="linux-headers-virtual" ;;
	"xenial-virtual-hwe"        ) KERNEL_HEADER_PACKAGE="linux-headers-virtual-hwe-16.04" ;;
	"bionic-virtual-hwe"        ) KERNEL_HEADER_PACKAGE="linux-headers-virtual-hwe-18.04" ;;
esac

################################################################################
# Cleanup
################################################################################

# Check Cache Directory
if [ ! -d "${CACHEDIR}" ]; then
	# Create Cache Directory
	mkdir -p "${CACHEDIR}"
fi

# Check Destination Directory
if [ -d "${DESTDIR}" ]; then
	# Cleanup Destination Directory
	find "${DESTDIR}" -type f -print0 | xargs -0 rm -f
else
	# Create Destination Directory
	mkdir -p "${DESTDIR}"
fi

# Unmount Root Partition
awk '{print $2}' /proc/mounts | grep -s "${WORKDIR}" | sort -r | xargs --no-run-if-empty umount

################################################################################
# Disk
################################################################################

# Mount Root File System Partition
mkdir -p "${WORKDIR}"
mount -t tmpfs -o 'mode=0755' tmpfs "${WORKDIR}"

################################################################################
# Debootstrap
################################################################################

# Install Base System
${DEBOOTSTRAP_COMMAND} ${DEBOOTSTRAP_VARIANT} ${DEBOOTSTRAP_COMPONENTS} ${DEBOOTSTRAP_INCLUDES} "${RELEASE}" "${WORKDIR}" "${MIRROR_UBUNTU}"

# Require Environment
declare -x PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
declare -x HOME="/root"
declare -x LC_ALL="C"
declare -x LANGUAGE="C"
declare -x LANG="C"
declare -x DEBIAN_FRONTEND="noninteractive"
declare -x DEBIAN_PRIORITY="critical"
declare -x DEBCONF_NONINTERACTIVE_SEEN="true"

# Cleanup Files
find "${WORKDIR}/dev"     -mindepth 1 -print0 | xargs -0 --no-run-if-empty rm -fr
find "${WORKDIR}/proc"    -mindepth 1 -print0 | xargs -0 --no-run-if-empty rm -fr
find "${WORKDIR}/run"     -mindepth 1 -print0 | xargs -0 --no-run-if-empty rm -fr
find "${WORKDIR}/sys"     -mindepth 1 -print0 | xargs -0 --no-run-if-empty rm -fr
find "${WORKDIR}/tmp"     -mindepth 1 -print0 | xargs -0 --no-run-if-empty rm -fr
find "${WORKDIR}/var/tmp" -mindepth 1 -print0 | xargs -0 --no-run-if-empty rm -fr

# Require Mount
mount -t devtmpfs                   devtmpfs "${WORKDIR}/dev"
mount -t devpts   -o gid=5,mode=620 devpts   "${WORKDIR}/dev/pts"
mount -t proc                       proc     "${WORKDIR}/proc"
mount -t tmpfs    -o mode=755       tmpfs    "${WORKDIR}/run"
mount -t sysfs                      sysfs    "${WORKDIR}/sys"
mount -t tmpfs                      tmpfs    "${WORKDIR}/tmp"
mount -t tmpfs                      tmpfs    "${WORKDIR}/var/tmp"
chmod 1777 "${WORKDIR}/dev/shm"

################################################################################
# Workaround
################################################################################

# Apt Speed Up
echo 'force-unsafe-io' > "${WORKDIR}/etc/dpkg/dpkg.cfg.d/02apt-speedup"

################################################################################
# Repository
################################################################################

# Official Repository
cat > "${WORKDIR}/etc/apt/sources.list" << __EOF__
# Official Repository
deb ${MIRROR_UBUNTU} ${RELEASE}           main restricted universe multiverse
deb ${MIRROR_UBUNTU} ${RELEASE}-updates   main restricted universe multiverse
deb ${MIRROR_UBUNTU} ${RELEASE}-backports main restricted universe multiverse
deb ${MIRROR_UBUNTU} ${RELEASE}-security  main restricted universe multiverse
__EOF__

# Partner Repository
cat > "${WORKDIR}/etc/apt/sources.list.d/ubuntu-partner.list" << __EOF__
# Partner Repository
deb ${MIRROR_UBUNTU_PARTNER} ${RELEASE} partner
__EOF__

################################################################################
# Upgrade
################################################################################

# Update Repository
chroot "${WORKDIR}" apt-get -y update

# Upgrade System
chroot "${WORKDIR}" apt-get -y dist-upgrade

################################################################################
# Kernel
################################################################################

# Install Kernel
chroot "${WORKDIR}" apt-get -y --no-install-recommends install "${KERNEL_IMAGE_PACKAGE}"

# Get Kernel Version
KERNEL_VERSION="$(chroot "${WORKDIR}" dpkg -l | awk '{print $2}' | grep -E 'linux-image-[0-9\.-]+-generic' | sed -E 's/linux-image-//')"

################################################################################
# Minimal
################################################################################

# Minimal Package
chroot "${WORKDIR}" apt-get -y install ubuntu-minimal

# Systemd Packages
chroot "${WORKDIR}" apt-get -y install systemd policykit-1

################################################################################
# Standard
################################################################################

# Check Environment Variable
if [ "${PROFILE}" != 'minimal' ]; then
	# Install Package
	chroot "${WORKDIR}" apt-get -y install ubuntu-standard
fi

################################################################################
# LiveBoot
################################################################################

# Require Package
chroot "${WORKDIR}" apt-get -y install cloud-initramfs-copymods cloud-initramfs-dyn-netconf cloud-initramfs-rooturl overlayroot

# Check Release Version
if [ "${RELEASE}" = 'xenial' ]; then
	# Workaround initramfs dns
	cat > "${WORKDIR}/usr/share/initramfs-tools/hooks/libnss_dns" <<- '__EOF__'
	#!/bin/sh -e

	[ "$1" = 'prereqs' ] && { exit 0; }

	. /usr/share/initramfs-tools/hook-functions

	for libnss_dns in /lib/x86_64-linux-gnu/libnss_dns*; do
		if [ -e "${libnss_dns}" ]; then
			copy_exec "${libnss_dns}" /lib
			copy_exec "${libnss_dns}" /lib/x86_64-linux-gnu
		fi
	done
	__EOF__

	# Execute Permission
	chmod 0755 "${WORKDIR}/usr/share/initramfs-tools/hooks/libnss_dns"
fi

# Include Kernel Modules
cat > "${WORKDIR}/usr/share/initramfs-tools/hooks/include_kernel_modules" <<- '__EOF__'
#!/bin/sh -e

[ "$1" = 'prereqs' ] && { exit 0; }

. /usr/share/initramfs-tools/hook-functions

# Bonding
manual_add_modules bonding
# Network Driver
copy_modules_dir kernel/drivers/net
# Mount Encoding
copy_modules_dir kernel/fs/nls
__EOF__

# Execute Permission
chmod 0755 "${WORKDIR}/usr/share/initramfs-tools/hooks/include_kernel_modules"

# Generate Reset Network Interface for Initramfs
cat > "${WORKDIR}/usr/share/initramfs-tools/scripts/local-top/liveroot" << '__EOF__'
#!/bin/sh

[ "$1" = 'prereqs' ] && { exit 0; }

liveroot_mount_squashfs() {
	local readonly device="$1" fstype="$2" option="$3" image="$4" target="$5"

	mkdir -p "/run/liveroot"
	mount -t "${fstype}" -o "${option}" "${device}" "/run/liveroot"

	if [ -f "/run/liveroot${image}" ]; then
		mkdir -p "${target}"
		mount -t squashfs -o loop "/run/liveroot${image}" "${target}"
		return 0
	else
		umount "/run/liveroot"
		return 1
	fi
}

liveroot() {
	local readonly target="$1" image="${2#file://}"
	local device fstype

	udevadm trigger
	udevadm settle

	modprobe nls_utf8

	for device in $(blkid -o device); do
		fstype="$(blkid -p -s TYPE -o value "${device}")"

		case "${fstype}" in
			iso9660) liveroot_mount_squashfs "${device}" "${fstype}" "loop"              "${image}" "${target}" && break ;;
			vfat)    liveroot_mount_squashfs "${device}" "${fstype}" "ro,iocharset=utf8" "${image}" "${target}" && break ;;
			*)       continue ;;
		esac
	done
}

. /scripts/functions

case "${ROOT}" in
	file://*.squashfs) log_warning_msg "ROOT=\"${ROOT}\"" ;;
	file://*.squash)   log_warning_msg "ROOT=\"${ROOT}\"" ;;
	file://*.sfs)      log_warning_msg "ROOT=\"${ROOT}\"" ;;
	*)                 exit 0 ;;
esac

liveroot "${rootmnt}.live" "${ROOT}" || exit 1

{
	echo 'ROOTFSTYPE="liveroot"'
	echo "ROOTFLAGS=\"-o move\""
	echo "ROOT=\"${rootmnt}.live\""
} > /conf/param.conf
__EOF__

# Execute Permission
chmod 0755 "${WORKDIR}/usr/share/initramfs-tools/scripts/local-top/liveroot"

# Generate Default Network Configuration
cat > "${WORKDIR}/usr/share/initramfs-tools/scripts/init-bottom/network-config" << '__EOF__'
#!/bin/sh

[ "$1" = 'prereqs' ] && { echo 'overlayroot'; exit 0; }

parse_cmdline() {
	local param
	for param in $(cat /proc/cmdline); do
		case "${param}" in
			ds=*) return 1 ;;
		esac
	done
	return 0
}

interfaces_config() {
	local intf
	echo 'auto lo'                >  "${rootmnt}/etc/network/interfaces.d/50-cloud-init.cfg"
	echo 'iface lo inet loopback' >> "${rootmnt}/etc/network/interfaces.d/50-cloud-init.cfg"
	for intf in /sys/class/net/*; do
		if [ "${intf##*/}" = 'lo' ]; then
			continue
		fi
		echo ""                            >> "${rootmnt}/etc/network/interfaces.d/50-cloud-init.cfg"
		echo "auto ${intf##*/}"            >> "${rootmnt}/etc/network/interfaces.d/50-cloud-init.cfg"
		echo "iface ${intf##*/} inet dhcp" >> "${rootmnt}/etc/network/interfaces.d/50-cloud-init.cfg"
	done
}

netplan_config() {
	local readonly cfgs="$(find ${rootmnt}/etc/netplan -type f -name '*.yaml' | wc -l)"
	if [ "${cfgs}" -gt 0 ]; then
		return 1
	fi
	echo "network:"     >  "${rootmnt}/etc/netplan/50-cloud-init.yaml"
	echo "  version: 2" >> "${rootmnt}/etc/netplan/50-cloud-init.yaml"
	echo "  ethernets:" >> "${rootmnt}/etc/netplan/50-cloud-init.yaml"
	local intf addr
	for intf in /sys/class/net/*; do
		if [ "${intf##*/}" = 'lo' ]; then
			continue
		fi
		addr="$(cat ${intf}/address)"
		echo "    ${intf##*/}:"            >> "${rootmnt}/etc/netplan/50-cloud-init.yaml"
		echo "      match:"                >> "${rootmnt}/etc/netplan/50-cloud-init.yaml"
		echo "        macaddress: ${addr}" >> "${rootmnt}/etc/netplan/50-cloud-init.yaml"
		echo "      set-name: ${intf##*/}" >> "${rootmnt}/etc/netplan/50-cloud-init.yaml"
		echo "      dhcp4: yes"            >> "${rootmnt}/etc/netplan/50-cloud-init.yaml"
		echo "      optional: true"        >> "${rootmnt}/etc/netplan/50-cloud-init.yaml"
	done
}

. /scripts/functions

case "${ROOTFSTYPE}" in
	liveroot) : ;;
	root_url) : ;;
	*)        exit 0 ;;
esac

parse_cmdline || exit 1
if [ -d "${rootmnt}/etc/netplan" ]; then
	netplan_config
elif [ -d "${rootmnt}/etc/network/interfaces.d" ]; then
	interfaces_config
fi
__EOF__

# Execute Permission
chmod 0755 "${WORKDIR}/usr/share/initramfs-tools/scripts/init-bottom/network-config"

# Generate Reset Network Interface for Initramfs
cat > "${WORKDIR}/usr/share/initramfs-tools/scripts/init-bottom/reset-network-interfaces" << '__EOF__'
#!/bin/sh

[ "$1" = 'prereqs' ] && { exit 0; }

reset_network_interfaces() {
	local intf
	for intf in /sys/class/net/*; do
		ip addr flush dev "${intf##*/}"
		ip link set "${intf##*/}" down
	done
}

. /scripts/functions

reset_network_interfaces
__EOF__

# Execute Permission
chmod 0755 "${WORKDIR}/usr/share/initramfs-tools/scripts/init-bottom/reset-network-interfaces"

################################################################################
# Network
################################################################################

# Check Release Version
if [ "${RELEASE}" = 'xenial' ]; then
	# Install Require Packages
	chroot "${WORKDIR}" apt-get -y install ethtool ifenslave

	if [[ ! "${PROFILE}" =~ ^.*cloud.*$ ]]; then
		# Install Package
		chroot "${WORKDIR}" apt-get -y --no-install-recommends install network-manager
	fi
fi

# Check Release Version
if [ "${RELEASE}" = 'bionic' ]; then
	# Install Package
	chroot "${WORKDIR}" apt-get -y install nplan
fi

# Default Hostname
echo 'localhost.localdomain' > "${WORKDIR}/etc/hostname"

# Resolv Local Hostname
sed -i -e 's@^\(127.0.0.1\s\+\)\(.*\)$@\1localhost.localdomain \2@' "${WORKDIR}/etc/hosts"
sed -i -e 's@^\(::1\s\+\)\(.*\)$@\1localhost.localdomain \2@' "${WORKDIR}/etc/hosts"

################################################################################
# Cloud
################################################################################

# Check Environment Variable
if [[ "${PROFILE}" =~ ^.*cloud.*$ ]]; then
	# Select Datasources
	chroot "${WORKDIR}" sh -c "echo 'cloud-init cloud-init/datasources multiselect ${DATASOURCES}' | debconf-set-selections"

	# Require Package
	chroot "${WORKDIR}" apt-get -y install cloud-init
fi

################################################################################
# Initramfs
################################################################################

# Cleanup Initramfs
chroot "${WORKDIR}" update-initramfs -d -k all

# Create Initramfs
chroot "${WORKDIR}" update-initramfs -c -k "${KERNEL_VERSION}"

################################################################################
# Workaround
################################################################################

# Remote Apt Speed Up
rm -f "${WORKDIR}/etc/dpkg/dpkg.cfg.d/02apt-speedup"

################################################################################
# Cleanup
################################################################################

# Kernel&Initramfs Old Symbolic Link
rm -f "${WORKDIR}/vmlinuz.old"
rm -f "${WORKDIR}/initrd.img.old"

# Out Of Packages
chroot "${WORKDIR}" apt-get -y autoremove --purge

# Package Archive
chroot "${WORKDIR}" apt-get -y clean

# Persistent Machine ID
echo -n '' > "${WORKDIR}/etc/machine-id"
ln -fs "/etc/machine-id" "${WORKDIR}/var/lib/dbus/machine-id"

# Journal Log Directory
if [ -d "${WORKDIR}/var/log/journal" ]; then
	rmdir "${WORKDIR}/var/log/journal"
fi

# Repository List
find "${WORKDIR}/var/lib/apt/lists" -type f -print0 | xargs -0 rm -f
touch "${WORKDIR}/var/lib/apt/lists/lock"
chmod 0640 "${WORKDIR}/var/lib/apt/lists/lock"

################################################################################
# Archive
################################################################################

# Packages List
chroot "${WORKDIR}" dpkg -l | sed -E '1,5d' | awk '{print $2 "\t" $3}' > "${DESTDIR}/packages.manifest"

# Unmount RootFs
awk '{print $2}' /proc/mounts | grep -s "${WORKDIR}/" | sort -r | xargs --no-run-if-empty umount

# Create SquashFS Image
mksquashfs "${WORKDIR}" "${DESTDIR}/rootfs.squashfs" -comp xz

# Copy Kernel
find "${WORKDIR}/boot" -type f -name "vmlinuz-*-generic" -exec cp {} "${DESTDIR}/kernel.img" \;

# Copy Initrd
find "${WORKDIR}/boot" -type f -name "initrd.img-*-generic" -exec cp {} "${DESTDIR}/initrd.img" \;

# Permission Files
find "${DESTDIR}" -type f -print0 | xargs -0 chmod 0644

# Owner/Group Files
if [ -n "${SUDO_UID}" ] && [ -n "${SUDO_GID}" ]; then
	chown -R "${SUDO_UID}:${SUDO_GID}" "${DESTDIR}"
fi

# Infomation Files
ls -lah "${DESTDIR}/"
