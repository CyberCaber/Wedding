#!/bin/bash
if [[ ! -z $1 && $1 != " " ]];then
while getopts b: flag
do
    case "${flag}" in
        b) EVENT_BROKER=${OPTARG};;
    esac
done
echo $EVENT_BROKER
else
EVENT_BROKER=10.10.100.96 # изменить на IP_Event_Broker (более ничего менять не надо);
# из из под рута выполняем chmod +x audit_bash.sh
# после ./audit_bash.sh
fi

VERSION_AUDITD_CONFIG="v0.1.2"

_error() {
  echo -e >&2 ":: $*"
}
# Detect package type from /etc/issue
_os_is() {
  [[ "$_OSTYPE" = "$*" ]]
}

_exec_() {
  local _type="$1"
  shift
  if _os_is $_type; then
    [[ -z "$_VERBOSE" ]] || _error "Going to execute: $* $_VERBOSE $_FORCE"
    eval "$* $_VERBOSE $_FORCE"
  fi
}

# Detect package type from /etc/issue
_found_arch() {
  local _ostype="$1"
  shift
  grep -qis "$*" /etc/issue && _OSTYPE="$_ostype"
}

# Detect package type
_OSTYPE_detect() {
  _found_arch PACMAN "Arch Linux" && return
  _found_arch DPKG   "Debian GNU/Linux" && return
  _found_arch DPKG   "Ubuntu" && return
  _found_arch YUM    "CentOS" && return
  _found_arch YUM    "Red Hat" && return
  _found_arch YUM    "Fedora" && return
  _found_arch ZYPPER "SUSE" && return

  [[ -z "$_OSTYPE" ]] || return

  if [[ "$OSTYPE" != "darwin"* ]]; then
    _error "Can't detect OS type from /etc/issue. Running fallback method."
  fi
  if [[ -x "/usr/bin/pacman" ]]; then
    grep -q "$FUNCNAME" '/usr/bin/pacman' >/dev/null 2>&1
    [[ $? -ge 1 ]] && _OSTYPE="PACMAN" && return
  fi
  [[ -x "/usr/bin/apt-get" ]]          && _OSTYPE="DPKG" && return
  [[ -x "/usr/bin/yum" ]]              && _OSTYPE="YUM" && return
  [[ -x "/opt/local/bin/port" ]]       && _OSTYPE="MACPORTS" && return
  command -v brew >/dev/null           && _OSTYPE="HOMEBREW" && return
  [[ -x "/usr/bin/emerge" ]]           && _OSTYPE="PORTAGE" && return
  [[ -x "/usr/bin/zypper" ]]           && _OSTYPE="ZYPPER" && return
  if [[ -z "$_OSTYPE" ]]; then
    _error "No supported package manager installed on system"
    _error "(supported: apt, homebrew, pacman, portage, yum)"
    exit 1
  fi
}

###
### Main
###

# Detect type of package manager.
_OSTYPE_detect
echo -e "\nМенеджер пакетов: "$_OSTYPE
echo -e "\n"$OSTYPE

#install auditd
if [[ "$_OSTYPE" == "DPKG" ]]; then
    apt-get update
    apt-get install -y auditd audispd-plugins
fi

if [[ "$_OSTYPE" == "YUM" ]]; then
    yum install -y audit audispd-plugins
fi

if [[ "$_OSTYPE" == "ZYPPER" ]]; then
    zypper install -y audit audit-audispd-plugins
fi

if [[ "$_OSTYPE" == "PORTAGE" ]]; then
    emerge --ask sys-process/audit
    emerge --ask app-admin/rsyslog
# проверить блоки ниже на работоспособность (Gentoo)
    if ! cat /var/db/pkg/net-misc/openssh-*/USE | grep "audit"; then
      echo "net-misc/openssh audit" >> /etc/portage/package.use/openssh
      emerge --ask --changed-use net-misc/openssh
    fi
    if ! cat /var/db/pkg/sys-libs/pam-*/USE | grep "audit"; then
      echo "sys-libs/pam audit" >> /etc/portage/package.use/pam
      emerge --ask --changed-use sys-libs/pam
    fi
    if ! cat /var/db/pkg/sys-apps/shadow-*/USE | grep "audit"; then
      echo "sys-apps/shadow audit" >> /etc/portage/package.use/shadow
      emerge --ask --changed-use sys-apps/shadow
    fi
    if ! cat /var/db/pkg/sys-apps/systemd-*/USE | grep "audit"; then
      echo "sys-apps/systemd audit" >> /etc/portage/package.use/systemd
      emerge --ask --changed-use sys-apps/systemd
    fi
    if ! cat /var/db/pkg/sys-apps/openrc-*/USE | grep "audit"; then
      echo "sys-apps/openrc audit" >> /etc/portage/package.use/openrc
      emerge --ask --changed-use sys-apps/openrc
    fi
    systemctl restart sshd
    rc-service sshd restart
fi

V_OS=$(awk -F"=| " '/^ID=/{gsub(/"/,"", $2); print tolower($2)}' /etc/os-release)
V_IP=$(ip route get 8.8.8.8 | awk -F"src " 'NR==1{split($2,a," ");print a[1]}')
V_HOSTNAME=$(uname -n)
V_AUDITD=$(auditctl -v | cut -d' ' -f3)
V_AUDITD_ONE=$(auditctl -v | cut -d' ' -f3 | cut -d '.' -f 1)
V_AUDITD_TO=$(auditctl -v | cut -d' ' -f3 | cut -d '.' -f 2)
V_AUDITD_THREE=($V_AUDITD_ONE,$V_AUDITD_TO)
V_V_OS_ONE=$(awk -F"=| " '/^VERSION_ID/{gsub(/"/, "", $2); print tolower($2)}' /etc/os-release | cut -d '.' -f1)
if (which syslog-ng 2> /dev/null); then
  V_VAR_syslog_ng_source=$(sed -rn 's/.*source\(([a-z_]+)\).*/\1/p' /etc/syslog-ng/syslog-ng.conf | head -n1)
fi

cp /etc/audit/auditd.conf /etc/audit/auditd.conf_BU_$(date +%d%m%Y)
if (cp /etc/audit/rules.d/audit.rules /etc/audit/rules.d/audit.rules_BU_$(date +%d%m%Y)) ; then
  audit_path='/etc/audit/rules.d/audit.rules'
else
  cp /etc/audit/audit.rules /etc/audit/audit.rules_BU_$(date +%d%m%Y)
  audit_path='/etc/audit/audit.rules' #проверить синтаксис
fi

echo -e "\nЗапись конфигурационного файла $audit_path"
cat <<EOF > $audit_path
-D
-b 32768
-f 1
-i
-a exclude,always -F msgtype=BPRM_FCAPS
-a exclude,always -F msgtype=CRED_DISP
-a exclude,always -F msgtype=CRED_REFR
-a exclude,always -F msgtype=CRYPTO_SESSION
-a exclude,always -F msgtype=CRYPTO_KEY_USER
-a exclude,always -F msgtype=LOGIN
-a exclude,always -F msgtype=NETFILTER_CFG
-a exclude,always -F msgtype=USER_ACCT
-a exclude,always -F msgtype=USER_ERR
-a exclude,always -F msgtype=USER_LOGOUT
-a exclude,always -F msgtype=USER_CMD
-a exit,never -F arch=b32 -S sendto
-a exit,never -F arch=b64 -S sendto
-a exit,never -F path=/bin/basename
-a exit,never -F path=/bin/cut
-a exit,never -F path=/bin/date
-a exit,never -F path=/bin/env
-a exit,never -F path=/bin/hostname
-a exit,never -F path=/bin/id
-a exit,never -F path=/bin/logger
-a exit,never -F path=/usr/sbin/nscd
-a exit,never -F path=/usr/sbin/sss_cache
-a exit,never -F path=/bin/run-parts
-a exit,never -F path=/bin/sleep
-a exit,never -F path=/bin/systemctl
-a exit,never -F path=/opt/cni/bin/calico
-a exit,never -F path=/opt/cni/bin/portmap
-a exit,never -F path=/sbin/ipset
-a exit,never -F path=/sbin/xtables-multi
-a exit,never -F path=/usr/bin/alligator
-a exit,never -F path=/usr/bin/apt-config
-a exit,never -F path=/usr/bin/basename
-a exit,never -F path=/usr/bin/cut
-a exit,never -F path=/usr/bin/date
-a exit,never -F path=/usr/bin/df
-a exit,never -F path=/usr/bin/dircolors
-a exit,never -F path=/usr/bin/dirname
-a exit,never -F path=/usr/bin/docker-containerd
-a exit,never -F path=/usr/bin/docker-containerd-shim
-a exit,never -F path=/usr/bin/docker-init
-a exit,never -F path=/usr/bin/docker-runc
-a exit,never -F path=/usr/bin/dockerd
-a exit,never -F path=/usr/bin/dockerd-current
-a exit,never -F path=/usr/bin/du
-a exit,never -F path=/usr/bin/env
-a exit,never -F path=/usr/bin/flock
-a exit,never -F path=/usr/bin/getconf
-a exit,never -F path=/usr/bin/host
-a exit,never -F path=/usr/bin/hostname
-a exit,never -F path=/usr/bin/id
-a exit,never -F path=/usr/bin/jq
-a exit,never -F path=/usr/bin/locale
-a exit,never -F path=/usr/bin/locale-check
-a exit,never -F path=/usr/bin/logger
-a exit,never -F path=/usr/bin/man
-a exit,never -F path=/usr/bin/manpath
-a exit,never -F path=/usr/bin/mesg
-a exit,never -F path=/usr/bin/nice
-a exit,never -F path=/usr/bin/openssl
-a exit,never -F path=/usr/bin/pager
-a exit,never -F path=/usr/bin/readlink
-a exit,never -F path=/usr/bin/runc
-a exit,never -F path=/usr/bin/sleep
-a exit,never -F path=/usr/bin/stat
-a exit,never -F path=/usr/bin/sv
-a exit,never -F path=/usr/bin/tput
-a exit,never -F path=/usr/bin/tr
-a exit,never -F path=/usr/bin/tty
-a exit,never -F path=/usr/bin/udevadm
-a exit,never -F path=/usr/bin/uniq
-a exit,never -F path=/usr/bin/vmtoolsd
-a exit,never -F path=/usr/bin/wc
-a exit,never -F path=/usr/bin/which
-a exit,never -F path=/usr/lib/vmware-tools
-a exit,never -F path=/usr/lib64/sa/sadc
-a exit,never -F path=/usr/libexec/openssh/ssh-keysign
-a exit,never -F path=/usr/local/bin/pager
-a exit,never -F path=/usr/local/bin/run-parts
-a exit,never -F path=/usr/local/sbin/run-parts
-a exit,never -F path=/usr/sbin/chronyd
-a exit,never -F path=/usr/sbin/cron
-a exit,never -F path=/usr/sbin/crond
-a exit,never -F path=/usr/sbin/ebtables-restore
-a exit,never -F path=/usr/sbin/exim4
-a exit,never -F path=/usr/sbin/fping
-a exit,never -F path=/usr/sbin/fping6
-a exit,never -F path=/usr/sbin/ip
-a exit,never -F path=/usr/sbin/ipset
-a exit,never -F path=/usr/sbin/ldconfig
-a exit,never -F path=/usr/sbin/logrotate
-a exit,never -F path=/usr/sbin/lvm
-a exit,never -F path=/usr/sbin/ntpd
-a exit,never -F path=/usr/sbin/ntpq
-a exit,never -F path=/usr/sbin/run-parts
-a exit,never -F path=/usr/sbin/xtables-legacy-multi
-a exit,never -F path=/usr/sbin/xtables-multi
-a exit,never -F path=/usr/bin/clear_console
-a exit,never -F dir=/usr/lib/systemd/
-a exit,never -F arch=b32 -S openat -F exe=/usr/sbin/sshd
-a exit,never -F arch=b64 -S openat -F exe=/usr/sbin/sshd
-w /etc/aliases -p wa -k Modify_MAIL_CFG_files_v0.1.2
-w /etc/anacrontab -p wa -k Modify_ANACRONTAB_CFG_files_v0.1.2
-w /etc/at.allow -p wa -k Modify_AT_CFG_files_v0.1.2
-w /etc/at.deny -p wa -k Modify_AT_CFG_files_v0.1.2
-w /etc/audisp/ -p wa -k Modify_Auditd_CFG_files_v0.1.2
-w /etc/audit/ -p wa -k Modify_Auditd_CFG_files_v0.1.2
-w /etc/auditbeat/ -p wa -k Modify_Auditbeat_CFG_files_v0.1.2
-w /etc/bash.bashrc -p wa -k Modify_Profile_and_Bashrc_CFG_files_v0.1.2
-w /etc/bashrc -p wa -k Modify_Profile_and_Bashrc_CFG_files_v0.1.2
-w /etc/cron.allow -p wa -k Modify_CRON_CFG_files_v0.1.2
-w /etc/cron.d/ -p wa -k Modify_CRON_CFG_files_v0.1.2
-w /etc/cron.daily/ -p wa -k Modify_CRON_CFG_files_v0.1.2
-w /etc/cron.deny -p wa -k Modify_CRON_CFG_files_v0.1.2
-w /etc/cron.hourly/ -p wa -k Modify_CRON_CFG_files_v0.1.2
-w /etc/cron.monthly/ -p wa -k Modify_CRON_CFG_files_v0.1.2
-w /etc/cron.weekly/ -p wa -k Modify_CRON_CFG_files_v0.1.2
-w /etc/crontab -p wa -k Modify_CRON_CFG_files_v0.1.2
-w /etc/csh.cshrc -p wa -k Modify_CSHRC_CFG_files_v0.1.2
-w /etc/csh.login -p wa -k Modify_CSH_Login_CFG_files_v0.1.2
-w /etc/csh.logout -p wa -k Modify_CSH_Logout_CFG_files_v0.1.2
-w /etc/hosts -p wa -k Modify_HOST_CFG_file_v0.1.2
-w /etc/init.d/ -p wa -k Modify_LSBINIT_CFG_files_v0.1.2
-w /etc/init/ -p wa -k Modify_LSBINIT_CFG_files_v0.1.2
-w /etc/inittab -p wa -k Modify_LSBINIT_CFG_files_v0.1.2
-w /etc/kshrc -p wa -k Modify_KSHRC_CFG_files_v0.1.2
-w /etc/kubernetes/ -p wa -k Modify_Kubernetes_CFG_files_v0.1.2
-w /etc/docker -p wa -k Modify_Docker_CFG_files_v0.1.2
-w /etc/sysconfig/docker -p wa -k Modify_Docker_CFG_files_v0.1.2
-w /etc/ld.so.conf -p wa -k Modify_LD.SO_CFG_files_v0.1.2
-w /etc/ld.so.conf.d/ -p wa -k Modify_LD.SO_CFG_files_v0.1.2
-w /etc/ld.so.preload -p w -k Modify_LD.SO_CFG_files_v0.1.2
-w /etc/libaudit.conf -p wa -k Modify_Auditd_CFG_files_v0.1.2
-w /etc/localtime -p wa -k Modify_LOCALTIME_v0.1.2
-w /etc/login.defs -p wa -k Modify_CFG_login_defs_v0.1.2
-w /etc/modprobe.conf -p wa -k Modify_Kernel_Modules_and_Extensions_v0.1.2
-w /etc/modprobe.d/ -p wa -k Modify_Kernel_Modules_and_Extensions_v0.1.2
-w /etc/modules -p wa -k Modify_Kernel_Modules_and_Extensions_v0.1.2
-w /etc/modules-load.d/ -p wa -k Modify_Kernel_Modules_and_Extensions_v0.1.2
-w /etc/network/ -p wa -k Modify_NETWOTRK_CFG_files_v0.1.2
-w /etc/pam.conf -p wa -k Modify_PAM_CFG_files_v0.1.2
-w /etc/pam.d/ -p wa -k Modify_PAM_CFG_files_v0.1.2
-w /etc/passwd -p rwa -k Modify_User_and_Group_CFG_files_v0.1.2
-w /etc/shadow -p rwa -k Modify_User_and_Group_CFG_files_v0.1.2
-w /etc/passwd- -p rwa -k Modify_User_and_Group_CFG_files_v0.1.2
-w /etc/shadow- -p rwa -k Modify_User_and_Group_CFG_files_v0.1.2
-w /etc/gshadow -p rwa -k Modify_User_and_Group_CFG_files_v0.1.2
-w /etc/group -p rwa -k Modify_User_and_Group_CFG_files_v0.1.2
-w /etc/group- -p rwa -k Modify_User_and_Group_CFG_files_v0.1.2
-w /etc/postfix/ -p wa -k Modify_MAIL_CFG_files_v0.1.2
-w /etc/profile -p wa -k Modify_Profile_and_Bashrc_CFG_files_v0.1.2
-w /etc/profile.d/ -p wa -k Modify_Profile_and_Bashrc_CFG_files_v0.1.2
-w /etc/rc.d/ -p wa -k Modify_SysVInit_CFG_files_v0.1.2
-w /etc/rc.local -p wa -k Modify_INIT_CFG_files_v0.1.2
-w /etc/rc0.d/ -p wa -k Modify_SysVInit_CFG_files_v0.1.2
-w /etc/rc1.d/ -p wa -k Modify_SysVInit_CFG_files_v0.1.2
-w /etc/rc2.d/ -p wa -k Modify_SysVInit_CFG_files_v0.1.2
-w /etc/rc3.d/ -p wa -k Modify_SysVInit_CFG_files_v0.1.2
-w /etc/rc4.d/ -p wa -k Modify_SysVInit_CFG_files_v0.1.2
-w /etc/rc5.d/ -p wa -k Modify_SysVInit_CFG_files_v0.1.2
-w /etc/rc6.d/ -p wa -k Modify_SysVInit_CFG_files_v0.1.2
-w /etc/rcS.d/ -p wa -k Modify_SysVInit_CFG_files_v0.1.2
-w /etc/resolv.conf -p wa -k Modify_RESOLV_CFG_file_v0.1.2
-w /etc/rsyslog.conf -p wa -k Modify_RSyslog_CFG_files_v0.1.2
-w /etc/rsyslog.d/ -p wa -k Modify_RSyslog_CFG_files_v0.1.2
-w /etc/securetty -p wa -k Modify_CFG_securetty_v0.1.2
-w /etc/security/ -p wa -k Modify_PAM_CFG_files_v0.1.2
-w /etc/selinux/ -p wa -k Modify_MAC_Policy_CFG_files_v0.1.2
-w /etc/shells -p wa -k Modify_Profile_and_Bashrc_CFG_files_v0.1.2
-w /etc/skel/.bash_profile -p wa -k Modify_Profile_and_Bashrc_CFG_files_v0.1.2
-w /etc/skel/.bashrc -p wa -k Modify_Profile_and_Bashrc_CFG_files_v0.1.2
-w /etc/ssh/sshd_config -p wa -k Modify_SSHD_CFG_file_v0.1.2
-w /etc/ssh/ssh_known_hosts -p wa -k Modify_SSHD_CFG_file_v0.1.2
-w /etc/sudoers -p wa -k Modify_SUDO_CFG_files_v0.1.2
-w /etc/sudoers.d/ -p wa -k Modify_SUDO_CFG_files_v0.1.2
-w /etc/sysconfig/auditd -p wa -k Modify_Auditd_CFG_files_v0.1.2
-w /etc/sysconfig/init -p wa -k Modify_INIT_CFG_files_v0.1.2
-w /etc/sysconfig/network -p wa -k Modify_NETWORK_CFG_files_v0.1.2
-w /etc/sysconfig/network-scripts/ -p wa -k Modify_NETWORK_CFG_files_v0.1.2
-w /etc/sysctl.conf -p wa -k Modify_Sysctl_CFG_v0.1.2
-w /etc/sysctl.d/ -p wa -k Modify_Sysctl_CFG_v0.1.2
-w /etc/syslog-ng/ -p wa -k Modify_Syslog-ng_CFG_files_v0.1.2
-w /etc/systemd/system/ -p wa -k Modify_SYSTEMD_CFG_files_v0.1.2
-w /etc/systemd/user/ -p wa -k Modify_SYSTEMD_CFG_files_v0.1.2
-w /etc/xinetd.conf -p wa -k Modify_Xinetd_CFG_files_v0.1.2
-w /etc/xinetd.d/ -p wa -k Modify_Xinetd_CFG_files_v0.1.2
-w /etc/zsh/zlogin -p wa -k Modify_ZSH_Login_CFG_files_v0.1.2
-w /etc/zsh/zlogout -p wa -k Modify_ZSH_Logout_CFG_files_v0.1.2
-w /etc/zsh/zprofile -p wa -k Modify_ZSH_Profile_CFG_files_v0.1.2
-w /etc/zsh/zshenv -p wa -k Modify_ZSHENV_CFG_files_v0.1.2
-w /etc/zsh/zshrc -p wa -k Modify_ZSHRC_CFG_files_v0.1.2
-w /etc/zshrc -p wa -k Modify_ZSHRC_CFG_files_v0.1.2
-w /etc/apt/apt.conf.d/ -p wa -k Modify_APT_CFG_files_v0.1.2
-w /etc/yum/pluginconf.d/ -p wa -k Modify_YUM_CFG_files_v0.1.2
-w /root/.config/autostart/ -p wa -k Modify_AUTOSTART_CFG_files_v0.1.2
-w /lib/systemd/system/ -p wa -k Modify_SYSTEMD_CFG_files_v0.1.2
-w /lib/systemd/user/ -p wa -k Modify_SYSTEMD_CFG_files_v0.1.2
-w /root/.bash_login -p wa -k Modify_BASH_Login_CFG_files_v0.1.2
-w /root/.bash_logout -p wa -k Modify_BASH_Logout_CFG_files_v0.1.2
-w /root/.bash_profile -p wa -k Modify_BASH_Profile_CFG_files_v0.1.2
-w /root/.bashrc -p wa -k Modify_BASHRC_CFG_files_v0.1.2
-w /root/.zshrc -p wa -k Modify_ZSHRC_CFG_files_v0.1.2
-w /root/.config/fish/config.fish -p wa -k Modify_FISHRC_CFG_files_v0.1.2
-w /root/.config/systemd/user.control/ -p wa -k Modify_SYSTEMD_CFG_files_v0.1.2
-w /root/.config/systemd/user.control/user/ -p wa -k Modify_SYSTEMD_CFG_files_v0.1.2
-w /root/.cshrc -p wa -k Modify_CSHRC_CFG_files_v0.1.2
-w /root/.ksh -p wa -k Modify_KSHRC_CFG_files_v0.1.2
-w /root/.local/share/systemd/user/ -p wa -k Modify_SYSTEMD_CFG_files_v0.1.2
-w /root/.logout -p wa -k Modify_BASH_Logout_CFG_files_v0.1.2
-w /root/.profile -p wa -k Modify_Profile_and_Bashrc_CFG_files_v0.1.2
-w /root/.ssh/authorized_keys -p wa -k Modify_AUTHKEYS_CFG_file_v0.1.2
-w /root/.ssh/authorized_keys2 -p wa -k Modify_AUTHKEYS_CFG_file_v0.1.2
-w /root/.ssh/config -p wa -k Modify_AUTH_CFG_file_v0.1.2
-w /root/.tcsh -p wa -k Modify_CSH_Logout_CFG_files_v0.1.2
-w /root/.zlogin -p wa -k Modify_ZSH_Login_CFG_files_v0.1.2
-w /root/.zlogout -p wa -k Modify_ZSH_Logout_CFG_files_v0.1.2
-w /root/.zprofile -p wa -k Modify_ZSH_Profile_CFG_files_v0.1.2
-w /run/systemd/system/ -p wa -k Modify_SYSTEMD_CFG_files_v0.1.2
-w /usr/lib/systemd/system/ -p wa -k Modify_SYSTEMD_CFG_files_v0.1.2
-w /usr/lib/systemd/user/ -p wa -k Modify_SYSTEMD_CFG_files_v0.1.2
-w /var/log/auth.log -p wa -k Modify_AUTH_LOG_files_v0.1.2
-w /var/log/boot.log -p wa -k Modify_BOOT_Log_v0.1.2
-w /var/log/cron -p wa -k Modify_CRON_Log_v0.1.2
-w /var/log/dmesg -p wa -k Modify_DMESG_Log_v0.1.2
-w /var/log/faillog -p wa -k Modify_FAILLOG_Log_v0.1.2
-w /var/log/lastlog -p wa -k Modify_LASTLOG_Log_v0.1.2
-w /var/log/secure -p wa -k Modify_SECURE_LOG_files_v0.1.2
-w /var/log/tallylog -p wa -k Modify_TALLYLOG_Log_v0.1.2
-w /var/run/faillock/ -p wa -k Modify_FAILLOCK_files_v0.1.2
-w /var/spool/anacron/ -p wa -k Modify_ANACRON_CFG_files_v0.1.2
-w /var/spool/at/ -p wa -k Modify_AT_CFG_files_v0.1.2
-w /var/spool/cron/ -p wa -k Modify_CRON_CFG_files_v0.1.2
-w /proc/sys/kernel/randomize_va_space -p rw -k Modify_SystemParameters_v0.1.2
-w /proc/sys/kernel/yama/ptrace_scope -p rw -k Modify_SystemParameters_v0.1.2
-w /proc/sys/kernel/nmi_watchdog -p rw -k Modify_SystemParameters_v0.1.2
-w /proc/sys/kernel/unprivileged_bpf_disabled -p rw -k Modify_SystemParameters_v0.1.2
-w /proc/sys/kernel/suid_dumpable -p rw -k Modify_SystemParameters_v0.1.2
-w /proc/sys/kernel/kexec_load_disabled -p rw -k Modify_SystemParameters_v0.1.2
-w /proc/sys/kernel/modules_disabled -p rw -k Modify_SystemParameters_v0.1.2
-w /proc/sys/kernel/core_pattern -p rw -k Modify_SystemParameters_v0.1.2
-w /proc/sys/net/ipv4/ip_forward -p rw -k Modify_SystemParameters_v0.1.2
-w /proc/config.gz -p r -k Modify_SystemParameters_v0.1.2

-w /proc/sys/fs/binfmt_misc -p wa -k Modify_SystemParameters_v0.1.2

-w /etc/grub.d/ -p wa -k Modify_GRUB_CFG_files_v0.1.2
-w /etc/grub.cfg -p wa -k Modify_GRUB_CFG_files_v0.1.2
-w /etc/default/grub -p wa -k Modify_GRUB_CFG_files_v0.1.2
-w /etc/grub/grub.cfg -p wa -k Modify_GRUB_CFG_files_v0.1.2
-w /etc/grub2/grub.cfg -p wa -k Modify_GRUB_CFG_files_v0.1.2

-w /usr/lib/x86_64-linux-gnu/security/ -p wa -k Modify_PAM_LIB_files_v0.1.2
-w /usr/lib64/security/ -p wa -k Modify_PAM_LIB_files_v0.1.2

-w /etc/exports -p wa -k 
-w /etc/fstab -p wa -k 

-w /etc/shosts.equiv -p wa -k
-w /etc/hosts.equiv -p wa -k 

-w /root/.rhosts -p wa -k 
-w /root/.shosts -p wa -k 


-a exit,always -F arch=b32 -S execve,execveat -k ALL_Execve_v0.1.2
-a exit,always -F arch=b64 -S execve,execveat -k ALL_Execve_v0.1.2
-a exit,always -F arch=b32 -S settimeofday,stime -k Modify_TIME_v0.1.2
-a exit,always -F arch=b64 -S settimeofday -k Modify_TIME_v0.1.2

-a exit,always -F arch=b32 -S ioctl -F a0=0x3 -F a1=0x40086602 -k Posible_Use_CHATTR_v0.1.2
-a exit,always -F arch=b64 -S ioctl -F a0=0x3 -F a1=0x40086602 -k Posible_Use_CHATTR_v0.1.2

-a exit,always -F arch=b32 -S clock_settime -F a0=0x0 -k Modify_TIME_v0.1.2
-a exit,always -F arch=b64 -S clock_settime -F a0=0x0 -k Modify_TIME_v0.1.2
-a exit,always -F arch=b32 -S finit_module -S init_module -S delete_module -F auid!=-1 -k Loading_and_Unloading_a_Kernel_Module_v0.1.2
-a exit,always -F arch=b64 -S finit_module -S init_module -S delete_module -F auid!=-1 -k Loading_and_Unloading_a_Kernel_Module_v0.1.2

-a exit,always -F arch=b32 -S ptrace -F a0=0x4 -k Code_Injection_v0.1.2
-a exit,always -F arch=b64 -S ptrace -F a0=0x4 -k Code_Injection_v0.1.2
-a exit,always -F arch=b32 -S ptrace -F a0=0x5 -k Data_Injection_v0.1.2
-a exit,always -F arch=b64 -S ptrace -F a0=0x5 -k Data_Injection_v0.1.2
-a exit,always -F arch=b32 -S ptrace -F a0=0x6 -k Register_Injection_v0.1.2
-a exit,always -F arch=b64 -S ptrace -F a0=0x6 -k Register_Injection_v0.1.2

-a exit,always -F arch=b32 -S socket -F a0=0x10 -F a1=0x3 -F a2=0x9 -F exe!=/usr/sbin/auditctl -F key=Unknown_Access_to_NETLINK_AUDIT_v0.1.2
-a exit,always -F arch=b64 -S socket -F a0=0x10 -F a1=0x3 -F a2=0x9 -F exe!=/usr/sbin/auditctl -F key=Unknown_Access_to_NETLINK_AUDIT_v0.1.2

-a exit,always -F arch=b64 -S splice -F a0=0x3 -F a2=0x5 -F a3=0x0 -F key=Expoit_DirtyPipe_v0.1.2
-a exit,always -F arch=b64 -S splice -F a0=0x6 -F a2=0x8 -F a3=0x0 -F key=Expoit_DirtyPipe_v0.1.2
-a exit,always -F arch=b64 -S splice -F a0=0x7 -F a2=0x9 -F a3=0x0 -F key=Expoit_DirtyPipe_v0.1.2

-a exit,always -F arch=b32 -S connect -F a0=0x3 -F a2=0x10 -F a3!=0x6 -F exe=/usr/sbin/sshd -F key=SSH_Tunnel_v0.1.2
-a exit,always -F arch=b64 -S connect -F a0=0x3 -F a2=0x10 -F a3!=0x6 -F exe=/usr/sbin/sshd -F key=SSH_Tunnel_v0.1.2
-a exit,always -F arch=b32 -S connect -F a0=0x9 -F a2=0x10 -F a3!=0x6 -F exe=/usr/sbin/sshd -F key=SSH_Tunnel_v0.1.2
-a exit,always -F arch=b64 -S connect -F a0=0x9 -F a2=0x10 -F a3!=0x6 -F exe=/usr/sbin/sshd -F key=SSH_Tunnel_v0.1.2
-a exit,always -F arch=b32 -S connect -F a0=0xA -F a2=0x10 -F a3!=0x6 -F exe=/usr/sbin/sshd -F key=SSH_Tunnel_v0.1.2
-a exit,always -F arch=b64 -S connect -F a0=0xA -F a2=0x10 -F a3!=0x6 -F exe=/usr/sbin/sshd -F key=SSH_Tunnel_v0.1.2
-a exit,always -F arch=b32 -S bind -F a0=0xA -F a2=0x10 -F exe=/usr/sbin/sshd -F key=SSH_Tunnel_v0.1.2
-a exit,always -F arch=b64 -S bind -F a0=0xA -F a2=0x10 -F exe=/usr/sbin/sshd -F key=SSH_Tunnel_v0.1.2

-a exit,always -F arch=b32 -S bind -F a2=0x10 -F exit=0 -F key=Network_IPv4_Bind_Port_v0.1.2
-a exit,always -F arch=b64 -S bind -F a2=0x10 -F exit=0 -F key=Network_IPv4_Bind_Port_v0.1.2

-a exit,always -F arch=b32 -S bind -F a2=0xc -F a3=0x10 -F exit=0 -F key=Network_IPv6_Bind_Port_v0.1.2
-a exit,always -F arch=b64 -S bind -F a2=0xc -F a3=0x10 -F exit=0 -F key=Network_IPv6_Bind_Port_v0.1.2

-a exit,always -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -S rmdir -F auid>=0 -F auid!=-1 -F dir=/var/log/ -k Remove_Logs_v0.1.2
-a exit,always -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -S rmdir -F auid>=0 -F auid!=-1 -F dir=/var/log/ -k Remove_Logs_v0.1.2
-a exit,always -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F path=/root/.bash_history -k Remove_Bash_History_v0.1.2
-a exit,always -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F path=/root/.bash_history -k Remove_Bash_History_v0.1.2
-a exit,always -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F path=/root/.history -k Remove_Bash_History_v0.1.2
-a exit,always -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F path=/root/.history -k Remove_Bash_History_v0.1.2
-a exit,always -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F path=/root/.sh_history -k Remove_Bash_History_v0.1.2
-a exit,always -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F path=/root/.sh_history -k Remove_Bash_History_v0.1.2
-a exit,always -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F path=/root/.ash_history -k Remove_Bash_History_v0.1.2
-a exit,always -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F path=/root/.ash_history -k Remove_Bash_History_v0.1.2
-a exit,always -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F path=/root/.csh_history -k Remove_Bash_History_v0.1.2
-a exit,always -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F path=/root/.csh_history -k Remove_Bash_History_v0.1.2
-a exit,always -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F path=/root/.tcsh_history -k Remove_Bash_History_v0.1.2
-a exit,always -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F path=/root/.tcsh_history -k Remove_Bash_History_v0.1.2
-a exit,always -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F path=/root/.ksh_history -k Remove_Bash_History_v0.1.2
-a exit,always -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F path=/root/.ksh_history -k Remove_Bash_History_v0.1.2
-a exit,always -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F path=/root/.zsh_history -k Remove_Bash_History_v0.1.2
-a exit,always -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F path=/root/.zsh_history -k Remove_Bash_History_v0.1.2
-a exit,always -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F path=/root/.local/share/fish/fish_history -k Remove_Bash_History_v0.1.2
-a exit,always -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F path=/root/.local/share/fish/fish_history -k Remove_Bash_History_v0.1.2
-a exit,always -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F path=/root/.mysql_history -k Remove_Bash_History_v0.1.2
-a exit,always -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F path=/root/.mysql_history -k Remove_Bash_History_v0.1.2
-a exit,always -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F path=/root/.psql_history -k Remove_Bash_History_v0.1.2
-a exit,always -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F path=/root/.psql_history -k Remove_Bash_History_v0.1.2
-a exit,always -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F path=/root/.dbshell -k Remove_Bash_History_v0.1.2
-a exit,always -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F path=/root/.dbshell -k Remove_Bash_History_v0.1.2

-a exit,never -F arch=b32 -S listen,connect,bind,sendto
-a exit,never -F arch=b64 -S listen,connect,bind,sendto

-a exit,never -F arch=b32 -S all
-a exit,never -F arch=b64 -S all
EOF
if (( $V_AUDITD_ONE >= 2 )) && (( $V_AUDITD_TO >= 6 )); then
  echo -e "\nНастройка конфигурационного /etc/audit/auditd.conf"
  sed -i '/log_format/s/.*/log_format = ENRICHED/' /etc/audit/auditd.conf
  sed -i '/name_format/s/.*/name_format = NONE/' /etc/audit/auditd.conf
fi


if (( $V_AUDITD_ONE >= 3 )); then
  plugin_path='/etc/audit/plugins.d/syslog.conf'
  echo -e "\nЗапись конфигурационного файла $plugin_path"
  cat <<EOF > $plugin_path
active = yes
direction = out
path = /sbin/audisp-syslog
type = always
args = LOG_DEBUG LOG_LOCAL0
format = string
EOF
else
  plugin_path='/etc/audisp/plugins.d/syslog.conf'
  echo -e "\nЗапись конфигурационного файла $plugin_path"
  cat <<EOF > $plugin_path
active = yes
direction = out
path = builtin_syslog
type = builtin
args = LOG_DEBUG LOG_LOCAL0
format = string
EOF
fi

#for SLES
if [[ "$V_OS" == "sles" && "$V_V_OS_ONE" == 11 ]]; then
  if ! (grep "^AUDITD_LANG=" /etc/sysconfig/auditd); then
    sed -i -e '$aAUDITD_LANG="en_US"' /etc/sysconfig/auditd
  else
    sed -i '/AUDITD_LANG/s/.*/AUDITD_LANG="en_US"/' /etc/sysconfig/auditd
  fi
  if ! (grep "^AUDITD_DISABLE_CONTEXTS=" /etc/sysconfig/auditd); then
    sed -i -e '$aAUDITD_DISABLE_CONTEXTS="no"' /etc/sysconfig/auditd
  else
    sed -i '/AUDITD_DISABLE_CONTEXTS/s/.*/AUDITD_DISABLE_CONTEXTS="no"/' /etc/sysconfig/auditd
  fi
  if ! (grep "^name_format" /etc/audisp/audispd.conf); then
    sed -i -e '$aname_format = NONE' /etc/audisp/audispd.conf
  else
    sed -i '/name_format/s/.*/name_format = NONE/' /etc/audisp/audispd.conf
  fi
  if ! (grep "^session.\+required.\+pam_loginuid.so" /etc/pam.d/login); then
    sed -i -e '$asession required pam_loginuid.so' /etc/pam.d/login
  fi
  if ! (grep "^session.\+include.\+common-session" /etc/pam.d/login); then
    sed -i -e '$asession include common-session' /etc/pam.d/login
  fi
  if ! (grep "^session.\+required.\+pam_loginuid.so" /etc/pam.d/sshd); then
    sed -i -e '$asession required pam_loginuid.so' /etc/pam.d/sshd
  fi
  if ! (grep "^session.\+include.\+common-session" /etc/pam.d/sshd); then
    sed -i -e '$asession include common-session' /etc/pam.d/sshd
  fi
  if ! (grep "^session.\+required.\+pam_loginuid.so" /etc/pam.d/crond); then
    sed -i -e '$asession required pam_loginuid.so' /etc/pam.d/crond
  fi
  if ! (grep "^session.\+include.\+common-session" /etc/pam.d/crond); then
    sed -i -e '$asession include common-session' /etc/pam.d/crond
  fi
  if ! (grep "^session.\+required.\+pam_loginuid.so" /etc/pam.d/atd); then
    sed -i -e '$asession required pam_loginuid.so' /etc/pam.d/atd
  fi
  if ! (grep "^session.\+include.\+common-session" /etc/pam.d/atd); then
    sed -i -e '$asession include common-session' /etc/pam.d/atd
  fi
fi

if ! (systemctl restart auditd); then
  if ! (service auditd restart); then
    rc-service auditd restart            # Gentoo(OpenRC)
    echo -e "\nРестарт rc-service auditd"
  fi
  echo -e "\nРестарт service auditd"
else
  echo -e "\nРестарт systemctl auditd"
fi

if ! (augenrules --load); then
  auditctl -R /etc/audit/audit.rules
  echo -e "\nПрименение правил auditd через auditctl"
else
  echo -e "\nПрименение правил auditd через augenrules"
fi
#ausearch -ts recent -i
#логи SSH
if ! (grep "^SyslogFacility" /etc/ssh/sshd_config); then
  sed -i -e '$aSyslogFacility AUTH' /etc/ssh/sshd_config
else
  sed -i '/SyslogFacility/s/.*/SyslogFacility AUTH/' /etc/ssh/sshd_config
fi
if ! (grep "^LogLevel" /etc/ssh/sshd_config); then
  sed -i -e '$aLogLevel VERBOSE' /etc/ssh/sshd_config
else
  sed -i '/LogLevel/s/.*/LogLevel VERBOSE/' /etc/ssh/sshd_config
fi
if ! (grep "^LOG_UNKFAIL_ENAB" /etc/login.defs); then
  sed -i -e '$aLOG_UNKFAIL_ENAB yes' /etc/login.defs
else
  sed -i '/LOG_UNKFAIL_ENAB/s/.*/LOG_UNKFAIL_ENAB yes/' /etc/login.defs
fi
if ! (grep "^FAILLOG_ENAB" /etc/login.defs); then
  sed -i -e '$aFAILLOG_ENAB yes' /etc/login.defs
else
  sed -i '/FAILLOG_ENAB/s/.*/FAILLOG_ENAB yes/' /etc/login.defs
fi
if ! (grep "^LOG_OK_LOGINS" /etc/login.defs); then
  sed -i -e '$aLOG_OK_LOGINS yes' /etc/login.defs
else
  sed -i '/LOG_OK_LOGINS/s/.*/LOG_OK_LOGINS yes/' /etc/login.defs
fi

if ! (systemctl restart sshd); then
  if ! (service sshd restart); then
    rc-service sshd restart            # Gentoo(OpenRC)
    echo -e "\nРестарт rc-service sshd"
  fi
  echo -e "\nРестарт service sshd"
else
  echo -e "\nРестарт systemctl sshd"
fi

if ! ( (which rsyslogd 2> /dev/null) || (which syslog-ng 2> /dev/null) ); then
  echo -e "\nУстановка rsyslog"
  if [[ "$_OSTYPE" == "DPKG" ]]; then
      apt-get update
      apt-get install -y rsyslog
  fi

  if [[ "$_OSTYPE" == "YUM" ]]; then
      yum install -y rsyslog
  fi

  if [[ "$_OSTYPE" == "ZYPPER" ]]; then
      zypper install -y rsyslog
  fi
fi

if (which rsyslogd 2> /dev/null); then
#echo -e "IP_Event_Broker ="
#read EVENT_BROKER
echo -e "\nЗапись конфигурационного файла /etc/rsyslog.d/security.conf"
cat <<EOF > /etc/rsyslog.d/security.conf
\$EscapeControlCharactersOnReceive off
\$RepeatedMsgReduction off
\$PreserveFQDN on

\$template audispd,"<%PRI%>%TIMESTAMP% %HOSTNAME% audispd: node=$V_IP %msg%"

module(load="immark" interval="600")

if \$programname == "sshd" and (\$msg contains "Accepted password" or \$msg contains "Accepted keyboard" or \$msg contains "Accepted publickey" or \$msg contains "Disconnected from " or \$msg contains "Failed password" or \$msg contains "Failed keyboard" or \$msg contains "Failed publickey" or \$msg contains "Failed none") then @@$EVENT_BROKER:514
if \$programname == "login" then @@$EVENT_BROKER:514
if \$programname == "sudo" then @@$EVENT_BROKER:514
if \$programname == "su" then @@$EVENT_BROKER:514
:programname, contains, "audispd" @@$EVENT_BROKER:514;audispd
:programname, contains, "audisp-syslog" @@$EVENT_BROKER:514;audispd
:msg, contains, "promiscuous mode" @@$EVENT_BROKER:514
:msg, contains, "USB Mass Storage" @@$EVENT_BROKER:514
EOF
fi

if (which syslog-ng 2> /dev/null); then
  if [[ "$V_OS" == "sles" && "$V_V_OS_ONE" == 11 ]]; then
    sed -i '/^options {/s/.*/options {mark-freq(600); use_fqdn (yes); use_dns(no); dns-cache(no); };/' /etc/syslog-ng/syslog-ng.conf
    if ! (grep "^filter f_security" /etc/syslog-ng/syslog-ng.conf); then
      echo -e "\nЗапись конфигурационного файла /etc/syslog-ng/syslog-ng.conf"
      cat <<EOF >> /etc/syslog-ng/syslog-ng.conf
filter f_security { (match('^sshd\[[0-9]+\]:') and (match("Accepted password") or match("Accepted keyboard") or match("Accepted publickey") or match("Disconnected from user") or match("Failed password for")) or match('audisp.+:') or match("promiscuous mode") or match("USB Mass Storage")); };
filter f_audispd { program('audisp');};

destination dst_syslog_security {
    tcp(
        "$EVENT_BROKER"
        port(514)
    );
};

destination dst_syslog_audispd {
    tcp(
        "$EVENT_BROKER"
        port(514)
        template("<\${PRI}>\${DATE} \${HOST} audispd: node=$V_IP \${MSGONLY}\n")
        template_escape(no)
    );
};

log {
    source($V_VAR_syslog_ng_source);
    filter(f_security);
    destination(dst_syslog_security);
};


log {
    source($V_VAR_syslog_ng_source);
    filter(f_audispd);
    destination(dst_syslog_audispd);
};
EOF
    fi
  else
    if ! (grep "\/etc\/syslog-ng\/conf.d\/\*\.conf" /etc/syslog-ng/syslog-ng.conf); then
      sed -i -e '$a@include "/etc/syslog-ng/conf.d/*.conf"' /etc/syslog-ng/syslog-ng.conf
      mkdir /etc/syslog-ng/conf.d
    fi
    echo -e "\nЗапись конфигурационного файла /etc/syslog-ng/conf.d/security.conf"

    cat <<EOF > /etc/syslog-ng/conf.d/security.conf
options {
    mark-freq(600);
    use_fqdn (yes);
    use_dns(no);
    dns-cache(no);
};


filter f_security {
    (program("sshd") and (message("Accepted password") or message("Accepted keyboard") or message("Accepted publickey") or message("Disconnected from ") or message("Failed password")  or message("Failed keyboard")  or message("Failed publickey") or message("Failed none"))) or program("login") or program("sudo") or program("su") or message("promiscuous mode") or message("USB Mass Storage");
};


filter f_audispd {
    program('audisp');
};


destination dst_syslog_security {
    network(
        "$EVENT_BROKER"
        port(514)
        persist-name("dst_syslog_security")
    );
};


destination dst_syslog_audispd {
    network(
        "$EVENT_BROKER"
        port(514)
        template("<${PRI}>${DATE} ${HOST} audispd: node=10.10.101.15 ${MSGONLY}\n")
        template_escape(no)
        persist-name("dst_syslog_audispd")
    );
};


log {
    source($V_VAR_syslog_ng_source);
    filter(f_security);
    destination(dst_syslog_security);
};


log {
    source($V_VAR_syslog_ng_source);
    filter(f_audispd);
    destination(dst_syslog_audispd);
};
EOF
  fi
fi

#sestatus
if [[ $(sestatus | awk -F":" '/^SELinux status/{gsub(/ /, "", $2); print tolower($2)}') == "enabled" ]]; then
  if [[ "$V_OS" == "centos" ]] && (( "$V_V_OS_ONE" >= 8 )); then
    yum install -y policycoreutils-python-utils #centOS 8
  else
    yum install -y policycoreutils-python #centOS 7
  fi
  semanage port -a -t syslogd_port_t -p tcp 514
fi


echo -e "\nЗапись файла /etc/profile.d/logger.sh"
cat <<'EOF' > /etc/profile.d/logger.sh
if [[ "${__bz_preexec_setup}" == "defined" ]]; then
    return 0
fi;

__bz_preexec_setup="defined"

__bz_etc_dir=${2:-"/etc/profile.d"}

__U_UID=$(id -u) 
__U_GID=$(id -g) 
__UN_UID=$(id -nu) 
__GN_UID=$(id -ng)
__AUDITD_VER=$(auditctl -v | cut -d' ' -f3)
__OS_RES=$(awk -F"=| " '/^ID=/{gsub(/"/,"", $2); print tolower($2)}' /etc/os-release)_$(awk -F"=| " '/^VERSION_ID/{gsub(/"/, "", $2); print tolower($2)}' /etc/os-release)
COMM_TEMP=""

# Bash/Zsh preexec hook handle
__bz_preexec() {
    if [[ ! -z $1 && $1 != "$COMM_TEMP" ]];then
        echo "$(printf '%s' \
            "type=BASH " \
            "msg=audit($(date +%s.%3N):000): comm=\"$1\" " \
            "pwd=\"${PWD}\" uid=${__U_UID} gid=${__U_GID} " \
            "UID=\"${__UN_UID}\" GID=\"${__GN_UID}\" ppid=${PPID} pid=$$ " \
            "terminal=\"${SSH_TTY}\" shell=\"${SHELL}\" shlvl=\"${SHLVL}\" " \
            "ssh_connection=\"${SSH_CONNECTION}\" " \
            "auver=${__AUDITD_VER} osres=\"${__OS_RES}\" " \
      )" | logger -p local0.debug -t audispd
    fi
}

if [[ -n "${BASH_VERSION:-}" ]]; then
    source ${__bz_etc_dir}/bash-preexec.sh
    preexec_functions+=(__bz_preexec)
elif [[ -n "${ZSH_VERSION:-}" ]]; then
    autoload -Uz add-zsh-hook
    add-zsh-hook preexec __bz_preexec
else
    return 1
fi;
EOF

chmod 644 /etc/profile.d/logger.sh
chown root:root /etc/profile.d/logger.sh
sstr="source \/etc\/profile\.d\/logger\.sh"
sed -i -e '/'"$sstr"'/{s//'"$sstr"'/;:a;n;ba;q}' -e '$a'"$sstr"'' /etc/skel/.bashrc /etc/profile /root/.bashrc
find /home/ -type f -name ".bashrc" -exec sh -c "sed -i -e '/$sstr/{s//$sstr/;:a;n;ba;q}' -e '\$a$sstr' {}" \;


echo -e "\nЗапись файла /etc/profile.d/bash-preexec.sh"
cat <<'EOF' > /etc/profile.d/bash-preexec.sh
# bash-preexec.sh -- Bash support for ZSH-like 'preexec' and 'precmd' functions.
# https://github.com/rcaloras/bash-preexec
#
#
# 'preexec' functions are executed before each interactive command is
# executed, with the interactive command as its argument. The 'precmd'
# function is executed before each prompt is displayed.
#
# Author: Ryan Caloras (ryan@bashhub.com)
# Forked from Original Author: Glyph Lefkowitz
#
# V0.5.0
#

# General Usage:
#
#  1. Source this file at the end of your bash profile so as not to interfere
#     with anything else that's using PROMPT_COMMAND.
#
#  2. Add any precmd or preexec functions by appending them to their arrays:
#       e.g.
#       precmd_functions+=(my_precmd_function)
#       precmd_functions+=(some_other_precmd_function)
#
#       preexec_functions+=(my_preexec_function)
#
#  3. Consider changing anything using the DEBUG trap or PROMPT_COMMAND
#     to use preexec and precmd instead. Preexisting usages will be
#     preserved, but doing so manually may be less surprising.
#
#  Note: This module requires two Bash features which you must not otherwise be
#  using: the "DEBUG" trap, and the "PROMPT_COMMAND" variable. If you override
#  either of these after bash-preexec has been installed it will most likely break.

# Make sure this is bash that's running and return otherwise.
# Use POSIX syntax for this line:
if [ -z "${BASH_VERSION:-}" ]; then
    return 1;
fi

# Avoid duplicate inclusion
if [[ -n "${bash_preexec_imported:-}" ]]; then
    return 0;
fi
bash_preexec_imported="defined"

# WARNING: This variable is no longer used and should not be relied upon.
# Use ${bash_preexec_imported} instead.
__bp_imported="${bash_preexec_imported}"

# Should be available to each precmd and preexec
# functions, should they want it. $? and $_ are available as $? and $_, but
# $PIPESTATUS is available only in a copy, $BP_PIPESTATUS.
# TODO: Figure out how to restore PIPESTATUS before each precmd or preexec
# function.
__bp_last_ret_value="$?"
BP_PIPESTATUS=("${PIPESTATUS[@]}")
__bp_last_argument_prev_command="$_"

__bp_inside_precmd=0
__bp_inside_preexec=0

# Initial PROMPT_COMMAND string that is removed from PROMPT_COMMAND post __bp_install
__bp_install_string=$'__bp_trap_string="$(trap -p DEBUG)"\ntrap - DEBUG\n__bp_install'

# Fails if any of the given variables are readonly
# Reference https://stackoverflow.com/a/4441178
__bp_require_not_readonly() {
  local var
  for var; do
    if ! ( unset "$var" 2> /dev/null ); then
      echo "bash-preexec requires write access to ${var}" >&2
      return 1
    fi
  done
}

# Remove ignorespace and or replace ignoreboth from HISTCONTROL
# so we can accurately invoke preexec with a command from our
# history even if it starts with a space.
__bp_adjust_histcontrol() {
    local histcontrol
    histcontrol="${HISTCONTROL:-}"
    histcontrol="${histcontrol//ignorespace}"
    # Replace ignoreboth with ignoredups
    if [[ "$histcontrol" == *"ignoreboth"* ]]; then
        histcontrol="ignoredups:${histcontrol//ignoreboth}"
    fi;
    export HISTCONTROL="$histcontrol"
}

# This variable describes whether we are currently in "interactive mode";
# i.e. whether this shell has just executed a prompt and is waiting for user
# input.  It documents whether the current command invoked by the trace hook is
# run interactively by the user; it's set immediately after the prompt hook,
# and unset as soon as the trace hook is run.
__bp_preexec_interactive_mode=""

# These arrays are used to add functions to be run before, or after, prompts.
declare -a precmd_functions
declare -a preexec_functions

# Trims leading and trailing whitespace from $2 and writes it to the variable
# name passed as $1
__bp_trim_whitespace() {
    local var=${1:?} text=${2:-}
    text="${text#"${text%%[![:space:]]*}"}"   # remove leading whitespace characters
    text="${text%"${text##*[![:space:]]}"}"   # remove trailing whitespace characters
    printf -v "$var" '%s' "$text"
}


# Trims whitespace and removes any leading or trailing semicolons from $2 and
# writes the resulting string to the variable name passed as $1. Used for
# manipulating substrings in PROMPT_COMMAND
__bp_sanitize_string() {
    local var=${1:?} text=${2:-} sanitized
    __bp_trim_whitespace sanitized "$text"
    sanitized=${sanitized%;}
    sanitized=${sanitized#;}
    __bp_trim_whitespace sanitized "$sanitized"
    printf -v "$var" '%s' "$sanitized"
}

# This function is installed as part of the PROMPT_COMMAND;
# It sets a variable to indicate that the prompt was just displayed,
# to allow the DEBUG trap to know that the next command is likely interactive.
__bp_interactive_mode() {
    __bp_preexec_interactive_mode="on";
}


# This function is installed as part of the PROMPT_COMMAND.
# It will invoke any functions defined in the precmd_functions array.
__bp_precmd_invoke_cmd() {
    # Save the returned value from our last command, and from each process in
    # its pipeline. Note: this MUST be the first thing done in this function.
    __bp_last_ret_value="$?" BP_PIPESTATUS=("${PIPESTATUS[@]}")

    # Don't invoke precmds if we are inside an execution of an "original
    # prompt command" by another precmd execution loop. This avoids infinite
    # recursion.
    if (( __bp_inside_precmd > 0 )); then
      return
    fi
    local __bp_inside_precmd=1

    # Invoke every function defined in our function array.
    local precmd_function
    for precmd_function in "${precmd_functions[@]}"; do

        # Only execute this function if it actually exists.
        # Test existence of functions with: declare -[Ff]
        if type -t "$precmd_function" 1>/dev/null; then
            __bp_set_ret_value "$__bp_last_ret_value" "$__bp_last_argument_prev_command"
            # Quote our function invocation to prevent issues with IFS
            "$precmd_function"
        fi
    done

    __bp_set_ret_value "$__bp_last_ret_value"
}

# Sets a return value in $?. We may want to get access to the $? variable in our
# precmd functions. This is available for instance in zsh. We can simulate it in bash
# by setting the value here.
__bp_set_ret_value() {
    return ${1:-}
}

__bp_in_prompt_command() {

    local prompt_command_array
    IFS=$'\n;' read -rd '' -a prompt_command_array <<< "${PROMPT_COMMAND:-}"

    local trimmed_arg
    __bp_trim_whitespace trimmed_arg "${1:-}"

    local command trimmed_command
    for command in "${prompt_command_array[@]:-}"; do
        __bp_trim_whitespace trimmed_command "$command"
        if [[ "$trimmed_command" == "$trimmed_arg" ]]; then
            return 0
        fi
    done

    return 1
}

# This function is installed as the DEBUG trap.  It is invoked before each
# interactive prompt display.  Its purpose is to inspect the current
# environment to attempt to detect if the current command is being invoked
# interactively, and invoke 'preexec' if so.
__bp_preexec_invoke_exec() {

    # Save the contents of $_ so that it can be restored later on.
    # https://stackoverflow.com/questions/40944532/bash-preserve-in-a-debug-trap#40944702
    __bp_last_argument_prev_command="${1:-}"
    # Don't invoke preexecs if we are inside of another preexec.
    if (( __bp_inside_preexec > 0 )); then
      return
    fi
    local __bp_inside_preexec=1

    # Checks if the file descriptor is not standard out (i.e. '1')
    # __bp_delay_install checks if we're in test. Needed for bats to run.
    # Prevents preexec from being invoked for functions in PS1
    if [[ ! -t 1 && -z "${__bp_delay_install:-}" ]]; then
        return
    fi

    if [[ -n "${COMP_LINE:-}" ]]; then
        # We're in the middle of a completer. This obviously can't be
        # an interactively issued command.
        return
    fi
    if [[ -z "${__bp_preexec_interactive_mode:-}" ]]; then
        # We're doing something related to displaying the prompt.  Let the
        # prompt set the title instead of me.
        return
    else
        # If we're in a subshell, then the prompt won't be re-displayed to put
        # us back into interactive mode, so let's not set the variable back.
        # In other words, if you have a subshell like
        #   (sleep 1; sleep 2)
        # You want to see the 'sleep 2' as a set_command_title as well.
        if [[ 0 -eq "${BASH_SUBSHELL:-}" ]]; then
            __bp_preexec_interactive_mode=""
        fi
    fi

    if  __bp_in_prompt_command "${BASH_COMMAND:-}"; then
        # If we're executing something inside our prompt_command then we don't
        # want to call preexec. Bash prior to 3.1 can't detect this at all :/
        __bp_preexec_interactive_mode=""
        return
    fi

    local this_command
    this_command=$(
        export LC_ALL=C
        HISTTIMEFORMAT= builtin history 1 | sed '1 s/^ *[0-9][0-9]*[* ] //'
    )

    # Sanity check to make sure we have something to invoke our function with.
    if [[ -z "$this_command" ]]; then
        return
    fi

    # Invoke every function defined in our function array.
    local preexec_function
    local preexec_function_ret_value
    local preexec_ret_value=0
    for preexec_function in "${preexec_functions[@]:-}"; do

        # Only execute each function if it actually exists.
        # Test existence of function with: declare -[fF]
        if type -t "$preexec_function" 1>/dev/null; then
            __bp_set_ret_value ${__bp_last_ret_value:-}
            # Quote our function invocation to prevent issues with IFS
            "$preexec_function" "$this_command"
            preexec_function_ret_value="$?"
            if [[ "$preexec_function_ret_value" != 0 ]]; then
                preexec_ret_value="$preexec_function_ret_value"
            fi
        fi
    done

    # Restore the last argument of the last executed command, and set the return
    # value of the DEBUG trap to be the return code of the last preexec function
    # to return an error.
    # If `extdebug` is enabled a non-zero return value from any preexec function
    # will cause the user's command not to execute.
    # Run `shopt -s extdebug` to enable
    __bp_set_ret_value "$preexec_ret_value" "$__bp_last_argument_prev_command"
}

__bp_install() {
    # Exit if we already have this installed.
    if [[ "${PROMPT_COMMAND:-}" == *"__bp_precmd_invoke_cmd"* ]]; then
        return 1;
    fi

    trap '__bp_preexec_invoke_exec "$_"' DEBUG

    # Preserve any prior DEBUG trap as a preexec function
    local prior_trap=$(sed "s/[^']*'\(.*\)'[^']*/\1/" <<<"${__bp_trap_string:-}")
    unset __bp_trap_string
    if [[ -n "$prior_trap" ]]; then
        eval '__bp_original_debug_trap() {
          '"$prior_trap"'
        }'
        preexec_functions+=(__bp_original_debug_trap)
    fi

    # Adjust our HISTCONTROL Variable if needed.
    __bp_adjust_histcontrol

    # Issue #25. Setting debug trap for subshells causes sessions to exit for
    # backgrounded subshell commands (e.g. (pwd)& ). Believe this is a bug in Bash.
    #
    # Disabling this by default. It can be enabled by setting this variable.
    if [[ -n "${__bp_enable_subshells:-}" ]]; then

        # Set so debug trap will work be invoked in subshells.
        set -o functrace > /dev/null 2>&1
        shopt -s extdebug > /dev/null 2>&1
    fi

    local existing_prompt_command
    # Remove setting our trap install string and sanitize the existing prompt command string
    existing_prompt_command="${PROMPT_COMMAND:-}"
    existing_prompt_command="${existing_prompt_command//$__bp_install_string[;$'\n']}" # Edge case of appending to PROMPT_COMMAND
    existing_prompt_command="${existing_prompt_command//$__bp_install_string}"
    __bp_sanitize_string existing_prompt_command "$existing_prompt_command"

    # Install our hooks in PROMPT_COMMAND to allow our trap to know when we've
    # actually entered something.
    PROMPT_COMMAND=$'__bp_precmd_invoke_cmd\n'
    if [[ -n "$existing_prompt_command" ]]; then
        PROMPT_COMMAND+=${existing_prompt_command}$'\n'
    fi
    PROMPT_COMMAND+='__bp_interactive_mode'

    # Add two functions to our arrays for convenience
    # of definition.
    precmd_functions+=(precmd)
    preexec_functions+=(preexec)

    # Invoke our two functions manually that were added to $PROMPT_COMMAND
    __bp_precmd_invoke_cmd
    __bp_interactive_mode
}

# Sets an installation string as part of our PROMPT_COMMAND to install
# after our session has started. This allows bash-preexec to be included
# at any point in our bash profile.
__bp_install_after_session_init() {
    # bash-preexec needs to modify these variables in order to work correctly
    # if it can't, just stop the installation
    __bp_require_not_readonly PROMPT_COMMAND HISTCONTROL HISTTIMEFORMAT || return

    local sanitized_prompt_command
    __bp_sanitize_string sanitized_prompt_command "${PROMPT_COMMAND:-}"
    if [[ -n "$sanitized_prompt_command" ]]; then
        PROMPT_COMMAND=${sanitized_prompt_command}$'\n'
    fi;
    PROMPT_COMMAND+=${__bp_install_string}
}

# Run our install so long as we're not delaying it.
if [[ -z "${__bp_delay_install:-}" ]]; then
    __bp_install_after_session_init
fi
EOF
chmod 644 /etc/profile.d/bash-preexec.sh
chown root:root /etc/profile.d/bash-preexec.sh

if  ! (systemctl enable auditd && (systemctl enable rsyslog || systemctl enable syslog)); then
  if ! (chkconfig --level 2345 auditd on && chkconfig --level 2345 rsyslog on); then
    rc-update add auditd default
    rc-update add rsyslog default
    echo -e "\nАвтозагрузка rc-service rsyslog и auditd"
  fi
  echo -e "\nАвтозагрузка chkconfig rsyslog и auditd"
else
  echo -e "\nАвтозагрузка systemctl rsyslog и auditd"
fi

if ! (systemctl restart auditd && (systemctl restart rsyslog || systemctl restart syslog-ng)); then
  if ! (service auditd restart && (service rsyslog restart || service syslog restart)); then
    rc-service rsyslog restart            # Gentoo(OpenRC)
    rc-service auditd restart
    echo -e "\nРестарт rc-service rsyslog и auditd"
  fi
  echo -e "\nРестарт service rsyslog/syslog-ng  и auditd"
else
  echo -e "\nРестарт systemctl rsyslog/syslog-ng и auditd"
fi