#Add funshell.sh to ~/.bashrc if not already added
egrep -q '/funshell.sh ' ~/.bashrc || ! echo '### Modifying ~/.bashrc' || echo  '. ~/funshell.sh'  >> ~/.bashrc 
 

##################     SERVER        ##############################

USERNAME_HOSTED='xxxx'
PASSWORD_HOSTED='xxxx'

USERNAME_SAT='xxxx'
PASSWORD_SAT='xxxx'


alias vi='vim'
alias isv='cat /proc/cpuinfo  | egrep "^flags" | sort -u | egrep -wc "vmx|svm"' # Does my CPU supports Virtualization?
alias wreg='fun-wreg'
alias reg='fun-reg'
alias mr='> lloogg;clear;make run 2>&1 | tee -a lloogg;'
#export PATH="$PATH:/mnt/tests/CoreOS/RHN-Satellite/Helper"


function fun-rhn-backup() { # Backup /etc/sysconfig/rhn and yum*
# Copied from rhn-satellite-install.sh
    [[ -e ${HOME}/rhn-backups ]] || mkdir ${HOME}/rhn-backups
    local dir=${1:-"${HOME}/rhn-backups/rhn-backup-$(date +"%Y-%m-%d-%H-%M-%S")"}
    [[ -d $dir ]] ||  mkdir -p $dir
  
    echo  "fun-rhn-backup: Using backup dir '$dir'"
    # Perform backup
    local score=0
    if [ -d /etc/sysconfig/rhn ]; then
        cp -pr /etc/sysconfig/rhn $dir/ || let score+=1
    fi
    if [ -L /etc/sysconfig/rhn ]; then
        mv /etc/sysconfig/rhn $dir/ || let score+=1
        cp -pr $( readlink $dir/rhn ) /etc/sysconfig/rhn || let score+=1
    fi
    if [ -e /etc/yum.conf ]; then
        cp -p /etc/yum.conf $dir/ || let score+=1
    fi
    if [ -d /etc/yum.repos.d ]; then
        cp -pr /etc/yum.repos.d $dir/ || let score+=1
    fi
    if [ -d /etc/yum ]; then
        cp -pr /etc/yum $dir/ || let score+=1
    fi
    if [[ -e /etc/rhn/rhn.conf ]];then
        cp -p /etc/rhn/rhn.conf $dir/ || let score+=1 
    fi
    return $score
}


function fun-rhn-restore() { # Restore /etc/sysconfig/rhn and yum*
# Copied from rhn-satellite-install.sh
    local dir=${1:-${HOME}/rhn-backups/$(ls  ${HOME}/rhn-backups/ | sort | tail -n 1)}
    if [ ! -d "$dir" ]; then
        echo  "Backup not found in '$dir'"
        return 1
    fi
    echo   "fun-rhn-restore: Using backup from dir '$dir'"
    # Cleanup
    local score=0
    [ -L /etc/sysconfig/rhn ] && rm -f /etc/sysconfig/rhn
    [ -d /etc/sysconfig/rhn ] && rm -rf /etc/sysconfig/rhn
    [ -e $dir/yum.conf ] && rm -f /etc/yum.conf
    [ -d $dir/yum.repos.d ] &&  rm -rf /etc/yum.repos.d
    [ -d $dir/yum ] &&  rm -rf /etc/yum
    [[ -e /etc/rhn/rhn.conf ]] && rm -f /etc/rhn/rhn.conf

    # Perform restore
    if [ -e $dir/rhn ]; then
        mv $dir/rhn /etc/sysconfig/ || let score+=1
    fi
    if [ -e $dir/yum.conf ]; then
        mv $dir/yum.conf /etc/ || let score+=1
    fi
    if [ -e $dir/yum.repos.d ]; then
        mv $dir/yum.repos.d /etc/ || let score+=1
    fi
    if [ -e $dir/yum ]; then
        mv $dir/yum /etc/ || let score+=1
    fi
    if [[ -e $dir/rhn.conf ]];then
        mv $dir/rhn.conf /etc/rhn/rhn.conf
    fi
    # Restore SELinux context
    [ $( getenforce ) == 'Enforcing' ] && restorecon -R /etc/sysconfig/rhn /etc/yum.conf /etc/yum.repos.d /etc/rhn/rhn.conf
    # Removing dir with backup
    rmdir $dir
    return $score
}


function fun-help() { # List all available functions Ex: bhelp or bhelp bhelp or bhelp alias
    FUNSHELL_LOCATION=~/ms.sh #TODO
    if [[ $# -ne 0 ]];then
    flag='noprint'
       if [[  `cat ${FUNSHELL_LOCATION} | egrep "( )*^function" | egrep -v "###" | tr '#{()' ' ' | awk '{print $2}' | grep -cw $1` -eq 1 ]];then
         while read line
          do 
            if [[ `echo $line | egrep -c "^function( )*$1().*"` -eq 1 ]];then 
                   flag='print'; 
            fi
            [[ $flag == "print" ]]&& echo $line
             
            if [[ $flag == 'print' &&  $line == '}' ]];then 
                break;
            fi  
          done < ${FUNSHELL_LOCATION}
      elif [[ $1 == 'alias' ]];then
         egrep "( )*alias" ${FUNSHELL_LOCATION}
      else
        echo "Function $1 does not exist." 
      fi
    else # print the list of functions
      #find the longest name
      declare arr_names=(`cat ${FUNSHELL_LOCATION} | egrep "( )*^function" | egrep -v "###"  | tr '#{()' ' ' | awk '{print $2}' | tr '\n' ' '`);
      max_len=0; 
      for fun_name in `echo ${arr_names[*]}`
        do
          if [[ $max_len -lt ${#fun_name} ]];then
               max_len=${#fun_name}
          fi
        done

      cat ${FUNSHELL_LOCATION} | egrep "( )*^function" |  egrep -v "###"  |tr '#{()' ' ' | awk '{$1="";print}' | while read line
        do
          fun_name=${line%% *}  # Get the functions name
          offset=$(( $max_len - ${#fun_name} ))
          for((i=0;i<offset;i++));do
              echo -n " ";
          done  
          echo  $fun_name : ${line#* }
        done
    fi
}

function fun-wreg() { # Where Registered - Host, RHN Proxy, Satellite

    if [[  `ps -ef | egrep -c "[0-9] ora_pmon"` -ne 0 || `ps -ef | egrep -c "[0-9] /usr/bin/postmaster"` -ne 0 ]];then 
          par_up2date=`egrep "^serverURL=http.*/XMLRPC$" /etc/sysconfig/rhn/up2date | tail -n 1 | sed 's/^serverURL=http[s]*:[\/]\{2\}xmlrpc\.\(.*\)\/XMLRPC$/\1/'`
          par_rhn=`egrep "^server.satellite.rhn_parent( )*=( )*satellite.*" /etc/rhn/rhn.conf | tail -n 1 | sed 's/^server.satellite.rhn_parent[ ]*=[ ]*satellite\.\([A-Za-z0-9\-\._]\+\)[ ]*$/\1/g' | sort -u`
          if [[ $par_up2date == $par_rhn ]];then
            echo "SATELLITE PARENT $par_up2date"
            fun-sys-info;
          else
            echo 'ERROR Parent Server in up2date and rhn.conf are different !!!'
         fi
    else

      if [[ `ps -ef | egrep -c  "[0-9] squid "` -gt 0  ]];then
         par_up2date=`egrep "^serverURL=http.*/XMLRPC$" /etc/sysconfig/rhn/up2date | tail -n 1 | sed 's/^serverURL=http[s]*:[\/]\{2\}\(.*\)\/XMLRPC$/\1/'`
          par_rhn=`egrep "^proxy.rhn_parent( )*=.*" /etc/rhn/rhn.conf | tail -n 1 | sed 's/^proxy.rhn_parent[ ]*=[ ]*\(.*\)$/\1/g' | sort -u`
          if [[ $par_up2date = $par_rhn ]];then
            echo  "PROXY PARENT = $par_up2date"
            fun-sys-info;
          else
            echo 'ERROR Parent Server in up2date and rhn.conf are different !!!'
         fi
      
      else # Host
       HOST_PARENT=`egrep "^serverURL=http.*/XMLRPC$" /etc/sysconfig/rhn/up2date | tail -n 1 |  sed 's/^serverURL=http[s]*:[\/]\{2\}\(.*\)\/XMLRPC$/\1/'`
       echo "HOST PARENT = $HOST_PARENT"
       fun-sys-info;
      fi
    fi
}


function fun-reg() { # Register Server to Satellite or Hosted

    if [[ $1 == '--help' || $# -eq 1 || $# -gt 4 ]];then
        echo 'Usage:'
        echo '  fun-reg                                        - Register to Errata.Stage with profile profile_${DATE}';
        echo '  fun-reg "" TEST_SERVER                         - Register to Errata.Stage';
        echo '  fun-reg <RHN_PROXY> <PROFILE_NAME> proxy       - Register to Hosted via RHN Proxy';
        echo '  fun-reg prod <PROFILE_NAME>                    - Register to rhn.redhat.com';
        echo '  fun-reg <RHN SATELLITE> <PROFILE_NAME>         - Register to <RHN SATELLITE>';
        echo '  fun-reg <RHN SATELLITE> <PROFILE_NAME> "" http - Register to <RHN SATELLITE> using HTTP instead of HTTPS';
        return 0
    fi
    # Backup rhn,yum repo, etc
    fun-rhn-backup;
    local RHN_PARENT_SERVER=${1:-"errata.stage"}
    local PROFILE_NAME=${2:-'profile'}
    local VIA_PROXY=${3}
    local PROTOCOL=${4:-'https'}
    SSL_CERT='/usr/share/rhn/RHNS-CA-CERT' 
    # Satellite to Hosted
    if [[ `echo $RHN_PARENT_SERVER | egrep -c "^errata\.stage$|^webqa$|^webdev$|^qa$"` -ne 0 ]];then
       echo "rhnreg_ks --username=${USERNAME_HOSTED} --serverUrl=${PROTOCOL}://xmlrpc.rhn.${RHN_PARENT_SERVER}.redhat.com/XMLRPC --sslCACert=${SSL_CERT}   --password=${PASSWORD_HOSTED} --force  --profilename=${PROFILE_NAME}_`date +"%D-%H-%M-%S"`"
       rhnreg_ks --username=${USERNAME_HOSTED} --serverUrl=${PROTOCOL}://xmlrpc.rhn.${RHN_PARENT_SERVER}.redhat.com/XMLRPC --sslCACert=${SSL_CERT}   --password=${PASSWORD_HOSTED} --force  --profilename=${PROFILE_NAME}_`date +"%D-%H-%M-%S"`
    elif [[ $RHN_PARENT_SERVER == 'prod'  ]];then
        echo "rhnreg_ks --username=${USERNAME_HOSTED} --serverUrl=${PROTOCOL}://xmlrpc.rhn.redhat.com/XMLRPC  --sslCACert=${SSL_CERT} --password=${PASSWORD_HOSTED} --force  --profilename=${PROFILE_NAME}_`date +"%D-%H-%M-%S"`"
        rhnreg_ks --username=${USERNAME_HOSTED} --serverUrl=${PROTOCOL}://xmlrpc.rhn.redhat.com/XMLRPC  --sslCACert=${SSL_CERT} --password=${PASSWORD_HOSTED} --force  --profilename=${PROFILE_NAME}_`date +"%D-%H-%M-%S"`
    elif [[ ${VIA_PROXY} == 'proxy' ]];then
        SSL_CERT='/usr/share/rhn/RHN-ORG-TRUSTED-SSL-CERT'
        wget https://${1}/pub/RHN-ORG-TRUSTED-SSL-CERT -O $SSL_CERT  --no-check-certificate &> /dev/null 
        echo "rhnreg_ks --username=${USERNAME_HOSTED} --serverUrl=${PROTOCOL}://${1}/XMLRPC --sslCACert=${SSL_CERT}  --password=${PASSWORD_HOSTED} --force  --profilename=${PROFILE_NAME}`date +"%D-%H-%M-%S"`"
        rhnreg_ks --username=${USERNAME_HOSTED} --serverUrl=${PROTOCOL}://${1}/XMLRPC --sslCACert=${SSL_CERT}  --password=${PASSWORD_HOSTED} --force  --profilename=${PROFILE_NAME}`date +"%D-%H-%M-%S"` 
    else  #Host to Satellite 
        SSL_CERT='/usr/share/rhn/RHN-ORG-TRUSTED-SSL-CERT' 
        wget https://${1}/pub/RHN-ORG-TRUSTED-SSL-CERT -O $SSL_CERT  --no-check-certificate &> /dev/null 
        echo "rhnreg_ks --username=${USERNAME_SAT} --serverUrl=${PROTOCOL}://${1}/XMLRPC --sslCACert=${SSL_CERT} --profilename=${PROFILE_NAME}_`date +"%D-%H-%M-%S"` --password=${PASSWORD_SAT} --force;"
        rhnreg_ks --username=${USERNAME_SAT} --serverUrl=${PROTOCOL}://${1}/XMLRPC --sslCACert=${SSL_CERT} --profilename=${PROFILE_NAME}_`date +"%D-%H-%M-%S"` --password=${PASSWORD_SAT} --force;
    fi
}



function fun-get-arch() { # Get system architecture
    local archi=$( uname -i 2>/dev/null || uname -m )
    case "$archi" in
        i486 | i586 | i686 | i386)
            echo 'i386'
            return 0 
        ;;
        ppc64)
            echo 'ppc'
            return 0
        ;;
        x86_64)
            echo 'x86_64'
            return 0
        ;;
        s390)
            echo 's390'
            return 0
        ;;
        s390x)
            echo 's390x' 
            return 0
        ;;
        *)
          echo 'Unknown'
          return 1;
        ;;
    esac
}

function fun-get-version() { # Get RHEL Version

    local version=0
    #if rpm -qa | egrep -q "^redhat-release" ; then
     if [[ -e /etc/redhat-release ]];then
      # version=$( rpm -q --qf="%{VERSION}" `rpm -qa | egrep "^redhat-release" | tail -n 1` )
        version=$( rpm -qf --qf="%{VERSION}" /etc/redhat-release) 
 #   if rpm -q redhat-release &>/dev/null; then
 #       version=$( rpm -q --qf="%{VERSION}" redhat-release )
        echo ${version} | sed "s/^\([0-9]\+\)[^0-9]\+.*$/\1/"
    elif rpm -q --qf="%{VERSION}" fedora-release &>/dev/null;then
          rpm -q --qf="%{VERSION}" fedora-release   
    else
      echo "# Error - Not able to recognize the RHEL Release Version"
      return 1
    fi
}

function fun-sys-info() { # Provides registration information from /etc/sysconfig/rhn/systemid

    CERT=$( egrep  "^sslCACert=" /etc/sysconfig/rhn/up2date | awk -F= '{print $2}' )
    if [[ -e /etc/sysconfig/rhn/systemid ]];then
       PROFILE=`tr -d '\n' < /etc/sysconfig/rhn/systemid | sed 's/.*profile_name..name..value..string.\([^<]*\)<.*/\1/'`
       ARCH=`tr -d '\n' < /etc/sysconfig/rhn/systemid | sed 's/.*architecture..name..value..string.\([^<]*\)<.*/\1/'`
       SYS_ID=`tr -d '\n' < /etc/sysconfig/rhn/systemid | sed 's/.*system_id..name..value..string.\([^<]*\)<.*/\1/'`
       OS_REL=`tr -d '\n' < /etc/sysconfig/rhn/systemid | sed 's/.*os_release..name..value..string.\([^<]*\)<.*/\1/'`

       echo "Profile=$PROFILE
       System ID=$SYS_ID
       Arch=$ARCH
       OS Release=$OS_REL
       sslCACert =$CERT"
    else
       echo 'The server is not registered to RHN !!!'
    fi 
    
}


function fun-regs() { # Register Satellite
    if [[ $1 == '--help' ]];then
       echo 'Usage:'
       echo '  fun-regs <HOSTED SERVER TAG> <SATELLITE_CERT>'
       echo '  fun-regs <HOSTED SERVER TAG>'
       echo '  fun-regs'
       echo 'Examples:'
       echo 'fun-regs'
       echo 'fun-regs prod'
       echo 'fun-regs prod  <SATELLITE_CERT>'
       echo 'fun-regs webqa  <SATELLITE_CERT>'
       echo 'fun-regs errata.stage  <SATELLITE_CERT>'
       return 1
    fi

    RHN_PARENT_SERVER=${1:-'errata.stage'}
    SSH_Cert=${2:-$(fun-download-sat-cert)}
    if [[ `echo $RHN_PARENT_SERVER | egrep -c "^errata\.stage$|^webqa$|^webdev$|^qa$"` -ne 0 ]];then
       sed -i.bak  "s/^\(server.satellite.rhn_parent\).*/\1 = satellite.rhn.${RHN_PARENT_SERVER}.redhat.com/g" /etc/rhn/rhn.conf
    elif [[ $RHN_PARENT_SERVER == 'prod' ]];then
       sed -i.bak  "s/^\(server.satellite.rhn_parent\).*/\1 = satellite.rhn.redhat.com/g" /etc/rhn/rhn.conf
    else
       echo 'Unknow HOSTED SERVER !!!' 
    fi
    echo "### Registering to $RHN_PARENT_SERVER"
    fun-reg $RHN_PARENT_SERVER satellite;
    echo "### rhn-satellite-activate --rhn-cert=${SSH_Cert}   --ignore-version-mismatch"
    rhn-satellite-activate --rhn-cert=${SSH_Cert}   --ignore-version-mismatch
}


function fun-unreg() { # Delete the profile from Satellite or Hosted

    if [[ $1 == '--help' ]];then
     echo 'Usage:'
     echo '  fun-unreg       - Unregister from Satellite or Hosted'
     echo '  fun-unreg proxy - Unregsiter from Hosted via RHN Proxy'
     return 0
    fi

    [[ ! -f /etc/sysconfig/rhn/systemid ]] && echo "Server is not registered !!! " && return 2

    [[ $1 == 'proxy' ]] || export local RHN_USER=${1:-$USERNAME_SAT}
    export local RHN_PASS=${2:-$PASSWORD_SAT}

    #Get the Server
    export local SERVER_NAME=`egrep "^serverURL=http.*/XMLRPC$" /etc/sysconfig/rhn/up2date | tail -n 1 | sed 's/^serverURL=http[s]*:[\/]\{2\}\(.*\)\/XMLRPC$/\1/'` 
    echo "RHN-SERVER=$SERVER_NAME"
    if [[ `echo $SERVER_NAME | egrep -c "errata\.stage\.redhat\.com$|webqa\.redhat\.com$|webdev\.redhat\.com$|qa\.redhat\.com$|^xmlrpc\.rhn\.redhat\.com$"` -ne 0  || $1 == 'proxy' ]];then
     export RHN_USER=${USERNAME_HOSTED}
     export RHN_PASS=${PASSWORD_HOSTED}
    fi
    #Get the system ID
    export local SERVER_SYS_ID=`tr -d '\n' < /etc/sysconfig/rhn/systemid | sed 's/.*system_id..name..value..string.ID-\([^<]*\)<.*/\1/'`
    echo "SERVER_SYS_ID=$SERVER_SYS_ID"

    python -c "import xmlrpclib,os;\
        SERVER = os.environ['SERVER_NAME'];\
        client = xmlrpclib.Server('http://%s/rpc/api' % SERVER, verbose=0);\
        USER = os.environ['RHN_USER'];\
        PASS = os.environ['RHN_PASS'];\
        key = client.auth.login(USER, PASS);\
        serverId=os.environ['SERVER_SYS_ID'];\
        arr_serverId=[int(serverId)];\
        client.system.deleteSystems(key,arr_serverId);"

    # Remove the system ID file
    [[ $? -eq 0 ]]  && rm -f /etc/sysconfig/rhn/systemid
}


function fun-gpg() { # GPG Check Enable/Disable

    if [[ $(fun-get-version) -lt 5 ]];then
         echo "This function is not available for RHEL 4"
         return 1
    fi

    STATUS=${1:-'OFF'}
    echo -n "yum.conf: "; grep gpgcheck /etc/yum.conf
    echo -n "rhnplugin.conf:"; grep gpgcheck /etc/yum/pluginconf.d/rhnplugin.conf 

     if [[ $STATUS = 'OFF' ]];then
        perl -p -e 's/gpgcheck=1/gpgcheck=0/' -i.bak /etc/yum.conf
        perl -p -e 's/gpgcheck = 1/gpgcheck = 0/' -i.bak /etc/yum/pluginconf.d/rhnplugin.conf
     else
        perl -p -e 's/gpgcheck=0/gpgcheck=1/' -i.bak /etc/yum.conf
        perl -p -e 's/gpgcheck = 0/gpgcheck = 1/' -i /etc/yum/pluginconf.d/rhnplugin.conf
     fi
    echo '--------'
    echo -n "yum.conf: "; grep gpgcheck /etc/yum.conf
    echo -n "rhnplugin.conf:"; grep gpgcheck /etc/yum/pluginconf.d/rhnplugin.conf 

}

######## LOGS START ###################################
function rhn_set_log_file_list(){ ### Do not call directly, used by rhn_set_log_mark()
 
  if [[ `netstat -anp | egrep -c -e  "5222.+LISTEN.+c2s" \
                      -e "5269.+LISTEN.+s2s" \
                      -e "8080.+LISTEN.+java" \
                      -e "443.+LISTEN.+httpd"`  -eq 4 ]]; then
    
      # RHN Satellite is running on this machine
       arr_logs_list=('/var/log/up2date'  
                 '/var/log/httpd/access_log' 
                 '/var/log/httpd/ssl_access_log' 
                 '/var/log/httpd/error_log' 
                 '/var/log/httpd/ssl_error_log' 
                 '/var/log/tomcat*/catalina.out' 
                 '/var/log/cobbler/cobbler.log' 
                 '/var/log/rhn/rhn_taskomatic_daemon.log'
                 '/var/log/audit/audit.log'
                 '/var/log/rhn/populate_db.log'
                 '/var/log/rhn/rhn_server_xp.log'
                 '/var/log/rhn/osa-dispatcher.log'
                 '/var/log/rhn/rhn_web_api.log'
                 '/var/log/rhn/rhn_upload_package_push.log'
                 '/var/log/rhn/rhn_server_xmlrpc.log'
                 '/var/log/rhn/rhn_server_app.log'
                 '/var/log/rhn/rhn_server_satellite.log'
                 '/var/log/rhn/rhn_config_management.log')

   elif [[ `netstat  -anp | egrep -c "80.*\(squid\)"` -ne 0 &&  `netstat  -anp | egrep -c "80.*httpd"` -ne 0 ]];then
   # Proxy is runnig 
       arr_logs_list=('/var/log/rhn/rhn_proxy_broker.log'  
                 '/var/log/rhn/rhn_proxy_redirect.log' 
                 '/var/log/squid/access.log' 
                 '/var/log/squid/cache.log'   
                 '/var/log/httpd/access_log' 
                 '/var/log/httpd/error_log' 
                 '/var/log/httpd/ssl_access_log' 
                 '/var/log/httpd/ssl_error_log' 
                 '/var/log/httpd/ssl_request_log')

       arr_err_log_list=(''); 
   else # What a shame :(
       arr_logs_list=('');
       arr_err_log_list=('');  
   fi
}

function rhn_get_log_mark() { ### Do not call directly, used by rhn_get_log_content()
    export MARK_DATE=${MARK_DATE:-$(date +%a_%b_%d_%Y_%H_%M_%S)};
    echo $MARK_DATE
}


function fun-set-log-mark() { # Sets Start Mark in the logs
    #Get Mark
    [[ $1 != 'fun_get_log_content' ]] && rhn_remove_log_mark # Clean the environment. In case some one called before fun-set-log-mark but not fun-get-log-con
    #rhn_get_log_mark > /dev/null # Creates  MARK_DATE varible
    rhn_get_log_mark

    # Set the Logs list
    rhn_set_log_file_list;

    for ((i=0;i<${#arr_logs_list[*]};i++))
      do
         # Put Mark only in the Log files that currently exists
         [ -e ${arr_logs_list[$i]} ] && echo $MARK_DATE >> ${arr_logs_list[$i]}  
         [[ $1 != 'fun_get_log_content' ]]  && echo   ${arr_logs_list[$i]}
      done

     return 0
}


function rhn_concat_logs(){  ### Do not call directly, used by rhn_get_log_content()

    for log_file in `ls ${1}*` 
      do
        if [[ `echo $log_file | egrep -c "\.[0-9]\.gz$"` -eq 0 ]];then
           arr_log_files=(${arr_log_files[*]} $log_file) 
        else
           gzip -cd $log_file > /tmp/rhn_temp_${log_file##*/}.log
           arr_log_files=(${arr_log_files[*]} /tmp/rhn_temp_${log_file##*/}.log)
        fi
      done

      cat `echo ${arr_log_files[*]}` >  /tmp/log_$(rhn_get_log_mark)

      unset arr_log_files
}

function rhn_remove_log_mark() { ### Do not call directly, used by rhn_get_log_content()

    rm -f /tmp/marked_log_*_$(rhn_get_log_mark) # remove aux files
    rm -f /tmp/log_$(rhn_get_log_mark)
    rm -f /tmp/rhn_temp_*.log
    unset MARK_DATE; # rhn_get_log_mark

}

function fun-get-log-content() { # Sets End Mark in the logs and collect content between Start and End Mark

   fun-set-log-mark 'fun_get_log_content' # Set the end MARK
   
   for index in `seq 0  $(( ${#arr_logs_list[*]} - 1 ))`
	do
          echo -e "\n###  ${arr_logs_list[$index]}   ##########################################" >> /tmp/marked_log_${index}_$(rhn_get_log_mark)
          
          if [[ -e  ${arr_logs_list[$index]} ]];then
          	rhn_concat_logs ${arr_logs_list[$index]};
      
          	# Take the line numbers of the marks 
          	arr_line_num=( `egrep -n -a "^$(rhn_get_log_mark)$" /tmp/log_$(rhn_get_log_mark) | awk -F: '{print $1}'` )
          	if [[ ${#arr_line_num[*]} -eq 1  ]];then 
           	  # the file did not exist before. Cut all lines from the begining till the Mark
            	 #head -n $(( ${arr_line_num[0]} - 1 )) /tmp/log_$(rhn_get_log_mark)  >>  /tmp/marked_log_${index}_$(rhn_get_log_mark)
            	 head -n ${arr_line_num[0]}  /tmp/log_$(rhn_get_log_mark)  >>  /tmp/marked_log_${index}_$(rhn_get_log_mark)

          	elif [[ ${#arr_line_num[*]} -eq 2  ]];then
          	   # Cut the contetn between the marks
          	   #head -n $(( ${arr_line_num[1]} - 1 )) /tmp/log_$(rhn_get_log_mark) | tail -n $(( ${arr_line_num[1]} - ${arr_line_num[0]} - 1 ))  >>  /tmp/marked_log_${index}_$(rhn_get_log_mark)
           	  head -n ${arr_line_num[1]} /tmp/log_$(rhn_get_log_mark) | tail -n $(( ${arr_line_num[1]} - ${arr_line_num[0]} +1 ))  >>  /tmp/marked_log_${index}_$(rhn_get_log_mark)
         	 else 
          	  echo "Something went terribly wrong"
         	 fi
          fi
          # Add the last results to the common result file
          cat /tmp/marked_log_${index}_$(rhn_get_log_mark) >>  /tmp/marked_log_$(rhn_get_log_mark)
	done # for

        # Print all logs
        cat   /tmp/marked_log_$(rhn_get_log_mark)
	# Clean
	rhn_remove_log_mark

} 

##################### LOGS END #############################
