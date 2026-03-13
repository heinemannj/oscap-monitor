#!/usr/bin/bash
#
# /opt/oscap-monitor/oscap-monitor.sh
#
# https://github.com/heinemannj/oscap-monitor

# Copyright 2026 Joerg Heinemann <heinemannj66@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# MPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

set -uo pipefail

export LOGFILE=/var/log/oscap.log
exec > >(tee $LOGFILE)
exec 2>&1

function die()
{
	echo
	echo "$*" >&2
	echo
	exit 1
}

function invalid()
{
	echo
	echo -e "$*\n" >&2
	usage
	exit 1
}

function usage()
{
	echo
	echo "oscap-monitor -- Tool for SCAP evaluation, remediation and monitoring of remote systems."
	echo
	echo "Usage:"
	echo
	echo "$ oscap-monitor xccdf eval [options] INPUT_SYSTEM_LIST"
	echo
	echo "supported xccdf eval options are:"
	echo "  --tailoring: INPUT_TAILORING_RULES"
	echo "  --remediate INPUT_REMEDIATION_RULES"
	echo
	echo "$ oscap-monitor oval eval INPUT_SYSTEM_LIST"
	echo
}

function packages_pinning()
{
	echo
	echo "$*" >&2
	echo
	echo "a) Add an additional 'apt source': '/etc/apt/sources.list.d/debian-unstable.sources'"
	echo
	echo "Types: deb"
	echo "URIs: http://deb.debian.org/debian"
	echo "Suites: testing unstable"
	echo "Components: contrib main"
	echo "Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg"
	echo "Enabled: yes"
	echo
	echo "b) Add an additional 'apt preference' for enabling testing and unstable package versions: '/etc/apt/preferences.d/unstable.pref'"
	echo
	echo "Package: *"
	echo "Pin: release a=unstable"
	echo "Pin-Priority: -10"
	echo
	echo "Package: *"
	echo "Pin: release a=testing"
	echo "Pin-Priority: -10"
	echo
	echo "Package: ssg-*"
	echo "Pin: release a=unstable"
	echo "Pin-Priority: 600"
	echo
	echo "Package: ssg-*"
	echo "Pin: release a=testing"
	echo "Pin-Priority: 600"
	echo

	exit 1
}

function dependencies_check()
{
	apt update &> /dev/null || die "Cannot update apt package lists."

	apt upgrade \
		lsb-base \
		lsb-release \
		bzip2 \
		openscap-scanner \
		openscap-common \
		openscap-utils \
		openscap-doc \
		ssg-applications \
		ssg-base \
		ssg-debderived \
		ssg-debian \
		ssg-nondebian \
		-y &> /dev/null || die "Cannot check apt package states."

	apt autoremove -y &> /dev/null || die "Cannot check apt package states for auto removal."

	#apt list | grep openscap
	#apt list | grep ssg-
	SSGVersion=$(dpkg-query -W -f '${Version}\n' ssg-debian | sed 's/\.//g' | sed 's/-//g')

	SSGVersionMin=01791
	[ $SSGVersion -ge $SSGVersionMin ] || packages_pinning "'ssg-*' package versions must be at least '0.1.79-1' or newer, please upgrade (see below)."

	which oscap > /dev/null || die "Cannot find oscap, please install openscap-scanner."
	which oscap-ssh > /dev/null || die "Cannot find oscap-ssh, please install openscap-utils."
	which autotailor > /dev/null || die "Cannot find autotailor, please install openscap-utils."
	which ssh > /dev/null || die "Cannot find ssh, please install the OpenSSH client."
	which scp > /dev/null || die "Cannot find scp, please install the OpenSSH client."
	which mktemp > /dev/null || die "Cannot find mktemp, please install coreutils."
	which lsb_release > /dev/null || die "Cannot find lsb_release, please install lsb-base and lsb-release."
	which bunzip2 > /dev/null || die "Cannot find bunzip2, please install bzip2."
}

function header()
{
	echo "$1" > $SUMMARY_FILE
	echo >> $SUMMARY_FILE
	echo "Scan started: $(date)" >> $SUMMARY_FILE
	echo >> $SUMMARY_FILE
}

function append()
{
	echo $SUMMARY >> $SUMMARY_FILE
}

function footer()
{
	echo >> $SUMMARY_FILE
	echo "$1" >> $SUMMARY_FILE
	echo >> $SUMMARY_FILE
	echo "Log file: $LOGFILE" >> $SUMMARY_FILE
}

function xccdf_eval_tailoring()
{
	echo
	echo "Initializing Tailoring --------------------------------------------------------------------------------"
	echo

	mkdir -p $CustomProfiles || die "Cannot create $CustomProfiles directory."

	mapfile -t myFILE_ARRAY < "$INPUT_TAILORING_RULES" || die "Cannot open $INPUT_TAILORING_RULES."
	RULE_ARRAY=()

	TailoringFile=$CustomProfiles/$Profile"_custom.xml"
	TailoringFileOption="--tailoring-file $TailoringFile"

	for myLINE in ${myFILE_ARRAY[@]}; do
		if [[ "$myLINE" != \#* ]]; then
			IFS=';' read -ra myLINE_ARRAY <<< "$myLINE"
			RULE_ID="${myLINE_ARRAY[0]}"
			RULE_ACTION=$(echo "${myLINE_ARRAY[1]}" | tr '[:upper:]' '[:lower:]')
			[[ $(grep $RULE_ID $BenchmarkFile) ]] && RULE_CHECK=true || RULE_CHECK=false;
			if [ $RULE_CHECK == true ]; then
				RULE_ARRAY+=(--$RULE_ACTION $RULE_ID)
			fi
		fi
	done

	autotailor \
	--tailored-profile-id $Profile"_custom" \
	${RULE_ARRAY[@]} \
	--output $TailoringFile \
	$BenchmarkFile \
	$Profile || die "Tailoring failed. Please check related error messages!"

	cat $TailoringFile || die "Cannot open $TailoringFile."

	Profile+="_custom"
	ProfileOption+="_custom"
}

function xccdf_eval_remediation_scan()
{
	echo
	echo "Initializing Remediation --------------------------------------------------------------------------------"
	echo

	mapfile -t myFILE_ARRAY < "$INPUT_REMEDIATION_RULES" || die "Cannot open $INPUT_REMEDIATION_RULES."
	RULE_ARRAY=()

	for myLINE in "${myFILE_ARRAY[@]}"; do
		if [[ "$myLINE" != \#* ]]; then
			IFS=';' read -ra myLINE_ARRAY <<< "$myLINE"
			RULE_ID="${myLINE_ARRAY[0]}"
			[[ $(grep $RULE_ID $BenchmarkFile) ]] && RULE_CHECK=true || RULE_CHECK=false;
			if [ $RULE_CHECK == true ]; then
				RULE_ARRAY+=(--rule $RULE_ID)
			fi
		fi
	done

	if (( ${#RULE_ARRAY[@]} != 0 )); then
		oscap-ssh --sudo $SSHUser@$HostName $SSHPort xccdf eval $ProfileOption $TailoringFileOption \
		--remediate ${RULE_ARRAY[@]} \
		$BenchmarkFile
		if [ $? == 1 ]; then
			false
			die "Remediation failed. Please check related error messages!"
		fi
	else
		echo "No '$DistributorID' matching remediation rules. Skipping remediation..."
	fi
}

function xccdf_eval_compliance_scan()
{
	echo
	echo "Starting Compliance Scan ---------------------------------------------------------------------------------"
	echo
	ResultsARF="$SCAPinoculars/reports/$HostName/$Profile"_"$HostName.xml"
	ResultsARFOption="--results-arf $ResultsARF"
	
	Report="$OSCAPMonitor/reports/$HostName/$Profile"_"$HostName.html"

	oscap-ssh --sudo $SSHUser@$HostName $SSHPort xccdf eval $ProfileOption $TailoringFileOption $ResultsARFOption $BenchmarkFile
	EXIT_CODE=$?

	oscap xccdf generate report --output $Report $ResultsARF || die "Cannot generate report $Report."

	Passed=$(grep -c '<result>pass</result>' "$ResultsARF" 2>/dev/null)
	Failed=$(grep -c '<result>fail</result>' "$ResultsARF" 2>/dev/null)
	Error=$(grep -c '<result>error</result>' "$ResultsARF" 2>/dev/null)
	Unknown=$(grep -c '<result>unknown</result>' "$ResultsARF" 2>/dev/null)
	NotApplicable=$(grep -c '<result>notapplicable</result>' "$ResultsARF" 2>/dev/null)
	NotChecked=$(grep -c '<result>notchecked</result>' "$ResultsARF" 2>/dev/null)
	NotSelected=$(grep -c '<result>notselected</result>' "$ResultsARF" 2>/dev/null)
	Informational=$(grep -c '<result>informational</result>' "$ResultsARF" 2>/dev/null)
	Fixed=$(grep -c '<result>fixed</result>' "$ResultsARF" 2>/dev/null)
	Score=$(cat $ResultsARF | grep score | awk -F '>' '{ print $2 }' | awk -F "<" '{ print $1 }')


	echo
	echo "Scan completed with exit code: ${EXIT_CODE}"
	echo
	echo "Passed        : $Passed"
	echo "Failed        : $Failed"
	echo "Error         : $Error"
	echo "Unknown       : $Unknown"
	echo "Not Applicable: $NotApplicable"
	echo "Not Checked   : $NotChecked"
	echo "Not Selected  : $NotSelected"
	echo "Informational : $Informational"
	echo "Fixed         : $Fixed"
	echo
	echo "Score         : $Score"
	echo "Maximum       : 100.000000"
	echo
	echo 'ResultsARF: '$ResultsARF
	echo 'Report: '$Report
	SUMMARY+="$Score;$Passed;$Failed;$Error;$Unknown;$NotApplicable;$NotChecked;$NotSelected;$Informational;$Fixed;$Report;"
}

function xccdf_eval()
{
	echo
	BenchmarkFile="$SSG/content/ssg-$DistributorID$Release-ds.xml"
	if [ -f $BenchmarkFile ]; then
		echo 'BenchmarkFile: '$BenchmarkFile
	else
		die "No valid Benchmark URL/File!"
	fi

	CPEDictionary="$SSG/content/ssg-$DistributorID$Release-cpe-dictionary.xml"
	if [ -f $CPEDictionary ]; then
		echo 'CPEDictionary: '$CPEDictionary
	else
		die "No valid CPE dictionary or language!"
	fi

	if [ "$Profile" != "" ]; then
		ProfileOption="--profile $Profile"
	else
		die "No valid Profile!"
	fi

	TailoringFileOption=""

	$TAILORING && xccdf_eval_tailoring

	echo
	echo "Selected xccdf eval scan options:"
	echo $ProfileOption
	$TAILORING && echo "--tailoring $INPUT_TAILORING_RULES"
	$TAILORING && echo "$TailoringFileOption"
	$REMEDIATE && echo "--remediate $INPUT_REMEDIATION_RULES"

	$REMEDIATE && xccdf_eval_remediation_scan
	xccdf_eval_compliance_scan
}

function oval_eval()
{
	echo
	echo "Starting Vulnerability Scan ---------------------------------------------------------------------------------"
	echo

	mkdir -p $OVAL || die "Cannot create $OVAL directory."

	echo "Checking latest version of $OvalURL/$OvalFile.bz2 ..."
	echo

	if test -e "$OVAL/$OvalZIP"
	then zflag=(-z "$OVAL/$OvalZIP")
	else zflag=()
	fi
	curl -o "$OVAL/$OvalZIP" "${zflag[@]}" "$OvalURL/$OvalZIP" || die "Cannot download $OvalURL/$OvalZIP."
	bunzip2 -kf $OVAL/$OvalZIP || die "Cannot unzip $OVAL/$OvalZIP."

	Results="$OSCAPMonitor/reports/$HostName/$OvalDef"_"$HostName.xml"
	ResultsOption="--results $Results"
	echo 'Results: '$Results

	Report="$OSCAPMonitor/reports/$HostName/$OvalDef"_"$HostName.html"
	ReportOption="--report $Report"
	echo 'Report: '$Report

	OvalFile=$OVAL/$OvalFile
	echo 'OvalFile: '$OvalFile

	oscap-ssh --sudo $SSHUser@$HostName $SSHPort oval eval $ResultsOption $OvalFile | grep -v false || echo "NOT compliant!" && echo "Compliant."
	EXIT_CODE=$?

	oscap oval generate report --output $Report $Results || die "Cannot generate report $Report."

	echo
	echo "Scan completed with exit code: ${EXIT_CODE}"
	echo
	echo 'Results: '$Results
	echo 'Report: '$Report
	echo
}

function main()
{
	SSG=/usr/share/xml/scap/ssg
	OVAL=/usr/share/xml/scap/oval
	OSCAPMonitor=/opt/oscap-monitor/ressources
	CustomProfiles=$OSCAPMonitor/custom_profiles
	SCAPinoculars=/opt/SCAPinoculars/resources

	[ "$SSG" != "" ] || [ -f "$SSG" ] || die "'$SSG' isn't a valid file path or the file doesn't exist!"
	[ "$OVAL" != "" ] || [ -f "$OVAL" ] || die "'$OVAL' isn't a valid file path or the file doesn't exist!"
	[ "$OSCAPMonitor" != "" ] || [ -f "$OSCAPMonitor" ] || die "'$OSCAPMonitor' isn't a valid file path or the file doesn't exist!"
	[ "$SCAPinoculars" != "" ] || [ -f "$SCAPinoculars" ] || die "'$SCAPinoculars' isn't a valid file path or the file doesn't exist!"

	mapfile -t myFILE_ARRAY < "$INPUT_SYSTEM_LIST" || die "Cannot open $INPUT_SYSTEM_LIST."

	SUMMARY_FILE="$OSCAPMonitor/reports/summary.txt"
	header "Report: $EVAL"

	for myLINE in ${myFILE_ARRAY[@]}; do
		if [[ "$myLINE" != \#* ]]; then
			IFS=';' read -ra myLINE_ARRAY <<< "$myLINE"
			HostName=$(echo "${myLINE_ARRAY[0]}" | tr '[:upper:]' '[:lower:]')
			SSHUser=$(echo "${myLINE_ARRAY[1]}" | tr '[:upper:]' '[:lower:]')
			SSHPort=$(echo "${myLINE_ARRAY[2]}" | tr '[:upper:]' '[:lower:]')
			Profile=$(echo "${myLINE_ARRAY[3]}" | tr '[:upper:]' '[:lower:]')

			SUMMARY=""

			echo
			echo "Scanning $HostName --------------------------------------------------------------------------------"
			echo
			echo "Connecting to '$SSHUser@$HostName' on port '$SSHPort' and installing/updating..."
			echo
			echo 'HostName: '$HostName
			echo 'SSHUser: '$SSHUser
			echo 'SSHPort: '$SSHPort
			SUMMARY+="$HostName;$SSHUser;$SSHPort;"

			if ! nc -z $HostName $SSHPort 2>/dev/null; then
				echo "System is not reachable."
				echo
				echo "Scan termination for $HostName ---------------------------------------------------------------------------------"
				SUMMARY+="not reachable;"
				append $SUMMARY
				continue
			else
				SUMMARY+="online;"
			fi

			ssh $SSHUser@$HostName sudo apt upgrade lsb-base lsb-release openscap-scanner openscap-utils -y &>/dev/null
			DistributorID=$(ssh $SSHUser@$HostName sudo lsb_release -is | tr '[:upper:]' '[:lower:]')
			Release=$(ssh $SSHUser@$HostName sudo lsb_release -rs)
			Release=${Release//./""}
			CodeName=$(ssh $SSHUser@$HostName sudo lsb_release -cs | tr '[:upper:]' '[:lower:]')

			echo 'DistributorID: '$DistributorID
			echo 'Release: '$Release
			echo 'CodeName: '$CodeName
			SUMMARY+="$DistributorID;$Release;$CodeName;"

			case $DistributorID in
			("debian")
				OvalURL="https://www.debian.org/security/oval"
				OvalZIP="oval-definitions-$CodeName.xml.bz2"
				OvalFile="oval-definitions-$CodeName.xml"
				OvalDef="oval_org.debian"
				;;
			("ubuntu")
				OvalURL="https://security-metadata.canonical.com/oval"
				OvalZIP="com.ubuntu.$CodeName.usn.oval.xml.bz2"
				OvalFile="com.ubuntu.$CodeName.usn.oval.xml"
				OvalDef="oval_com.ubuntu.$CodeName"
				;;
			*)
				die "Unsupported OS/Distributor."
				;;
			esac

			echo 'OvalURL: '$OvalURL
			echo 'OvalZIP: '$OvalZIP
			echo 'OvalFile: '$OvalFile
			echo 'OvalDef: '$OvalDef

			echo
			echo "Installing/Updating SSG and OVAL content ---------------------------------------------------------------------------------"
			echo

			mkdir -p $OSCAPMonitor/reports/$HostName
			mkdir -p $SCAPinoculars/reports/$HostName

			ssh $SSHUser@$HostName sudo rm /usr/share/openscap/cpe &>/dev/null
			ssh $SSHUser@$HostName sudo mkdir -p /usr/share/openscap/cpe
			ssh $SSHUser@$HostName sudo rm $SSG/content/openscap-cpe-dict.xml &>/dev/null

			scp $SSG/content/ssg-$DistributorID$Release* $SSHUser@$HostName:/tmp
			ssh $SSHUser@$HostName sudo cp /tmp/ssg-$DistributorID$Release-cpe-dictionary.xml /usr/share/openscap/cpe/openscap-cpe-dict.xml 
			ssh $SSHUser@$HostName sudo cp /tmp/ssg-$DistributorID$Release-cpe-oval.xml /usr/share/openscap/cpe/ 
			ssh $SSHUser@$HostName sudo mv /tmp/ssg-$DistributorID$Release* $SSG/content/

			
			if [ "$EVAL" == "xccdf" ]; then
				xccdf_eval
			elif [ "$EVAL" == "oval" ]; then
				oval_eval
			fi
			
			echo
			echo "Scanned $HostName ---------------------------------------------------------------------------------"
			append $SUMMARY
		fi
	done
	echo
	footer "Scan finished: $(date)"
	exit 0
}

if [ $# -lt 1 ]; then
	invalid "No arguments provided."
elif [ "$1" == "-?" ] || [ "$1" == "-h" ] || [ "$1" == "--help" ]; then
	usage
	exit 0
elif [ "$1 $2" == "xccdf eval" ]; then
	EVAL=$1
elif [ "$1 $2" == "oval eval" ]; then
	EVAL=$1
else
	invalid "This script only support 'xccdf eval', 'oval eval'."
fi

shift 2

args=("$@")

INPUT_SYSTEM_LIST=""
TAILORING=false
INPUT_TAILORING_RULES=""
REMEDIATE=false
INPUT_REMEDIATION_RULES=""

for i in $(seq 0 `expr $# - 1`); do
	let j=i+1

	case "${args[i]}" in
	("--tailoring")
		TAILORING=true
		INPUT_TAILORING_RULES=${args[j]}
		;;
	("--remediate")
		REMEDIATE=true
		INPUT_REMEDIATION_RULES=${args[j]}
		;;
	*)
		;;
	esac
done

# Last argument should be the INPUT_SYSTEM_LIST path
INPUT_SYSTEM_LIST="${args[`expr $# - 1`]}"

[ "$INPUT_SYSTEM_LIST" != "" ] || [ -f "$INPUT_SYSTEM_LIST" ] || die "Expected the last argument to be an input file, '$INPUT_SYSTEM_LIST' isn't a valid file path or the file doesn't exist!"

dependencies_check
main
