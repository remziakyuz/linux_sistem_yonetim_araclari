#!/bin/bash

OLVM_URL="https://olvmm.lab.akyuz.tech/ovirt-engine/api"
USER="remzi@internal"
PASS="remzi12345678"

OUTFILE="/tmp/olvm_api_dump_$(date +%Y%m%d_%H%M%S).txt"

ENDPOINTS=(
""
"datacenters"
"clusters"
"hosts"
"vms"
"storagedomains"
"networks"
"templates"
"disks"
"users"
"groups"
"roles"
"permissions"
"events"
"jobs"
"tags"
"vm_pools"
"affinitygroups"
"affinitylabels"
"macpools"
"bookmarks"
"icon"
"openstacknetworkproviders"
"openstackvolumetypes"
"operatingsystems"
"schedulingpolicies"
"storageconnections"
"storageconnectionsdiscover"
"providers"
"quotas"
)

echo "OLVM API FULL DUMP" > "$OUTFILE"
echo "Generated: $(date)" >> "$OUTFILE"
echo >> "$OUTFILE"

for EP in "${ENDPOINTS[@]}"
do
    URL="${OLVM_URL}/${EP}"
    URL=$(echo "$URL" | sed 's#//$#/#')

    CMD="curl -k -u '${USER}:********' '${URL}'"

    {
        echo "================================================================="
        echo "COMMAND:"
        echo "$CMD"
        echo
        echo "OUTPUT:"
        echo
    } >> "$OUTFILE"

    curl -s -k \
        -u "${USER}:${PASS}" \
        -H "Accept: application/xml" \
        "$URL" >> "$OUTFILE" 2>&1

    {
        echo
        echo
    } >> "$OUTFILE"

done

echo "Rapor oluşturuldu:"
echo "$OUTFILE"
