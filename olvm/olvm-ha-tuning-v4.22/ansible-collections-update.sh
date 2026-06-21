#!/bin/bash

# Ansible community collection update script
# Reads the currently installed collections from their .info directories and
# upgrades each one to the latest version.

set -e  # Stop on error. If you prefer to continue per-collection, use 'set +e'.

COLLECTION_BASE="$HOME/.ansible/collections/ansible_collections"

if [ ! -d "$COLLECTION_BASE" ]; then
    echo "Error: directory $COLLECTION_BASE not found!"
    exit 1
fi

echo "Updating Ansible Community Collections..."
echo "Directory: $COLLECTION_BASE"
echo "----------------------------------------"

for info_dir in "$COLLECTION_BASE"/*.info; do
    # Only process directories (the real .info directories)
    [ -d "$info_dir" ] || continue

    dir_name=$(basename "$info_dir")
    # Extract the collection name: strip the version number and .info suffix
    # Example: community.aws-11.0.0.info -> community.aws
    collection=$(echo "$dir_name" | sed -E 's/-[0-9]+(\.[0-9]+)*\.info$//')

    echo "Updating: $collection"
    if ansible-galaxy collection install "$collection" --upgrade; then
        echo "OK: $collection updated successfully."
    else
        echo "FAILED: error while updating $collection. Continuing..."
    fi
    echo "----------------------------------------"
done

echo "Done."
