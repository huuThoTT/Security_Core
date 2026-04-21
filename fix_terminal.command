#!/bin/bash
cd "$(dirname "$0")"
# Clear system quarantine for the whole folder
sudo xattr -rd com.apple.quarantine .
# Set execution bit properly
chmod +x SEC-Wallet-App.command
# Update launch logic
echo "------------------------------------------------"
echo "Fixing permissions complete."
echo "------------------------------------------------"
