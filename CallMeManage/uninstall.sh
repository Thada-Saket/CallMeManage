#!/usr/bin/env bash
# Remove CallMe Manage so it can be installed again from the start:
#
#   sudo ./uninstall.sh
#
# Removes the services, the callmemanage command and the config file (a root-only backup is
# kept in /root). Asks before deleting the database, the Redis password, the built files and
# the call-home key - all kept by default. Same as: sudo ./install.sh --uninstall
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/install.sh" --uninstall "$@"
