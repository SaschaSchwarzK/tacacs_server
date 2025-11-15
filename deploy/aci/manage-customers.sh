#!/bin/bash
# manage-customers.sh - Manage existing TACACS instances
# Usage: ./deploy/aci/manage-customers.sh <command> [args...]

set -e

RG="tacacs-rg"

COMMAND=$1
CUSTOMER_ID=$2

if [ -z "$COMMAND" ]; then
    echo "Usage: $0 <command> [customer-id]"
    echo ""
    echo "Commands:"
    echo "  list                      - List all deployed customers"
    echo "  info <customer-id>        - Show customer details"
    echo "  logs <customer-id>        - Tail container logs"
    echo "  restart <customer-id>     - Restart container"
    echo "  delete <customer-id>      - Delete container (keep data)"
    echo "  purge <customer-id>       - Delete container and data"
    echo "  backup-list <customer-id> - List backups"
    exit 1
fi

case "$COMMAND" in
    list)
        echo "Deployed TACACS containers:"
        az container list \
          --resource-group $RG \
          --query "[?starts_with(name, 'tacacs-')].[name,ipAddress.ip,provisioningState]" \
          -o table
        ;;
    info)
        if [ -z "$CUSTOMER_ID" ]; then
            echo "Usage: $0 info <customer-id>"
            exit 1
        fi
        az container show \
          --resource-group $RG \
          --name "tacacs-${CUSTOMER_ID}" \
          -o json
        ;;
    logs)
        if [ -z "$CUSTOMER_ID" ]; then
            echo "Usage: $0 logs <customer-id>"
            exit 1
        fi
        az container logs \
          --resource-group $RG \
          --name "tacacs-${CUSTOMER_ID}" \
          --follow
        ;;
    restart)
        if [ -z "$CUSTOMER_ID" ]; then
            echo "Usage: $0 restart <customer-id>"
            exit 1
        fi
        az container restart \
          --resource-group $RG \
          --name "tacacs-${CUSTOMER_ID}"
        ;;
    delete)
        if [ -z "$CUSTOMER_ID" ]; then
            echo "Usage: $0 delete <customer-id>"
            exit 1
        fi
        az container delete \
          --resource-group $RG \
          --name "tacacs-${CUSTOMER_ID}" \
          --yes
        ;;
    purge)
        if [ -z "$CUSTOMER_ID" ]; then
            echo "Usage: $0 purge <customer-id>"
            exit 1
        fi
        echo "Purging container and data for customer: ${CUSTOMER_ID}"
        az container delete \
          --resource-group $RG \
          --name "tacacs-${CUSTOMER_ID}" \
          --yes
        echo "⚠ Data purge from storage must be handled separately"
        ;;
    backup-list)
        if [ -z "$CUSTOMER_ID" ]; then
            echo "Usage: $0 backup-list <customer-id>"
            exit 1
        fi
        echo "Listing backups for ${CUSTOMER_ID}..."
        echo "(Use az storage blob list / download with your storage account and container)"
        ;;
    *)
        echo "Unknown command: $COMMAND"
        exit 1
        ;;
esac

