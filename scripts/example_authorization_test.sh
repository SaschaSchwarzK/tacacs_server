#!/bin/bash
# Example TACACS+ Authorization Testing Script

echo "=== TACACS+ Authorization Testing Examples ==="
echo

# Set common variables
HOST="localhost"
PORT="49"
SECRET="tacacs123"

echo "1. Testing admin user with high privilege command:"
poetry run python scripts/tacacs_authorization_client.py $HOST $PORT $SECRET admin "configure terminal" shell --privilege-level 15

echo
echo "2. Testing regular user with allowed command:"
poetry run python scripts/tacacs_authorization_client.py $HOST $PORT $SECRET user "show version" shell --privilege-level 1

echo
echo "3. Testing regular user with denied command:"
poetry run python scripts/tacacs_authorization_client.py $HOST $PORT $SECRET user "configure terminal" shell --privilege-level 1

echo
echo "4. Testing exec service authorization:"
poetry run python scripts/tacacs_authorization_client.py $HOST $PORT $SECRET admin "" exec --privilege-level 15

echo
echo "=== Authorization Testing Complete ==="