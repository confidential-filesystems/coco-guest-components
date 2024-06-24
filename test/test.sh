#!/bin/bash

CurrDir=$(cd "$(dirname "$0")"; pwd)

cd /usr/local/bin/

./confidential-data-hub &

sleep 3

./api-server-rest --bind=127.0.0.1:8006 --features=all &

sleep 3

#
export FS_NAME=fs1

export ACCOUNT_ADDR=0xac0618f0b105faf17b8e1370f98febdb2e1ffc5b


# get secret resource
curl -X GET \
	-w "%{http_code}\n" \
	--data '{"controller_crp_token":"", "controller_attestation_report":"", "controller_cert_chain":"", "aa_attester":"controller", "extra_request":"extra-request-get_secret_resource"}' \
	http://127.0.0.1:8006/cdh/resource_extra/${ACCOUNT_ADDR}/ecsk/123

# set secret resource
curl -X POST \
	-w "%{http_code}\n" \
	--data '{"controller_crp_token":"", "controller_attestation_report":"", "controller_cert_chain":"", "aa_attester":"controller", "extra_request":"extra-request-set_secret_resource"}' \
	http://127.0.0.1:8006/cdh/resource_extra/${ACCOUNT_ADDR}/seeds/seeds

# get token
curl -X GET \
	-w "%{http_code}\n" \
	--data '{"controller_crp_token":"", "controller_attestation_report":"", "controller_cert_chain":"", "aa_attester":"controller", "extra_request":"extra-request-get_token"}' \
	http://127.0.0.1:8006/aa/token_extra?token_type=kbs

# get evidence
curl -X GET \
	-w "%{http_code}\n" \
	--data '{"controller_crp_token":"", "controller_attestation_report":"", "controller_cert_chain":"", "aa_attester":"controller", "extra_request":"extra-request-get_evidence"}' \
	http://127.0.0.1:8006/aa/evidence_extra?runtime_data=123456

# get filesystems
curl -X GET \
	-w "%{http_code}\n" \
	--data '{"controller_crp_token":"", "controller_attestation_report":"", "controller_cert_chain":"", "aa_attester":"controller", "extra_request":"extra-request-get_filesystems"}' \
	http://127.0.0.1:8006/cdh/resource_extra/ownership/filesystems/${FS_NAME}

# get accounts metatx
curl -X GET \
	-w "%{http_code}\n" \
	--data '{"controller_crp_token":"", "controller_attestation_report":"", "controller_cert_chain":"", "aa_attester":"controller", "extra_request":"extra-request-get_accounts_metatx"}' \
	http://127.0.0.1:8006/cdh/resource_extra/ownership/accounts_metatx/${ACCOUNT_ADDR}

# get configure .well-known
curl -X GET \
	-w "%{http_code}\n" \
	--data '{"controller_crp_token":"", "controller_attestation_report":"", "controller_cert_chain":"", "aa_attester":"controller", "extra_request":"extra-request-get_configure_.well-known"}' \
	http://127.0.0.1:8006/cdh/resource_extra/ownership/configure/.well-known

# mint filesystems
curl -H "Content-Type:application/json" \
  -X POST \
	-w "%{http_code}\n" \
	--data '{"meta_tx_request":{"from":"err","to":"err","value":"err","gas":"err","nonce":"err","deadline":100,"data":"err"},"meta_tx_signature":"err"}' \
	http://127.0.0.1:8006/cdh/resource_extra/ownership/filesystems/${FS_NAME}

# burn filesystems
curl -H "Content-Type:application/json" \
  -X DELETE \
	-w "%{http_code}\n" \
	--data '{"meta_tx_request":{"from":"err","to":"err","value":"err","gas":"err","nonce":"err","deadline":100,"data":"err"},"meta_tx_signature":"err"}' \
	http://127.0.0.1:8006/cdh/resource_extra/ownership/filesystems/${FS_NAME}


#end.
