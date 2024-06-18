#!/bin/bash

CurrDir=$(cd "$(dirname "$0")"; pwd)

cd /usr/local/bin/

./confidential-data-hub &

sleep 3

./api-server-rest --bind=127.0.0.1:8006 --features=all &

sleep 3

# get secret resource
curl -X GET \
	-w "%{http_code}\n" \
	--data '{"controller_crp_token":"", "controller_attestation_report":"", "controller_cert_chain":"", "aa_attester":"controller", "container_name":""}' \
	http://127.0.0.1:8006/cdh/resource_extra/0xac0618f0b105faf17b8e1370f98febdb2e1ffc5b/ecsk/123

# set secret resource
curl -X POST \
	-w "%{http_code}\n" \
	--data '{"controller_crp_token":"", "controller_attestation_report":"", "controller_cert_chain":"", "aa_attester":"controller", "container_name":""}' \
	http://127.0.0.1:8006/cdh/resource_extra/0xac0618f0b105faf17b8e1370f98febdb2e1ffc5b/seeds/seeds

# get token
curl -X GET \
	-w "%{http_code}\n" \
	--data '{"controller_crp_token":"", "controller_attestation_report":"", "controller_cert_chain":"", "aa_attester":"controller", "container_name":""}' \
	http://127.0.0.1:8006/aa/token_extra?token_type=kbs

# get evidence
curl -X GET \
	-w "%{http_code}\n" \
	--data '{"controller_crp_token":"", "controller_attestation_report":"", "controller_cert_chain":"", "aa_attester":"controller", "container_name":""}' \
	http://127.0.0.1:8006/aa/evidence_extra?runtime_data=123456

# get filesystems
curl -X GET \
	-w "%{http_code}\n" \
	--data '{"controller_crp_token":"", "controller_attestation_report":"", "controller_cert_chain":"", "aa_attester":"controller", "container_name":""}' \
	http://127.0.0.1:8006/cdh/resource_extra/ownership/filesystems/fs1

# get accounts metatx
curl -X GET \
	-w "%{http_code}\n" \
	--data '{"controller_crp_token":"", "controller_attestation_report":"", "controller_cert_chain":"", "aa_attester":"controller", "container_name":""}' \
	http://127.0.0.1:8006/cdh/resource_extra/ownership/accounts-metatx/0xac0618f0b105faf17b8e1370f98febdb2e1ffc5b

# get configure .well-known
curl -X GET \
	-w "%{http_code}\n" \
	--data '{"controller_crp_token":"", "controller_attestation_report":"", "controller_cert_chain":"", "aa_attester":"controller", "container_name":""}' \
	http://127.0.0.1:8006/cdh/resource_extra/ownership/configure/.well-known

# mint filesystems
curl -H "Content-Type:application/json" \
  -X POST \
	-w "%{http_code}\n" \
	--data '{"metaTxRequest":{"from":"err","to":"err","value":"err","gas":"err","nonce":"err","deadline":100,"data":"err"},"metaTxSignature":"err"}' \
	http://127.0.0.1:8006/cdh/resource_extra/ownership/filesystems/mint

# burn filesystems
curl -H "Content-Type:application/json" \
  -X POST \
	-w "%{http_code}\n" \
	--data '{"metaTxRequest":{"from":"err","to":"err","value":"err","gas":"err","nonce":"err","deadline":100,"data":"err"},"metaTxSignature":"err"}' \
	http://127.0.0.1:8006/cdh/resource_extra/ownership/filesystems/burn


#end.
