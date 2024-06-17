#!/bin/bash

CurrDir=$(cd "$(dirname "$0")"; pwd)

cd /usr/local/bin/

./confidential-data-hub &

sleep 3

./api-server-rest --bind=127.0.0.1:8006 --features=all &

sleep 3

curl -X GET \
	-w "%{http_code}\n" \
	--data '{"controller_crp_token":"", "controller_attestation_report":"", "controller_cert_chain":"", "aa_attester":"controller", "container_name":""}' \
	http://127.0.0.1:8006/cdh/resource/0xac0618f0b105faf17b8e1370f98febdb2e1ffc5b/ecsk/123


curl -X GET \
	-w "%{http_code}\n" \
	--data '{"controller_crp_token":"", "controller_attestation_report":"", "controller_cert_chain":"", "aa_attester":"controller", "container_name":""}' \
	http://127.0.0.1:8006/cdh/resource_extra/0xac0618f0b105faf17b8e1370f98febdb2e1ffc5b/ecsk/123


curl -X POST \
	-w "%{http_code}\n" \
	--data '{"controller_crp_token":"", "controller_attestation_report":"", "controller_cert_chain":"", "aa_attester":"controller", "container_name":""}' \
	http://127.0.0.1:8006/cdh/resource_extra/0xac0618f0b105faf17b8e1370f98febdb2e1ffc5b/seeds/seeds


curl -X GET \
	-w "%{http_code}\n" \
	--data '{"controller_crp_token":"", "controller_attestation_report":"", "controller_cert_chain":"", "aa_attester":"controller", "container_name":""}' \
	http://127.0.0.1:8006/aa/token_extra?token_type=kbs


curl -X GET \
	-w "%{http_code}\n" \
	--data '{"controller_crp_token":"", "controller_attestation_report":"", "controller_cert_chain":"", "aa_attester":"controller", "container_name":""}' \
	http://127.0.0.1:8006/aa/evidence_extra?runtime_data=123456




#end.
