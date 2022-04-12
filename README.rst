LogStream for F5 Distributed Cloud | Security Events
####################################################

.. figure:: _picture/architecture.png

.. contents:: Table of Contents

Introduction
==================================================
Use Case
**************************************************

LogStream forwards http security event logs - received from `F5 XC <https://docs.cloud.f5.com/docs/api/app-security>`_ - to remote servers (log collector, SIEM).

Supported downstream protocol:

- Syslog
- HTTP(s) + Bearer token

Demo
**************************************************

.. raw:: html

    <a href="http://www.youtube.com/watch?v=X9ewljh9lSc"><img src="http://img.youtube.com/vi/X9ewljh9lSc/0.jpg" width="800" height="600" title="Logstream for F5 XC" alt="Logstream for F5 XC"></a>

Security consideration
**************************************************
No logs are stored. LogStream receives logs and then PUSH them directly to remote log collector servers.

API reference
=================================================
API Dev Portal is available on your LogStream instance via ``/apidocs/``

API reference can be downloaded `here <https://github.com/nergalex/f5-xc-logstream/blob/master/swagger.json>`_

A Postman collection is available `here <https://github.com/nergalex/f5-xc-logstream/blob/master/LogStream-F5_XC.postman_collection.json>`_

Example of Declaration
**************************************************
Specification of LogStream are stored as a declaration in JSON format.
Reference schema is available in the description of ``/declare`` API endpoint.

Example of a declaration:

.. code:: json

    {
        "f5xc_tenant": {
            "api_key": "XXXXXXXXXXXXX",
            "name": "f5-emea-ent",
            "namespaces": [
                {
                    "event_filter": {
                        "sec_event_type": "waf_sec_event"
                    },
                    "name": "al-dacosta",
                    "event_start_time": {
                        "year": 2022,
                        "month": 4,
                        "day": 10,
                        "hour": 20,
                        "minute": 0
                    }
                }
            ]
        },
        "logcollector": {
            "http": [
                {
                    "host": "52.177.94.15",
                    "port": 8888,
                    "path": "/debug.test"
                }
            ],
            "syslog": [
                {
                    "ip_address": "52.177.94.15",
                    "port": 5140
                }
            ]
        }
    }

Log format
==================================================

INPUT - F5 XC
***************************

.. code:: json

    {
      "app_type": "cloudbuilder",
      "signatures": [
        {
          "attack_type": "ATTACK_TYPE_CROSS_SITE_SCRIPTING",
          "matching_info": "Matched 7 characters on offset 7 against value: '/c/?a=<script>cat /etc/password</script>'. ",
          "context": "header (path)",
          "name": "XSS script tag end (Headers)",
          "accuracy": "high_accuracy",
          "id": "200000091",
          "state": "Enabled",
          "id_name": "200000091, XSS script tag end (Headers)"
        },
        {
          "attack_type": "ATTACK_TYPE_CROSS_SITE_SCRIPTING",
          "matching_info": "Matched 7 characters on offset 6 against value: '/c/?a=<script>cat /etc/password</script>'. ",
          "context": "header (path)",
          "name": "XSS script tag (Headers)",
          "accuracy": "high_accuracy",
          "id": "200000097",
          "state": "Enabled",
          "id_name": "200000097, XSS script tag (Headers)"
        },
        {
          "attack_type": "ATTACK_TYPE_CROSS_SITE_SCRIPTING",
          "matching_info": "Matched 7 characters on offset 2 against value: 'a=<script>cat /etc/password</script>'. ",
          "context": "parameter (a)",
          "name": "XSS script tag (Parameter)",
          "accuracy": "high_accuracy",
          "id": "200000098",
          "state": "Enabled",
          "id_name": "200000098, XSS script tag (Parameter)"
        },
        {
          "attack_type": "ATTACK_TYPE_CROSS_SITE_SCRIPTING",
          "matching_info": "Matched 7 characters on offset 3 against value: 'a=<script>cat /etc/password</script>'. ",
          "context": "parameter (a)",
          "name": "XSS script tag end (Parameter) (2)",
          "accuracy": "high_accuracy",
          "id": "200001475",
          "state": "Enabled",
          "id_name": "200001475, XSS script tag end (Parameter) (2)"
        }
      ],
      "req_id": "7d2d785c-0f32-4f4d-8bf1-c2a1032227ed",
      "hostname": "master-13",
      "bot_verification_failed": false,
      "original_authority": "",
      "rtt_upstream_seconds": "",
      "src_instance": "FR",
      "req_headers": "{\"Accept\":\"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\",\"Accept-Encoding\":\"gzip, deflate, br\",\"Accept-Language\":\"en-US,en;q=0.9,fr;q=0.8\",\"Cache-Control\":\"max-age=0\",\"Cookie\":\"1d625=1649083663121-224247291; _imp_apg_r_=%7B%22diA%22%3A%22AciXP2IAAAAAgyqEB%2BOQg7HcJ9AtrCIU%22%2C%22diB%22%3A%22AdLY9pzeIosqLRJ7XWTN8I8rcD5GcoYO%22%7D; _imp_di_pc_=AciXP2IAAAAAgyqEB%2BOQg7HcJ9AtrCIU; 1d6203=4Q6H4PTMi9x7pRoC4tvaF7kZmANgGjGLk9xFninLl+IlFGsyvlnCNXxuJRHwT/Z4B67Fs3AOzSdTuYGjgdUEbBFSMgioG0ihuMqwdSa/mwcC0KNiwRBQgGvEPc0JFL2tglq2mOj+yRVnVZAIkJL4k7hiIU/BnUhKRdaqIN6i/QCJiWND; TS01120553=01795b7bc030829070ed3521d4fbcd0e6d8c9d951fb851bdefdc7efeb0a5695e916088d988f80e321180b744b96e5a5269e76667c5; TS01120553028=01d8db7103af00b2ca08ea64cf2be04fe54b5267b7ac39dbed20a7d2bf5ee1d29c2c300163ce3ba71d1519cf502c69e8fd8b727c88; TS01dc4fc6=01371e37ded1361e15dc34629806271234fdca4b53165b822945af4df88a06de5a431140d6e65a8ee28d1d553966c2ac4473e530dd; 1d621=3c457337a368d5a5bcc0991ac95a444900003d5a3029dab13d60\",\"Host\":\"sentence-front-managed1.f5dc.dev\",\"Method\":\"GET\",\"Path\":\"/c/?a=%3Cscript%3Ecat%20/etc/password%3C/script%3E\",\"Scheme\":\"https\",\"Sec-Ch-Ua\":\"\\\" Not A;Brand\\\";v=\\\"99\\\", \\\"Chromium\\\";v=\\\"100\\\", \\\"Google Chrome\\\";v=\\\"100\\\"\",\"Sec-Ch-Ua-Mobile\":\"?0\",\"Sec-Ch-Ua-Platform\":\"\\\"Windows\\\"\",\"Sec-Fetch-Dest\":\"document\",\"Sec-Fetch-Mode\":\"navigate\",\"Sec-Fetch-Site\":\"none\",\"Sec-Fetch-User\":\"?1\",\"Upgrade-Insecure-Requests\":\"1\",\"User-Agent\":\"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.60 Safari/537.36\",\"X-Envoy-External-Address\":\"82.66.123.186\",\"X-Forwarded-For\":\"82.66.123.186\",\"X-Forwarded-Proto\":\"https\",\"X-Request-Id\":\"7d2d785c-0f32-4f4d-8bf1-c2a1032227ed\"}",
      "tenant": "f5-emea-ent-bceuutam",
      "app": "obelix",
      "policy_hits": {
        "policy_hits": {}
      },
      "method": "GET",
      "threat_campaigns": {},
      "violations": {},
      "source_type": "kafka",
      "dst_instance": "",
      "x_forwarded_for": "82.66.123.186",
      "duration_with_no_data_tx_delay": "",
      "waf_rule_tags": "{}",
      "rsp_code_class": "2xx",
      "waf_mode": "block",
      "time_to_last_upstream_rx_byte": 0,
      "scheme": "",
      "city": "",
      "dst_site": "",
      "latitude": "48.858200",
      "messageid": "c102667e-dea5-4551-b495-71bf4217a9f6",
      "no_active_detections": false,
      "tls_version": "",
      "duration_with_data_tx_delay": "",
      "stream": "svcfw",
      "violation_rating": "5",
      "req_size": "1640",
      "waf_rules_hit": "[]",
      "tls_fingerprint": "6351a79c0fa176d8764f5712c1f02895",
      "time_to_first_upstream_rx_byte": 0,
      "sni": "sentence-front-managed1.f5dc.dev",
      "response_flags": "",
      "site": "pa4-par",
      "@timestamp": "2022-04-10T21:14:25.855Z",
      "calculated_action": "block",
      "req_params": "a=%3Cscript%3Ecat%20/etc/password%3C/script%3E",
      "sample_rate": "",
      "original_headers": [
        "method",
        "host",
        "scheme",
        "path",
        "cache-control",
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
        "upgrade-insecure-requests",
        "user-agent",
        "accept",
        "sec-fetch-site",
        "sec-fetch-mode",
        "sec-fetch-user",
        "sec-fetch-dest",
        "accept-encoding",
        "accept-language",
        "cookie",
        "x-forwarded-for",
        "x-forwarded-proto",
        "x-envoy-external-address",
        "x-request-id"
      ],
      "dst_port": "0",
      "req_path": "/c/",
      "asn": "Free SAS(12322)",
      "node_id": "",
      "proxy_type": "",
      "is_truncated_field": false,
      "country": "FR",
      "kubernetes": {},
      "browser_type": "Chrome",
      "device_type": "Other",
      "bot_classification": "",
      "vhost_id": "017d647f-b87d-4eac-99e5-98c7cfa91d62",
      "detections": {},
      "longitude": "2.338700",
      "rtt_downstream_seconds": "",
      "http_version": "HTTP/1.1",
      "time_to_last_downstream_tx_byte": 0,
      "waf_rule_hit_count": "",
      "num_rules_hit": "",
      "vh_type": "",
      "rsp_size": "0",
      "api_endpoint": "{}",
      "authority": "sentence-front-managed1.f5dc.dev",
      "region": "",
      "time_to_first_downstream_tx_byte": 0,
      "rsp_code_details": "",
      "dst": "",
      "connection_state": "",
      "dst_ip": "72.19.3.187",
      "is_new_dcid": false,
      "network": "82.66.122.0",
      "src_site": "pa4-par",
      "src_ip": "82.66.123.186",
      "tls_cipher_suite": "",
      "original_path": "",
      "message_key": null,
      "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.60 Safari/537.36",
      "severity": "info",
      "cluster_name": "pa4-par-int-ves-io",
      "headers": {},
      "types": "input:string",
      "src": "N:public",
      "rsp_code": "200",
      "time_to_first_upstream_tx_byte": 0,
      "attack_types": [
        {
          "name": "ATTACK_TYPE_CROSS_SITE_SCRIPTING"
        }
      ],
      "src_port": "58950",
      "dcid": "1649083663121-224247291",
      "req_body": "",
      "time_to_last_upstream_tx_byte": 0,
      "namespace": "al-dacosta",
      "time": "2022-04-10T21:14:25.855Z",
      "waf_instance_id": "",
      "sec_event_type": "waf_sec_event",
      "user": "Cookie-_imp_di_pc_-AciXP2IAAAAAgyqEB%2BOQg7HcJ9AtrCIU",
      "vh_name": "ves-io-http-loadbalancer-sentence-front-managed1"
    }

OUTPUT - HTTP
***************************

.. code:: json

    {
        "app": "sentence-front-managed1.f5dc.dev",
        "bot_classification": "",
        "bot_verification_failed": false,
        "browser_type": "Chrome",
        "attack_types":
        [
            {
                "name": "ATTACK_TYPE_CROSS_SITE_SCRIPTING"
            }
        ],
        "component": "/c/",
        "correlation_id": "c102667e-dea5-4551-b495-71bf4217a9f6",
        "description": "ves-io-http-loadbalancer-sentence-front-managed1",
        "environment": "f5-emea-ent-bceuutam",
        "gateway": "pa4-par",
        "http.hostname": "sentence-front-managed1.f5dc.dev",
        "http.remote_addr": "82.66.123.186",
        "http.remote_port": "58950",
        "http.request_method": "GET",
        "http.response_code": "200",
        "http.server_addr": "72.19.3.187",
        "http.server_port": "0",
        "http.uri": "/c/?a=%3Cscript%3Ecat%20/etc/password%3C/script%3E",
        "is_truncated": false,
        "level": "info",
        "policy_name": "NotAvailable",
        "request_headers":
        {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-US,en;q=0.9,fr;q=0.8",
            "Cache-Control": "max-age=0",
            "Cookie": "1d625=1649083663121-224247291; _imp_apg_r_=%7B%22diA%22%3A%22AciXP2IAAAAAgyqEB%2BOQg7HcJ9AtrCIU%22%2C%22diB%22%3A%22AdLY9pzeIosqLRJ7XWTN8I8rcD5GcoYO%22%7D; _imp_di_pc_=AciXP2IAAAAAgyqEB%2BOQg7HcJ9AtrCIU; 1d6203=4Q6H4PTMi9x7pRoC4tvaF7kZmANgGjGLk9xFninLl+IlFGsyvlnCNXxuJRHwT/Z4B67Fs3AOzSdTuYGjgdUEbBFSMgioG0ihuMqwdSa/mwcC0KNiwRBQgGvEPc0JFL2tglq2mOj+yRVnVZAIkJL4k7hiIU/BnUhKRdaqIN6i/QCJiWND; TS01120553=01795b7bc030829070ed3521d4fbcd0e6d8c9d951fb851bdefdc7efeb0a5695e916088d988f80e321180b744b96e5a5269e76667c5; TS01120553028=01d8db7103af00b2ca08ea64cf2be04fe54b5267b7ac39dbed20a7d2bf5ee1d29c2c300163ce3ba71d1519cf502c69e8fd8b727c88; TS01dc4fc6=01371e37ded1361e15dc34629806271234fdca4b53165b822945af4df88a06de5a431140d6e65a8ee28d1d553966c2ac4473e530dd; 1d621=3c457337a368d5a5bcc0991ac95a444900003d5a3029dab13d60",
            "Host": "sentence-front-managed1.f5dc.dev",
            "Method": "GET",
            "Path": "/c/?a=%3Cscript%3Ecat%20/etc/password%3C/script%3E",
            "Scheme": "https",
            "Sec-Ch-Ua": "\" Not A;Brand\";v=\"99\", \"Chromium\";v=\"100\", \"Google Chrome\";v=\"100\"",
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": "\"Windows\"",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.60 Safari/537.36",
            "X-Envoy-External-Address": "82.66.123.186",
            "X-Forwarded-For": "82.66.123.186",
            "X-Forwarded-Proto": "https",
            "X-Request-Id": "7d2d785c-0f32-4f4d-8bf1-c2a1032227ed"
        },
        "request_outcome": "block",
        "request_outcome_reason": "NotAvailable",
        "signatures":
        [
            {
                "attack_type": "ATTACK_TYPE_CROSS_SITE_SCRIPTING",
                "matching_info": "Matched 7 characters on offset 7 against value: '/c/?a=<script>cat /etc/password</script>'. ",
                "context": "header (path)",
                "name": "XSS script tag end (Headers)",
                "accuracy": "high_accuracy",
                "id": "200000091",
                "state": "Enabled",
                "id_name": "200000091, XSS script tag end (Headers)"
            },
            {
                "attack_type": "ATTACK_TYPE_CROSS_SITE_SCRIPTING",
                "matching_info": "Matched 7 characters on offset 6 against value: '/c/?a=<script>cat /etc/password</script>'. ",
                "context": "header (path)",
                "name": "XSS script tag (Headers)",
                "accuracy": "high_accuracy",
                "id": "200000097",
                "state": "Enabled",
                "id_name": "200000097, XSS script tag (Headers)"
            },
            {
                "attack_type": "ATTACK_TYPE_CROSS_SITE_SCRIPTING",
                "matching_info": "Matched 7 characters on offset 2 against value: 'a=<script>cat /etc/password</script>'. ",
                "context": "parameter (a)",
                "name": "XSS script tag (Parameter)",
                "accuracy": "high_accuracy",
                "id": "200000098",
                "state": "Enabled",
                "id_name": "200000098, XSS script tag (Parameter)"
            },
            {
                "attack_type": "ATTACK_TYPE_CROSS_SITE_SCRIPTING",
                "matching_info": "Matched 7 characters on offset 3 against value: 'a=<script>cat /etc/password</script>'. ",
                "context": "parameter (a)",
                "name": "XSS script tag end (Parameter) (2)",
                "accuracy": "high_accuracy",
                "id": "200001475",
                "state": "Enabled",
                "id_name": "200001475, XSS script tag end (Parameter) (2)"
            }
        ],
        "signature_ids":
        [
            "200000091",
            "200000097",
            "200000098",
            "200001475"
        ],
        "signature_names":
        [
            "200000091, XSS script tag end (Headers)",
            "200000097, XSS script tag (Headers)",
            "200000098, XSS script tag (Parameter)",
            "200001475, XSS script tag end (Parameter) (2)"
        ],
        "sub_violations": "NotAvailable",
        "support_id": "7d2d785c-0f32-4f4d-8bf1-c2a1032227ed",
        "type": "waf_sec_event",
        "version": "HTTP/1.1",
        "violation_rating": "5",
        "violations": {},
        "x_forwarded_for_header_value": "82.66.123.186",
        "event_host": "master-13",
        "event_source": "pa4-par",
        "event_sourcetype": "kafka",
        "event_time": "2022-04-10T21:14:25.855Z"
    }

OUTPUT - Syslog
***************************

:kbd:`2022-04-10 23:17:10.000000000 +0000 debug.logstream.user.warn: {"host":"logstream","ident":"logger","message":"app=sentence-front-managed1.f5dc.dev;bot_classification=;bot_verification_failed=False;browser_type=Chrome;attack_types=[{'name': 'ATTACK_TYPE_CROSS_SITE_SCRIPTING'}];component=/c/;correlation_id=c102667e-dea5-4551-b495-71bf4217a9f6;description=ves-io-http-loadbalancer-sentence-front-managed1;environment=f5-emea-ent-bceuutam;gateway=pa4-par;http.hostname=sentence-front-managed1.f5dc.dev;http.remote_addr=82.66.123.186;http.remote_port=58950;http.request_method=GET;http.response_code=200;http.server_addr=72.19.3.187;http.server_port=0;http.uri=/c/?a=%3Cscript%3Ecat%20/etc/password%3C/script%3E;is_truncated=False;level=info;policy_name=NotAvailable;request=NotAvailable;request_outcome=block;request_outcome_reason=NotAvailable;signature_cves=NotAvailable;signature_ids=['200000091', '200000097', '200000098', '200001475'];signature_names=['200000091, XSS script tag end (Headers)', '200000097, XSS script tag (Headers)', '200000098, XSS script tag (Parameter)', '200001475, XSS script tag end (Parameter) (2)'];sub_violations=NotAvailable;support_id=7d2d785c-0f32-4f4d-8bf1-c2a1032227ed;type=waf_sec_event;version=HTTP/1.1;violation_rating=NotAvailable;violations={};x_forwarded_for_header_value=82.66.123.186;event_host=master-13;event_source=pa4-par;event_sourcetype=kafka;event_time=2022-04-10T21:14:25.855Z"}`

Configure
=================================================
Different ways to configure Logstream.

Regional Edge
********************

- ``Distributed Apps`` > ``Virtual K8S`` > ``myVirtualCluster``

Modify ``declaration.json`` in ``workload``:

- ``workloads`` > ``logstream-xc`` > ``...`` > ``Manage configuration`` > ``Edit Configuration``
- ``Type of Workload`` > ``Service``  > ``Edit configuration``
- ``Configuration Parameters`` > ``declaration.json`` > ``...``  > ``Edit``
- ``File`` > ``Edit configuration``
- ``Data``: modify in ASCII view or in JSON view
- ``Apply`` for each opened screens
- ``Save and Exit`` for each opened screens

Start a new ``POD``:

- ``PODs`` > ``logstream-xc`` > ``...`` > ``Delete``

Local declaration file
********************
Define an environment variable:
- key: ``declaration_file_path``
- value: absolute path to a declaration file or a relative path in wsgi folder

By default, if a *declaration* environment variable ``declaration_file_path`` is absent,
LogStream will start using ``declaration.json`` present in local folder.

Local log file
********************
Define an environment variable:
- key: ``log_file_path``
- value: absolute path to a log file or a relative path in wsgi folder

By default, if a *declaration* environment variable ``log_file_path`` is absent,
LogStream will start using ``logstream.log`` present in local folder.

API
***************
If *declaration* file is absent, LogStream will NOT start its engine.
Use LogStream API to configure it and then to start its engine.

API allows you to:
- `declare` endpoint to configure entirely LogStream. Refer to API Dev Portal for parameter and allowed values.
- `action` endpoint to start/stop the engine.
- `declare` anytime you need to reconfigure LogStream and launch `restart` `action` to apply the new configuration.
- Note that the last `declaration` is saved locally

Deployment on a VM
==================================================
An example of a deployment on an Azure VM using Ansible Tower.

Virtualenv
***************************
- Create a virtualenv following `this guide <https://docs.ansible.com/ansible-tower/latest/html/upgrade-migration-guide/virtualenv.html>`_
- In virtualenv, as a prerequisite for Azure collection, install Azure SDK following `this guide <https://github.com/ansible-collections/azure>`_

Credential
***************************
- Create a Service Principal on Azure following `this guide <https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app>`_
- Create a Microsoft Azure Resource Manager following `this guide <https://docs.ansible.com/ansible-tower/latest/html/userguide/credentials.html#microsoft-azure-resource-manager>`_
- Create Credentials ``cred_NGINX`` to manage access to NGINX instances following `this guide <https://docs.ansible.com/ansible-tower/latest/html/userguide/credentials.html#machine>`_

=====================================================   =============================================   =============================================   =============================================   =============================================
REDENTIAL TYPE                                          USERNAME                                        SSH PRIVATE KEY                                 SIGNED SSH CERTIFICATE                          PRIVILEGE ESCALATION METHOD
=====================================================   =============================================   =============================================   =============================================   =============================================
``Machine``                                             ``my_VM_admin_user``                            ``my_VM_admin_user_key``                        ``my_VM_admin_user_CRT``                        ``sudo``
=====================================================   =============================================   =============================================   =============================================   =============================================

Ansible role structure
***************************
- Deployment is based on ``workflow template``. Example: ``workflow template`` = ``wf-create_create_edge_security_inbound``
- ``workflow template`` includes multiple ``job template``. Example: ``job template`` = ``poc-azure_create_hub_edge_security_inbound``
- ``job template`` have an associated ``playbook``. Example: ``playbook`` = ``playbooks/poc-azure.yaml``
- ``playbook`` launch a ``play`` in a ``role``. Example: ``role`` = ``poc-azure``

.. code:: yaml

    - hosts: localhost
      gather_facts: no
      roles:
        - role: poc-azure

- ``play`` is an ``extra variable`` named ``activity`` and set in each ``job template``. Example: ``create_hub_edge_security_inbound``
- The specified ``play`` (or ``activity``) is launched by the ``main.yaml`` task located in the role ``tasks/main.yaml``

.. code:: yaml

    - name: Run specified activity
      include_tasks: "{{ activity }}.yaml"
      when: activity is defined

- The specified ``play`` contains ``tasks`` to execute. Example: play=``create_hub_edge_security_inbound.yaml``

Ansible workflow
***************************
Create and launch a workflow template ``wf-create_create_vm_app_nginx_unit_logstream`` that includes those Job templates in this order:

=============================================================   =============================================       =============================================   =============================================   =============================================   =============================================   =============================================
Job template                                                    objective                                           playbook                                        activity                                        inventory                                       limit                                           credential
=============================================================   =============================================       =============================================   =============================================   =============================================   =============================================   =============================================
``poc-azure_create-vm-nginx_unit``                              Deploy a VM                                         ``playbooks/poc-azure.yaml``                    ``create-vm-nginx_unit``                        ``my_project``                                  ``localhost``                                   ``my_azure_credential``
``poc-onboarding_nginx_unit_faas_app_logstream``                Install NGINX Unit + App                            ``playbooks/poc-nginx_vm.yaml``                 ``onboarding_nginx_unit_faas_app_logstream``    ``localhost``                                                                                   ``cred_NGINX``
=============================================================   =============================================       =============================================   =============================================   =============================================   =============================================   =============================================

==============================================  =============================================
Extra variable                                  Description
==============================================  =============================================
``extra_vm``                                    Dict of VM properties
``extra_vm.ip``                                 VM IP address
``extra_vm.name``                               VM name
``extra_vm.size``                               Azure VM type
``extra_vm.availability_zone``                  Azure AZ
``extra_vm.location``                           Azure location
``extra_vm.admin_username``                     admin username
``extra_vm.key_data``                           admin user's public key
``extra_platform_name``                         platform name used for Azure resource group
``extra_platform_tags``                         Azure VM tags
``extra_subnet_mgt_on_premise``                 Cross management zone
``faas_app``                                    Dict of Function as a Service
``faas_app.name``                               App's name
``faas_app.repo``                               Logstream repo
``faas_app.ca_pem``                             Intermediate CA that signed App's keys
``faas_app.cert_pem``                           App's certificate
``faas_app.key_pem``                            App's key
==============================================  =============================================

.. code:: yaml

    extra_logstream_declaration_b64: eyJmNXhjX3RlbmFudCI6IHsiYXBpX2tleSI6ICJYWFhYWFhYWFhYWD0iLCAibmFtZSI6ICJmNS1lbWVhLWVudCIsICJuYW1lc3BhY2VzIjogW3siZXZlbnRfZmlsdGVyIjogeyJzZWNfZXZlbnRfdHlwZSI6ICJ3YWZfc2VjX2V2ZW50In0sICJuYW1lIjogImFsLWRhY29zdGEiLCAiZXZlbnRfc3RhcnRfdGltZSI6IHsieWVhciI6IDIwMjIsICJtb250aCI6IDQsICJkYXkiOiAxMCwgImhvdXIiOiAyMCwgIm1pbnV0ZSI6IDAgfSB9IF0gfSwgImxvZ2NvbGxlY3RvciI6IHsiaHR0cCI6IFt7Imhvc3QiOiAiNTIuMTc3Ljk0LjE1IiwgInBvcnQiOiA4ODg4LCAicGF0aCI6ICIvZGVidWcudGVzdCJ9IF0sICJzeXNsb2ciOiBbeyJpcF9hZGRyZXNzIjogIjUyLjE3Ny45NC4xNSIsICJwb3J0IjogNTE0MCB9IF0gfSB9
    extra_platform_name: Demo
    extra_platform_tags: environment=DMO platform=Demo project=LogStream
    extra_subnet_mgt_on_premise: 10.0.0.0/24
    extra_vm:
      admin_username: cyber
      availability_zone:
        - 1
      ip: 10.100.0.54
      key_data: -----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----
      location: eastus2
      name: logstream-xc
      size: Standard_B2s
    faas_app:
      ca_pem: "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----"
      cert_pem: "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----"
      key_pem: "-----BEGIN RSA PRIVATE KEY-----...-----END RSA PRIVATE KEY-----"
      name: logstream-xc
      repo: 'https://github.com/nergalex/f5-xc-logstream.git'

Deployment on a F5 XC RE
==================================================
An example of a deployment on a container hosted in a Regional Edge of F5 Distributed Cloud, using Ansible Tower.

Create and launch a workflow template ``wf-vk8s-unit-logstream`` that includes those Job templates in this order:

=============================================================   =============================================       =============================================   =============================================   =============================================   =============================================
Job template                                                    objective                                           playbook                                        activity                                        inventory                                       credential
=============================================================   =============================================       =============================================   =============================================   =============================================   =============================================
``poc-k8s-create_nginx_unit_image``                             Build image of NGINX Unit + logstream App           ``playbooks/poc-k8s.yaml``                      ``create_nginx_unit_image``                     ``localhost``                                   ``cred_server``
``poc-volterra-create_app_logstream``                           Deploy POD in a RE                                  ``playbooks/poc-volterra.yaml``                 `create_app_logstream``                         ``localhost``
=============================================================   =============================================       =============================================   =============================================   =============================================   =============================================

==============================================  =============================================
Extra variable                                  Description
==============================================  =============================================
``extra_vm``                                    Dict of VM properties
``extra_vm.ip``                                 VM IP address
``extra_vm.name``                               VM name
``extra_vm.size``                               Azure VM type
``extra_vm.availability_zone``                  Azure AZ
``extra_vm.location``                           Azure location
``extra_vm.admin_username``                     admin username
``extra_vm.key_data``                           admin user's public key
``extra_platform_name``                         platform name used for Azure resource group
``extra_platform_tags``                         Azure VM tags
``extra_subnet_mgt_on_premise``                 Cross management zone
``faas_app``                                    Dict of Function as a Service
``faas_app.name``                               App's name
``faas_app.repo``                               Logstream repo
``faas_app.ca_pem``                             Intermediate CA that signed App's keys
``faas_app.cert_pem``                           App's certificate
``faas_app.key_pem``                            App's key
==============================================  =============================================

.. code:: yaml

    extra_logstream_declaration_b64: ewogICAgImY1eGNfdGVuYW50IjogewogICAgICAgICJhcGlfa2V5IjogWCIsCiAgICAgICAgIm5hbWUiOiAiWCIsCiAgICAgICAgIm5hbWVzcGFjZXMiOiBbCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJldmVudF9maWx0ZXIiOiB7CiAgICAgICAgICAgICAgICAgICAgInNlY19ldmVudF90eXBlIjogIndhZl9zZWNfZXZlbnQiCiAgICAgICAgICAgICAgICB9LAogICAgICAgICAgICAgICAgIm5hbWUiOiAiWCIKICAgICAgICAgICAgfQogICAgICAgIF0KICAgIH0sCiAgICAibG9nY29sbGVjdG9yIjogewogICAgICAgICJzeXNsb2ciOiBbCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJpcF9hZGRyZXNzIjogIjEwLjEwMC4wLjgiLAogICAgICAgICAgICAgICAgInBvcnQiOiA1MTQwCiAgICAgICAgICAgIH0KICAgICAgICBdCiAgICB9Cn0=
    extra_owner_email: xxx@xxx.com
    extra_volterra:
      tenant:
        full: xxx-ccc
        short: xxx
      token: XXXXXXXXXXXXXXXXXXXX
    extra_volterra_namespace: xxx
    extra_volterra_re: xxx
    extra_volterra_site_id: 1
    faas_app:
      ca_pem: "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----"
      cert_pem: "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----"
      key_pem: "-----BEGIN RSA PRIVATE KEY-----...-----END RSA PRIVATE KEY-----"
      name: logstream-xc
      repo: 'https://github.com/nergalex/f5-xc-logstream.git'
      volume_declaration: /config
      volume_unit: /unit
    stats_acr_login_server: fqdn_of_a_container_registry
    stats_acr_password: password_credential_of_a_container_registry
    stats_acr_username: username_credential_of_a_container_registry
    stats_jumphost_ip: host_to_build_image

Remote Log Collector
==================================================
Example of a Log Collector using Fluentd

-  `Optimize the Network Kernel Parameters <https://docs.fluentd.org/installation/before-install#optimize-the-network-kernel-parameters>`_

.. code:: bash

    vi /etc/sysctl.conf
        net.core.somaxconn = 1024
        net.core.netdev_max_backlog = 5000
        net.core.rmem_max = 16777216
        net.core.wmem_max = 16777216
        net.ipv4.tcp_wmem = 4096 12582912 16777216
        net.ipv4.tcp_rmem = 4096 12582912 16777216
        net.ipv4.tcp_max_syn_backlog = 8096
        net.ipv4.tcp_slow_start_after_idle = 0
        net.ipv4.tcp_tw_reuse = 1
        net.ipv4.ip_local_port_range = 10240 65535
    sysctl -p

- Install `Fluentd <https://docs.fluentd.org/installation/install-by-rpm>`_

.. code:: bash

    curl -L https://toolbelt.treasuredata.com/sh/install-redhat-td-agent4.sh | sh

- Configure Fluentd with a TCP syslog INPUT

.. code:: bash

    vi /etc/td-agent/td-agent.conf

.. code:: xml

        <match debug.**>
          @type stdout
          @id output_stdout
        </match>
        <source>
          @type http
          @id input_http
          port 8888
          bind 0.0.0.0
        </source>
        <source>
          @type syslog
          tag debug.logstream
          port 5140
          bind 0.0.0.0
          <transport tcp>
            </transport>
        </source>

- Start service

.. code:: bash

    systemctl start td-agent.service


- Unit test

.. code:: bash

    tail -f -n 1 /var/log/td-agent/td-agent.log &
    curl -X POST -d 'json={"json":"message"}' http://localhost:8888/debug.test

Troubleshoot
==================================================

View TLS configuration on Unit:

:kbd:`curl http://localhost:8000/certificates/logstream-xc/chain/0`

View App configuration on Unit:

:kbd:`curl http://localhost:8000/config/`

VM
**************************************************

View audit log:

:kbd:`tail -100 /var/log/unit/unit.log`

View access log:

:kbd:`tail -f /var/log/unit/access.log`

View app log:

:kbd:`tail -f /etc/faas-apps/logstream-xc/logstream.log`

Container
**************************************************

Understand NGINX Unit startup: `here <https://unit.nginx.org/howto/source/#startup-and-shutdown>`_

View startup log:

:kbd:`cat /unit/docker-entrypoint.log`

View audit log:

:kbd:`tail -f /unit/unit.log`

View access log:

:kbd:`tail -f /unit/access.log`

View app log:

:kbd:`tail -f /unit/logstream.log`

View local configuration:

:kbd:`cat /config/declaration.json`



