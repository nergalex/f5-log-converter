import logging
import socket
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from datetime import datetime
from logging.handlers import SysLogHandler
from LogStream import storage_engine
from collections import deque


class RemoteSyslog(storage_engine.DatabaseFormat):
    def __init__(self, ip_address, logger, port=514):
        super(RemoteSyslog, self).__init__(logger)
        # Table
        self.type = 'syslog'
        # Primary key
        self.id = ip_address + ':' + str(port)
        self.ip_address = ip_address
        if port is None:
            self.port = 514
        else:
            self.port = port
        self.handler = logging.handlers.SysLogHandler(address=(ip_address, port), socktype=socket.SOCK_STREAM)
        self.handler.append_nul = False
        self.events = deque()

    def add_events(self, events):
        self.events.extend(events)

    def emit(self):
        # emit events
        while self.events:
            event = self.events.popleft()

            #  signature_ids
            signature_ids = []
            for signature in event['signatures']:
                signature_ids.append(signature['id'])

            #  signature_names
            signature_names = []
            for signature in event['signatures']:
                signature_names.append(signature['id_name'])

            #  signature_names
            if 'Path' in event['req_headers'].keys():
                req_headers_path = event['req_headers']['Path']
            else:
                req_headers_path = "Not Available"

            struct_message = [
                'app=' + str(event['authority']),
                'bot_classification=' + str(event['bot_classification']),
                'bot_verification_failed=' + str(event['bot_verification_failed']),
                'browser_type=' + str(event['browser_type']),
                'attack_types=' + str(event['attack_types']),
                'component=' + str(event['req_path']),
                'correlation_id=' + str(event['messageid']),
                'description=' + str(event['vh_name']),
                'environment=' + str(event['tenant']),
                'gateway=' + str(event['src_site']),
                'http.hostname=' + str(event['req_headers']['Host']),
                'http.remote_addr=' + str(event['src_ip']),
                'http.remote_port=' + str(event['src_port']),
                'http.request_method=' + str(event['method']),
                'http.response_code=' + str(event['rsp_code']),
                'http.server_addr=' + str(event['dst_ip']),
                'http.server_port=' + str(event['dst_port']),
                'http.uri=' + str(req_headers_path),
                'is_truncated=' + str(event['is_truncated_field']),
                'level=' + str(event['severity']),
                'policy_name=' + 'NotAvailable',
                'request=' + 'NotAvailable',
                'request_outcome=' + str(event['calculated_action']),
                'request_outcome_reason=' + 'NotAvailable',
                'signature_cves=' + 'NotAvailable',
                'signature_ids=' + str(signature_ids),
                'signature_names=' + str(signature_names),
                'sub_violations=' + 'NotAvailable',
                'support_id=' + str(event['req_id']),
                'type=' + str(event['sec_event_type']),
                'version=' + str(event['http_version']),
                'violation_rating=' + 'NotAvailable',
                'violations=' + str(event['violations']),
                'x_forwarded_for_header_value=' + str(event['x_forwarded_for']),
                'event_host=' + str(event['hostname']),
                'event_source=' + str(event['site']),
                'event_sourcetype=' + str(event['source_type']),
                'event_time=' + str(event['time']),
            ]
            now = datetime.now()
            struct_message = now.strftime("%B %d %H:%M:%S") + " logstream logger: " + ';'.join(struct_message) + '\n'
            self.logger.debug("%s::%s: SEND LOG: %s" %
                              (__class__.__name__, __name__, struct_message))
            record = logging.makeLogRecord({
                'msg': struct_message,
            })
            self.handler.emit(record)

    def get_json(self):
        return {
            'ip_address': self.ip_address,
            'port': self.port
        }


class RemoteHTTP(storage_engine.DatabaseFormat):
    def __init__(self,
                 logger,
                 host: str,
                 port: int = None,
                 protocol: str = 'http',
                 path: str = '/',
                 token: str = 'f5-xc-logstream'):
        super(RemoteHTTP, self).__init__(logger)
        # Table
        self.type = 'http'
        # Primary key
        self.id = host + ':' + str(port) + str(path)
        self.protocol = protocol
        self.host = host
        self.port = port
        self.path = path
        self.token = token
        self.events = deque()

        # sets up a session with the server
        self.session = requests.session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Authorization': 'Bearer %s' % self.token
        })
        # self.session.mount('%s://' % self.protocol, HTTPAdapter(
        #     max_retries=Retry(
        #         total=5,
        #         backoff_factor=0.5,
        #         status_forcelist=[403, 500]
        #     ),
        #     pool_connections=100,
        #     pool_maxsize=100
        # ))

    def add_events(self, events):
        self.events.extend(events)

    def emit(self):

        # set target uri
        if self.port is None:
            url = self.protocol + "://" + self.host + self.path
        else:
            url = self.protocol + "://" + self.host + ':' + str(self.port) + self.path

        # emit events
        while self.events:
            event = self.events.popleft()

            #  signature_ids
            signature_ids = []
            for signature in event['signatures']:
                signature_ids.append(signature['id'])

            #  signature_names
            signature_names = []
            for signature in event['signatures']:
                signature_names.append(signature['id_name'])

            struct_message = {
                'app': event['authority'],
                'bot_classification': event['bot_classification'],
                'bot_verification_failed': event['bot_verification_failed'],
                'browser_type': event['browser_type'],
                'attack_types': event['attack_types'],
                'component': event['req_path'],
                'correlation_id': event['messageid'],
                'description': event['vh_name'],
                'environment': event['tenant'],
                'gateway': event['src_site'],
                'http.hostname': event['req_headers']['Host'],
                'http.remote_addr': event['src_ip'],
                'http.remote_port': event['src_port'],
                'http.request_method': event['method'],
                'http.response_code': event['rsp_code'],
                'http.server_addr': event['dst_ip'],
                'http.server_port': event['dst_port'],
                'http.uri': event['req_headers']['Path'] if 'Path' in event['req_headers'].keys() else "Not Available",
                'is_truncated': event['is_truncated_field'],
                'level': event['severity'],
                'policy_name': 'NotAvailable',
                'request_headers': event['req_headers'],
                'request_outcome': event['calculated_action'],
                'request_outcome_reason': 'NotAvailable',
                'signatures': event['signatures'],
                'signature_ids': signature_ids,
                'signature_names': signature_names,
                'sub_violations': 'NotAvailable',
                'support_id': event['req_id'],
                'type': event['sec_event_type'],
                'version': event['http_version'],
                'violation_rating': event['violation_rating'],
                'violations': event['violations'],
                'x_forwarded_for_header_value': event['x_forwarded_for'],
                'event_host': event['hostname'],
                'event_source': event['site'],
                'event_sourcetype': event['source_type'],
                'event_time': event['time']
            }
            
            # http request
            if self.protocol == 'https':
                r = self.session.post(
                    url=url,
                    json=struct_message,
                    verify=False)

            # https request
            else:
                r = self.session.post(
                    url=url,
                    json=struct_message)

            # response
            if r.status_code not in (200, 201, 202, 204):
                self.generate_error(r)
            self.logger.debug("%s::%s: SEND LOG: %s" %
                              (__class__.__name__, __name__, event))

    def get_json(self):
        return {
            'protocol':  self.protocol,
            'host':  self.host,
            'port':  self.port,
            'path':  self.path,
            'token':  self.token
        }

    def generate_error(self, r):
        if self.logger:
            self.logger.error('%s::%s: code %s; %s' %
                              (__class__.__name__, __name__, r.status_code, r.text))
        raise ConnectionError('%s::%s: code %s; %s' %
                              (__class__.__name__, __name__, r.status_code, r.text))


class LogCollectorDB(storage_engine.DatabaseFormat):
    def __init__(self, logger):
        super(LogCollectorDB, self).__init__(logger)
        self.handlers = {}
        # Relationship with other tables
        self.children['syslog'] = {}
        self.children['http'] = {}

    def add(self, log_instance):
        if log_instance.id not in self.children[log_instance.type].keys():
            self.create_child(log_instance)

    def remove(self, log_instance):
        if log_instance.id in self.children[log_instance.type].keys():
            log_instance.delete()

    def get_json(self):
        data_all_types = {}

        for instance_type in ('http', 'syslog'):
            data = []
            for log_instance in self.children[instance_type].values():
                data.append(log_instance.get_json())
            data_all_types[instance_type] = data

        return data_all_types

    def get_instances(self):
        data_all_types = []

        for instance_type in ('http', 'syslog'):
            for log_instance in self.children[instance_type].values():
                data_instance = log_instance.get_json()
                data_instance['type'] = instance_type
                data_all_types.append(data_instance)
        return data_all_types

    def add_events(self, events):
        """
        populate event queue of all log collectors
        :param events:
        :return:
        """
        for logcol_type in ('http', 'syslog'):
            for logcol_instance in self.children[logcol_type].values():
                logcol_instance.add_events(events)

    def emit(self, logcol_id):
        """
        Emit logs for all log collectors if logcol_id is not set.
        If logcol_id is set, emit logs only to logcol_id
        :param events:
        :param logcol_id: position of logcollector in list returned by get_json()
        :return:
        """
        cur_index = 0
        for logcol_type in ('http', 'syslog'):
            for logcol_instance in self.children[logcol_type].values():
                if logcol_id is None:
                    logcol_instance.emit()
                elif cur_index == logcol_id:
                    logcol_instance.emit()





