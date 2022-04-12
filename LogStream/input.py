import json

from LogStream import storage_engine
import pytz
import datetime
import requests
import xmltodict
from collections import deque


class F5XCGeneric (storage_engine.DatabaseFormat):
    def __init__(self, name, api_key, logger, timezone='Europe/London'):
        super(F5XCGeneric, self).__init__(logger)
        # Table
        self.type = 'f5xc'
        # Primary key
        self.id = name
        # Attribute
        self.api_key = api_key
        self._update_timezone(timezone)
        self.session = requests.session()
        self._f5xc_log_idle_timeout = 2

    def generate_error(self, r):
        if self.logger:
            self.logger.error('%s::%s: code %s; %s' %
                              (__class__.__name__, __name__, r.status_code, r.text))
        raise ConnectionError('%s::%s: code %s; %s' %
                              (__class__.__name__, __name__, r.status_code, r.text))

    def _get(self, host, path, parameters=None):
        # URL builder
        if parameters and len(parameters) > 0:
            uri = path + '?' + '&'.join(parameters)
        else:
            uri = path

        url = 'https://' + host + uri
        headers = {
            'Authorization': 'APIToken ' + self.api_key,
            'Content-Type': 'application/json'
        }
        r = self.session.get(
            url,
            headers=headers,
            verify=False)
        if r.status_code not in (200, 201, 202, 204):
            self.generate_error(r)

        return r.json()

    def _post(self, host, path, data):
        url = 'https://' + host + path
        headers = {
            'Authorization': 'APIToken ' + self.api_key,
            'Content-Type': 'application/json'
        }
        r = self.session.post(
            url,
            headers=headers,
            json=data,
            verify=True)
        self.logger.debug('%s::%s: post json ; url=%s; data=%s' %
                          (__class__.__name__, __name__, url, data))
        if r.status_code not in (200, 201, 202, 204):
            self.generate_error(r)

        if r.text == '':
            return {}
        else:
            return r.json()

    @staticmethod
    def get_timezones():
        from pytz import common_timezones

        return common_timezones

    def _update_timezone(self, timezone):
        if timezone in F5XCGeneric.get_timezones():
            self.timezone = timezone
        else:
            raise KeyError('%s::%s: unknown timezone %s n' %
                           (__class__.__name__, __name__, timezone))

    def _update_time_now(self):
        # now minus the delay for F5XC to generate events logs
        date = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=self._f5xc_log_idle_timeout)
        return date


class F5XCNamespace (F5XCGeneric):
    def __init__(self, name, api_key, logger):
        super(F5XCNamespace, self).__init__(name, api_key, logger)
        # Table
        self.type = 'f5xc_namespace'
        # Primary key
        self.id = name
        # Attribute
        self.name = name
        self.time_fetch_security_events = self._update_time_now()
        self.events = deque()
        self.filter = ''
        self.event_filter = {}
        self.event_start_time = {}

    def update(self, data_json, tenant_api_key):
        # event_start_time
        key = 'event_start_time'
        if key in data_json.keys() and len(data_json[key]) > 0:
            self.event_start_time = data_json[key]
            self._set_event_start_time(data_json[key])
        else:
            self.event_start_time = {}
            self.time_fetch_security_events = self._update_time_now()

        # event_filter
        key = 'event_filter'
        if key in data_json.keys() and len(data_json[key]) > 0:
            self.event_filter = data_json[key]
            self._set_filter(data_json[key])
        else:
            self.event_filter = {}
            self.filter = ''

        # api_key
        key = 'api_key'
        if key in data_json.keys():
            self.api_key = data_json[key]
        else:
            self.api_key = tenant_api_key

    def _set_event_start_time(self, date):
        """
        fetch security events whose timestamp >= start_time

        :param date: year, month, day, hour = 0, minute = 0, timezone = None
        """
        # Default values
        if 'hour' not in date.keys():
            date['hour'] = 0
        if 'minute' not in date.keys():
            date['minute'] = 0
        if 'timezone' in date.keys():
            self._update_timezone(date['timezone'])

        # set time
        self.time_fetch_security_events = datetime.datetime(date['year'], date['month'], date['day'], date['hour'], date['minute']).replace(tzinfo=pytz.timezone(self.timezone))

    def fetch_security_events(self, host):
        # set timer
        start_time = self.time_fetch_security_events.strftime("%Y-%m-%dT%H:%M:%SZ")
        self.time_fetch_security_events = self._update_time_now()
        end_time = self.time_fetch_security_events.strftime("%Y-%m-%dT%H:%M:%SZ")

        # If start_time and end_time are not in the same second, then adjust end_time
        # Issue: duplicate logs if a same second is retrieved 2 times
        if start_time != end_time:
            end_time = (self.time_fetch_security_events - datetime.timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")

        # fetch security events
        path = "/api/data/namespaces/" + self.name + "/app_security/events"
        data = {
                "namespace": self.name,
                "scroll": False,
                "sort": "ASCENDING",
                "start_time": start_time,
                "end_time": end_time,
                "query": self.filter,
            }
        dirty_events = self._post(host, path, data)['events']

        # Clean
        for dirty_event in dirty_events:
            event = json.loads(dirty_event)

            # req_headers
            if 'req_headers' in event.keys():
                event['req_headers'] = json.loads(event['req_headers'])
            else:
                event['req_headers'] = ''

            # violation_details
            if 'violation_details' in event.keys() and event['violation_details'] != '':
                event['violation_details'] = json.loads(json.dumps(xmltodict.parse(event['violation_details'])))
            else:
                event['violation_details'] = ''

            self.events.append(event)

    def _set_filter(self, event_filter):
        """
        query is used to specify the list of matchers syntax

        :param event_filter: dict. deep 1. Example: filter = {sni: 'www.f5dc.dev', src_ip: '34.77.162.20'}
        :return:
        """
        query = '{'
        first_element = True
        for key, value in event_filter.items():
            if first_element:
                query += key + '="' + value + '"'
                first_element = False
            else:
                query += ', ' + key + '="' + value + '"'
        query += '}'
        self.filter = query

    def get_security_events(self):
        return self.events

    def pop_security_events(self):
        data = list(self.events)
        self.events.clear()
        return data

    def get_json(self):
        return {
            'name': self.id,
            'event_filter': self.event_filter,
            'event_start_time': self.event_start_time
        }


class F5XCTenant (F5XCGeneric):
    def __init__(self, name, logger, api_key=None):
        super(F5XCTenant, self).__init__(name, api_key, logger)
        # Table
        self.type = 'f5xc_tenant'
        # Primary key
        self.id = name
        # Relationship with other tables
        self.name = name
        self.children['f5xc_namespace'] = {}
        self.f5xc_namespace_ids = self.children['f5xc_namespace'].keys()
        self.f5xc_namespaces = self.children['f5xc_namespace'].values()
        # Attribute
        self.host = name + ".console.ves.volterra.io"

    def _create_namespace(self, name, api_key=None, start_time=None):
        if api_key is None:
            # Global API KEY for a Tenant
            api_key = self.api_key
        f5xc_namespace = F5XCNamespace(
            name=name,
            api_key=api_key,
            logger=self.logger)
        self.create_child(f5xc_namespace)

    def _delete_namespace(self, name):
        self.children['f5xc_namespace'][name].delete()

    def fetch_security_events(self):
        for f5xc_namespace in self.f5xc_namespaces:
            f5xc_namespace.fetch_security_events(host=self.host)

    def get_security_events(self):
        events = {}
        for f5xc_namespace in self.f5xc_namespaces:
            events[f5xc_namespace.name] = f5xc_namespace.get_security_events()
        return events

    def pop_security_events(self):
        events = deque()
        for f5xc_namespace in self.f5xc_namespaces:
            events.extend(f5xc_namespace.pop_security_events())
        return list(events)

    def get_json(self):
        data = {
            'name': self.name,
            'api_key': self.api_key,
            'namespaces': []
        }
        for f5xc_namespace_id, f5xc_namespace in self.children['f5xc_namespace'].items():
            data['namespaces'].append(f5xc_namespace.get_json())
        return data

    def get_namespaces(self):
        return self.f5xc_namespaces

    def update(self, data_json):
        # Update Tenant
        self.id = data_json['name']
        self.name = data_json['name']
        self.host = data_json['name'] + ".console.ves.volterra.io"
        if 'api_key' in data_json.keys():
            self.api_key = data_json['api_key']

        declaration_namespace_names = []
        # Create Namespaces
        for namespace in data_json['namespaces']:
            declaration_namespace_names.append(namespace['name'])
            if namespace['name'] not in self.f5xc_namespace_ids:
                self._create_namespace(name=namespace['name'])

            # Update Namespace
            self.children['f5xc_namespace'][namespace['name']].update(namespace, tenant_api_key=self.api_key)

        # Delete Namespaces
        for namespace in self.f5xc_namespaces:
            if namespace.name not in declaration_namespace_names:
                self._delete_namespace(name=namespace['name'])


def setup_logging(log_level, log_file):
    import logging

    if log_level == 'debug':
        log_level = logging.DEBUG
    elif log_level == 'verbose':
        log_level = logging.INFO
    else:
        log_level = logging.WARNING

    logging.basicConfig(filename=log_file, format='%(asctime)s %(levelname)s %(message)s', level=log_level)
    return logging.getLogger(__name__)



