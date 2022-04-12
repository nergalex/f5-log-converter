from flask import (Flask, request)
from flask_restful import (Api, Resource)
from flasgger import Swagger
from LogStream import input, filter, output, local_file_manager
import logging
import threading
import uuid
import time
import json
import os
import base64

application = Flask(__name__)
api = Api(application)
swagger = Swagger(application)


def setup_logging(log_level, log_file):
    if log_level == 'debug':
        log_level = logging.DEBUG
    elif log_level == 'verbose':
        log_level = logging.INFO
    else:
        log_level = logging.WARNING

    logging.basicConfig(filename=log_file, format='%(asctime)s %(levelname)s %(message)s', level=log_level)
    return logging.getLogger(__name__)


@swagger.definition('f5xc_tenant', tags=['v2_model'])
class ConfigF5XCTenant:
    """
    Tenant
    ---
    tags:
      - Input
    required:
      - name
      - namespaces
    properties:
      name:
        type: string
        description: short name of Tenant in F5 XC portal URI
      api_key:
        type: string
        description: API KEY set as a Credential for a Namespace by default
        default: None
      namespaces:
          type: array
          items:
            type: object
            schema:
            $ref: '#/definitions/f5xc_namespace'
    """

    @staticmethod
    def sanity_check(data_json):
        evaluation = {}
        declaration = {}

        # unknown key
        for key in data_json.keys():
            if key in ('name', 'api_key'):
                evaluation[key] = {
                    'code': 200,
                    'message': 'OK',
                    'value': data_json[key]
                }
                declaration[key] = data_json[key]
            else:
                evaluation[key] = {
                    'code': 400,
                    'message': 'unknown key',
                    'key': key
                }

        # namespaces
        key = 'namespaces'
        if key in data_json.keys():
            declaration[key] = []
            evaluation[key] = {
                'list': [],
                'code': 0
            }
            for namespace in data_json[key]:
                (tmp_evaluation, tmp_declaration) = ConfigF5XCNamespace.sanity_check(namespace)
                evaluation[key]['code'] = max(evaluation[key]['code'], tmp_evaluation['code'])
                evaluation[key]['list'].append(tmp_evaluation)
                declaration[key].append(tmp_declaration)
        else:
            evaluation[key] = {
                'code': 400,
                'message': 'key must be set',
                'key': key
            }

        # response
        code = 0
        for result in evaluation.values():
            code = max(code, result['code'])
        evaluation['code'] = code
        return evaluation, declaration

    @staticmethod
    def update(data_json):
        f5xc_tenant.update(data_json)

    @staticmethod
    def get():
        if f5xc_tenant is not None:
            return f5xc_tenant.get_json()
        else:
            return None


@swagger.definition('f5xc_event_filter', tags=['v2_model'])
class ConfigF5XCEventFilter:
    """
    EventFilter
    ---
    tags:
      - Input
    required:
      - sec_event_filter
    properties:
      sec_event_filter:
        type: string
        description: "filter on security event type"
        enum: [waf_sec_event, malicious_user_sec_event]
      src_ip:
        type: string
        description: "filter on source IP"
    """


@swagger.definition('f5xc_event_start_time', tags=['v2_model'])
class ConfigF5XCEventStartTime:
    """
    EventStartTime
    ---
    tags:
      - Input
    required:
      - year
      - month
      - day
    properties:
      year:
        type: integer
      month:
        type: integer
      day:
        type: integer
      hour:
        type: integer
        description: timezone='Europe/London'
        default: 0
      minute:
        type: integer
        default: 0

    """

    @staticmethod
    def sanity_check(data_json):
        evaluation = {}
        declaration = {}

        # Unknown key
        for key in data_json.keys():
            if key in ('year', 'month', 'day', 'hour', 'minute'):
                evaluation[key] = {
                    'code': 200,
                    'message': 'OK',
                    'value': data_json[key]
                }
                declaration[key] = data_json[key]
            else:
                evaluation[key] = {
                    'code': 400,
                    'message': 'unknown key',
                    'key': key
                }

        # Required keys
        for key in ('year', 'month', 'day'):
            if key in data_json.keys():
                evaluation[key] = {
                    'code': 200,
                    'message': 'OK',
                    'value': data_json[key]
                }
                declaration[key] = data_json[key]
            else:
                evaluation[key] = {
                    'code': 400,
                    'message': 'key must be set',
                    'key': key
                }

        # response
        code = 0
        for result in evaluation.values():
            code = max(code, result['code'])
        evaluation['code'] = code
        return evaluation, declaration


@swagger.definition('f5xc_namespace', tags=['v2_model'])
class ConfigF5XCNamespace:
    """
    Namespace
    ---
    tags:
      - Input
    required:
      - name
      - api_key
    properties:
      name:
        type: string
        description: name of Namespace
      api_key:
        type: string
        description: "API KEY set as a Credential.
            If no api_key set by default, api_key must be set for each namespace.
            If api_key is set in a namespace, it overrides default api_key."
        default: None
      event_start_time:
        type: object
        description: starting time of event timestamps to be fetch from F5XC
        schema:
        $ref: '#/definitions/f5xc_event_start_time'
      event_filter:
        type: object
        description: filter to apply before fetching events
        schema:
        $ref: '#/definitions/f5xc_event_filter'
    """

    @staticmethod
    def sanity_check(data_json):
        evaluation = {}
        declaration = {}

        # Unknown key
        for key in data_json.keys():
            if key in ('name', 'api_key', 'event_filter', 'event_start_time'):
                evaluation[key] = {
                    'code': 200,
                    'message': 'OK',
                    'value': data_json[key]
                }
                declaration[key] = data_json[key]
            else:
                evaluation[key] = {
                    'code': 400,
                    'message': 'unknown key',
                    'key': key
                }

        # Unknown key
        key = 'event_start_time'
        if key in data_json.keys():
            (evaluation[key], declaration[key]) = ConfigF5XCEventStartTime.sanity_check(data_json['event_start_time'])


        # response
        code = 0
        for result in evaluation.values():
            code = max(code, result['code'])
        evaluation['code'] = code
        return evaluation, declaration

    @staticmethod
    def set(data_json):
        f5xc_tenant.api_key = data_json['api_key']

    @staticmethod
    def get():
        if f5xc_tenant is not None:
            return f5xc_tenant.get_json()
        else:
            return None


@swagger.definition('logcollector', tags=['v2_model'])
class ConfigLogCollector:
    """
    Configure remote logging servers. At least one type of logcollector is required
    ---
    required:
      - syslog
      - http
    properties:
        syslog:
          type: array
          items:
            type: object
            schema:
            $ref: '#/definitions/syslog_server'
        http:
          type: array
          items:
            type: object
            schema:
            $ref: '#/definitions/http_server'
    """

    @staticmethod
    def sanity_check(data_json):
        evaluation = {}
        declaration = {}

        # syslog
        keys = ('syslog', 'http')
        key_found = False
        for key in keys:
            if key in data_json.keys():
                key_found = True
                declaration[key] = []
                evaluation[key] = {
                    'list': [],
                    'code': 0
                }
                for instance in data_json[key]:
                    if key == 'syslog':
                        (tmp_evaluation, tmp_declaration) = ConfigSyslogServer.sanity_check(instance)
                    elif key == 'http':
                        (tmp_evaluation, tmp_declaration) = ConfigHTTPServer.sanity_check(instance)
                    evaluation[key]['code'] = max(evaluation[key]['code'], tmp_evaluation['code'])
                    evaluation[key]['list'].append(tmp_evaluation)
                    declaration[key].append(tmp_declaration)
        if not key_found:
            evaluation['LogCollector'] = {
                'code': 400,
                'message': 'At least one LogCollector must be set',
                'key': ['http', 'syslog']
            }

        # response
        code = 0
        for result in evaluation.values():
            code = max(code, result['code'])
        evaluation['code'] = code
        return evaluation, declaration

    @staticmethod
    def update(data_json):
        if 'http' in data_json.keys():
            for instance in data_json['http']:
                ConfigHTTPServer.update(instance)
        if 'syslog' in data_json.keys():
            for instance in data_json['syslog']:
                ConfigSyslogServer.update(instance)

    @staticmethod
    def get():
        return logcol_db.get_json()


@swagger.definition('syslog_server', tags=['v2_model'])
class ConfigSyslogServer:
    """
    Configure a syslog server
    ---
    required:
      - ip_address
      - port
    properties:
      ip_address:
        type: string
        pattern: '^\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}$'
        description: ipv4 address
        example:
          1.1.1.1
      port:
        type: integer
        description: port listener
        default: 514
    """

    @staticmethod
    def sanity_check(data_json):
        evaluation = {}
        declaration = {}

        # Sanity check
        for key in data_json.keys():
            if key in ('ip_address', 'port'):
                evaluation[key] = {
                    'code': 200,
                    'message': 'OK',
                    'value': data_json[key]
                }
                declaration[key] = data_json[key]
            else:
                evaluation[key] = {
                    'code': 400,
                    'message': 'unknown key',
                    'key': key
                }

        # response
        code = 0
        for result in evaluation.values():
            code = max(code, result['code'])
        evaluation['code'] = code
        return evaluation, declaration

    @staticmethod
    def update(data_json):
        # set default value
        if 'port' in data_json.keys():
            port = data_json['port']
        else:
            port = None

        logcol_db.add(output.RemoteSyslog(
            ip_address=data_json['ip_address'],
            port=port,
            logger=logger)
        )


@swagger.definition('http_server', tags=['v2_model'])
class ConfigHTTPServer:
    """
    Configure a http(s) server
    ---
    required:
      - host
    properties:
      protocol:
        type: string
        enum: [http, https]
        default: http
      host:
        type: string
        description: FQDN or IP address
      port:
        type: integer
        description: custom listening port
      path:
        type: string
        description: path
        default: /
      token:
        type: string
        description: Bearer token
        default: 'f5-xc-logstream'
    """

    @staticmethod
    def sanity_check(data_json):
        evaluation = {}
        declaration = {}

        # Sanity check
        for key in data_json.keys():
            if key in ('protocol', 'host', 'port', 'path', 'token'):
                evaluation[key] = {
                    'code': 200,
                    'message': 'OK',
                    'value': data_json[key]
                }
                declaration[key] = data_json[key]
            else:
                evaluation[key] = {
                    'code': 400,
                    'message': 'unknown key',
                    'key': key
                }

        # response
        code = 0
        for result in evaluation.values():
            code = max(code, result['code'])
        evaluation['code'] = code
        return evaluation, declaration

    @staticmethod
    def update(data_json):
        # set default value
        port = data_json['port'] if 'port' in data_json.keys() else None
        protocol = data_json['protocol'] if 'protocol' in data_json.keys() else 'http'
        path = data_json['path'] if 'path' in data_json.keys() else '/'
        token = data_json['token'] if 'token' in data_json.keys() else 'f5-xc-logstream'

        logcol_db.add(output.RemoteHTTP(
            protocol=protocol,
            host=data_json['host'],
            port=port,
            path=path,
            token=token,
            logger=logger)
        )


class Declare(Resource):
    def get(self):
        """
        Get LogStream current declaration
        ---
        tags:
          - Global
        responses:
          200:
            schema:
              required:
                - f5xc_tenant
                - logcollector
              properties:
                f5xc_tenant:
                  type: object
                  schema:
                  $ref: '#/definitions/f5xc_tenant'
                logcollector:
                  type: object
                  schema:
                  $ref: '#/definitions/logcollector'
        """
        return {
            'f5xc_tenant': ConfigF5XCTenant.get(),
            'logcollector': ConfigLogCollector.get(),
        }, 200

    def post(self):
        """
        Configure LogStream in one declaration
        ---
        tags:
          - Global
        consumes:
          - application/json
        parameters:
          - in: body
            name: body
            schema:
              required:
                - f5xc_tenant
                - logcollector
              properties:
                f5xc_tenant:
                  type: object
                  schema:
                  $ref: '#/definitions/f5xc_tenant'
                logcollector:
                  type: object
                  schema:
                  $ref: '#/definitions/logcollector'
        responses:
          200:
            description: Deployment done
         """
        evaluation = {}
        declaration = {}

        data_json = request.get_json()
        (evaluation, declaration) = Declare.sanity_check(data_json=data_json)

        # malformed data
        if evaluation['code'] != 200:
            evaluation['status'] = "error"

        # clean data
        else:
            Declare.deploy(declaration=declaration)
            Declare.save(declaration=declaration)
            evaluation['status'] = "deployed"

        return evaluation, evaluation['code']

    @staticmethod
    def sanity_check(data_json):
        evaluation = {}
        declaration = {}

        # f5xc_tenant
        key = 'f5xc_tenant'
        if key in data_json.keys():
            (evaluation[key], declaration[key]) = ConfigF5XCTenant.sanity_check(data_json[key])
        else:
            evaluation[key] = {
                'code': 400,
                'message': 'parameter must be set',
                'value': data_json[key]
            }

        # logcollector
        key = 'logcollector'
        if key in data_json.keys():
            (evaluation[key], declaration[key]) = ConfigLogCollector.sanity_check(data_json[key])
        else:
            evaluation[key] = {
                'code': 400,
                'message': 'parameter must be set',
                'value': data_json[key]
            }

        # response
        code = 0
        for result in evaluation.values():
            code = max(code, result['code'])
        evaluation['code'] = code
        return evaluation, declaration

    @staticmethod
    def deploy(declaration):
        cur_class = 'f5xc_tenant'
        if cur_class in declaration.keys():
            ConfigF5XCTenant.update(declaration[cur_class])

        cur_class = 'logcollector'
        if cur_class in declaration.keys():
            ConfigLogCollector.update(declaration[cur_class])

    @staticmethod
    def save(declaration):
        local_config.set_json(declaration)
        local_config.save()


class EngineThreading(Resource):
    @staticmethod
    def start_main():
        if len(thread_manager['thread_queue'].keys()) == 0 and thread_manager['event'].is_set():
            thread_manager['event'].clear()
            for cur_index, logcol_instance in enumerate(logcol_db.get_instances()):
                thread_name = str(uuid.uuid4())
                t = threading.Thread(
                    target=EngineThreading.task_producer_consumer,
                    name=thread_name,
                    args=(thread_manager['event'], thread_name, cur_index)
                )
                thread_manager['thread_queue'][thread_name] = t
                logger.debug("%s::%s: NEW THREAD: id=%s;index:%s" %
                            (__class__.__name__, __name__, t.name, cur_index))
                t.start()
            return "Engine started", 200
        else:
            return "Engine already started", 202

    @staticmethod
    def stop_main():
        """
        Stop gracefully threads
        :return:
        """
        if not thread_manager['event'].is_set():
            # set flag as a signal to threads for stop processing their next fetch logs iteration
            thread_manager['event'].set()
            logger.debug("%s::%s: Main - event set" %
                         (__class__.__name__, __name__))

            # wait for threads to stop processing their current fetch logs iteration
            while len(thread_manager['thread_queue'].keys()) > 0:
                logger.debug("%s::%s: Main - wait for dying thread" %
                             (__class__.__name__, __name__))
                time.sleep(thread_manager['update_interval'])

            logger.debug("%s::%s: Main - all thread died" %
                         (__class__.__name__, __name__))
            return "Engine stopped", 200
        else:
            return "Engine already stopped", 202

    @staticmethod
    def restart_main():
        EngineThreading.stop_main()
        return EngineThreading.start_main()

    @staticmethod
    def task_producer_consumer(thread_flag, thread_name, cur_index):
        """
        fetch events and send them on remote logging servers
        after sending all logs, sleep during update_interval
        :param thread_flag:
        :param thread_name:
        :param cur_index: thread ID in pool, also logcollector ID
        :return:
        """
        while not thread_flag.is_set():
            # fetch events from all namespaces in Tenant
            # filter events
            # populate event queue of all log collectors
            f5xc_tenant.fetch_security_events()
            logcol_db.add_events(
                filter.WAF.filter_example(
                    f5xc_tenant.pop_security_events()))

            # emit logs for one logcollector with id 'cur_index' in list
            logcol_db.emit(logcol_id=cur_index)
            logger.debug("%s::%s: THREAD sent events: name=%s;index:%s" %
                         (__class__.__name__, __name__, thread_name, cur_index))

            # sleep
            logger.debug("%s::%s: THREAD is sleeping: name=%s;index:%s" %
                         (__class__.__name__, __name__, thread_name, cur_index))
            time.sleep(thread_manager['update_interval'])
            logger.debug("%s::%s: THREAD is awake: name=%s;index:%s" %
                         (__class__.__name__, __name__, thread_name, cur_index))

        logger.debug("%s::%s: THREAD exited his work: name=%s" %
                     (__class__.__name__, __name__, thread_name))
        thread_manager['thread_queue'].pop(thread_name, None)


class Engine(Resource):
    def get(self):
        """
        Get engine status
        ---
        tags:
          - LogStream
        responses:
          200:
            schema:
              required:
                - status
              properties:
                status:
                  type: string
                  description: status
                threads:
                  type: integer
                  description: number of running threads
        """
        data = {}
        if len(thread_manager['thread_queue'].keys()) > 0:
            data['status'] = 'sync processing'
            data['threads'] = len(thread_manager['thread_queue'].keys())
        else:
            data['status'] = 'no sync process'
        return data

    def post(self):
        """
            Start/Stop engine
            ---
            tags:
              - LogStream
            consumes:
              - application/json
            parameters:
              - in: body
                name: body
                schema:
                  required:
                    - action
                  properties:
                    action:
                      type: string
                      description : Start/Stop engine
                      enum: ['start', 'stop', 'restart']
            responses:
              200:
                description: Action done
        """
        data_json = request.get_json()

        # Sanity check
        cur_class = 'action'
        if cur_class not in data_json.keys() or \
                data_json[cur_class] not in ('start', 'stop', 'restart'):
            return {
                'code': 400,
                'msg': 'parameters: ' + cur_class + ' must be set'
            }
        else:
            # Sanity check
            if data_json[cur_class].lower() == 'start':
                return EngineThreading.start_main()
            elif data_json[cur_class].lower() == 'stop':
                return EngineThreading.stop_main()
            elif data_json[cur_class].lower() == 'restart':
                return EngineThreading.restart_main()
            else:
                return "Unknown action", 400


# Global var
log_file_path = os.getenv('log_file_path')
if log_file_path is None:
    log_file_path = '/unit/logstream.log'
logger = setup_logging(
    log_level='warning',
    log_file=log_file_path
)
logcol_db = output.LogCollectorDB(logger)
thread_manager = {
    'event': threading.Event(),
    'thread_queue': {},
    'update_interval': 30,
}

# event = True == engine stopped
thread_manager['event'].set()

f5xc_tenant = input.F5XCTenant(
    name='None',
    api_key=None,
    logger=logger
)

# load configuration
declaration_file_path = os.getenv('declaration_file_path')
if declaration_file_path is None:
    declaration_file_path = 'declaration.json'
local_config = local_file_manager.Configuration(backup_file=declaration_file_path).get_json()

# Run
if local_config is not None:
    (local_evaluation, local_declaration) = Declare.sanity_check(local_config)
    if local_evaluation['code'] == 200:
        Declare.deploy(local_declaration)
        EngineThreading.start_main()
    else:
        raise Exception('Local configuration file is malformated', local_evaluation)

# API
api.add_resource(Declare, '/declare')
api.add_resource(Engine, '/engine')

# Start program in developer mode
if __name__ == '__main__':
    print("Dev Portal: http://127.0.0.1:3001/apidocs/")
    application.run(
        host="0.0.0.0",
        debug=False,
        use_reloader=False,
        port=3001
    )



