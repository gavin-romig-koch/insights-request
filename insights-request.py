#!/bin/env python2.7

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

"""
Handle adding files and preparing the archive for upload
"""
import tempfile
import time
import os
import shutil
import subprocess
import shlex
import logging
import atexit
import ConfigParser
import requests
import sys
import json

found_conf_name = 'insights-client'
found_default_conf_dir = os.path.join('/etc', found_conf_name)
for each in ['insights-client', 'redhat-access-insights']:
    if os.path.exists(os.path.join('/etc', each, each + '.conf')):
        found_conf_name = each
        found_default_conf_dir = os.path.join('/etc', each)
        break

# from constants import InsightsConstants as constants
#class InsightsConstants(object):
class constants(object):
    app_name = 'insights-request'
    conf_name = found_conf_name
    version = '0.0.1'
    auth_method = 'BASIC'
    log_level = 'DEBUG'
    package_path = os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))
    sleep_time = 300
    user_agent = os.path.join(app_name, 'version')
    default_conf_dir = found_default_conf_dir
    log_dir = os.path.join(os.sep, 'var', 'log', app_name)
    default_log_file = os.path.join(log_dir, app_name) + '.log'
    default_conf_file_name = conf_name + '.conf'
    default_conf_file = os.path.join(default_conf_dir, default_conf_file_name)
    default_sed_file = os.path.join(default_conf_dir, '.exp.sed')
    default_ca_file = "auto" #os.path.join(default_conf_dir, 'cert-api.access.redhat.com.pem')
    base_url = 'cert-api.access.redhat.com/r/insights'
    collection_rules_file = os.path.join(default_conf_dir, '.cache.json')
    collection_fallback_file = os.path.join(default_conf_dir, '.fallback.json')
    collection_remove_file_name = 'remove.conf'
    collection_remove_file = os.path.join(default_conf_dir, collection_remove_file_name)
    unregistered_file = os.path.join(default_conf_dir, '.unregistered')
    registered_file = os.path.join(default_conf_dir, '.registered')
    lastupload_file = os.path.join(default_conf_dir, '.lastupload')
    pub_gpg_path = os.path.join(default_conf_dir, 'redhattools.pub.gpg')
    machine_id_file = os.path.join(default_conf_dir, 'machine-id')
    docker_group_id_file = os.path.join(default_conf_dir, 'docker-group-id')
    default_target = [{'type': 'host', 'name': ''}]
    default_branch_info = {'remote_branch': -1, 'remote_leaf': -1}
    docker_image_name = None
    default_cmd_timeout = 600  # default command execution to ten minutes, prevents long running commands that will hang

CONF_NAME = constants.conf_name
logger = logging.getLogger(CONF_NAME)

class InsightsClient:
    class options:
        retries = 1
        container_mode = False

def parse_config_file(conf_file):
    """
    Parse the configuration from the file
    """
    parsedconfig = ConfigParser.RawConfigParser(
        {'loglevel': constants.log_level,
         'trace': 'False',
         'app_name': constants.app_name,
         'auto_config': 'True',
         'authmethod': constants.auth_method,
         'base_url': constants.base_url,
         'upload_url': None,
         'api_url': None,
         'branch_info_url': None,
         'auto_update': 'True',
         'collection_rules_url': None,
         'obfuscate': 'False',
         'obfuscate_hostname': 'False',
         'cert_verify': constants.default_ca_file,
         'gpg': 'True',
         'username': None,
         'password': None,
         'systemid': None,
         'proxy': None,
         'insecure_connection': 'False',
         'no_schedule': 'False',
         'docker_image_name': '',
         'display_name': None})
    try:
        parsedconfig.read(conf_file)
    except ConfigParser.Error:
        logger.error("ERROR: Could not read configuration file, using defaults")
    try:
        # Try to add the insights-client section
        parsedconfig.add_section(CONF_NAME)
        # Try to add the redhat_access_insights section for back compat
        parsedconfig.add_section(constants.conf_name)
        # Try to add the redhat_access_insights section for back compat
        parsedconfig.add_section('redhat_access_insights')
    except ConfigParser.Error:
        pass
    return parsedconfig

def determine_hostname(display_name=None):
    return display_name if display_name else "cato"

SAVED_MACHINE_ID = None

def generate_machine_id(new=False, docker_group=False):
    """
    We can't (yet) do registration, so
    we can only do systems that already have a machine-id
    /etc/insights-client/machine-id
    """
    return SAVED_MACHINE_ID


def write_data_to_file(data, filepath):
    '''
    Write data to file
    '''
    if data == None:
        return

    try:
        os.makedirs(os.path.dirname(filepath), 0o700)
    except OSError:
        pass

    with open(filepath, 'w') as _file:
        _file.write(data)

def magic_plan_b(filename):
    '''
    Use this in instances where
    python-magic is MIA and can't be installed
    for whatever reason
    '''
    cmd = shlex.split('file --mime-type --mime-encoding ' + filename)
    stdout, stderr = subprocess.Popen(cmd, stdout=subprocess.PIPE).communicate()
    mime_str = stdout.split(filename + ': ')[1].strip()
    return mime_str


possible_CA_VERIFY_files = [
    "/etc/rhsm/ca/redhat-uep.pem",
    "/etc/redhat-access-insights/cert-api.access.redhat.com.pem",
    "/etc/insights-client/cert-api.access.redhat.com.pem",
]

class InsightsConnection(object):

    """
    Helper class to manage details about the connection
    """

    def __init__(self, username=None, password=None):
        self.user_agent = constants.user_agent
        self.username = username if username != None else InsightsClient.config.get(CONF_NAME, "username")
        self.password = password if password != None else InsightsClient.config.get(CONF_NAME, "password")
        
        self.cert_verify = InsightsClient.config.get(CONF_NAME, "cert_verify")
        if self.cert_verify.lower() == 'false':
            self.cert_verify = False
        elif self.cert_verify.lower() == 'true':
            self.cert_verify = True
        elif self.cert_verify.lower() == 'auto':
            # check the 'usual' places for a portal verify cert
            for filename in possible_CA_VERIFY_files:
                try:
                    open(filename)
                    self.cert_verify = filename
                    break
                except:
                    pass
            # if we are still 'auto' then none of the usual places worked, so don't verify
            if self.cert_verify.lower() == 'auto':
                self.cert_verify = False


        protocol = "https://"
        insecure_connection = InsightsClient.config.getboolean(CONF_NAME,
                                                               "insecure_connection")
        if insecure_connection:
            # This really should not be used.
            protocol = "http://"
            self.cert_verify = False

        self.auto_config = InsightsClient.config.getboolean(CONF_NAME,
                                                            'auto_config')
        self.base_url = protocol + InsightsClient.config.get(CONF_NAME, "base_url")
        self.upload_url = InsightsClient.config.get(CONF_NAME, "upload_url")
        if self.upload_url is None:
            self.upload_url = self.base_url + "/uploads"
        self.api_url = InsightsClient.config.get(CONF_NAME, "api_url")
        if self.api_url is None:
            self.api_url = self.base_url
        self.branch_info_url = InsightsClient.config.get(CONF_NAME, "branch_info_url")
        if self.branch_info_url is None:
            self.branch_info_url = self.base_url + "/v1/branch_info"
        self.authmethod = InsightsClient.config.get(CONF_NAME, 'authmethod')
        self.systemid = InsightsClient.config.get(CONF_NAME, 'systemid')
        self.get_proxies()
        self._validate_hostnames()
        self.session = self._init_session()
        # need this global -- [barfing intensifies]
        # tuple of self-signed cert flag & cert chain list
        self.cert_chain = (False, [])

    def _init_session(self):
        """
        Set up the session, auth is handled here
        """
        session = requests.Session()
#        session.headers = {'User-Agent': self.user_agent,
#                           'Accept': 'application/json'}
        session.headers = {}
        #if self.systemid is not None:
        #    session.headers.update({'systemid': self.systemid})
        if self.authmethod == "BASIC":
            session.auth = (self.username, self.password)
        elif self.authmethod == "CERT":
            cert = rhsmCertificate.certpath()
            key = rhsmCertificate.keypath()
            if rhsmCertificate.exists():
                session.cert = (cert, key)
            else:
                logger.error('ERROR: Certificates not found.')
        session.verify = self.cert_verify
        session.proxies = self.proxies
        session.trust_env = False
        print("Session Verify Cert: %s" % session.verify)
        logger.debug("Session Verify Cert: %s" % session.verify)
        if self.proxy_auth:
            # HACKY
            try:
                # Need to make a request that will fail to get proxies set up
                session.request(
                    "GET", "https://cert-api.access.redhat.com/r/insights")
            except requests.ConnectionError:
                pass
            # Major hack, requests/urllib3 does not make access to
            # proxy_headers easy
            proxy_mgr = session.adapters['https://'].proxy_manager[self.proxies['https']]
            auth_map = {'Proxy-Authorization': self.proxy_auth}
            proxy_mgr.proxy_headers = auth_map
            proxy_mgr.connection_pool_kw['_proxy_headers'] = auth_map
            conns = proxy_mgr.pools._container
            for conn in conns:
                connection = conns[conn]
                connection.proxy_headers = auth_map
        return session

    def get_proxies(self):
        """
        Determine proxy configuration
        """
        # Get proxy from ENV or Config
        from urlparse import urlparse
        proxies = None
        proxy_auth = None
        no_proxy = os.environ.get('NO_PROXY')
        logger.debug("NO PROXY: %s", no_proxy)

        # CONF PROXY TAKES PRECEDENCE OVER ENV PROXY
        conf_proxy = InsightsClient.config.get(CONF_NAME, 'proxy')
        if ((conf_proxy is not None and
             conf_proxy.lower() != 'None'.lower() and
             conf_proxy != "")):
            if '@' in conf_proxy:
                scheme = conf_proxy.split(':')[0] + '://'
                logger.debug("Proxy Scheme: %s", scheme)
                location = conf_proxy.split('@')[1]
                logger.debug("Proxy Location: %s", location)
                username = conf_proxy.split(
                    '@')[0].split(':')[1].replace('/', '')
                logger.debug("Proxy User: %s", username)
                password = conf_proxy.split('@')[0].split(':')[2]
                proxy_auth = requests.auth._basic_auth_str(username, password)
                conf_proxy = scheme + location
            logger.debug("CONF Proxy: %s", conf_proxy)
            proxies = {"https": conf_proxy}

        # HANDLE NO PROXY CONF PROXY EXCEPTION VERBIAGE
        if no_proxy and conf_proxy:
            logger.debug("You have environment variable NO_PROXY set "
                         "as well as 'proxy' set in your configuration file. "
                         "NO_PROXY environment variable will be ignored.")

        # IF NO CONF PROXY, GET ENV PROXY AND NO PROXY
        if proxies is None:
            env_proxy = os.environ.get('HTTPS_PROXY')
            if env_proxy:
                if '@' in env_proxy:
                    scheme = env_proxy.split(':')[0] + '://'
                    logger.debug("Proxy Scheme: %s", scheme)
                    location = env_proxy.split('@')[1]
                    logger.debug("Proxy Location: %s", location)
                    username = env_proxy.split('@')[0].split(':')[1].replace('/', '')
                    logger.debug("Proxy User: %s", username)
                    password = env_proxy.split('@')[0].split(':')[2]
                    proxy_auth = requests.auth._basic_auth_str(username, password)
                    env_proxy = scheme + location
                logger.debug("ENV Proxy: %s", env_proxy)
                proxies = {"https": env_proxy}
            if no_proxy:
                insights_service_host = urlparse(self.base_url).hostname
                logger.debug('Found NO_PROXY set. Checking NO_PROXY %s against base URL %s.', no_proxy, insights_service_host)
                for no_proxy_host in no_proxy.split(','):
                    logger.debug('Checking %s against %s', no_proxy_host, insights_service_host)
                    if no_proxy_host == '*':
                        proxies = None
                        proxy_auth = None
                        logger.debug('Found NO_PROXY asterisk(*) wildcard, disabling all proxies.')
                        break
                    elif no_proxy_host.startswith('.') or no_proxy_host.startswith('*'):
                        if insights_service_host.endswith(no_proxy_host.replace('*', '')):
                            proxies = None
                            proxy_auth = None
                            logger.debug('Found NO_PROXY range %s matching %s', no_proxy_host, insights_service_host)
                            break
                    elif no_proxy_host == insights_service_host:
                        proxies = None
                        proxy_auth = None
                        logger.debug('Found NO_PROXY %s exactly matching %s', no_proxy_host, insights_service_host)
                        break

        self.proxies = proxies
        self.proxy_auth = proxy_auth

    def _validate_hostnames(self):
        """
        Validate that the hostnames we got from config are sane
        """
        from urlparse import urlparse
        import socket
        endpoint_url = urlparse(self.upload_url)
        try:
            # Ensure we have something in the scheme and netloc
            if endpoint_url.scheme == "" or endpoint_url.netloc == "":
                logger.error("Invalid upload_url: " + self.upload_url + "\n"
                             "Be sure to include a protocol "
                             "(e.g. https://) and a "
                             "fully qualified domain name in " +
                             constants.default_conf_file)
                sys.exit()
            endpoint_addr = socket.gethostbyname(
                endpoint_url.netloc.split(':')[0])
            logger.debug(
                "hostname: %s ip: %s", endpoint_url.netloc, endpoint_addr)
        except socket.gaierror as e:
            logger.debug(e)
            logger.error(
                "Could not resolve hostname: %s", endpoint_url.geturl())
            sys.exit(1)
        if self.proxies is not None:
            proxy_url = urlparse(self.proxies['https'])
            try:
                # Ensure we have something in the scheme and netloc
                if proxy_url.scheme == "" or proxy_url.netloc == "":
                    logger.error("Proxies: %s", self.proxies)
                    logger.error("Invalid proxy!"
                                 "Please verify the proxy setting"
                                 " in " + constants.default_conf_file)
                    sys.exit()
                proxy_addr = socket.gethostbyname(
                    proxy_url.netloc.split(':')[0])
                logger.debug(
                    "Proxy hostname: %s ip: %s", proxy_url.netloc, proxy_addr)
            except socket.gaierror as e:
                logger.debug(e)
                logger.error("Could not resolve proxy %s", proxy_url.geturl())
                sys.exit(1)

    def _test_urls(self, url, method):
        """
        Actually test the url
        """
        from urlparse import urlparse
        # tell the api we're just testing the URL
        test_flag = {'test': 'test'}
        url = urlparse(url)
        test_url = url.scheme + "://" + url.netloc
        last_ex = None
        for ext in (url.path + '/', '', '/r', '/r/insights'):
            try:
                logger.info("Testing: %s", test_url + ext)
                if method is "POST":
                    test_req = self.session.post(
                        test_url + ext, timeout=10, data=test_flag)
                elif method is "GET":
                    test_req = self.session.get(test_url + ext, timeout=10)
                logger.info("HTTP Status Code: %d", test_req.status_code)
                logger.info("HTTP Status Text: %s", test_req.reason)
                logger.debug("HTTP Response Text: %s", test_req.text)
                # Strata returns 405 on a GET sometimes, this isn't a big deal
                if test_req.status_code == 200 or test_req.status_code == 201:
                    logger.info(
                        "Successfully connected to: %s", test_url + ext)
                    return True
                else:
                    logger.info("Connection failed")
                    return False
            except requests.ConnectionError, exc:
                last_ex = exc
                logger.error(
                    "Could not successfully connect to: %s", test_url + ext)
                logger.error(exc)
        if last_ex:
            raise last_ex

    def _verify_check(self, conn, cert, err, depth, ret):
        del conn
        # add cert to chain
        self.cert_chain[1].append(cert)
        logger.info('depth=' + str(depth))
        logger.info('verify error:num=' + str(err))
        logger.info('verify return:' + str(ret))
        if err == 19:
            # self-signed cert
            self.cert_chain[0] = True
        return True

    def _generate_cert_str(self, cert_data, prefix):
        return prefix + '/'.join(['='.join(a) for a in
                                  cert_data.get_components()])

    def _test_openssl(self):
        '''
        Run a test with openssl to detect any MITM proxies
        '''
        from urlparse import urlparse
        from OpenSSL import SSL, crypto
        import socket
        success = True
        hostname = urlparse(self.base_url).netloc.split(':')
        sock = socket.socket()
        sock.setblocking(1)
        if self.proxies:
            connect_str = 'CONNECT {0} HTTP/1.0\r\n'.format(hostname[0])
            if self.proxy_auth:
                connect_str += 'Proxy-Authorization: {0}\r\n'.format(self.proxy_auth)
            connect_str += '\r\n'
            proxy = urlparse(self.proxies['https']).netloc.split(':')
            try:
                sock.connect((proxy[0], int(proxy[1])))
            except Exception as e:
                logger.debug(e)
                logger.error('Failed to connect to proxy %s. Connection refused.', self.proxies['https'])
                sys.exit(1)
            sock.send(connect_str)
            res = sock.recv(4096)
            if '200 Connection established' not in res:
                logger.error('Failed to connect to %s. Invalid hostname.', self.base_url)
                sys.exit(1)
        else:
            try:
                sock.connect((hostname[0], 443))
            except socket.gaierror:
                logger.error('Error: Failed to connect to %s. Invalid hostname.', self.base_url)
                sys.exit(1)
        ctx = SSL.Context(SSL.TLSv1_METHOD)
        if type(self.cert_verify) is not bool:
            if os.path.isfile(self.cert_verify):
                ctx.load_verify_locations(self.cert_verify, None)
            else:
                logger.error('Error: Invalid cert path: %s', self.cert_verify)
                sys.exit(1)
        ctx.set_verify(SSL.VERIFY_PEER, self._verify_check)
        ssl_conn = SSL.Connection(ctx, sock)
        ssl_conn.set_connect_state()
        try:
            # output from verify generated here
            ssl_conn.do_handshake()
            # print cert chain
            certs = self.cert_chain[1]
            # put them in the right order
            certs.reverse()
            logger.info('---\nCertificate chain')
            for depth, c in enumerate(certs):
                logger.info(self._generate_cert_str(c.get_subject(),
                                                    str(depth) + ' s :/'))
                logger.info(self._generate_cert_str(c.get_issuer(),
                                                    '  i :/'))
            # print server cert
            server_cert = ssl_conn.get_peer_certificate()
            logger.info('---\nServer certificate')
            logger.info(crypto.dump_certificate(crypto.FILETYPE_PEM, server_cert))
            logger.info(self._generate_cert_str(server_cert.get_subject(), 'subject=/'))
            logger.info(self._generate_cert_str(server_cert.get_issuer(), 'issuer=/'))
            logger.info('---')
        except SSL.Error as e:
            logger.debug('SSL error: %s', e)
            success = False
            logger.error('Certificate chain test failed!')
        ssl_conn.shutdown()
        ssl_conn.close()
        if self.cert_chain[0]:
            logger.error('Certificate chain test failed!  Self '
                         'signed certificate detected in chain')
        return success and not self.cert_chain[0]

    def test_connection(self, rc=0):
        """
        Test connection to Red Hat
        """
        logger.info("Connection test config:")
        logger.info("Proxy config: %s", self.proxies)
        logger.info("Certificate Verification: %s", self.cert_verify)
        try:
            logger.info("=== Begin Certificate Chain Test ===")
            cert_success = self._test_openssl()
            logger.info("=== End Certificate Chain Test: %s ===\n",
                        "SUCCESS" if cert_success else "FAILURE")
            logger.info("=== Begin Upload URL Connection Test ===")
            upload_success = self._test_urls(self.upload_url, "POST")
            logger.info("=== End Upload URL Connection Test: %s ===\n",
                        "SUCCESS" if upload_success else "FAILURE")
            logger.info("=== Begin API URL Connection Test ===")
            api_success = self._test_urls(self.api_url, "GET")
            logger.info("=== End API URL Connection Test: %s ===\n",
                        "SUCCESS" if api_success else "FAILURE")
            if cert_success and upload_success and api_success:
                logger.info("\nConnectivity tests completed successfully")
            else:
                logger.info("\nConnectivity tests completed with some errors")
                rc = 1
        except requests.ConnectionError, exc:
            logger.error(exc)
            logger.error('Connectivity test failed! '
                         'Please check your network configuration')
            logger.error('Additional information may be in'
                         ' /var/log/' + CONF_NAME + "/" + CONF_NAME + ".log")
            sys.exit(1)
        sys.exit(rc)

    def handle_fail_rcs(self, req):
        """
        Bail out if we get a 401 and leave a message
        """

        # always display HTTP response information
        try:
            logger.info("HTTP Status Code: %s", req.status_code)
            logger.info("HTTP Response Text: %s", req.text)
            logger.debug("HTTP Response Reason: %s", req.reason)
            logger.debug("HTTP Response Content: %s", req.content)
        except:
            logger.error("Malformed HTTP Request.")

        # attempt to read the HTTP response JSON message
        try:
            logger.info("HTTP Response Message: %s", req.json()["message"])
        except:
            logger.debug("No HTTP Response message present.")

        # handle specific status codes
        if req.status_code >= 400:
            logger.error("ERROR: Upload failed!")
            logger.info("Debug Information:\nHTTP Status Code: %s",
                        req.status_code)
            logger.info("HTTP Status Text: %s", req.reason)
            if req.status_code == 401:
                logger.error("Authorization Required.")
                logger.error("Please ensure correct credentials "
                             "in " + constants.default_conf_file)
                logger.debug("HTTP Response Text: %s", req.text)
            if req.status_code == 402:
                # failed registration because of entitlement limit hit
                logger.debug('Registration failed by 402 error.')
                try:
                    logger.error(req.json()["message"])
                except LookupError:
                    logger.error("Got 402 but no message")
                    logger.debug("HTTP Response Text: %s", req.text)
                except:
                    logger.error("Got 402 but no message")
                    logger.debug("HTTP Response Text: %s", req.text)
            if req.status_code == 403 and self.auto_config:
                # Insights disabled in satellite
                from urlparse import urlparse
                rhsm_hostname = urlparse(self.base_url).hostname
                if (rhsm_hostname != 'subscription.rhn.redhat.com' and
                   rhsm_hostname != 'subscription.rhsm.redhat.com'):
                    logger.error('Please enable Insights on Satellite server '
                                 '%s to continue.', rhsm_hostname)
            if req.status_code == 412:
                try:
                    unreg_date = req.json()["unregistered_at"]
                    logger.error(req.json()["message"])
                    write_unregistered_file(unreg_date)
                except LookupError:
                    unreg_date = "412, but no unreg_date or message"
                    logger.debug("HTTP Response Text: %s", req.text)
                except:
                    unreg_date = "412, but no unreg_date or message"
                    logger.debug("HTTP Response Text: %s", req.text)
            sys.exit(1)

    if False:
        # don't do this because we aren't on host machine
        def get_satellite5_info(self, branch_info):
            """
            Get remote_leaf for Satellite 5 Managed box
            """
            logger.debug(
                "Remote branch not -1 but remote leaf is -1, must be Satellite 5")
            if os.path.isfile('/etc/sysconfig/rhn/systemid'):
                logger.debug("Found systemid file")
                sat5_conf = ET.parse('/etc/sysconfig/rhn/systemid').getroot()
                leaf_id = None
                for member in sat5_conf.getiterator('member'):
                    if member.find('name').text == 'system_id':
                        logger.debug("Found member 'system_id'")
                        leaf_id = member.find('value').find(
                            'string').text.split('ID-')[1]
                        logger.debug("Found leaf id: %s", leaf_id)
                        branch_info['remote_leaf'] = leaf_id
                if leaf_id is None:
                    sys.exit("Could not determine leaf_id!  Exiting!")

    def branch_info(self):
        """
        Retrieve branch_info from Satellite Server
        """
        logger.debug("Obtaining branch information from %s",
                     self.branch_info_url)
        branch_info = self.session.get(self.branch_info_url)
        logger.debug("GET branch_info status: %s", branch_info.status_code)
        try:
            logger.debug("Branch information: %s",
                         json.dumps(branch_info.json()))
        except ValueError:
            raise LookupError
        branch_info = branch_info.json()

        if 'remote_branch' not in branch_info or 'remote_leaf' not in branch_info:
            raise LookupError

        # Determine if we are connected to Satellite 5
        if ((branch_info['remote_branch'] is not -1 and
             branch_info['remote_leaf'] is -1)):
            # don't do this because we aren't on host machine
            self.get_satellite5_info(branch_info)

        return branch_info

    def create_system(self, new_machine_id=False):
        """
        Create the machine via the API
        """
        client_hostname = determine_hostname()
        machine_id = generate_machine_id(new_machine_id)

        try:
            branch_info = self.branch_info()
            remote_branch = branch_info['remote_branch']
            remote_leaf = branch_info['remote_leaf']

        except LookupError:
            logger.error(
                "ERROR: Could not determine branch information, exiting!")
            logger.error(
                "Could not register system, running configuration test")
            self.test_connection(1)

        except requests.ConnectionError as e:
            logger.debug(e)
            logger.error(
                "ERROR: Could not determine branch information, exiting!")
            logger.error(
                "Could not register system, running configuration test")
            self.test_connection(1)

        data = {'machine_id': machine_id,
                'remote_branch': remote_branch,
                'remote_leaf': remote_leaf,
                'hostname': client_hostname}
        if InsightsClient.config.get(CONF_NAME, 'display_name') is not None:
            data['display_name'] = InsightsClient.config.get(CONF_NAME, 'display_name')
        if InsightsClient.options.display_name is not None:
            data['display_name'] = InsightsClient.options.display_name
        data = json.dumps(data)
        headers = {'Content-Type': 'application/json'}
        post_system_url = self.api_url + '/v1/systems'
        logger.debug("POST System: %s", post_system_url)
        logger.debug(data)
        system = None
        try:
            system = self.session.post(post_system_url,
                                       headers=headers,
                                       data=data)
            logger.debug("POST System status: %d", system.status_code)
        except requests.ConnectionError as e:
            logger.debug(e)
            logger.error(
                "Could not register system, running configuration test")
            self.test_connection(1)
        return system

    def do_group(self):
        """
        Do grouping on register
        """
        group_id = InsightsClient.options.group
        api_group_id = None
        headers = {'Content-Type': 'application/json'}
        group_path = self.api_url + '/v1/groups'
        group_get_path = group_path + ('?display_name=%s' % group_id)

        logger.debug("GET group: %s", group_get_path)
        get_group = self.session.get(group_get_path)
        logger.debug("GET group status: %s", get_group.status_code)
        if get_group.status_code == 200:
            api_group_id = get_group.json()['id']

        if get_group.status_code == 404:
            # Group does not exist, POST to create
            logger.debug("POST group")
            data = json.dumps({'display_name': group_id})
            post_group = self.session.post(group_path,
                                           headers=headers,
                                           data=data)
            logger.debug("POST group status: %s", post_group.status_code)
            logger.debug("POST Group: %s", post_group.json())
            self.handle_fail_rcs(post_group)
            api_group_id = post_group.json()['id']

        logger.debug("PUT group")
        data = json.dumps({'machine_id': generate_machine_id()})
        put_group = self.session.put(group_path +
                                     ('/%s/systems' % api_group_id),
                                     headers=headers,
                                     data=data)
        logger.debug("PUT group status: %d", put_group.status_code)
        logger.debug("PUT Group: %s", put_group.json())

    def api_registration_check(self):
        '''
        Check registration status through API
        '''
        logger.debug('Checking registration status...')
        machine_id = generate_machine_id()
        try:
            res = self.session.get(self.api_url + '/v1/systems/' + machine_id, timeout=10)
        except requests.ConnectionError as e:
            # can't connect, run connection test
            logger.error('Connection timed out. Running connection test...')
            self.test_connection()
            return False
        # had to do a quick bugfix changing this around,
        #   which makes the None-False-True dichotomy seem fucking weird
        #   TODO: reconsider what gets returned, probably this:
        #       True for registered
        #       False for unregistered
        #       None for system 404
        try:
            # check the 'unregistered_at' key of the response
            unreg_status = json.loads(res.content).get('unregistered_at', 'undefined')
            # set the global account number
            InsightsClient.account_number = json.loads(res.content).get('account_number', 'undefined')
        except ValueError:
            # bad response, no json object
            return False
        if unreg_status == 'undefined':
            # key not found, machine not yet registered
            return None
        elif unreg_status is None:
            # unregistered_at = null, means this machine IS registered
            return True
        else:
            # machine has been unregistered, this is a timestamp
            return unreg_status

    def unregister(self):
        """
        Unregister this system from the insights service
        """
        machine_id = generate_machine_id()
        try:
            logger.debug("Unregistering %s", machine_id)
            self.session.delete(self.api_url + "/v1/systems/" + machine_id)
            logger.info(
                "Successfully unregistered from the Red Hat Insights Service")
            write_unregistered_file()
            InsightsSchedule().remove_scheduling()
        except requests.ConnectionError as e:
            logger.debug(e)
            logger.error("Could not unregister this system")

    def register(self):
        """
        Register this machine
        """

        delete_unregistered_file()

        client_hostname = determine_hostname()
        # This will undo a blacklist
        logger.debug("API: Create system")
        system = self.create_system(new_machine_id=False)

        # If we get a 409, we know we need to generate a new machine-id
        if system.status_code == 409:
            system = self.create_system(new_machine_id=True)
        self.handle_fail_rcs(system)

        logger.debug("System: %s", system.json())

        message = system.headers.get("x-rh-message", "")

        write_registered_file()

        # Do grouping
        if InsightsClient.options.group is not None:
            self.do_group()

        # Display registration success messasge to STDOUT and logs
        if system.status_code == 201:
            try:
                system_json = system.json()
                machine_id = system_json["machine_id"]
                account_number = system_json["account_number"]
                logger.info("You successfully registered %s to account %s." % (machine_id, account_number))
            except:
                logger.debug('Received invalid JSON on system registration.')
                logger.debug('API still indicates valid registration with 201 status code.')
                logger.debug(system)
                logger.debug(system.json())

        if InsightsClient.options.group is not None:
            return (message, client_hostname, InsightsClient.options.group, InsightsClient.options.display_name)
        elif InsightsClient.options.display_name is not None:
            return (message, client_hostname, "None", InsightsClient.options.display_name)
        else:
            return (message, client_hostname, "None", "")

    def upload_archive(self, data_collected, duration, cluster=None):
        """
        Do an HTTPS Upload of the archive
        """
        file_name = os.path.basename(data_collected)
        try:
            import magic
            m = magic.open(magic.MAGIC_MIME)
            m.load()
            mime_type = m.file(data_collected)
        except ImportError:
            magic = None
            logger.debug('python-magic not installed, using backup function...')
            mime_type = magic_plan_b(data_collected)

        fo = open(data_collected, 'rb')

        files = {
            'file': (file_name, fo, mime_type)}

        if cluster:
            upload_url = self.upload_url + '/' + cluster
        else:
            upload_url = self.upload_url + '/' + generate_machine_id()

        logger.debug("Uploading %s to %s", data_collected, upload_url)

        headers = {'x-rh-collection-time': duration}
        upload = self.session.post(upload_url, files=files, headers=headers)

        logger.debug("Upload status: %s %s %s",
                     upload.status_code, upload.reason, upload.text)
        logger.debug("Upload duration: %s", upload.elapsed)
        return upload


def _do_upload(pconn, tar_file, logging_name, collection_duration, result):
    # do the upload
    logger.info('Uploading Insights data for %s, this may take a few minutes', logging_name)
    for tries in range(InsightsClient.options.retries):
        upload = pconn.upload_archive(tar_file, collection_duration,
                                      cluster=generate_machine_id(
                                          docker_group=InsightsClient.options.container_mode))
        if upload.status_code == 201:
            machine_id = generate_machine_id()
            #logger.info("You successfully uploaded a report from %s to account %s." % (machine_id, InsightsClient.account_number))
            logger.info("You successfully uploaded a report from %s to account %s." % (machine_id, upload.json()['upload']['account_number']))
            logger.info("Upload completed successfully!")
            result['ansible_facts']['insights_upload_results'] = upload.json()
            return result
        elif upload.status_code == 412:
            pconn.handle_fail_rcs(upload)
            return dict(failed=True,
                        msg="Failed to upload %s, http status 412" % tar_file)
        else:
            logger.error("Upload attempt %d of %d failed! Status Code: %s",
                         tries + 1, InsightsClient.options.retries, upload.status_code)
            if tries + 1 != InsightsClient.options.retries:
                logger.info("Waiting %d seconds then retrying",
                            constants.sleep_time)
                time.sleep(constants.sleep_time)
            else:
                logger.error("All attempts to upload have failed!")
                return dict(failed=True,
                            msg="Failed to upload (%s times) %s" % (tries + 1, tar_file))
    return dict(failed=True,
                msg="Failed to upload (%s times) %s" % (tries + 1, tar_file))


class InsightsLoginException(Exception):
    pass

class InsightsSession:
    def __init__(self, username=None, password=None):
        InsightsClient.config = parse_config_file(constants.default_conf_file)

        self.pconn = InsightsConnection(username, password)

        try:
            self.branch_info = self.pconn.branch_info()
        except requests.ConnectionError:
            raise InsightsLoginException("Could not log into Insights connection error")
        except LookupError:
            raise InsightsLoginException("Could not log into Insights Lookup error")

    def get(self, id, data):
        host = "https://cert-api.access.redhat.com"
        #host = "https://insights.redhat.com/"
        commands = {
            "reports" : "/r/insights/v1/systems/{system_id}/reports",
            "systemV1" : "/r/insights/v1/systems/{system_id}",
            "system" : "/r/insights/v2/systems/{system_id}",
            "maintenance" : "/r/insights/v3/maintenance?ansible=true",
            "top" : "/r/insights/",
            "policies" : "/r/insights/v3/systems/{system_id}/policies",
            "policy" : "/r/insights/v3/systems/{system_id}/policies/{policy_name}",
            }

        url = host + commands[id].format(**data)
        print("URL:", url)
        return self.pconn.session.get(url, timeout=10)

    def delete(self, id, data):
        host = "https://cert-api.access.redhat.com"
        #host = "https://insights.redhat.com/"
        commands = {
            "reports" : "/r/insights/v1/systems/{system_id}/reports",
            "systemV1" : "/r/insights/v1/systems/{system_id}",
            "system" : "/r/insights/v2/systems/{system_id}",
            "maintenance" : "/r/insights/v3/maintenance?ansible=true",
            "top" : "/r/insights/",
            "policies" : "/r/insights/v3/systems/{system_id}/policies",
            "policy" : "/r/insights/v3/systems/{system_id}/policies/{policy_name}",
            }

        url = host + commands[id].format(**data)
        print("URL:", url)
        return self.pconn.session.delete(url, timeout=10)

    def put(self, id, data):
        host = "https://cert-api.access.redhat.com"
        #host = "https://insights.redhat.com/"
        commands = {
            "reports" : "/r/insights/v1/systems/{system_id}/reports",
            "systemV1" : "/r/insights/v1/systems/{system_id}",
            "system" : "/r/insights/v2/systems/{system_id}",
            "maintenance" : "/r/insights/v3/maintenance?ansible=true",
            "top" : "/r/insights/",
            "policies" : "/r/insights/v3/systems/{system_id}/policies",
            "policy" : "/r/insights/v3/systems/{system_id}/policies/{policy_name}",
            }

        headers = {'Content-Type': 'application/json'}
        url = host + commands[id].format(**data)
        body = json.dumps(data["policy"])
        print("URL:", url)
        print("BODY:", body)
        return self.pconn.session.put(url, data=body, headers=headers)

    def getJSON(self, id, data):
        response = self.get(id, data)
        if response.status_code == 200:
            if 'Content-Type' in response.headers and 'json' in response.headers['Content-Type']:
                return json.loads(response.text)
        raise UnexpectedResponse(response)

    def get_and_print(self, id, data):
        self.print_response(self.get(id, data))

    def delete_and_print(self, id, data):
        self.print_response(self.delete(id, data))

    def put_and_print(self, id, data):
        self.print_response(self.put(id, data))

    def print_response(self, response):
        print("HTTP Status Code: %d" % response.status_code)
        print("HTTP Status Text: %s" % response.reason)
        print("HTTP HEADERS:")
        for key,value in response.headers.items():
            print("  %s: %s" % (key,value))
        if 'Content-Type' in response.headers and 'json' in response.headers['Content-Type']:
            print("HTTP Response JSON: %s" % json.dumps(json.loads(response.text), indent=2))
        else:
            print("HTTP Response Text: %s" % response.text)

class UnexpectedResponse(Exception):
    def __init__(self, response):
        self.response = response

def test1(session, system_id):
    try: 
        print("System {} has type {}".format(system_id,
                                             session.getJSON("reports", { "system_id": system_id })["system_type_id"]))
    except UnexpectedResponse as ex:
        print("Unexpected Response")
        session.print_response(ex.response)

def test2(session, system_id):
    session.get_and_print("systemV1", { "system_id": system_id })

def test3(session, system_id):
    session.get_and_print("system", { "system_id": system_id })

def test4(session, system_id):
    session.get_and_print("reports", { "system_id": system_id })

def test5(session, system_id):
    session.get_and_print("maintenance", {})
    
def test6(session, system_id):
    session.get_and_print("top", {})
    
def test7(session, system_id):
    session.get_and_print("policies", { "system_id": system_id })

def test8(session, system_id, policy_name, policy):
    session.put_and_print("policy",
                          {
                              "system_id" : system_id,
                              "policy_name" : policy_name,
                              "policy" : policy,
                          })

def test9(session, system_id, policy_name):
    session.delete_and_print("policy",
                             {
                                 "system_id" : system_id,
                                 "policy_name" : policy_name,
                             })

def test10(session, system_id, policy_name, policy):
    session.delete_and_print("policy",
                          {
                              "system_id" : system_id,
                              "policy_name" : policy_name,
                          })
    session.put_and_print("policy",
                          {
                              "system_id" : system_id,
                              "policy_name" : policy_name,
                              "policy" : policy,
                          })

def test11(session, system_id, policy_name):
    session.get_and_print("policy",
                          {
                              "system_id" : system_id,
                              "policy_name" : policy_name,
                          })

    
APolicyName = "policy-30"
APolicy = {
    "raw_output": "",
    "check_results": [
        {
            "name": "fips mode must be enabled",
            "result": "failed"
        },
        {
            "name": "hostname must not be \"localhost\"",
            "result": "passed"
        },
        {
            "name": "prelink package must be absent (not installed)",
            "result": "failed"
        },
        {
            "name": "kernel package must be the latest",
            "result": "failed"
        },
        {
            "name": "sshd config file must be owned by root and only readable by root",
            "result": "passed"
        }
    ]
}

if __name__ == "__main__":
    session = InsightsSession()
    system_id="534b6f8f-8953-416f-be72-86af08b825a5"
    #    test1(session, system_id)
    #    test2(session, system_id)
    #    test3(session, system_id)
    #    test4(session, system_id)
    #    test5(session, system_id)
    #    test6(session, system_id)
    #test7(session, system_id)
    #test8(session, system_id, APolicyName, APolicy)
    #test9(session, system_id, APolicyName)
    test11(session, system_id, APolicyName)

