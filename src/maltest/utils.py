"""
malcolm-test module containing classes used for managing and interfacing with a Malcolm VM

The classes of interest in this module include:

- MalcolmTestCollection - A pytest plugin used to gather the list of tests to be run
- MalcolmVM - Represents a Malcolm instance running inside a virter-managed libvirt virtual machine
"""

# -*- coding: utf-8 -*-

import ast
import glob
import hashlib
import json
import mmguero
import os
import petname
import re
import requests
import subprocess
import sys
import time
import tomli
import tomli_w
import urllib3
import warnings

from collections import defaultdict
from datetime import datetime, timezone
from requests.auth import HTTPBasicAuth

# the name of this Python project used for packaging
MALTEST_PROJECT_NAME = "malcolm-test"

# silence warning about self-signed TLS certificates
urllib3.disable_warnings()
warnings.filterwarnings(
    "ignore",
    message="Unverified HTTPS request",
)

# tests should define UPLOAD_ARTIFACTS for files (e.g., PCAP, evtx, etc.) they need uploaded to Malcolm
UPLOAD_ARTIFACT_LIST_NAME = 'UPLOAD_ARTIFACTS'

# tests should define NETBOX_ENRICH=True for PCAPs to be netbox-enriched (default false)
NETBOX_ENRICH_BOOL_NAME = "NETBOX_ENRICH"

# parameters for checking that a Malcolm instance is ready
MALCOLM_READY_TIMEOUT_SECONDS = 600
MALCOLM_READY_CHECK_PERIOD_SECONDS = 30
MALCOLM_READY_REQUIRED_COMPONENTS = [
    'arkime',
    'logstash_lumberjack',
    'logstash_pipelines',
    'netbox',
    'opensearch',
    'pcap_monitor',
]
MALCOLM_LAST_INGEST_AGE_SECONDS_THRESHOLD = 300
MALCOLM_LAST_INGEST_AGE_SECONDS_TIMEOUT = 3600

# used to check with Arkime to see if a PCAP file has already been uploaded
ARKIME_FILES_INDEX = "arkime_files"
ARKIME_FILE_SIZE_FIELD = "filesize"

# Global variable used to set or check that the program is being prematurely
# interrupted (e.g., with CTRL+C or SIGKILL)
ShuttingDown = [False]

"""
As malcolm-test is only used against one Malcolm instance at a time, this global
variable represents the info dict (see MalcolmVM.Info) containing information
about the currently-connected-to Malcolm instance. Mainly this is used so it
can be accessed by the pytest fixtures for connection info.
"""
MalcolmVmInfo = None

"""
ArtifactHashMap contains a map of artifact files' full path to their
file hash as calculated by shakey_file_hash. The presence
of a file in this dict means that the file has
been successfully uploaded to the Malcolm instance for processing,
meaning (assuming auto-tagging based on filename is turned on)
the hash can be used as a query filter for tags.
"""
ArtifactHashMap = defaultdict(lambda: None)


def shakey_file_hash(filename, digest_len=8):
    """
    shakey_file_hash: Calculate SHAKE256 file hash for the contents of a file
    See https://docs.python.org/3/library/hashlib.html#hashlib.shake_256

    Args:
        filename   - filename of file to open and hash
        digest_len - byte length of the digest to return for the hash (default 8)

    Returns:
        str hex representation of digest (of length digest_len*2) for the SHAKE256 of the file
    """
    try:
        with open(filename, 'rb', buffering=0) as f:
            return hashlib.file_digest(f, 'shake_256').hexdigest(digest_len)
    except:
        return None


def parse_virter_log_line(log_line):
    """
    parse_virter_log_line: Return a dict created by parsing the name/value pairs output
    from running a "virter" command", handling quote escaping

    Args:
        log_line - str of the log line returned by virter

    Returns:
        dict() of the name/value pairs from the log line, unescaping the quotes
    """
    pattern = r'(\w+)=(".*?"|\S+)'
    matches = re.findall(pattern, log_line)
    log_dict = defaultdict(lambda: log_line)
    if matches:
        for key, value in matches:
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1].replace('\\"', '"')
            log_dict[key] = value

    return log_dict


def set_malcolm_vm_info(info):
    """
    set_malcolm_vm_info: Sets the global MalcolmVmInfo variable to the provided info object

    Args:
        info - The info object to store as MalcolmVmInfo

    Returns:
        the global MalcolmVmInfo object
    """
    global MalcolmVmInfo
    MalcolmVmInfo = info
    return MalcolmVmInfo


def get_malcolm_vm_info():
    """
    get_malcolm_vm_info: Return the global MalcolmVmInfo object

    Args:
        None

    Returns:
        the global MalcolmVmInfo object
    """
    global MalcolmVmInfo
    return MalcolmVmInfo


def set_artifact_hash(artifactFileSpec, artifactFileHash=None):
    """
    set_artifact_hash: Given a filespec for an artifact file, store its hash in the global ArtifactHashMap

    Args:
        artifactFileSpec - a filename for an artifact file
        artifactFileHash - the hash for the artifact file; if not yet calculated, it will be

    Returns:
        the hash for the artifact file as stored in ArtifactHashMap
    """
    global ArtifactHashMap
    if tmpHash := artifactFileHash if artifactFileHash else shakey_file_hash(artifactFileSpec):
        ArtifactHashMap[artifactFileSpec] = tmpHash
    return ArtifactHashMap[artifactFileSpec]


def get_artifact_hash_map():
    """
    get_artifact_hash_map: Return the global ArtifactHashMap object

    Args:
        None

    Returns:
        the global ArtifactHashMap object
    """
    global ArtifactHashMap
    return ArtifactHashMap


def get_malcolm_http_auth(info=None):
    """
    get_malcolm_http_auth: Return a HTTPBasicAuth object with username and password
    from the provided info dict, or from global MalcolmVmInfo if one is not provided

    Args:
        info - an dict containing info for a MalcolmVM object (see MalcolmVM.Info)

    Returns:
        an HTTPBasicAuth with username and password from info, or None for invalid input
    """
    global MalcolmVmInfo
    if tmpInfo := info if info else MalcolmVmInfo:
        return HTTPBasicAuth(
            tmpInfo.get('username', ''),
            tmpInfo.get('password', ''),
        )
    else:
        return None


def get_malcolm_url(info=None):
    """
    get_malcolm_url: Return the Malcolm URL from the provided info dict, or from the
    global MalcolmVmInfo if one is not provided

    Args:
        info - an dict containing info for a MalcolmVM object (see MalcolmVM.Info)

    Returns:
        the Malcolm URL with https:// prefix
    """
    global MalcolmVmInfo
    if tmpInfo := info if info else MalcolmVmInfo:
        return f"https://{tmpInfo.get('ip', '')}"
    else:
        return 'http://localhost'


def get_database_objs(info=None):
    """
    get_database_objs: Return the DatabaseObjs class from the provided info dict, or from the
    global MalcolmVmInfo if one is not provided

    Args:
        info - an dict containing info for a MalcolmVM object (see MalcolmVM.Info)

    Returns:
        the DatabaseObjs object stored as 'database_objs' in the info dict
    """
    global MalcolmVmInfo
    if tmpInfo := info if info else MalcolmVmInfo:
        return tmpInfo.get('database_objs', DatabaseObjs())
    else:
        return DatabaseObjs()


class DatabaseObjs(object):
    """
    DatabaseObjs: Parent class for objects containing classes references
    for either the OpenSearch or Elasticsearch Python libraries

    Attributes:
        DatabaseClass    - the OpenSearch or Elasticsearch class
        SearchClass      - the Search class
        AggregationClass - the Aggregation class
        DatabaseInitArgs - a dict of arguments to pass into the DatabaseClass
                           constructor (e.g., **obj.DatabaseInitArgs)
    """

    def __init__(self):
        """
        __init__: Initialize object attributes to their "unset" values

        Args:
            None

        Returns:
            None
        """
        self.DatabaseClass = None
        self.SearchClass = None
        self.AggregationClass = None
        self.DatabaseInitArgs = defaultdict(lambda: None)
        self.DatabaseInitArgs['request_timeout'] = 1
        self.DatabaseInitArgs['verify_certs'] = False
        self.DatabaseInitArgs['ssl_assert_hostname'] = False
        self.DatabaseInitArgs['ssl_show_warn'] = False


class OpenSearchObjs(DatabaseObjs):
    """
    OpenSearchObjs: Child class of DatabaseObjs for OpenSearch Python library

    Attributes:
        OpenSearchImport - the opensearchpy import (dynamically imported)
    """

    def __init__(self, username=None, password=None):
        """
        __init__: Sets the class references and initialization args for using
        the OpenSearch python library

        Args:
            username - the username string to set in the http_auth init argument
            password - the password string to set in the http_auth init argument

        Returns:
            None
        """
        super().__init__()
        self.OpenSearchImport = mmguero.DoDynamicImport('opensearchpy', 'opensearch-py', interactive=False)
        if self.OpenSearchImport:
            self.DatabaseClass = self.OpenSearchImport.OpenSearch
            self.SearchClass = self.OpenSearchImport.Search
            self.AggregationClass = self.OpenSearchImport.A
        if username:
            self.DatabaseInitArgs['http_auth'] = (username, password)


class ElasticsearchObjs(DatabaseObjs):
    """
    ElasticsearchObjs: Child class of DatabaseObjs for Elasticsearch and Elasticsearch-DSL Python library

    Attributes:
        ElasticImport - the elasticsearch import (dynamically imported)
        ElasticDslImport - the elasticsearch_dsl import (dynamically imported)
    """

    def __init__(self, username=None, password=None):
        """
        __init__: Sets the class references and initialization args for using
        the Elasticsearch/Elasticsearch-DSL python libraries

        Args:
            username - the username string to set in the basic_auth init argument
            password - the password string to set in the basic_auth init argument

        Returns:
            None
        """
        super().__init__()
        self.ElasticImport = mmguero.DoDynamicImport('elasticsearch', 'elasticsearch', interactive=False)
        self.ElasticDslImport = mmguero.DoDynamicImport('elasticsearch_dsl', 'elasticsearch-dsl', interactive=False)
        if self.ElasticImport:
            self.DatabaseClass = self.elasticImport.Elasticsearch
        if self.ElasticDslImport:
            self.SearchClass = self.elasticDslImport.Search
            self.AggregationClass = self.elasticDslImport.A
        if username:
            self.DatabaseInitArgs['basic_auth'] = (username, password)


class MalcolmTestCollection(object):
    """
    MalcolmTestCollection: A pytest plugin (https://docs.pytest.org/en/stable/how-to/writing_plugins.html)
    used to hook pytest_collection_modifyitems to gather the list of tests to be run
    by pytest. To be used with pytest's --collect-only option, e.g.:

        testSetPreExec = MalcolmTestCollection()
        pytest.main(['--collect-only', '-p', 'no:terminal'], plugins=[testSetPreExec])
        if testSetPreExec.collected:
            for artifactFile, artifactAttrs in testSetPreExec.ArtifactsReferenced().items():
                ...

    This allows for determining artifacts used by tests prior to running the tests themselves.

    Attributes:
        logger - the Python logging object for debug, info, warning, etc.
        collected - a set of the pytest files to be run
    """

    def __init__(self, logger=None):
        """
        __init__: Initialize the MalcolmTestCollection to default values

        Args:
            logger - the Python logging object for debug, info, warning, etc.

        Returns:
            None
        """
        self.logger = logger
        self.collected = set()

    def pytest_collection_modifyitems(self, items):
        """
        pytest_collection_modifyitems: Hook for pytest called after test collection has been performed
        see https://docs.pytest.org/en/latest/reference/reference.html#pytest.hookspec.pytest_collection_modifyitems

        Args:
            items - list of item objects

        Returns:
            None
        """
        for item in items:
            self.collected.add(str(item.reportinfo()[0]))

    def ArtifactsReferenced(self):
        """
        ArtifactsReferenced: Process collected pytest test files by parsing them and looking for UPLOAD_ARTIFACTS,
        which are then collected into a set of all referenced artifacts to be uploaded.
        This can be used to upload these artifacts to Malcolm and make sure they finish processing prior to
        running the tests that depend on them. Other variables looked for include:
            NETBOX_ENRICH - True to indicate that the artifact should be NetBox-enriched, otherwise it will not be;
                            sets "netbox" in file sub-dict to True or False

        Args:
            None

        Returns:
            A dict of all files defined in UPLOAD_ARTIFACTS for all tests to be run, where the
            key is the file name and the value is a dict containing other relevant information, e.g.:
            {
                "foobar.pcap" : {
                    "netbox": True
                },
                "barbaz.pcap" : {
                    "netbox": False
                },
            }
        """
        result = dict()
        for testPyPath in self.collected:
            try:
                testArtifactList = list()
                testNetBoxEnrich = False
                with open(testPyPath, "r") as f:
                    testPyContent = f.read()
                for node in ast.walk(ast.parse(testPyContent)):
                    if isinstance(node, ast.Assign):
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                if target.id == UPLOAD_ARTIFACT_LIST_NAME:
                                    testArtifactList.append(ast.literal_eval(node.value))
                                elif target.id == NETBOX_ENRICH_BOOL_NAME:
                                    testNetBoxEnrich = mmguero.str2bool(str(ast.literal_eval(node.value)))
                for artifact in list(set(mmguero.Flatten(testArtifactList))):
                    if artifact not in result:
                        result[artifact] = defaultdict(lambda: None)
                    if testNetBoxEnrich:
                        result[artifact]["netbox"] = True
            except FileNotFoundError:
                self.logger.error(f"Error: '{testPyPath}' not found")
            except SyntaxError:
                self.logger.error(f"Error: '{testPyPath}' has invalid syntax")
            except ValueError as ve:
                self.logger.error(f"Error: Unable to evaulate '{variable_name}' in '{testPyPath}': {ve}")
            except Exception as e:
                self.logger.error(f"Error: '{testPyPath}': {e}")
        return result


###################################################################################################
class MalcolmVM(object):
    """
    MalcolmVM: Represents a Malcolm instance running inside a virter-managed libvirt virtual machine

    Attributes:
        ...                         - all attributes from argparse.Namespace are added as attributes
        apiSession                  - a requests.Session() object to be used to cache HTTP connections
        buildMode                   - True if we are only building a vm (virter image build), False otherwise
        buildNameCur                - the name of the current layer of the vm being build (if buildMode == True)
        buildNamePre                - the name of the parent layer of the vm being build (if buildMode == True)
        dbObjs                      - the DatabaseObjs object with the class reference for this Malcolm's DB type
        debug                       - True or False if debug flags have been set (logging level >= DEBUG)
        logger                      - the Python logging object for debug, info, warning, etc.
        malcolmPassword             - username str for the Malcolm instance
        malcolmUsername             - password str for the Malcolm instance
        osEnv                       - a copy of the system's environment variables which may be tweaked to run subprocesses
        provisionEnvArgs            - a dict of arguments to pass to virter during provisioning, mainly containing environment variables
        provisionErrorEncountered   - True if an error was encountered during provisioning, False otherwise
        vmTomlMalcolmFiniPath       - path for Malcolm "fini" TOML provisioning files
        vmTomlMalcolmInitPath       - path for Malcolm "init" TOML provisioning files
        vmTomlVMFiniPath            - path for VM "fini" TOML provisioning files
        vmTomlVMInitPath            - path for VM "init" TOML provisioning files
    """

    def __init__(
        self,
        args,
        debug=False,
        logger=None,
    ):
        """
        __init__: Initialize a new MalcolmVM object by processing some environment variables
        and preparing to run virter commands

        Args:
            args   - an argparse.Namespace (as-is from parse_known_args via command-line arguments, see parser in maltest.py)
            debug  - True or False if debug flags have been set (logging level >= DEBUG)
            logger - the Python logging object for debug, info, warning, etc.

        Returns:
            None
        """

        # copy all attributes from the argparse Namespace to the object itself
        for key, value in vars(args).items():
            setattr(self, key, value)

        self.debug = debug
        self.logger = logger
        self.apiSession = requests.Session()
        self.dbObjs = None
        self.provisionErrorEncountered = False

        self.buildMode = False
        self.buildNameCur = ''
        self.buildNamePre = []

        self.vmTomlMalcolmInitPath = os.path.join(self.vmProvisionPath, 'malcolm-init')
        self.vmTomlMalcolmFiniPath = os.path.join(self.vmProvisionPath, 'malcolm-fini')
        self.vmTomlVMInitPath = os.path.join(self.vmProvisionPath, os.path.join(self.vmImage, 'init'))
        self.vmTomlVMFiniPath = os.path.join(self.vmProvisionPath, os.path.join(self.vmImage, 'fini'))

        self.osEnv = os.environ.copy()

        self.provisionEnvArgs = [
            '--set',
            f"env.VERBOSE={str(debug).lower()}",
            '--set',
            f"env.REPO_URL={self.repoUrl}",
            '--set',
            f"env.REPO_BRANCH={self.repoBranch}",
            '--set',
            f"env.DEBIAN_FRONTEND=noninteractive",
            '--set',
            f"env.TERM=xterm",
        ]

        # We will take any environment variables prefixed with MALCOLM_
        #   and pass them in as environment variables during provisioning
        for varName, varVal in [
            (key.upper(), value)
            for key, value in self.osEnv.items()
            if key.upper().startswith('MALCOLM_')
            and key.upper()
            not in (
                'MALCOLM_REPO_URL',
                'MALCOLM_REPO_BRANCH',
                'MALCOLM_TEST_PATH',
                'MALCOLM_TEST_ARTIFACTS_PATH',
                'MALCOLM_AUTH_PASSWORD',
                'MALCOLM_AUTH_USERNAME',
            )
        ]:
            self.provisionEnvArgs.extend(
                [
                    '--set',
                    f"env.{varName.removeprefix('MALCOLM_')}={varVal}",
                ]
            )

        # MALCOLM_AUTH_PASSWORD is a special case: we need to create the appropriate hashes
        #   for that value (openssl and htpasswd versions) and set them as
        #   AUTH_PASSWORD_OPENSSL and AUTH_PASSWORD_HTPASSWD, respectively.
        # These are the defaults set in 02-auth-setup.toml, don't be stupid and use them in production.
        self.malcolmUsername = self.osEnv.get('MALCOLM_AUTH_USERNAME', 'maltest')
        self.provisionEnvArgs.extend(
            [
                '--set',
                f"env.AUTH_USERNAME={self.malcolmUsername}",
            ]
        )
        self.malcolmPassword = self.osEnv.get('MALCOLM_AUTH_PASSWORD', 'M@lc0lm')
        err, out = mmguero.RunProcess(
            ['openssl', 'passwd', '-quiet', '-stdin', '-1'],
            stdout=True,
            stderr=False,
            stdin=self.malcolmPassword,
            env=self.osEnv,
            debug=self.debug,
            logger=self.logger,
        )
        if (err == 0) and (len(out) > 0):
            self.provisionEnvArgs.extend(
                [
                    '--set',
                    f"env.AUTH_PASSWORD_OPENSSL={out[0]}",
                ]
            )
        err, out = mmguero.RunProcess(
            ['htpasswd', '-i', '-n', '-B', self.malcolmUsername],
            stdout=True,
            stderr=False,
            stdin=self.malcolmPassword,
            env=self.osEnv,
            debug=self.debug,
            logger=self.logger,
        )
        if (err == 0) and (len(out) > 0) and (pwVals := out[0].split(':')) and (len(pwVals) >= 2):
            self.provisionEnvArgs.extend(
                [
                    '--set',
                    f"env.AUTH_PASSWORD_HTPASSWD={pwVals[1]}",
                ]
            )

    def __del__(self):
        """
        __del__: Finalize a running Malcolm virter VM by finalizing any remaining provisioning and,
        if requested, destroying the VM

        Args:
            None

        Returns:
            None
        """
        try:
            # if there are any remaining provisioning steps, handle them now
            self.ProvisionFini()
        finally:
            # if requested, make sure to shut down the VM
            if self.removeAfterExec and not self.buildMode:
                tmpExitCode, output = mmguero.RunProcess(
                    ['virter', 'vm', 'rm', self.name],
                    env=self.osEnv,
                    debug=self.debug,
                    logger=self.logger,
                )
                self.PrintVirterLogOutput(output)

    def PrintVirterLogOutput(self, output):
        """
        PrintVirterLogOutput: log (with INFO severity) virter command output for debugging purposes

        Args:
            output - the output from a "virter" command"

        Returns:
            None
        """
        for x in mmguero.GetIterable(output):
            if x:
                self.logger.info(parse_virter_log_line(x)['msg'])

    def Exists(self):
        """
        Exists: Ascertain whether or not the virter VM this object represents is actually running

        Args:
            None

        Returns:
            True if "virter vm exists" succeeds with a 0 error code, False otherwise
        """
        exitCode, output = mmguero.RunProcess(
            ['virter', 'vm', 'exists', self.name],
            env=self.osEnv,
            debug=self.debug,
            logger=self.logger,
        )
        return bool(exitCode == 0)

    def Ready(self, waitUntilReadyOrTimeout=True):
        """
        Ready: Connect to the Malcolm "ready" API and check if all of the MALCOLM_READY_REQUIRED_COMPONENTS
        services return that they are up and running, optionally waiting up to MALCOLM_READY_TIMEOUT_SECONDS

        Args:
            waitUntilReadyOrTimeout - if True, wait up to MALCOLM_READY_TIMEOUT_SECONDS seconds until ready

        Returns:
            True if the Malcolm instance is ready to process data, False otherwise
        """
        global ShuttingDown
        ready = False

        if not self.buildMode:

            url, auth = self.ConnectionParams()

            startWaitEnd = time.time() + MALCOLM_READY_TIMEOUT_SECONDS
            while (ready == False) and (ShuttingDown[0] == False) and (time.time() < startWaitEnd):
                try:
                    response = self.apiSession.get(
                        f"{url}/mapi/ready",
                        allow_redirects=True,
                        auth=auth,
                        verify=False,
                    )
                    response.raise_for_status()
                    readyInfo = response.json()
                    self.logger.debug(json.dumps(readyInfo))
                    # "ready" means the services required for PCAP processing are running
                    ready = isinstance(readyInfo, dict) and all(
                        [readyInfo.get(x, False) for x in MALCOLM_READY_REQUIRED_COMPONENTS]
                    )
                except Exception as e:
                    self.logger.warning(f"Error \"{e}\" waiting for Malcolm to become ready")

                if not ready:
                    if waitUntilReadyOrTimeout:
                        sleepCtr = 0
                        while (
                            (ShuttingDown[0] == False)
                            and (sleepCtr < MALCOLM_READY_CHECK_PERIOD_SECONDS)
                            and (time.time() < startWaitEnd)
                        ):
                            sleepCtr = sleepCtr + 1
                            time.sleep(1)
                    else:
                        break

            if ready:
                self.logger.info(f'Malcolm instance at {url} is up and ready to process data')
            elif waitUntilReadyOrTimeout:
                self.logger.error(f'Malcolm instance at {url} never became ready')
            else:
                self.logger.info(f'Malcolm instance at {url} not yet ready')

        return ready

    def WaitForLastEventTime(
        self,
        lastDocIngestAge=MALCOLM_LAST_INGEST_AGE_SECONDS_THRESHOLD,
        timeout=MALCOLM_LAST_INGEST_AGE_SECONDS_TIMEOUT,
        doctype='network',
    ):
        """
        WaitForLastEventTime: Wait until the last time Malcolm processed a network traffic log is at least
        some period in the past, up to a given timeout. In other words, "make sure the latest log is at least
        N seconds old."

        Args:
            lastDocIngestAge - the number of seconds in the past the most recently-ingested network traffic log
                               must be before returning True
            timeout - to avoid waiting forever, return regardless if the time exceeds this number of seconds
            doctype - network|host (for MALCOLM_NETWORK_INDEX_PATTERN vs MALCOLM_OTHER_INDEX_PATTERN)

        Returns:
            True if the most recentlyly-ingested log was ingested at least lastDocIngestAge ago, False on timeout
        """

        global ShuttingDown
        result = False

        if not self.buildMode:

            url, auth = self.ConnectionParams()

            timeoutEnd = time.time() + timeout
            while (result == False) and (ShuttingDown[0] == False) and (time.time() < timeoutEnd):
                try:
                    # check the ingest statistics which returns a dict of host.name -> event.ingested
                    response = self.apiSession.get(
                        f"{url}/mapi/ingest-stats?doctype={doctype}",
                        allow_redirects=True,
                        auth=auth,
                        verify=False,
                    )
                    response.raise_for_status()
                    dataSourceStats = response.json()
                    self.logger.debug(json.dumps(dataSourceStats))
                except Exception as e:
                    self.logger.warning(f"Error \"{e}\" getting ingest statistics")
                    dataSourceStats = {}

                if (
                    isinstance(dataSourceStats, dict)
                    and ("sources" in dataSourceStats)
                    and isinstance(dataSourceStats["sources"], dict)
                    and dataSourceStats["sources"]
                    and all(
                        (
                            (datetime.now(timezone.utc) - datetime.fromisoformat(timestamp)).total_seconds()
                            > lastDocIngestAge
                        )
                        for timestamp in dataSourceStats["sources"].values()
                    )
                ):
                    # We received a dict of host.name -> event.ingested, it has
                    #   at least some data in it, and every one of the timestamps
                    #   is older than the threshold. We can assume all data
                    #   has been ingested and the system is "idle".
                    result = True

                else:
                    # We haven't yet reached "idle" state with regards to our
                    #   log ingestion, so sleep for a bit and check again.
                    sleepCtr = 0
                    while (
                        (ShuttingDown[0] == False)
                        and (sleepCtr < MALCOLM_READY_CHECK_PERIOD_SECONDS)
                        and (time.time() < timeoutEnd)
                    ):
                        sleepCtr = sleepCtr + 1
                        time.sleep(1)

        return result

    def ArkimeAlreadyHasFile(
        self,
        filename,
    ):
        """
        ArkimeAlreadyHasFile: Query Arkime's files index to see if it's already processed a file

        Args:
            filename - the artifact filename to query

        Returns:
            True if Arkime has already seen a file with this name, False otherwise
        """
        result = False

        if not self.buildMode:
            url, auth = self.ConnectionParams()
            if self.dbObjs:
                try:
                    s = self.dbObjs.SearchClass(
                        using=self.dbObjs.DatabaseClass(
                            hosts=[
                                f"{url}/mapi/opensearch",
                            ],
                            **self.dbObjs.DatabaseInitArgs,
                        ),
                        index=ARKIME_FILES_INDEX,
                        # note that the query here is *foobar.pcap, so it will match both
                        #   foobar.pcap and NBSITEID0,foobar.pcap
                    ).query("wildcard", name=f"*{os.path.basename(filename)}")
                    response = s.execute()
                    for hit in response:
                        fileInfo = hit.to_dict()
                        if (ARKIME_FILE_SIZE_FIELD in fileInfo) and (fileInfo[ARKIME_FILE_SIZE_FIELD] > 0):
                            result = True
                            break
                except Exception as e:
                    self.logger.warning(f"Error \"{e}\" getting files list")
                    dataSourceStats = {}
            self.logger.debug(f'ArkimeAlreadyHasFile({filename}): {result}')

        return result

    # for the running vm represented by this object, return something like this:
    # {
    #   "id": "136",
    #   "network": "default",
    #   "mac": "52:54:00:00:00:88",
    #   "ip": "192.168.122.136",
    #   "hostname": "malcolm-136",
    #   "host_device": "vnet0"
    # }
    def Info(self):
        """
        Info: Return a dict containing information about the VM and the Malcolm instance
        Example output:
            {
              "id": "254",
              "name": "malcolm-free-asp",
              "network": "default",
              "mac": "52:54:00:00:00:fe",
              "ip": "192.168.122.254",
              "hostname": "malcolm-free-asp",
              "host_device": "vnet0",
              "username": "xxxxxxx",
              "password": "yyyyyyy",
              "version": {
                <contents of Malcolm's /mapi/version API>
              },
              "database_objs": <self.dbObjs>
            }

        Args:
            None

        Returns:
            dict containing information about the VM and the Malcolm instance
        """
        result = {}
        # list the VMs so we can figure out the host network name of this one
        exitCode, output = mmguero.RunProcess(
            ['virter', 'vm', 'list'],
            env=self.osEnv,
            debug=self.debug,
            logger=self.logger,
        )
        if (exitCode == 0) and (len(output) > 1):
            # split apart VM name, id, and network name info a dict
            vmListRegex = re.compile(r'(\S+)(?:\s+(\S+))?(?:\s+(.*))?')
            vms = {}
            for line in output[1:]:
                if match := vmListRegex.match(line):
                    name = match.group(1)
                    id_ = match.group(2) if match.group(2) else None
                    network = match.group(3).strip() if match.group(3) else None
                    vms[name] = {"id": id_, "name": name, "network": network}
            # see if we found this vm in the list of VMs returned
            result = vms.get(self.name, {})
            if result and result.get('network', None):
                # get additional information about this VM's networking
                exitCode, output = mmguero.RunProcess(
                    ['virter', 'network', 'list-attached', result['network']],
                    env=self.osEnv,
                    debug=self.debug,
                    logger=self.logger,
                )
                if (exitCode == 0) and (len(output) > 1):
                    # populate the result with the mac address, IP, hostname, and host device name
                    for line in output[1:]:
                        if (vals := line.split()) and (len(vals) >= 2) and (vals[0] == self.name):
                            result['mac'] = vals[1]
                            if len(vals) >= 3:
                                result['ip'] = vals[2]
                            if len(vals) >= 4:
                                result['hostname'] = vals[3]
                            if len(vals) >= 5:
                                result['host_device'] = vals[4]

        result['username'] = self.malcolmUsername
        result['password'] = self.malcolmPassword

        # last but not least, try to access the API to get the version info
        try:
            response = self.apiSession.get(
                f"{get_malcolm_url(result)}/mapi/version",
                allow_redirects=True,
                auth=get_malcolm_http_auth(result),
                verify=False,
            )
            response.raise_for_status()
            if versionInfo := response.json():
                result['version'] = versionInfo
        except Exception as e:
            self.logger.warning(f"Error getting version API: {e}")

        try:
            # the first time we call Info for this object, set up our database classes, etc.
            if self.dbObjs is None:
                self.dbObjs = (
                    ElasticsearchObjs(self.malcolmUsername, self.malcolmPassword)
                    if ('elastic' in mmguero.DeepGet(result, ['version', 'mode'], '').lower())
                    else OpenSearchObjs(self.malcolmUsername, self.malcolmPassword)
                )
        except Exception as e:
            self.logger.error(f"Error getting database objects: {e}")

        result['database_objs'] = self.dbObjs

        return result

    def ConnectionParams(self):
        """
        ConnectionParams: return the URL and HTTP auth parameters from this object's Info

        Args:
            None

        Returns:
            a tuple containing the Malcolm URL and HTTPBasicAuth information
        """
        if tmpInfo := self.Info():
            return get_malcolm_url(tmpInfo), get_malcolm_http_auth(tmpInfo)
        else:
            return None, None

    def Build(self):
        """
        Build: Use "virter image build" to build and provision a VM and tag it for later reuse

        Args:
            None

        Returns:
            0 upon success
        """
        self.buildMode = True

        # use virter to build a new virtual machine image
        if not self.vmBuildName:
            self.vmBuildName = petname.Generate()
        self.buildNameCur = ''
        self.buildNamePre.append(self.vmImage)
        self.ProvisionInit()

        return 0

    def Start(self):
        """
        Start: Start a virter VM (or adopt an existing one) and provision it

        Args:
            None

        Returns:
            exit code from "virter vm run" command
        """
        global ShuttingDown

        self.buildMode = False

        cmd = []
        output = []
        exitCode = 1
        if self.vmExistingName:
            # use an existing VM (by name)
            self.name = self.vmExistingName
            if self.Exists():
                self.logger.info(f'{self.name} exists as indicated')
                exitCode = 0
            else:
                self.logger.error(f'{self.name} does not already exist')

        elif ShuttingDown[0] == False:
            # use virter to execute a virtual machine
            self.name = f"{self.vmNamePrefix}-{petname.Generate()}"
            cmd = [
                'virter',
                'vm',
                'run',
                self.vmImage,
                '--id',
                '0',
                '--name',
                self.name,
                '--vcpus',
                self.vmCpuCount,
                '--memory',
                f'{self.vmMemoryGigabytes}GB',
                '--bootcapacity',
                f'{self.vmDiskGigabytes}GB',
                '--user',
                self.vmImageUsername,
                '--wait-ssh',
            ]

            cmd = [str(x) for x in list(mmguero.Flatten(cmd))]
            self.logger.info(cmd)
            exitCode, output = mmguero.RunProcess(
                cmd,
                env=self.osEnv,
                debug=self.debug,
                logger=self.logger,
            )

        if exitCode == 0:
            self.PrintVirterLogOutput(output)
            time.sleep(5)
            self.ProvisionInit()
        else:
            raise subprocess.CalledProcessError(exitCode, cmd, output=output)

        self.logger.info(f'{self.name} is provisioned and running')
        return exitCode

    def ProvisionFile(
        self,
        provisionFile,
        continueThroughShutdown=False,
        tolerateFailure=False,
        overrideBuildName=None,
    ):
        """
        ProvisionFile: Execute provisioning steps (provided in a TOML file) for this VM

        Args:
            provisionFile           - a TOML file containing provisioning steps
                                      (see https://github.com/LINBIT/virter/blob/master/doc/provisioning.md)
            continueThroughShutdown - if True, will execute even if ShuttingDown is True
            tolerateFailure         - if True, will not abort the operation even if an error is encountered
            overrideBuildName       - if in build mode, use this for the layer name instead of autocreating one

        Returns:
            exit code from virter command(s)
        """

        global ShuttingDown
        skipped = False

        out = []
        cmd = []
        if (ShuttingDown[0] == False) or (continueThroughShutdown == True):

            if self.buildMode:
                if 'reboot' in os.path.basename(provisionFile).lower():
                    skipped = True
                else:
                    self.name = f"{self.vmNamePrefix}-{petname.Generate()}"
                    self.buildNameCur = overrideBuildName if overrideBuildName else petname.Generate()
                    cmd = [
                        'virter',
                        'image',
                        'build',
                        self.buildNamePre[-1],
                        self.buildNameCur,
                        '--id',
                        '0',
                        '--name',
                        self.name,
                        '--vcpus',
                        self.vmCpuCount,
                        '--memory',
                        f'{self.vmMemoryGigabytes}GB',
                        '--bootcap',
                        f'{self.vmDiskGigabytes}GB',
                        '--provision',
                        provisionFile,
                        '--user',
                        self.vmImageUsername,
                    ]
            else:
                cmd = [
                    'virter',
                    'vm',
                    'exec',
                    self.name,
                    '--provision',
                    provisionFile,
                ]

            if skipped:
                code = 0
                out = []
            else:
                if self.provisionEnvArgs:
                    cmd.extend(self.provisionEnvArgs)
                cmd = [str(x) for x in list(mmguero.Flatten(cmd))]
                self.logger.info(cmd)
                code, out = mmguero.RunProcess(
                    cmd,
                    env=self.osEnv,
                    debug=self.debug,
                    logger=self.logger,
                )

            if code != 0:
                debugInfo = dict()
                debugInfo['code'] = code
                debugInfo['response'] = out
                try:
                    with open(provisionFile, "rb") as f:
                        debugInfo['request'] = tomli.load(f)
                except:
                    pass
                if tolerateFailure:
                    self.logger.warning(json.dumps(debugInfo))
                else:
                    self.logger.error(json.dumps(debugInfo))

            if (code == 0) or (tolerateFailure == True):
                code = 0
                self.PrintVirterLogOutput(out)
                time.sleep(5)
                if self.buildMode and (skipped == False):
                    self.buildNamePre.append(self.buildNameCur)
            else:
                self.provisionErrorEncountered = True
                raise subprocess.CalledProcessError(code, cmd, output=out)

        else:
            code = 1

        return code

    def ProvisionTOML(
        self,
        data,
        continueThroughShutdown=False,
        tolerateFailure=False,
        overrideBuildName=None,
    ):
        """
        ProvisionTOML: Save provided data as a TOML file and provision it (see ProvisionFile)

        Args:
            data                    - data structure to convert to TOML for provisioning
            continueThroughShutdown - if True, will execute even if ShuttingDown is True
            tolerateFailure         - if True, will not abort the operation even if an error is encountered
            overrideBuildName       - if in build mode, use this for the layer name instead of autocreating one

        Returns:
            exit code from ProvisionFile
        """
        with mmguero.TemporaryFilename(suffix='.toml') as tomlFileName:
            with open(tomlFileName, 'w') as tomlFile:
                tomlFile.write(tomli_w.dumps(data))
            return self.ProvisionFile(
                tomlFileName,
                continueThroughShutdown=continueThroughShutdown,
                tolerateFailure=tolerateFailure,
                overrideBuildName=overrideBuildName,
            )

    def CopyFile(
        self,
        sourceFileSpec,
        destFileSpec,
        makeDestDirWorldWritable=False,
        continueThroughShutdown=False,
        tolerateFailure=False,
        overrideBuildName=None,
    ):
        """
        CopyFile: Perform a file copy operation with the virter VM (virter vm cp)

        Args:
            sourceFileSpec           - source filespec on the local machine
            destFileSpec             - destination filespec on the VM
            makeDestDirWorldWritable - if True, will mkdir -p and chmod 777 the destination directory first
            continueThroughShutdown  - if True, will execute even if ShuttingDown is True
            tolerateFailure          - if True, will not abort the operation even if an error is encountered
            overrideBuildName        - if in build mode, use this for the layer name instead of autocreating one

        Returns:
            exit code from the virter command(s)
        """
        code = 0
        if makeDestDirWorldWritable:
            code = self.ProvisionTOML(
                data={
                    'version': 1,
                    'steps': [
                        {
                            'shell': {
                                'script': f'sudo mkdir -p {os.path.dirname(destFileSpec)}\n'
                                f'sudo chmod 777 {os.path.dirname(destFileSpec)}\n'
                            }
                        }
                    ],
                },
                continueThroughShutdown=continueThroughShutdown,
                tolerateFailure=tolerateFailure,
                overrideBuildName=overrideBuildName,
            )
        if (code == 0) or (tolerateFailure == True):
            code = self.ProvisionTOML(
                data={
                    'version': 1,
                    'steps': [
                        {
                            'rsync': {
                                'source': sourceFileSpec,
                                'dest': destFileSpec,
                            }
                        }
                    ],
                },
                continueThroughShutdown=continueThroughShutdown,
                tolerateFailure=tolerateFailure,
                overrideBuildName=overrideBuildName,
            )
        return code

    def ProvisionInit(self):
        """
        ProvisionInit: Execute "initialization" provisioning steps, first for the VM and
        then for Malcolm itself, then start Malcolm if requested

        Args:
            None

        Returns:
            None
        """
        global ShuttingDown

        if self.vmProvisionOS and os.path.isdir(self.vmTomlVMInitPath):
            # first execute any provisioning in this image's "init" directory, if it exists
            #   (this needs to install rsync if it's not already part of the image)
            for provisionFile in sorted(glob.glob(os.path.join(self.vmTomlVMInitPath, '*.toml'))):
                self.ProvisionFile(provisionFile)

        if self.vmProvisionMalcolm and os.path.isdir(self.vmTomlMalcolmInitPath):
            # now, rsync the container image file to the VM if specified
            if self.containerImageFile:
                if (
                    self.CopyFile(
                        self.containerImageFile,
                        '/usr/local/share/images/malcolm_images.tar.xz',
                        makeDestDirWorldWritable=True,
                    )
                    == 0
                ):
                    self.provisionEnvArgs.extend(
                        [
                            '--set',
                            f"env.IMAGE_FILE=/usr/local/share/images/malcolm_images.tar.xz",
                        ]
                    )

            # now execute provisioning from the "malcolm init" directory
            for provisionFile in sorted(glob.glob(os.path.join(self.vmTomlMalcolmInitPath, '*.toml'))):
                self.ProvisionFile(provisionFile)

        # rsync the netbox database restore file to the VM if specified
        if self.netboxRestoreFile:
            if (
                self.CopyFile(
                    self.netboxRestoreFile,
                    f'/home/{self.vmImageUsername}/Malcolm/netbox/preload/{os.path.basename(self.netboxRestoreFile)}',
                )
                != 0
            ):
                self.logger.warning(f"Error copying the NetBox backup file to ./netbox/preload")

        # sleep a bit, if indicated
        sleepCtr = 0
        while (ShuttingDown[0] == False) and (self.buildMode == False) and (sleepCtr < self.postInitSleep):
            sleepCtr = sleepCtr + 1
            time.sleep(1)

        if (self.buildMode == False) and self.startMalcolm and (ShuttingDown[0] == False):
            # run ./scripts/start but return shortly
            if (
                self.ProvisionTOML(
                    data={
                        'version': 1,
                        'steps': [
                            {
                                'shell': {
                                    'script': (
                                        "pushd ~/Malcolm &>/dev/null\n"
                                        "~/Malcolm/scripts/start &>/dev/null &\n"
                                        "START_PID=$!\n"
                                        f"sleep {MALCOLM_READY_CHECK_PERIOD_SECONDS}\n"
                                        "kill $START_PID\n"
                                        "echo 'Malcolm is starting...'\n"
                                        "popd &>/dev/null\n"
                                    )
                                }
                            }
                        ],
                    }
                )
                == 0
            ):
                self.apiSession = requests.Session()

    def ProvisionFini(self):
        """
        ProvisionFini: Execute "finalization" provisioning steps, first for the Malcolm and then the VM.
        These steps only execute if no fatal initialization provisioning errors were encountered. Also,
        if we're in "build mode", then the final build layer will be tagged with the name provided.

        Args:
            None

        Returns:
            None
        """

        if not self.provisionErrorEncountered:

            # now execute provisioning from the "malcolm fini" directory
            if self.vmProvisionMalcolm and os.path.isdir(self.vmTomlMalcolmFiniPath):
                for provisionFile in sorted(glob.glob(os.path.join(self.vmTomlMalcolmFiniPath, '*.toml'))):
                    self.ProvisionFile(provisionFile, continueThroughShutdown=True, tolerateFailure=True)

            # finally, execute any provisioning in this image's "fini" directory, if it exists
            if self.vmProvisionOS and os.path.isdir(self.vmTomlVMFiniPath):
                for provisionFile in sorted(glob.glob(os.path.join(self.vmTomlVMFiniPath, '*.toml'))):
                    self.ProvisionFile(provisionFile, continueThroughShutdown=True, tolerateFailure=True)

        # if we're in a build mode, we need to "tag" our final build
        if self.buildMode and self.buildNameCur:
            if not self.provisionErrorEncountered:
                self.ProvisionTOML(
                    data={
                        'version': 1,
                        'steps': [
                            {
                                'shell': {
                                    'script': '''
                                        echo "Image provisioned"
                                    '''
                                }
                            }
                        ],
                    },
                    continueThroughShutdown=True,
                    tolerateFailure=True,
                    overrideBuildName=self.vmBuildName,
                )
            if not self.vmBuildKeepLayers and self.buildNamePre:
                for layer in self.buildNamePre:
                    if layer not in [self.vmBuildName, self.vmImage]:
                        tmpCode, tmpOut = mmguero.RunProcess(
                            ['virter', 'image', 'rm', layer],
                            env=self.osEnv,
                            debug=self.debug,
                            logger=self.logger,
                        )

    def WaitForShutdown(self):
        """
        WaitForShutdown: Wait forever as long ShuttingDown is False and the VM Exists(). If the VM
        appears to go away, wait five minutes before giving up and returning.

        Args:
            None

        Returns:
            0 if ShuttingDown became True, 1 if the VM disappeared
        """
        global ShuttingDown

        returnCode = 0
        sleepCtr = 0
        noExistCtr = 0

        while ShuttingDown[0] == False:
            time.sleep(1)
            sleepCtr = sleepCtr + 1
            if sleepCtr > 60:
                sleepCtr = 0
                if self.Exists():
                    noExistCtr = 0
                else:
                    noExistCtr = noExistCtr + 1
                    self.logger.warning(f'Failed to ascertain existence of {self.name} (x {noExistCtr})')
                    if noExistCtr >= 5:
                        self.logger.error(f'{self.name} no longer exists, giving up')
                        ShuttingDown[0] = True
                        returnCode = 1

        return returnCode
