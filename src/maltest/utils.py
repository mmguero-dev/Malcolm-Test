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

MALTEST_PROJECT_NAME = "malcolm-test"

ShuttingDown = [False]

MalcolmVmInfo = None

# PcapHashMap contains a map of PCAP files' full path to their
#   file hash as calculated by shakey_file_hash. The presence
#   of a PCAP file in this dict means that the PCAP file has
#   been successfully uploaded to the Malcolm instance for processing,
#   meaning (assuming auto-tagging based on filename is turned on)
#   the hash can be used as a query filter for tags.
PcapHashMap = defaultdict(lambda: None)


class DatabaseObjs:
    def __init__(self):
        self.DatabaseClass = None
        self.SearchClass = None
        self.DatabaseInitArgs = defaultdict(lambda: None)


UPLOAD_ARTIFACT_LIST_NAME = 'UPLOAD_ARTIFACTS'

MALCOLM_READY_TIMEOUT_SECONDS = 600
MALCOLM_READY_CHECK_PERIOD_SECONDS = 30
MALCOLM_READY_REQUIRED_COMPONENTS = [
    'arkime',
    'logstash_lumberjack',
    'logstash_pipelines',
    'opensearch',
    'pcap_monitor',
]
MALCOLM_LAST_INGEST_AGE_SECONDS_THRESHOLD = 300
MALCOLM_LAST_INGEST_AGE_SECONDS_TIMEOUT = 3600

ARKIME_FILES_INDEX = "arkime_files"
ARKIME_FILE_SIZE_FIELD = "filesize"

urllib3.disable_warnings()
warnings.filterwarnings(
    "ignore",
    message="Unverified HTTPS request",
)


###################################################################################################
def shakey_file_hash(filename, digest_len=8):
    try:
        with open(filename, 'rb', buffering=0) as f:
            return hashlib.file_digest(f, 'shake_256').hexdigest(digest_len)
    except:
        return None


###################################################################################################
def set_malcolm_vm_info(info):
    global MalcolmVmInfo
    MalcolmVmInfo = info


def get_malcolm_vm_info():
    global MalcolmVmInfo
    return MalcolmVmInfo


def set_pcap_hash(pcapFileSpec, pcapFileHash):
    global PcapHashMap
    if tmpHash := pcapFileHash if pcapFileHash else shakey_file_hash(pcapFileSpec):
        PcapHashMap[pcapFileSpec] = tmpHash
    return PcapHashMap[pcapFileSpec]


def get_pcap_hash_map():
    global PcapHashMap
    return PcapHashMap


def get_malcolm_http_auth(info=None):
    global MalcolmVmInfo
    if tmpInfo := info if info else MalcolmVmInfo:
        return HTTPBasicAuth(
            tmpInfo.get('username', ''),
            tmpInfo.get('password', ''),
        )
    else:
        return None


def get_malcolm_url(info=None):
    global MalcolmVmInfo
    if tmpInfo := info if info else MalcolmVmInfo:
        return f"https://{tmpInfo.get('ip', '')}"
    else:
        return 'http://localhost'


def get_database_objs(info=None):
    global MalcolmVmInfo
    if tmpInfo := info if info else MalcolmVmInfo:
        return tmpInfo.get('database_objs', DatabaseObjs())
    else:
        return DatabaseObjs()


###################################################################################################
def parse_virter_log_line(log_line):
    pattern = r'(\w+)=(".*?"|\S+)'
    matches = re.findall(pattern, log_line)
    log_dict = defaultdict(lambda: log_line)
    if matches:
        for key, value in matches:
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1].replace('\\"', '"')
            log_dict[key] = value

    return log_dict


###################################################################################################
class MalcolmTestCollection(object):
    def __init__(
        self,
        logger=None,
    ):
        self.logger = logger
        self.collected = set()

    def pytest_collection_modifyitems(self, items):
        for item in items:
            self.collected.add(str(item.reportinfo()[0]))

    def PCAPsReferenced(self):
        result = list()
        for testPyPath in self.collected:
            try:
                with open(testPyPath, "r") as f:
                    testPyContent = f.read()
                for node in ast.walk(ast.parse(testPyContent)):
                    if isinstance(node, ast.Assign):
                        for target in node.targets:
                            if isinstance(target, ast.Name) and (target.id == UPLOAD_ARTIFACT_LIST_NAME):
                                result.append(ast.literal_eval(node.value))
            except FileNotFoundError:
                self.logger.error(f"Error: '{testPyPath}' not found")
            except SyntaxError:
                self.logger.error(f"Error: '{testPyPath}' has invalid syntax")
            except ValueError as ve:
                self.logger.error(f"Error: Unable to evaulate '{variable_name}' in '{testPyPath}': {ve}")
            except Exception as e:
                self.logger.error(f"Error: '{testPyPath}': {e}")
        return set(mmguero.Flatten(result))


###################################################################################################
class MalcolmVM(object):
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def __init__(
        self,
        args,
        debug=False,
        logger=None,
    ):
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
                'MALCOLM_AUTH_PASSWORD',
                'MALCOLM_AUTH_USERNAME',
            )
        ]:
            self.provisionEnvArgs.extend(
                [
                    '--set',
                    f"env.{varName.removeprefix("MALCOLM_")}={varVal}",
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

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def __del__(self):
        # if requested, make sure to shut down the VM
        try:
            self.ProvisionFini()
        finally:
            if self.removeAfterExec and not self.buildMode:
                tmpExitCode, output = mmguero.RunProcess(
                    ['virter', 'vm', 'rm', self.name],
                    env=self.osEnv,
                    debug=self.debug,
                    logger=self.logger,
                )
                self.PrintVirterLogOutput(output)

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def PrintVirterLogOutput(self, output):
        for x in mmguero.GetIterable(output):
            if x:
                self.logger.info(parse_virter_log_line(x)['msg'])

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def Exists(self):
        exitCode, output = mmguero.RunProcess(
            ['virter', 'vm', 'exists', self.name],
            env=self.osEnv,
            debug=self.debug,
            logger=self.logger,
        )
        return bool(exitCode == 0)

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def Ready(self, waitUntilReadyOrTimeout=True):
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
                    #
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

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def WaitForLastEventTime(
        self,
        lastDocIngestAge=MALCOLM_LAST_INGEST_AGE_SECONDS_THRESHOLD,
        timeout=MALCOLM_LAST_INGEST_AGE_SECONDS_TIMEOUT,
    ):
        global ShuttingDown
        result = False

        if not self.buildMode:

            url, auth = self.ConnectionParams()

            timeoutEnd = time.time() + MALCOLM_LAST_INGEST_AGE_SECONDS_TIMEOUT
            while (result == False) and (ShuttingDown[0] == False) and (time.time() < timeoutEnd):
                try:
                    # check the ingest statistics which returns a dict of host.name -> event.ingested
                    response = self.apiSession.get(
                        f"{url}/mapi/ingest-stats",
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
                    and dataSourceStats
                    and all(
                        (
                            (datetime.now(timezone.utc) - datetime.fromisoformat(timestamp)).total_seconds()
                            > MALCOLM_LAST_INGEST_AGE_SECONDS_THRESHOLD
                        )
                        for timestamp in dataSourceStats.values()
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

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def ArkimeAlreadyHasFile(
        self,
        filename,
    ):
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

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
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
            self.logger.error(f"Error getting version API: {e}")

        try:
            # the first time we call Info for this object, set up our database classes, etc.
            if self.dbObjs is None:

                self.dbObjs = DatabaseObjs()
                self.dbObjs.DatabaseInitArgs['request_timeout'] = 1
                self.dbObjs.DatabaseInitArgs['verify_certs'] = False
                self.dbObjs.DatabaseInitArgs['ssl_assert_hostname'] = False
                self.dbObjs.DatabaseInitArgs['ssl_show_warn'] = False

                if 'elastic' in mmguero.DeepGet(result, ['version', 'mode'], '').lower():
                    elasticImport = mmguero.DoDynamicImport(
                        'elasticsearch', 'elasticsearch', interactive=False, debug=self.debug
                    )
                    elasticDslImport = mmguero.DoDynamicImport(
                        'elasticsearch_dsl', 'elasticsearch-dsl', interactive=False, debug=self.debug
                    )
                    self.dbObjs.DatabaseClass = elasticImport.Elasticsearch
                    self.dbObjs.SearchClass = elasticDslImport.Search
                    if self.malcolmUsername:
                        self.dbObjs.DatabaseInitArgs['basic_auth'] = (self.malcolmUsername, self.malcolmPassword)
                else:
                    osImport = mmguero.DoDynamicImport(
                        'opensearchpy', 'opensearch-py', interactive=False, debug=self.debug
                    )
                    self.dbObjs.DatabaseClass = osImport.OpenSearch
                    self.dbObjs.SearchClass = osImport.Search
                    if self.malcolmUsername:
                        self.dbObjs.DatabaseInitArgs['http_auth'] = (self.malcolmUsername, self.malcolmPassword)

        except Exception as e:
            self.logger.error(f"Error getting database objects: {e}")

        result['database_objs'] = self.dbObjs

        return result

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def ConnectionParams(self):
        if tmpInfo := self.Info():
            return get_malcolm_url(tmpInfo), get_malcolm_http_auth(tmpInfo)
        else:
            return None, None

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def Build(self):
        self.buildMode = True

        # use virter to build a new virtual machine image
        if not self.vmBuildName:
            self.vmBuildName = petname.Generate()
        self.buildNameCur = ''
        self.buildNamePre.append(self.vmImage)
        self.ProvisionInit()

        return 0

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def Start(self):
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

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def ProvisionFile(
        self,
        provisionFile,
        continueThroughShutdown=False,
        tolerateFailure=False,
        overrideBuildName=None,
    ):
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

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def ProvisionTOML(
        self,
        data,
        continueThroughShutdown=False,
        tolerateFailure=False,
        overrideBuildName=None,
    ):
        with mmguero.TemporaryFilename(suffix='.toml') as tomlFileName:
            with open(tomlFileName, 'w') as tomlFile:
                tomlFile.write(tomli_w.dumps(data))
            return self.ProvisionFile(
                tomlFileName,
                continueThroughShutdown=continueThroughShutdown,
                tolerateFailure=tolerateFailure,
                overrideBuildName=overrideBuildName,
            )

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def CopyFile(
        self,
        sourceFileSpec,
        destFileSpec,
        makeDestDirWorldWritable=False,
        continueThroughShutdown=False,
        tolerateFailure=False,
        overrideBuildName=None,
    ):
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

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def ProvisionInit(self):
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

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def ProvisionFini(self):

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

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def WaitForShutdown(self):
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
