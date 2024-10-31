# -*- coding: utf-8 -*-

import glob
import json
import mmguero
import os
import petname
import re
import subprocess
import sys
import time
import tomli
import tomli_w
import urllib3
import warnings

from collections import defaultdict


ShuttingDown = [False]

MalcolmVmInfo = None

urllib3.disable_warnings()
warnings.filterwarnings(
    "ignore",
    message="Unverified HTTPS request",
)


###################################################################################################
def set_malcolm_vm_info(info):
    global MalcolmVmInfo
    MalcolmVmInfo = info


def get_malcolm_vm_info():
    global MalcolmVmInfo
    return MalcolmVmInfo


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
        self.name = None
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
        return result

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

        if self.startMalcolm:
            self.logger.info(f'Malcolm is started and ready to process data on {self.name}')
        else:
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

        # start Malcolm and wait for it to become ready to process data
        if (self.buildMode == False) and self.startMalcolm and (ShuttingDown[0] == False):
            self.ProvisionTOML(
                data={
                    'version': 1,
                    'steps': [
                        {
                            'shell': {
                                'script': '''
                                    pushd ~/Malcolm &>/dev/null
                                    ~/Malcolm/scripts/start &>/dev/null &
                                    START_PID=$!
                                    sleep 30
                                    kill $START_PID
                                    sleep 10
                                    while [[ $(( docker compose exec api curl -sSL localhost:5000/mapi/ready 2>/dev/null | jq 'if (.arkime and .logstash_lumberjack and .logstash_pipelines and .opensearch and .pcap_monitor) then 1 else 0 end' 2>/dev/null ) || echo 0) != '1' ]]; do echo 'Waiting for Malcolm to become ready...' ; sleep 10; done
                                    echo 'Malcolm is ready!'
                                    popd &>/dev/null
                                '''
                            }
                        }
                    ],
                }
            )

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
