#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import copy
import errno
import glob
import json
import logging
import mmguero
import multiprocessing
import os
import psutil
import re
import signal
import subprocess
import sys
import time
import toml

from random import randrange
from collections import defaultdict

###################################################################################################
script_name = os.path.basename(__file__)
script_path = os.path.dirname(os.path.realpath(__file__))
shuttingDown = [False]


###################################################################################################
# handle sigint/sigterm and set a global shutdown variable
def shutdown_handler(signum, frame):
    global shuttingDown
    shuttingDown[0] = True


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
        self.id = None
        self.name = None

        self.vmTomlMalcolmInitPath = os.path.join(self.vmProvisionPath, 'malcolm-init')
        self.vmTomlMalcolmFiniPath = os.path.join(self.vmProvisionPath, 'malcolm-fini')
        self.vmTomlVMInitPath = os.path.join(self.vmProvisionPath, os.path.join(self.vmImage, 'init'))
        self.vmTomlVMFiniPath = os.path.join(self.vmProvisionPath, os.path.join(self.vmImage, 'fini'))

        self.osEnv = os.environ.copy()
        self.osEnv.pop('SSH_AUTH_SOCK', None)
        # TODO: this does't seem to work...
        # if self.verbose > logging.DEBUG:
        #     osEnv["VIRTER_LOG_LEVEL"] = 'debug'
        # elif self.verbose > logging.INFO:
        #     osEnv["VIRTER_LOG_LEVEL"] = 'info'
        # elif self.verbose > logging.WARNING:
        #     osEnv["VIRTER_LOG_LEVEL"] = 'warning'
        # else:
        #     osEnv["VIRTER_LOG_LEVEL"] = 'error'

        self.provisionEnvArgs = [
            '--set',
            f"env.VERBOSE={str(debug).lower()}",
            '--set',
            f"env.REPO_URL={self.repoUrl}",
            '--set',
            f"env.REPO_BRANCH={self.repoBranch}",
        ]

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def __del__(self):
        # if requested, make sure to shut down the VM
        try:
            self.ProvisionFini()
        finally:
            if self.removeAfterExec:
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
    def Start(self):
        global shuttingDown

        output = []
        exitCode = 1
        if self.vmExistingName:
            # use an existing VM (by name)
            self.name = self.vmExistingName
            if self.Exists():
                self.logger.info(f'{self.name} exists as indicated')
                exitCode = 0
            else:
                self.logger.info(f'{self.name} does not already exist')

        elif shuttingDown[0] == False:
            # use virter to execute a virtual machine
            self.id = 120 + randrange(80)
            self.name = f"{self.vmNamePrefix}-{self.id}"
            cmd = [
                'virter',
                'vm',
                'run',
                self.vmImage,
                '--id',
                self.id,
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
            logging.info(cmd)
            exitCode, output = mmguero.RunProcess(
                cmd,
                env=self.osEnv,
                debug=self.debug,
                logger=self.logger,
            )

        if exitCode == 0:
            self.PrintVirterLogOutput(output)
            self.ProvisionInit()
        else:
            raise subprocess.CalledProcessError(exitCode, cmd, output=output)

        return exitCode

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def ProvisionFile(self, provisionFile, continueThroughShutdown=False, tolerateFailure=False):
        global shuttingDown

        if (shuttingDown[0] == False) or (continueThroughShutdown == True):
            cmd = [
                'virter',
                'vm',
                'exec',
                self.name,
                '--provision',
                provisionFile,
            ]
            if self.provisionEnvArgs:
                cmd.extend(self.provisionEnvArgs)
            self.logger.info(cmd)
            code, out = mmguero.RunProcess(
                cmd,
                env=self.osEnv,
                debug=self.debug,
                logger=self.logger,
            )
            if (code == 0) or (tolerateFailure == True):
                self.PrintVirterLogOutput(out)
            else:
                raise subprocess.CalledProcessError(code, cmd, output=out)

        else:
            code = 1

        return code

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def ProvisionInit(self):
        if self.vmProvision and os.path.isdir(self.vmProvisionPath):

            # first execute any provisioning in this image's "init" directory, if it exists
            #   (this needs to install rsync if it's not already part of the image)
            if os.path.isdir(self.vmTomlVMInitPath):
                for provisionFile in sorted(glob.glob(os.path.join(self.vmTomlVMInitPath, '*.toml'))):
                    self.ProvisionFile(provisionFile)

            # now, rsync the container image file to the VM if specified
            if self.containerImageFile:
                with mmguero.TemporaryFilename(suffix='.toml') as tomlFileName:
                    with open(tomlFileName, 'w') as tomlFile:
                        tomlFile.write(
                            toml.dumps(
                                {
                                    'version': 1,
                                    'steps': [
                                        {
                                            'rsync': {
                                                'source': self.containerImageFile,
                                                'dest': "/tmp/malcolm_images.tar.xz",
                                            }
                                        }
                                    ],
                                }
                            )
                        )
                    self.ProvisionFile(tomlFileName)
                    self.provisionEnvArgs.extend(
                        [
                            '--set',
                            f"env.IMAGE_FILE=/tmp/malcolm_images.tar.xz",
                        ]
                    )

            # now execute provisioning from the "malcolm init" directory
            if os.path.isdir(self.vmTomlMalcolmInitPath):
                for provisionFile in sorted(glob.glob(os.path.join(self.vmTomlMalcolmInitPath, '*.toml'))):
                    self.ProvisionFile(provisionFile)

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def ProvisionFini(self):
        if self.vmProvision and os.path.isdir(self.vmProvisionPath):

            # now execute provisioning from the "malcolm fini" directory
            if os.path.isdir(self.vmTomlMalcolmFiniPath):
                for provisionFile in sorted(glob.glob(os.path.join(self.vmTomlMalcolmFiniPath, '*.toml'))):
                    self.ProvisionFile(provisionFile, continueThroughShutdown=True)

            # finally, execute any provisioning in this image's "fini" directory, if it exists
            if os.path.isdir(self.vmTomlVMFiniPath):
                for provisionFile in sorted(glob.glob(os.path.join(self.vmTomlVMFiniPath, '*.toml'))):
                    self.ProvisionFile(provisionFile, continueThroughShutdown=True)

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def WaitForShutdown(self):
        global shuttingDown

        sleepCtr = 0
        noExistCtr = 0
        while shuttingDown[0] == False:
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
                        shuttingDown[0] = True


###################################################################################################
# main
def main():
    parser = argparse.ArgumentParser(
        description='\n'.join(
            [
                '',
            ]
        ),
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False,
        usage=f'{script_name} <arguments>',
    )
    parser.add_argument(
        '--verbose',
        '-v',
        action='count',
        default=1,
        help='Increase verbosity (e.g., -v, -vv, etc.)',
    )
    parser.add_argument(
        '-r',
        '--rm',
        dest='removeAfterExec',
        type=mmguero.str2bool,
        nargs='?',
        metavar="true|false",
        const=True,
        default=False,
        help="Remove virtual Malcolm instance after execution is complete",
    )

    repoArgGroup = parser.add_argument_group('Malcolm Git repo')
    repoArgGroup.add_argument(
        '-g',
        '--github-url',
        required=False,
        dest='repoUrl',
        metavar='<string>',
        type=str,
        default=os.getenv('MALCOLM_REPO_URL', 'idaholab'),
        help='Malcolm repository url (e.g., https://github.com/idaholab/Malcolm)',
    )
    repoArgGroup.add_argument(
        '-b',
        '--github-branch',
        required=False,
        dest='repoBranch',
        metavar='<string>',
        type=str,
        default=os.getenv('MALCOLM_REPO_BRANCH', 'main'),
        help='Malcolm repository branch (e.g., main)',
    )

    vmSpecsArgGroup = parser.add_argument_group('Virtual machine specifications')
    vmSpecsArgGroup.add_argument(
        '-c',
        '--cpus',
        dest='vmCpuCount',
        required=False,
        metavar='<integer>',
        type=int,
        default=(multiprocessing.cpu_count() // 2),
        help='Number of CPUs for virtual Malcolm instance',
    )
    vmSpecsArgGroup.add_argument(
        '-m',
        '--memory',
        dest='vmMemoryGigabytes',
        required=False,
        metavar='<integer>',
        type=int,
        default=max(16, int(round(psutil.virtual_memory().total / (1024.0**3))) // 2),
        help='System memory (GB) for virtual Malcolm instance',
    )
    vmSpecsArgGroup.add_argument(
        '-d',
        '--disk',
        dest='vmDiskGigabytes',
        required=False,
        metavar='<integer>',
        type=int,
        default=64,
        help='Disk size (GB) for virtual Malcolm instance',
    )
    repoArgGroup.add_argument(
        '-i',
        '--image',
        required=False,
        dest='vmImage',
        metavar='<string>',
        type=str,
        default=os.getenv('QEMU_IMAGE', 'debian-12'),
        help='Malcolm virtual instance base image name (e.g., debian-12)',
    )
    repoArgGroup.add_argument(
        '--image-user',
        required=False,
        dest='vmImageUsername',
        metavar='<string>',
        type=str,
        default=os.getenv('QEMU_USER', 'debian'),
        help='Malcolm virtual instance base image username (e.g., debian)',
    )
    repoArgGroup.add_argument(
        '--vm-name-prefix',
        required=False,
        dest='vmNamePrefix',
        metavar='<string>',
        type=str,
        default=os.getenv('QEMU_NAME_PREFIX', 'malcolm'),
        help='Prefix for Malcolm VM name (e.g., malcolm)',
    )
    repoArgGroup.add_argument(
        '--existing-vm',
        required=False,
        dest='vmExistingName',
        metavar='<string>',
        type=str,
        default=os.getenv('QEMU_EXISTING', ''),
        help='Name of an existing virter VM to use rather than starting up a new one',
    )
    repoArgGroup.add_argument(
        '--vm-provision',
        dest='vmProvision',
        type=mmguero.str2bool,
        nargs='?',
        metavar="true|false",
        const=True,
        default=True,
        help=f'Perform VM provisioning',
    )
    repoArgGroup.add_argument(
        '--vm-provision-path',
        required=False,
        dest='vmProvisionPath',
        metavar='<string>',
        type=str,
        default=os.getenv('QEMU_PROVISION_PATH', os.path.join(script_path, 'virter')),
        help=f'Path containing subdirectories with TOML files for VM provisioning (e.g., {os.path.join(script_path, "virter")})',
    )

    configArgGroup = parser.add_argument_group('Malcolm runtime configuration')
    configArgGroup.add_argument(
        '--container-image-file',
        required=False,
        dest='containerImageFile',
        metavar='<string>',
        type=str,
        default='',
        help='Malcolm container images .tar.xz file for installation (instead of "docker load")',
    )

    try:
        parser.error = parser.exit
        args = parser.parse_args()
    except SystemExit as e:
        mmguero.eprint(f'Invalid argument(s): {e}')
        parser.print_help()
        sys.exit(2)

    # configure logging levels based on -v, -vv, -vvv, etc.
    args.verbose = logging.CRITICAL - (10 * args.verbose) if args.verbose > 0 else 0
    logging.basicConfig(
        level=args.verbose, format='%(asctime)s %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S'
    )
    logging.info(os.path.join(script_path, script_name))
    logging.info("Arguments: {}".format(sys.argv[1:]))
    logging.info("Arguments: {}".format(args))
    if args.verbose > logging.DEBUG:
        sys.tracebacklimit = 0

    # handle sigint and sigterm for graceful shutdown
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    malcolmVm = MalcolmVM(
        args=args,
        debug=(args.verbose > logging.DEBUG),
        logger=logging,
    )
    try:
        exitCode = malcolmVm.Start()
        malcolmVm.WaitForShutdown()
    finally:
        del malcolmVm

    logging.info(f'{script_name} returning {exitCode}')
    return exitCode


###################################################################################################
if __name__ == '__main__':
    if main() > 0:
        sys.exit(0)
    else:
        sys.exit(1)
