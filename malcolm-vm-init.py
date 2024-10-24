#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import logging
import mmguero
import multiprocessing
import os
import psutil
import re
import signal
import sys

from random import randrange
from subprocess import PIPE, STDOUT, DEVNULL, Popen, TimeoutExpired

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
# main
def main():
    global shuttingDown

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
        dest='repoOwner',
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
    repoArgGroup.add_argument(
        '-t',
        '--github-token',
        required=False,
        dest='githubToken',
        metavar='<string>',
        type=str,
        default=os.getenv('GITHUB_TOKEN', os.getenv('GITHUB_OAUTH_TOKEN', '')),
        help='GitHub personal access token',
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
        default=min(16, int(round(psutil.virtual_memory().total / (1024.0**3)))),
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
        default=os.getenv('QEMU_VM_NAME_PREFIX', 'malcolm'),
        help='Prefix for Malcolm VM name (e.g., malcolm)',
    )
    repoArgGroup.add_argument(
        '--existing-vm',
        required=False,
        dest='vmExistingName',
        metavar='<string>',
        type=str,
        default=os.getenv('QEMU_VM_EXISTING', ''),
        help='Name of an existing virter VM to use rather than starting up a new one',
    )

    # configArgGroup = parser.add_argument_group('Malcolm runtime configuration')

    try:
        parser.error = parser.exit
        args, extraArgs = parser.parse_known_args()
    except SystemExit:
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
    osEnv = os.environ.copy()
    osEnv.pop('SSH_AUTH_SOCK', None)

    # TODO: this does't seem to work...
    # if args.verbose > logging.DEBUG:
    #     osEnv["VIRTER_LOG_LEVEL"] = 'debug'
    # elif args.verbose > logging.INFO:
    #     osEnv["VIRTER_LOG_LEVEL"] = 'info'
    # elif args.verbose > logging.WARNING:
    #     osEnv["VIRTER_LOG_LEVEL"] = 'warning'
    # else:
    #     osEnv["VIRTER_LOG_LEVEL"] = 'error'

    # handle sigint and sigterm for graceful shutdown
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    if args.vmExistingName:
        # use an existing VM (by name)
        vmId = None
        vmName = args.vmExistingName
        exitCode, output = mmguero.RunProcess(
            ['virter', 'vm', 'exists', vmName],
            env=osEnv,
            debug=(args.verbose > logging.DEBUG),
            logger=logging,
        )
        logging.info(f'{vmName} exists: {bool(exitCode == 0)}')

    else:
        # use virter to execute a virtual machine
        vmId = 120 + randrange(80)
        vmName = f"{args.vmNamePrefix}-{vmId}"
        cmd = [
            'virter',
            'vm',
            'run',
            args.vmImage,
            '--id',
            vmId,
            '--name',
            vmName,
            '--vcpus',
            args.vmCpuCount,
            '--memory',
            f'{args.vmMemoryGigabytes}GB',
            '--bootcapacity',
            f'{args.vmDiskGigabytes}GB',
            '--user',
            args.vmImageUsername,
            '--wait-ssh',
        ]
        if extraArgs:
            cmd.extend(extraArgs)

        cmd = [str(x) for x in list(mmguero.Flatten(cmd))]
        logging.info(cmd)
        process = Popen(
            cmd,
            env=osEnv,
            text=True,
            bufsize=1,
            stdout=PIPE,
            stderr=PIPE,
        )
        while not shuttingDown[0]:
            output = process.stdout.readline()
            errput = process.stderr.readline() if process.stderr else None
            if not output and not errput:
                if process.poll() is not None:
                    break
                else:
                    time.sleep(0.5)
            else:
                if output:
                    logging.info(output)
                if errput:
                    logging.debug(errput)
        if shuttingDown[0]:
            process.terminate()
            try:
                process.wait(timeout=15.0)
            except TimeoutExpired:
                process.kill()
        exitCode = process.returncode

    if exitCode == 0:
        # at this point the VM should exist
        pass

    if args.removeAfterExec:
        tmpExitCode, output = mmguero.RunProcess(
            ['virter', 'vm', 'rm', vmName],
            env=osEnv,
            debug=(args.verbose > logging.DEBUG),
            logger=logging,
        )
        logging.info(f'{tmpExitCode} shutting down {vmName}: {output}')

    logging.debug(f'{script_name} returning {exitCode}')
    return exitCode


###################################################################################################
if __name__ == '__main__':
    if main() > 0:
        sys.exit(0)
    else:
        sys.exit(1)
