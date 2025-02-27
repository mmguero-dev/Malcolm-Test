"""
malcolm-test module containing the CLI interface and high-level execution logic
"""

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import logging
import magic
import mmguero
import multiprocessing
import os
import psutil
import pytest
import re
import signal
import sys

import importlib.metadata

from maltest.utils import (
    MALTEST_PROJECT_NAME,
    MalcolmTestCollection,
    MalcolmVM,
    set_malcolm_vm_info,
    set_artifact_hash,
    shakey_file_hash,
    ShuttingDown,
)

script_name = os.path.basename(__file__)
script_path = os.path.dirname(os.path.realpath(__file__))


def shutdown_handler(signum, frame):
    """
    shutdown_handler: Signal handler for interrupting program execution with SIGKILL or SIGINT,
    setting ShuttingDown to True

    Args:
        signum - The signal number (e.g., signal.SIGINT for Ctrl-C)
        frame - The current stack frame

    Returns:
        None
    """
    ShuttingDown[0] = True


def main():
    """
    main: Main program execution

    Args:
        None (see --help for command-line arguments)

    Returns:
        0 for success, non-0 for error
    """
    global ShuttingDown

    parser = argparse.ArgumentParser(
        description='\n'.join(
            [
                'See README.md for usage details.',
            ]
        ),
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=True,
        usage=f'{MALTEST_PROJECT_NAME} <options> -- <extra arguments for pytest>',
    )
    parser.add_argument(
        '--verbose',
        '-v',
        action='count',
        default=1,
        help='Increase verbosity (e.g., -v, -vv, etc.)',
    )
    parser.add_argument(
        '--version',
        dest='showVersion',
        type=mmguero.str2bool,
        nargs='?',
        metavar="true|false",
        const=True,
        default=False,
        help="Show script version and exit",
    )

    repoArgGroup = parser.add_argument_group('Malcolm Git repo')
    repoArgGroup.add_argument(
        '-g',
        '--github-url',
        required=False,
        dest='repoUrl',
        metavar='<string>',
        type=str,
        default=os.getenv('MALCOLM_REPO_URL', 'https://github.com/idaholab/Malcolm'),
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
    vmSpecsArgGroup.add_argument(
        '-i',
        '--image',
        required=False,
        dest='vmImage',
        metavar='<string>',
        type=str,
        default=os.getenv('VIRTER_IMAGE', 'debian-12'),
        help='Malcolm virtual instance base image name (e.g., debian-12)',
    )
    vmSpecsArgGroup.add_argument(
        '--image-user',
        required=False,
        dest='vmImageUsername',
        metavar='<string>',
        type=str,
        default=os.getenv('VIRTER_USER', 'debian'),
        help='Malcolm virtual instance base image username (e.g., debian)',
    )
    vmSpecsArgGroup.add_argument(
        '--vm-name-prefix',
        required=False,
        dest='vmNamePrefix',
        metavar='<string>',
        type=str,
        default=os.getenv('VIRTER_NAME_PREFIX', 'malcolm'),
        help='Prefix for Malcolm VM name (e.g., malcolm)',
    )
    vmSpecsArgGroup.add_argument(
        '--existing-vm',
        required=False,
        dest='vmExistingName',
        metavar='<string>',
        type=str,
        default=os.getenv('VIRTER_EXISTING', ''),
        help='Name of an existing virter VM to use rather than starting up a new one',
    )
    vmSpecsArgGroup.add_argument(
        '--vm-provision-os',
        dest='vmProvisionOS',
        type=mmguero.str2bool,
        nargs='?',
        metavar="true|false",
        const=True,
        default=True,
        help=f'Perform VM provisioning (OS-specific)',
    )
    vmSpecsArgGroup.add_argument(
        '--vm-provision-malcolm',
        dest='vmProvisionMalcolm',
        type=mmguero.str2bool,
        nargs='?',
        metavar="true|false",
        const=True,
        default=True,
        help=f'Perform VM provisioning (Malcolm-specific)',
    )
    vmSpecsArgGroup.add_argument(
        '--vm-provision-path',
        required=False,
        dest='vmProvisionPath',
        metavar='<string>',
        type=str,
        default=os.getenv('VIRTER_PROVISION_PATH', os.path.join(script_path, 'virter')),
        help=f'Path containing subdirectories with TOML files for VM provisioning (e.g., {os.path.join(script_path, "virter")})',
    )
    vmSpecsArgGroup.add_argument(
        '--build-vm',
        required=False,
        dest='vmBuildName',
        metavar='<string>',
        type=str,
        default=os.getenv('VIRTER_BUILD_VM', ''),
        help='The name for a new VM image to build and commit instead of running one',
    )
    vmSpecsArgGroup.add_argument(
        '--build-vm-keep-layers',
        dest='vmBuildKeepLayers',
        type=mmguero.str2bool,
        nargs='?',
        metavar="true|false",
        const=True,
        default=False,
        help=f"Don't remove intermediate layers when building a new VM image",
    )

    configArgGroup = parser.add_argument_group('Malcolm runtime configuration')
    configArgGroup.add_argument(
        '--container-image-file',
        required=False,
        dest='containerImageFile',
        metavar='<string>',
        type=str,
        default='',
        help='Malcolm container images .tar.xz file for installation (instead of "docker pull")',
    )
    configArgGroup.add_argument(
        '--netbox-restore-file',
        required=False,
        dest='netboxRestoreFile',
        metavar='<string>',
        type=str,
        default='',
        help='NetBox backup file to place in ./netbox/preload/',
    )
    configArgGroup.add_argument(
        '-s',
        '--start',
        dest='startMalcolm',
        type=mmguero.str2bool,
        nargs='?',
        metavar="true|false",
        const=True,
        default=True,
        help=f'Start Malcolm once provisioning is complete (default true)',
    )
    configArgGroup.add_argument(
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
    configArgGroup.add_argument(
        '--stay-up',
        dest='stayUp',
        type=mmguero.str2bool,
        nargs='?',
        metavar="true|false",
        const=True,
        default=False,
        help=f'Stay running until CTRL+C or SIGKILL is received',
    )
    configArgGroup.add_argument(
        '--sleep',
        dest='postInitSleep',
        required=False,
        metavar='<integer>',
        type=int,
        default=30,
        help='Seconds to sleep after init before starting Malcolm (default 30)',
    )

    testArgGroup = parser.add_argument_group('Testing configuration')
    testArgGroup.add_argument(
        '--test-path',
        required=False,
        dest='testPath',
        metavar='<string>',
        type=str,
        default=os.getenv('MALCOLM_TEST_PATH', os.path.join(script_path, 'tests')),
        help=f"Path containing test definitions (e.g., {os.path.join(script_path, 'tests')})",
    )
    testArgGroup.add_argument(
        '-a',
        '--artifacts-path',
        required=False,
        dest='artifactsPath',
        metavar='<string>',
        type=str,
        default=os.getenv('MALCOLM_TEST_ARTIFACTS_PATH', ''),
        help=f'Path containing artifacts used by tests (UPLOAD_ARTIFACTS in tests should resolve relative to this path)',
    )
    testArgGroup.add_argument(
        '-t',
        '--run-tests',
        dest='runTests',
        type=mmguero.str2bool,
        nargs='?',
        metavar="true|false",
        const=True,
        default=True,
        help=f'Run test suite once Malcolm is started',
    )
    testArgGroup.add_argument(
        '-w',
        '--wait-for-idle',
        dest='waitForIdle',
        type=mmguero.str2bool,
        nargs='?',
        metavar="true|false",
        const=True,
        default=True,
        help=f'Wait for ingest idle state before running tests',
    )
    testArgGroup.add_argument(
        '--no-upload',
        dest='noUpload',
        type=mmguero.str2bool,
        nargs='?',
        metavar="true|false",
        const=True,
        default=False,
        help=f"Don't actually upload artifacts",
    )

    if len(sys.argv) == 1:
        mmguero.eprint(f'{MALTEST_PROJECT_NAME} v{importlib.metadata.version(MALTEST_PROJECT_NAME)}')
        parser.print_usage(sys.stderr)
        sys.exit(1)

    try:
        parser.error = parser.exit
        args, extraArgs = parser.parse_known_args()
    except SystemExit as e:
        if str(e) != '0':
            mmguero.eprint(f'Invalid argument(s): {e}')
        sys.exit(2)

    # configure logging levels based on -v, -vv, -vvv, etc.
    args.verbose = logging.CRITICAL - (10 * args.verbose) if args.verbose > 0 else 0
    logging.basicConfig(
        level=args.verbose, format='%(asctime)s %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S'
    )
    logging.info(os.path.join(script_path, script_name))
    logging.info("Arguments: {}".format(sys.argv[1:]))
    logging.info("Arguments: {}".format(args))
    if extraArgs:
        if '--' in extraArgs:
            extraArgs.remove('--')
        logging.info("Extra arguments: {}".format(extraArgs))
    if args.verbose > logging.DEBUG:
        sys.tracebacklimit = 0

    if args.showVersion:
        mmguero.eprint(f'{MALTEST_PROJECT_NAME} v{importlib.metadata.version(MALTEST_PROJECT_NAME)}')
        return 0

    if (not args.vmBuildName) and (not os.path.isdir(args.artifactsPath)):
        logging.error('Artifacts path must be specified with -a/--artifacts-path or MALCOLM_TEST_ARTIFACTS_PATH')
        return 1

    # the whole thing runs on virter, so if we don't have that what are we even doing here
    err, _ = mmguero.RunProcess(['virter', 'version'])
    if err != 0:
        logging.error(f'{MALTEST_PROJECT_NAME} requires virter, please see https://github.com/LINBIT/virter')
        return 1

    # handle sigint and sigterm for graceful shutdown
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    # pass "args" into the constructor of our Malcolm VM object for its parameters
    malcolmVm = MalcolmVM(
        args=args,
        debug=(args.verbose <= logging.DEBUG),
        logger=logging,
    )
    try:
        if args.vmBuildName:
            # use "virter image build" to build a VM for later use
            exitCode = malcolmVm.Build()

        else:
            # run (and provision, if requested) a VM and start Malcolm (if requested)
            exitCode = malcolmVm.Start()

            # get connection information about the VM and set it so the tests can access it as a fixture
            malcolmInfo = malcolmVm.Info()
            logging.info(json.dumps(malcolmInfo, default=mmguero.JsonObjSerializer))
            set_malcolm_vm_info(malcolmInfo)

            # malcolm is started; wait for it to be ready to process data, then start testing
            if args.runTests and os.path.isdir(args.testPath) and malcolmVm.Ready():

                # first, collect the set of test .py files that pytest would execute
                testSetPreExec = MalcolmTestCollection(logger=logging)
                pytest.main(
                    list(mmguero.Flatten(['--collect-only', '-p', 'no:terminal', args.testPath, extraArgs])),
                    plugins=[testSetPreExec],
                )

                # for the tests we're about to run, get the set of PCAP files referenced and upload them to Malcolm
                artifacts = {}
                hasNonPcapArtifacts = False
                if testSetPreExec.collected:
                    artifacts = testSetPreExec.ArtifactsReferenced()
                    logging.debug(json.dumps({'tests': list(testSetPreExec.collected), 'artifacts': artifacts}))
                    for artifactFile, artifactAttrs in artifacts.items():
                        artifactFilespec = (
                            artifactFile
                            if os.path.isabs(artifactFile)
                            else os.path.join(args.artifactsPath, artifactFile)
                        )
                        artifactFileParts = os.path.splitext(artifactFilespec)
                        if artifactHash := shakey_file_hash(artifactFilespec):
                            fileMime = magic.from_file(artifactFilespec, mime=True)
                            fileType = magic.from_file(artifactFilespec)
                            fileIsPcap = (
                                fileMime in ('application/vnd.tcpdump.pcap', 'application/x-pcapng')
                            ) or re.search(r'pcap-?ng', fileType, re.IGNORECASE)
                            hasNonPcapArtifacts = not fileIsPcap
                            artifactNewName = artifactHash + artifactFileParts[1]
                            if ShuttingDown[0] == False:
                                if args.noUpload or (
                                    # TODO: is there a way we can detect duplicate non-PCAP (evtx, etc.) files?
                                    (fileIsPcap == True)
                                    and malcolmVm.ArkimeAlreadyHasFile(artifactNewName)
                                ):
                                    # we've already uploaded this file, so we don't need to upload it again
                                    set_artifact_hash(artifactFile, artifactHash)
                                else:
                                    # copy the file to Malcolm for processing
                                    copyCode = malcolmVm.CopyFile(
                                        artifactFilespec,
                                        # TODO: Assuming the Malcolm directory like this might not be very robust
                                        f"/home/{args.vmImageUsername}/Malcolm/pcap/upload/{'' if (artifactAttrs['netbox'] == True) else 'NBSITEID0,'}{artifactNewName}",
                                        tolerateFailure=True,
                                    )
                                    if copyCode == 0:
                                        set_artifact_hash(artifactFile, artifactHash)
                        else:
                            logging.error(f'Failed to calculate hash for {artifactFilespec}')

                # wait for all logs to finish being ingested into the system
                if artifacts and args.waitForIdle:
                    if not malcolmVm.WaitForLastEventTime():
                        logging.warning(f"Malcolm instance never achieved idle state after inserting network logs")
                    elif hasNonPcapArtifacts and (not malcolmVm.WaitForLastEventTime(doctype='host')):
                        logging.warning(f"Malcolm instance never achieved idle state after inserting EVTX logs")

                # run the tests
                if ShuttingDown[0] == False:
                    exitCode = pytest.main(list(mmguero.Flatten(['-p', 'no:cacheprovider', args.testPath, extraArgs])))

            # if we started Malcolm, sleep until instructed
            if args.stayUp:
                malcolmVm.WaitForShutdown()

    finally:
        del malcolmVm

    logging.info(f'{MALTEST_PROJECT_NAME} returning {exitCode}')
    return exitCode


if __name__ == '__main__':
    if main() > 0:
        sys.exit(0)
    else:
        sys.exit(1)
