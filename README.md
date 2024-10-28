# Malcolm-Test

## Package source layout (under `src/malcolm_test`)

* 🐍 [`malcolm_test.py`](#MalcolmVMInitScript) - A Python script for running Malcolm in a VM with virter (see below)
* 🐍 `__init__.py` - Python package definition file
* 🗁 `virter/` - A directory structure containing TOML files for [provisioning](https://github.com/LINBIT/virter/blob/master/doc/provisioning.md) the virter VMs in which Malcolm will run. Its subdirectories are arranged thusly:
    - 🗁 `debian-12/` - A directory matching the name of the virter image (supplied to [`malcolm_test.py`](#MalcolmVMInitScript) with the `-i`/`--image` argument)
        + 🗁 `init/` - TOML files for the initial steps of provisioning the OS (before setting up and starting Malcolm)
        + 🗁 `fini/` - TOML files for the final stages of provisioning the OS (after shutting down Malcolm)
    - 🗁 `malcolm-init/` - Distribution-agnostic provisioning TOML files for setting up Malcolm prior to starting it
    - 🗁 `malcolm-fini/` - Distribution-agnostic provisioning TOML files for tearing down Malcolm after tests are complete
* 🗁 `tests/` - A directory structure containing the test definitions, built using the [pytest](https://docs.pytest.org/en/stable/) framework

## <a name="MalcolmVMInitScript"></a> malcolm_test.py

`malcolm_test.py` is a Python script for Linux that uses [virter](https://github.com/LINBIT/virter) (a command line tool for simple creation and cloning of virtual machines) to run an instance of [Malcolm](https://github.com/idaholab/malcolm/) against which automated system tests can be run. 

### Usage

```
usage: malcolm_test.py <arguments>

options:
  --verbose, -v         Increase verbosity (e.g., -v, -vv, etc.)
  -r [true|false], --rm [true|false]
                        Remove virtual Malcolm instance after execution is complete

Malcolm Git repo:
  -g <string>, --github-url <string>
                        Malcolm repository url (e.g., https://github.com/idaholab/Malcolm)
  -b <string>, --github-branch <string>
                        Malcolm repository branch (e.g., main)

Virtual machine specifications:
  -c <integer>, --cpus <integer>
                        Number of CPUs for virtual Malcolm instance
  -m <integer>, --memory <integer>
                        System memory (GB) for virtual Malcolm instance
  -d <integer>, --disk <integer>
                        Disk size (GB) for virtual Malcolm instance
  -i <string>, --image <string>
                        Malcolm virtual instance base image name (e.g., debian-12)
  --image-user <string>
                        Malcolm virtual instance base image username (e.g., debian)
  --vm-name-prefix <string>
                        Prefix for Malcolm VM name (e.g., malcolm)
  --existing-vm <string>
                        Name of an existing virter VM to use rather than starting up a new one
  --vm-provision [true|false]
                        Perform VM provisioning
  --vm-provision-path <string>
                        Path containing subdirectories with TOML files for VM provisioning (e.g., /home/user/Malcolm-Test/virter)

Malcolm runtime configuration:
  --container-image-file <string>
                        Malcolm container images .tar.xz file for installation (instead of "docker pull")
  -s [true|false], --start [true|false]
                        Start Malcolm once provisioning is complete (default true)
  --sleep <integer>     Seconds to sleep after init before starting Malcolm (default 30)
```

### Example

*with INFO-level `-vv` verbosity, output reduced for length*

```
2024-10-25 12:42:51 INFO: /home/user/Malcolm-Test/malcolm_test.py
2024-10-25 12:42:51 INFO: Arguments: ['-vv', '--rm', '--github-url', 'https://github.com/idaholab/Malcolm', '--github-branch', 'main']
2024-10-25 12:42:51 INFO: Arguments: Namespace(verbose=20, removeAfterExec=True, repoUrl='https://github.com/idaholab/Malcolm', repoBranch='main', vmCpuCount=8, vmMemoryGigabytes=31, vmDiskGigabytes=64, vmImage='debian-12', vmImageUsername='debian', vmNamePrefix='malcolm', vmExistingName='', vmProvision=True, vmProvisionPath='/home/user/Malcolm-Test/virter', containerImageFile='', startMalcolm=True, postInitSleep=30)
2024-10-25 12:42:51 INFO: ['virter', 'vm', 'run', 'debian-12', '--id', '126', '--name', 'malcolm-126', '--vcpus', '8', '--memory', '31GB', '--bootcapacity', '64GB', '--user', 'debian', '--wait-ssh']
2024-10-25 12:43:04 INFO: malcolm-126
2024-10-25 12:43:04 INFO: ['virter', 'vm', 'exec', 'malcolm-126', '--provision', '/home/user/Malcolm-Test/virter/debian-12/init/00-apt-init.toml', '--set', 'env.VERBOSE=false', '--set', 'env.REPO_URL=https://github.com/idaholab/Malcolm', '--set', 'env.REPO_BRANCH=main']
2024-10-25 12:44:27 INFO: malcolm-126 out: Linux malcolm-126 6.1.0-26-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.112-1 (2024-09-30) x86_64
…
2024-10-25 12:44:27 INFO: malcolm-126 out: Installing system packages...
…
2024-10-25 13:03:37 INFO: malcolm-126 out: Pulling Malcolm container images...
…
2024-10-25 13:05:11 INFO: malcolm-126 out: Waiting for Malcolm to become ready...
2024-10-25 13:06:34 INFO: Malcolm is started and ready to process data
```
