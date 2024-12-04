# malcolm-test

`malcolm-test` serves to run an instance of [Malcolm](https://idaholab.github.io/Malcolm/) and verify the results of system tests executed against it. It consists mostly of a [control script](#Usage), TOML files containing provisioning steps for virtual machine creation, and the test files themselves. See [this issue](https://github.com/idaholab/Malcolm/issues/11) in the Malcolm repository for the discussion leading up to its creation.

* [Installation](#Installation)
* [Usage](#Usage)
    - [Examples](#UsageExamples)
        + [Provisioning a Malcolm VM and Running the Tests From Scratch](#FromScratch)
        + [Provisioning a Malcolm VM For Reuse With Subsequent Test Runs](#BuildAndReuse)
        + [Starting a Malcolm VM and Leaving It Running For Subsequent Test Runs](#LongRunning)
    - [Cleaning Up](#Cleanup)
* [Source Code](#PackageSource)
* [Creating Tests](#TestCreation)

## <a name="Installation"></a> Installation

[![Latest Version](https://img.shields.io/pypi/v/malcolm-test)](https://pypi.python.org/pypi/malcolm-test/)

Using `pip`, to install the latest [release from PyPI](https://pypi.org/project/malcolm-test/):

```
python3 -m pip install -U malcolm-test
```

Or to install directly from GitHub:

```
python3 -m pip install -U 'git+https://github.com/idaholab/Malcolm-Test'
```

This project makes use of:

* [virter](https://github.com/LINBIT/virter) for the creation and execution of libvirt-based virtual machines running Malcolm
* [pytest](https://docs.pytest.org/en/stable/) for the testing framework

pytest will be installed as a dependency by `pip`, but you will need to install and configure virter prior to running `mmalcolm-test`. See [its GitHub page](https://github.com/LINBIT/virter) for instructions.

## <a name="Usage"></a> Usage

When [installed](#Installation) via pip, this script may be executed as `malcolm-test` from the Linux command line. 

### Usage

```
usage: malcolm-test <flags> <extra arguments for pytest>

See README.md for usage details.

options:
  -h, --help            show this help message and exit
  --verbose, -v         Increase verbosity (e.g., -v, -vv, etc.)
  --version [true|false]
                        Show script version and exit

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
  --vm-provision-os [true|false]
                        Perform VM provisioning (OS-specific)
  --vm-provision-malcolm [true|false]
                        Perform VM provisioning (Malcolm-specific)
  --vm-provision-path <string>
                        Path containing subdirectories with TOML files for VM provisioning (e.g., /home/user/.local/lib/python3.12/site-packages/maltest/virter)
  --build-vm <string>   The name for a new VM image to build and commit instead of running one
  --build-vm-keep-layers [true|false]
                        Don't remove intermediate layers when building a new VM image

Malcolm runtime configuration:
  --container-image-file <string>
                        Malcolm container images .tar.xz file for installation (instead of "docker pull")
  --netbox-restore-file <string>
                        NetBox backup file to place in ./netbox/preload/
  -s [true|false], --start [true|false]
                        Start Malcolm once provisioning is complete (default true)
  -r [true|false], --rm [true|false]
                        Remove virtual Malcolm instance after execution is complete
  --stay-up [true|false]
                        Stay running until CTRL+C or SIGKILL is received
  --sleep <integer>     Seconds to sleep after init before starting Malcolm (default 30)

Testing configuration:
  --test-path <string>  Path containing test definitions (e.g., /home/user/.local/lib/python3.12/site-packages/maltest/tests)
  -p <string>, --pcap-path <string>
                        Path containing PCAP files used by tests (UPLOAD_ARTIFACTS in tests should resolve relative to this path)
  -t [true|false], --run-tests [true|false]
                        Run test suite once Malcolm is started
  -w [true|false], --wait-for-idle [true|false]
                        Wait for ingest idle state before running tests
```

### <a name="UsageExamples"></a> Examples

Here are some examples of use cases for `malcolm-test`. The output here is shown without verbose logging enabled; increasing the level of verbosity with `-v`, `-vv`, etc., can provide more information about the operations being performed.

#### <a name="FromScratch"></a> Provisioning a Malcolm VM and Running the Tests From Scratch

To provision the Malcolm VM from scratch, run the tests, then discard the VM:

```bash
$ malcolm-test --rm --pcap-path /path/to/Malcolm-Test-PCAP
====================== test session starts ======================
platform linux -- Python 3.13.0, pytest-8.3.3, pluggy-1.5.0
rootdir: <...>
collected 4 items                                                                                                                                                                             

<...>/site-packages/maltest/tests/test_malcolm_db_health.py .                                                                                   [ 25%]
<...>/site-packages/maltest/tests/test_malcolm_exists.py .                                                                                      [ 50%]
<...>/site-packages/maltest/tests/test_malcolm_pcap.py .                                                                                        [ 75%]
<...>/site-packages/maltest/tests/test_malcolm_response.py .                                                                                    [100%]

====================== 4 passed in 0.26s ======================
```

Explanation of arguments:

* `--rm`: discard the VM after running the tests
* `--pcap-path /path/to/Malcolm-Test-PCAP`: specify the path to the upload artifacts used by the tests

#### <a name="BuildAndReuse"></a> Provisioning a Malcolm VM For Reuse With Subsequent Test Runs

Depending on the use case, because a complete from-scratch provisioning of the Malcolm VM can take a **long time** (due to installing packages, pulling Malcolm container images, waiting for startup, etc.), building a Malcolm image that can then be reused for multiple test runs may be useful. The steps to do this might look like this:

To build and provision a new Malcolm VM image and tag it as `malcolm-testing`:

```bash
$ malcolm-test --build-vm malcolm-testing
```

To run the tests using this already-provisioned VM image, then shut it down:

```bash
$ virter image ls
Name             Top Layer                                                                Created         
malcolm-testing  sha256:fd2320408c79045dca9aa914f50858f686a740bd053d481c7f33b670d0d3f4c9  3 minutes ago

$ malcolm-test \
    --rm \
    --image malcolm-testing \
    --vm-provision-os false \
    --pcap-path /path/to/Malcolm-Test-PCAP
====================== test session starts ======================
platform linux -- Python 3.13.0, pytest-8.3.3, pluggy-1.5.0
rootdir: <...>
collected 4 items                                                                                                                                                                             

<...>/site-packages/maltest/tests/test_malcolm_db_health.py .                                                                                   [ 25%]
<...>/site-packages/maltest/tests/test_malcolm_exists.py .                                                                                      [ 50%]
<...>/site-packages/maltest/tests/test_malcolm_pcap.py .                                                                                        [ 75%]
<...>/site-packages/maltest/tests/test_malcolm_response.py .                                                                                    [100%]

====================== 4 passed in 0.62s ======================
```

Explanation of arguments:

* `--rm`: discard the VM after running the tests
* `--image malcolm-testing`: use the `malcolm-testing` image already built instead of building one from scratch
* `--vm-provision-os false`: since the image is already provisioned, skip VM provisioning steps
* `--pcap-path /path/to/Malcolm-Test-PCAP`: specify the path to the upload artifacts used by the tests

#### <a name="LongRunning"></a> Starting a Malcolm VM and Leaving It Running For Subsequent Test Runs

During test development, or in other instances where you wish to run the tests over and over again without bringing Malcolm up and down, this could be accomplished as described below.

In one shell session start a Malcolm VM using the already-provisioned image, keeping Malcolm running until interrupted, without running the tests:

```bash
$ malcolm-test \
    --stay-up \
    --rm \
    --image malcolm-testing \
    --vm-provision-os false \
    --run-tests false
```

Explanation of arguments:

* `--stay-up`: keep Malcolm up until interrupted (with CTRL+C or SIGKILL)
* `--rm`: discard the VM after shutting down
* `--image malcolm-testing`: use the `malcolm-testing` image already built instead of building one from scratch
* `--vm-provision-os false`: since the image is already provisioned, skip VM provisioning steps
* `--run-tests false`: don't run the tests with this instance of `malcolm-test`, just start Malcolm and wait

In another shell session, connecting to the existing running Malcolm instance for a test run:

```bash
$ virter vm ls
Name                  ID   Access Network  
malcolm-nearby-satyr  254  default   

$ malcolm-test \
  --rm false \
  --start false \
  --sleep 0 \
  --existing-vm malcolm-nearby-satyr \
  --vm-provision-os false \
  --run-tests \
  --pcap-path /path/to/Malcolm-Test-PCAP
====================== test session starts ======================
platform linux -- Python 3.13.0, pytest-8.3.3, pluggy-1.5.0
rootdir: <...>
collected 4 items                                                                                                                                                                             

<...>/site-packages/maltest/tests/test_malcolm_db_health.py .                                                                                   [ 25%]
<...>/site-packages/maltest/tests/test_malcolm_exists.py .                                                                                      [ 50%]
<...>/site-packages/maltest/tests/test_malcolm_pcap.py .                                                                                        [ 75%]
<...>/site-packages/maltest/tests/test_malcolm_response.py .                                                                                    [100%]

====================== 4 passed in 0.25s ======================
```

* `--rm false`: don't destroy the VM after running the tests (the other instance of `malcolm-test` will handle that)
* `--start false`: since Malcolm was already started by the other instance of `malcolm-test`, don't attempt to start it
* `--sleep 0`: since Malcolm was already started, there is no need to sleep before beginning test execution
* `--existing-vm malcolm-nearby-satyr`: specify the name of the existing running VM obtained by `virter vm ls`
* `--vm-provision-os false`: since the image is already provisioned, skip VM provisioning steps
* `--vm-provision-malcolm false`: since the Malcolm instance is already configured, skip Malcolm provisioning steps
* `--run-tests`: run the test suite
* `--pcap-path /path/to/Malcolm-Test-PCAP`: specify the path to the upload artifacts used by the tests

Repeat the previous command as many times as needed as you adjust your tests. When finished, return to the first shell session and press CTRL+C to terminate and discard the Malcolm VM.

### <a name="Cleanup"></a> Cleaning Up

If the `malcolm-test` script exits uncleanly for some reason and leaves orphaned running VMs, they can be cleaned up like this:

```bash
$ virter vm ls
Name                  ID   Access Network  
malcolm-nearby-satyr  254  default   

$ virter vm rm malcolm-nearby-satyr
```

To list and clean up any leftover Malcolm image tags:

```bash
$ virter image ls
Name            Top Layer                                                                Created         
rested-krill    sha256:cd98ad4f552ce98f2a9ab0429b5fbb701483bc2980b590c5c91ebca2a8935f99  27 minutes ago  
robust-condor   sha256:e5306d90f825787b8142dcc94816902dfee4698fe9c00bc55aa4406eb5d830f5  26 minutes ago  
up-quagga       sha256:3889161a396f8f6ef41c0605323af07e2a9820cc980660563551a4488f0a7a3c  23 minutes ago  
malcolm-testing sha256:fd2320408c79045dca9aa914f50858f686a740bd053d481c7f33b670d0d3f4c9  3 minutes ago

$ virter image rm rested-krill robust-condor up-quagga
```

## <a name="PackageSource"></a> Source Code

Package source highlights (under [`./src/maltest`](src/maltest)):

* 🐍 [`maltest.py`](#Usage) - A Python script for running Malcolm in a VM with virter
* 🗁 `virter/` - A directory structure containing TOML files for [provisioning](https://github.com/LINBIT/virter/blob/master/doc/provisioning.md) the virter VMs in which Malcolm will run. Its subdirectories are arranged thusly:
    - 🗁 `debian-12/` - A directory matching the name of the virter image (supplied to `maltest.py`) with the `-i`/`--image` argument)
        + 🗁 `init/` - TOML files for the initial steps of provisioning the OS (before setting up and starting Malcolm)
        + 🗁 `fini/` - TOML files for the final stages of provisioning the OS (after shutting down Malcolm)
    - 🗁 `malcolm-init/` - Distribution-agnostic provisioning TOML files for setting up Malcolm prior to starting it
    - 🗁 `malcolm-fini/` - Distribution-agnostic provisioning TOML files for tearing down Malcolm after tests are complete
* 🗁 `tests/` - A directory structure containing the test definitions, built using the [pytest](https://docs.pytest.org/en/stable/) framework

## <a name="TestCreation"></a> Creating Tests

`malcolm-test` uses the [`pytest` framework](https://docs.pytest.org/en/stable/index.html). Please familiarize yourself with `pytest` as you begin developing new tests for the project.

New tests should be placed in the [`./src/maltest/tests/`](src/maltest/tests/) directory. Tests have access to the connection information for the running Malcolm instance through [fixtures](https://docs.pytest.org/en/stable/reference/fixtures.html#conftest-py-sharing-fixtures-across-multiple-files) provided by [`./src/maltest/tests/conftest.py`](src/maltest/tests/conftest.py).

Use `UPLOAD_ARTIFACTS` to specify a PCAP file or files required by your test. This example test would succeed if both `foobar.pcap` and `barbaz.pcap` were uploaded to Malcolm and their hashes stored in the global `pcap_hash_map`:

```python
UPLOAD_ARTIFACTS = ['foobar.pcap', 'barbaz.pcap']

def test_malcolm_pcap_hash(
    pcap_hash_map,
):
    assert all([pcap_hash_map.get(x, None) for x in UPLOAD_ARTIFACTS])
```

As PCAP files are uploaded to Malcolm by `malcolm-test`, they are [hashed](https://docs.python.org/3/library/hashlib.html#hashlib.shake_256) and stored in `pcap_hash_map` which maps the PCAP filename to its hash. The PCAP file is renamed to the hex-representation of the hash digest and the file extension (e.g., if the contents of `foobar.pcap` hashed to `52b92cdcec4af0e1`, the file would be uploaded as `52b92cdcec4af0e1.pcap`). This is done to ensure that conflicting PCAP filenames among different tests are resolved prior to processing. Since Malcolm automatically [assigns tags](https://idaholab.github.io/Malcolm/docs/upload.html#Tagging) to uploaded PCAP files, this hash should be used as a filter for the `tags` field for any network log-based queries for data related to that PCAP file. This way your tests can have reproducible outputs without being affected by PCAPs for other tests.

By default, `malcolm-test` instructs Malcolm to skip [NetBox enrichment](https://idaholab.github.io/Malcolm/docs/upload.html#UploadNetBoxSite) for PCAPs found in `UPLOAD_ARTIFACTS`. To make a test perform NetBox enrichment for its PCAP (using the Malcolm instance's default NetBox site), set `NETBOX_ENRICH` to `True` in the test source.

See the following tests for examples of how to access and use these fixtures:

* [test_malcolm_response.py](src/maltest/tests/test_malcolm_response.py) - querying the [Malcolm API](https://idaholab.github.io/Malcolm/docs/api.html#API) using the [Requests](https://requests.readthedocs.io/en/latest/) library
* [test_malcolm_db_health.py](src/maltest/tests/test_malcolm_db_health.py) - querying the [data store](https://idaholab.github.io/Malcolm/docs/opensearch-instances.html#OpenSearchInstance) directly using the [OpenSearch](https://opensearch.org/docs/latest/clients/python-low-level/) or [Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/client/python-api/current/index.html) client
* [test_common_protocols.py](src/maltest/tests/test_common_protocols.py) - querying the [Malcolm Field Aggregation API](https://idaholab.github.io/Malcolm/docs/api-aggregations.html), specifying a `from` query start time filter to search all historical data, a filter on `event.provider` to limit the result set to records from Zeek, and a `tags` filter to limit the matching records to the tags represented by the uploaded PCAPs (see above)
