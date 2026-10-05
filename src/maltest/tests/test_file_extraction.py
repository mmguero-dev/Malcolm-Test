import logging
import mmguero
import pytest
import random
import re
import requests
from bs4 import BeautifulSoup
from stream_unzip import stream_unzip, AE_2, AES_256

LOGGER = logging.getLogger(__name__)

UPLOAD_ARTIFACTS = [
    "pcap/plugins/smb_mimikatz_copy_to_host.pcap",
    "pcap/plugins/zeek-EternalSafety/eternalchampion.pcap",
]


def zipped_chunks(response, chunk_size=65536):
    for chunk in response.iter_content(chunk_size=chunk_size):
        yield chunk


@pytest.mark.carving
@pytest.mark.webui
@pytest.mark.pcap
def test_extracted_files_download(
    malcolm_url,
    malcolm_http_auth,
):
    """test_extracted_files_download

    List the .exe files from the /extracted-files page, then download one of them.
        With the assumption that the downloaded .exe file is zipped (the test suite's default) and
        encrypted with a password of "infected" (the test suite's default), it attempts to decrypt
        and unzip the file.

    Args:
        malcolm_url (str): URL for connecting to the Malcolm instance
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
    """
    response = requests.get(
        f"{malcolm_url}/extracted-files/",
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    soup = BeautifulSoup(response.content, 'html.parser')
    exePattern = re.compile(r'\.exe$')
    urls = [link['href'] for link in soup.find_all('a', href=exePattern)]
    LOGGER.debug(urls)
    assert urls
    response = requests.get(
        f"{malcolm_url}/extracted-files/{random.choice(urls)}",
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    assert len(response.content) > 1000
    for fileName, fileSize, unzippedChunks in stream_unzip(
        zipped_chunks(response),
        password=b'infected',
        allowed_encryption_mechanisms=(
            AE_2,
            AES_256,
        ),
    ):
        bytesSize = 0
        with mmguero.temporary_filename(suffix='.exe') as exeFileName:
            with open(exeFileName, 'wb') as exeFile:
                for chunk in unzippedChunks:
                    bytesSize = bytesSize + len(chunk)
                    exeFile.write(chunk)
        LOGGER.debug(f"{fileName.decode('utf-8')} {len(response.content)} -> {bytesSize})")
        assert fileName
        assert unzippedChunks
        assert bytesSize


@pytest.mark.carving
@pytest.mark.opensearch
@pytest.mark.pcap
def test_file_strings(
    malcolm_http_auth,
    malcolm_url,
    database_objs,
):
    """test_file_strings

    Check for file.strings being populated by the ScanStrings Strelka scanner

    Args:
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
        malcolm_url (str): URL for connecting to the Malcolm instance
        database_objs (DatabaseObjs): object containing classes references for either the OpenSearch or Elasticsearch Python libraries
    """
    dbObjs = database_objs

    client = dbObjs.DatabaseClass(
        hosts=[
            f"{malcolm_url}/mapi/opensearch",
        ],
        **dbObjs.DatabaseInitArgs,
    )

    response = client.search(
        index='malcolm_network',
        body={
            'size': 1,
            'query': {
                'wildcard': {
                    'file.strings': {
                        'value': '*',
                    },
                },
            },
            '_source': ['file.strings'],
        },
    )

    hits = response.get('hits', {}).get('hits', [])
    assert len(hits) > 0, "No documents found with file.strings populated"

    # Verify the field actually contains a non-empty value in the returned doc
    file_strings_value = hits[0].get('_source', {}).get('file', {}).get('strings')
    LOGGER.debug(f"file.strings value from first matching document: {file_strings_value!r}")
    assert file_strings_value, f"file.strings field exists in index but returned empty/null: {file_strings_value!r}"


@pytest.mark.carving
@pytest.mark.opensearch
@pytest.mark.pcap
def test_filescan_tree_depth(
    malcolm_http_auth,
    malcolm_url,
    database_objs,
):
    """test_filescan_tree_depth

    Check that filescan.tree.depth is populated with both shallow (depth == 1)
    and nested (depth > 1) records, indicating multi-level file tree extraction
    is occurring via Strelka/filescan.

    Args:
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
        malcolm_url (str): URL for connecting to the Malcolm instance
        database_objs (DatabaseObjs): object containing classes references for either the OpenSearch or Elasticsearch Python libraries
    """
    dbObjs = database_objs

    client = dbObjs.DatabaseClass(
        hosts=[
            f"{malcolm_url}/mapi/opensearch",
        ],
        **dbObjs.DatabaseInitArgs,
    )

    for label, query in {
        'depth == 1': {'term': {'filescan.tree.depth': 1}},
        'depth > 1': {'range': {'filescan.tree.depth': {'gt': 1}}},
    }.items():
        response = client.search(
            index='malcolm_network',
            body={
                'size': 1,
                'query': query,
                '_source': ['filescan.tree.depth'],
            },
        )
        hits = response.get('hits', {}).get('hits', [])
        depth_value = hits[0].get('_source', {}).get('filescan', {}).get('tree', {}).get('depth') if hits else None
        LOGGER.debug(f"filescan.tree.depth ({label}) first matching document value: {depth_value!r}")
        assert len(hits) > 0, f"No documents found with filescan.tree.depth {label}"
