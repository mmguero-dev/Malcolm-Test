import pytest
import mmguero
import requests
import logging
import petname
import json
import time
from uuid import uuid4
from urllib.parse import quote

from maltest.utils import get_malcolm_http_auth, get_malcolm_url
from datetime import datetime, timedelta, UTC

LOGGER = logging.getLogger(__name__)


@pytest.mark.mapi
def test_mapi_indices(
    malcolm_url,
    malcolm_http_auth,
):
    """test_mapi_indices

    Test the /mapi/indices API

    Args:
        malcolm_url (str): URL for connecting to the Malcolm instance
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
    """
    response = requests.get(
        f"{malcolm_url}/mapi/indices",
        headers={"Content-Type": "application/json"},
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    indices = {item['index']: item for item in response.json().get('indices', [])}
    LOGGER.debug(indices)
    assert indices


@pytest.mark.mapi
def test_mapi_fields(
    malcolm_url,
    malcolm_http_auth,
):
    """test_mapi_fields

    Test the /mapi/fields API

    Args:
        malcolm_url (str): URL for connecting to the Malcolm instance
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
    """
    response = requests.get(
        f"{malcolm_url}/mapi/fields",
        headers={"Content-Type": "application/json"},
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    fieldsResponse = response.json()
    LOGGER.debug(fieldsResponse)
    fieldsTotal = fieldsResponse.get("total", 0)
    assert fieldsTotal > 1000
    assert len(fieldsResponse.get("fields", [])) == fieldsTotal


@pytest.mark.mapi
def test_mapi_dashboard_export(
    malcolm_url,
    malcolm_http_auth,
):
    """test_mapi_dashboard_export

    Test the /mapi/dashboard-export API by exporting the "Overview" dashboard and checking its title

    Args:
        malcolm_url (str): URL for connecting to the Malcolm instance
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
    """
    response = requests.get(
        f"{malcolm_url}/mapi/dashboard-export/0ad3d7c2-3441-485e-9dfe-dbb22e84e576",
        headers={"Content-Type": "application/json"},
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    dashboardData = response.json()
    LOGGER.debug(dashboardData)
    assert dashboardData.get("objects", [])[0].get("attributes", {}).get("title", "") == "Overview"


@pytest.mark.mapi
def test_event_log_mapi(
    malcolm_http_auth,
    malcolm_url,
):
    """test_event_log_mapi

    Test the /mapi/event API to log an event via the loopback alert webhook

    Args:
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
        malcolm_url (str): URL for connecting to the Malcolm instance
    """
    alert = {
        "alert": {
            "monitor": {"name": "Malcolm API Loopback Monitor"},
            "trigger": {"name": "Malcolm API Loopback Trigger", "severity": 4},
            "period": {
                "end": datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
                "start": (datetime.now(UTC) - timedelta(minutes=1)).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
            },
            "results": [
                {
                    "_shards": {"total": 5, "failed": 0, "successful": 5, "skipped": 0},
                    "hits": {"hits": [], "total": {"value": 697, "relation": "eq"}, "max_score": None},
                    "took": 1,
                    "timed_out": False,
                }
            ],
            "body": "",
            "alert": petname.Generate(),
            "error": "",
        }
    }

    response = requests.post(
        f"{malcolm_url}/mapi/event",
        headers={"Content-Type": "application/json"},
        json=alert,
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    responseData = response.json()
    LOGGER.debug(responseData)
    assert mmguero.deep_get(responseData, ['result', '_id'], '')
    assert mmguero.deep_get(responseData, ['result', '_index'], '')
    assert mmguero.deep_get(responseData, ['result', 'result'], '') in ['created', 'updated']


# Search tests seed their own documents through the already-tested event API.
# No UPLOAD_ARTIFACTS or PCAP marker is needed. Unique tags isolate each run (and
# each xdist worker) from ingestion elsewhere in the suite. Only the documents
# created by this fixture are deleted, never an index or an unscoped query.
#
# Use /agg for the default event.provider aggregation. The explicit
# /agg/event.provider alias redirects to /agg and can expose an incorrect
# external scheme/port when the API runs behind a reverse proxy. Unexpected
# redirects fail at the original response, with Location included in the error.
#
# These are black-box integration tests. Partial-shard failures, backend timeouts,
# and absent backend metadata need controlled backend fault injection or unit
# tests beside the API source. We do not destabilize the shared cluster here.


@pytest.fixture(scope="module")
def mapi_search_api():
    """Use the same credential/URL providers as conftest, with module lifetime."""
    url = get_malcolm_url().rstrip('/')
    with requests.Session() as session:
        session.auth = get_malcolm_http_auth()
        session.verify = False

        def call(method, endpoint, arguments=None, expected_status=200, timeout=60):
            arguments = {} if arguments is None else arguments
            kwargs = {}
            if method == 'GET':
                kwargs['params'] = {
                    key: value if isinstance(value, str) else json.dumps(value)
                    for key, value in arguments.items()
                }
            else:
                kwargs['json'] = arguments
            response = session.request(
                method,
                f'{url}/mapi/{endpoint.lstrip("/")}',
                headers={'Content-Type': 'application/json'},
                allow_redirects=False,
                timeout=timeout,
                **kwargs,
            )
            assert response.status_code == expected_status, (
                f'{method} {endpoint}: expected HTTP {expected_status}, '
                f'got {response.status_code}, Location={response.headers.get("Location")!r}: '
                f'{response.text[:2000]}'
            )
            result = response.json()
            assert isinstance(result, dict), f'{method} {endpoint}: expected a JSON object'
            return result

        yield call


def _assert_search_status(result):
    """Every normal query must expose complete, healthy backend status."""
    assert 'shards' in result and 'timed_out' in result, result
    shards = result['shards']
    assert isinstance(shards, dict), result
    for name in ('total', 'successful', 'skipped', 'failed'):
        assert type(shards.get(name)) is int and shards[name] >= 0, shards
    assert shards['total'] == shards['successful'] + shards['failed'], shards
    assert shards['skipped'] <= shards['successful'], shards
    assert shards['failed'] == 0, shards
    assert result['timed_out'] is False, result
    if 'failures' in shards:
        assert isinstance(shards['failures'], list) and not shards['failures'], shards
    assert isinstance(result.get('range'), list) and len(result['range']) == 2, result
    assert all(type(value) is int for value in result['range']), result
    assert 'filter' in result, result


def _assert_documents(result, expected_total=None, expected_count=None, counted=True):
    _assert_search_status(result)
    assert isinstance(result.get('results'), list), result
    assert 'total' in result, result
    if counted:
        total = result['total']
        assert isinstance(total, dict), result
        assert type(total.get('value')) is int and total['value'] >= 0, total
        assert total.get('relation') in ('eq', 'gte'), total
        if expected_total is not None:
            assert total == {'value': expected_total, 'relation': 'eq'}, total
    else:
        assert result['total'] is None, result
    if expected_count is not None:
        assert len(result['results']) == expected_count, result


def _assert_aggregation(result, fields):
    _assert_search_status(result)
    assert result.get('fields') == fields, result
    assert isinstance(result.get(fields[0]), dict), result
    assert isinstance(result[fields[0]].get('buckets'), list), result
    return result[fields[0]]['buckets']


def _identity(hit):
    return hit['_index'], hit['_id']


def _epoch_milliseconds(value):
    """Convert authored/source dates without relying on API sort metadata."""
    if isinstance(value, (int, float)):
        return int(value)
    return int(datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp() * 1000)


@pytest.fixture(scope="module")
def mapi_search_data(mapi_search_api):
    """Create six known events with timestamp ties and distinct secondary keys."""
    token = f'mapi-search-{uuid4().hex}'
    start = (datetime.now(UTC) - timedelta(minutes=5)).replace(microsecond=0)
    query = {
        'doctype': 'network',
        'from': str(int(start.timestamp()) - 1),
        'to': str(int(start.timestamp()) + 3),
        'filter': {'tags': token},
    }
    documents = []
    cleanup = []
    try:
        # Neither insertion order nor ID order follows the timestamp order.
        for seconds, suffix in ((2, 4), (0, 5), (1, 3), (0, 1), (2, 2), (1, 0)):
            timestamp = (start + timedelta(seconds=seconds)).isoformat().replace('+00:00', 'Z')
            event_id = f'{token}-{suffix}'
            response = mapi_search_api('POST', 'event', {
                'alert': {
                    'alert': event_id,
                    'monitor': {'name': token},
                    'trigger': {'name': 'API search fixture', 'severity': 4},
                    'period': {'start': timestamp, 'end': timestamp},
                    'body': {'tags': [token], '@timestamp': timestamp},
                },
            })
            indexed = response.get('result', {})
            assert indexed.get('_index') and indexed.get('_id'), response
            cleanup.append((indexed['_index'], indexed['_id']))
            assert indexed.get('result') == 'created', response
            documents.append({
                '_index': indexed['_index'], '_id': indexed['_id'],
                'event_id': event_id, 'timestamp': _epoch_milliseconds(timestamp),
            })

        # Wait for search visibility, rather than assuming an index refresh has
        # happened when /event acknowledges the write. Missing data is a failure.
        deadline = time.monotonic() + 60
        while True:
            result = mapi_search_api('POST', 'document', {
                **query, 'limit': 6, 'track_total_hits': True,
            })
            _assert_documents(result)
            if result['total'] == {'value': 6, 'relation': 'eq'} and len(result['results']) == 6:
                assert {_identity(hit) for hit in result['results']} == set(cleanup), result
                break
            assert time.monotonic() < deadline, f'Fixture documents never became searchable: {result}'
            time.sleep(1)
        yield {'query': query, 'documents': documents, 'start': start, 'token': token}
    finally:
        failures = []
        for index, doc_id in cleanup:
            try:
                # A refresh wait can stall when automatic refresh is disabled
                # or delayed. Each run has a unique tag, so cleanup only needs
                # the delete acknowledgement, not immediate search visibility.
                mapi_search_api(
                    'DELETE',
                    f'opensearch/{quote(index, safe="")}/_doc/{quote(doc_id, safe="")}',
                    timeout=10,
                )
            except Exception as exc:
                failures.append(f'{index}/{doc_id}: {exc}')
        assert not failures, 'Could not clean up API fixture documents:\n' + '\n'.join(failures)


@pytest.mark.mapi
class TestMAPISearch:
    """Document/aggregation contracts tested through the public authenticated API."""

    @pytest.mark.parametrize('method', ['GET', 'POST'])
    @pytest.mark.parametrize('endpoint', ['document', 'agg'])
    def test_legacy_request_without_parameters(self, mapi_search_api, method, endpoint):
        result = mapi_search_api(method, endpoint)
        if endpoint == 'document':
            _assert_documents(result)
            assert all('sort' not in hit for hit in result['results']), result
        else:
            _assert_aggregation(result, ['event.provider'])
        assert result['filter'] is None, result

    @pytest.mark.parametrize('method', ['GET', 'POST'])
    def test_legacy_filtered_lookup(self, mapi_search_api, mapi_search_data, method):
        query = mapi_search_data['query']
        result = mapi_search_api(method, 'document', {**query, 'limit': '2'})
        _assert_documents(result, expected_total=6, expected_count=2)
        assert result['filter'] == query['filter']
        assert result['range'] == [int(query['from']), int(query['to'])]
        assert all('sort' not in hit for hit in result['results'])
        expected = {_identity(doc) for doc in mapi_search_data['documents']}
        assert {_identity(hit) for hit in result['results']} <= expected

    @pytest.mark.parametrize('method', ['GET', 'POST'])
    @pytest.mark.parametrize('doctype', ['network', 'host', 'arkime'])
    def test_doctype_count_only(self, mapi_search_api, method, doctype):
        result = mapi_search_api(method, 'document', {'doctype': doctype, 'from': '0', 'limit': 0})
        _assert_documents(result, expected_count=0)

    @pytest.mark.parametrize('method', ['GET', 'POST'])
    @pytest.mark.parametrize('field', ['firstPacket', '@timestamp'])
    @pytest.mark.parametrize('form,descending', [
        ('{}', False), ('{}:asc', False), ('-{}', True),
        ('{}:desc', True), (' {}:ASC ', False),
    ], ids=['bare-ascending', 'explicit-ascending', 'minus-descending', 'explicit-descending', 'trim-uppercase'])
    def test_sort_matches_source_and_known_values(self, mapi_search_api, mapi_search_data, method, field, form, descending):
        result = mapi_search_api(method, 'document', {
            **mapi_search_data['query'], 'limit': 6, 'sort': form.format(field),
        })
        _assert_documents(result, expected_total=6, expected_count=6)
        expected = sorted((doc['timestamp'] for doc in mapi_search_data['documents']), reverse=descending)
        assert [hit['sort'] for hit in result['results']] == [[value] for value in expected]
        assert [_epoch_milliseconds(hit['_source'][field]) for hit in result['results']] == expected
        assert {_identity(hit) for hit in result['results']} == {_identity(doc) for doc in mapi_search_data['documents']}

    @pytest.mark.parametrize('method,array', [('GET', False), ('POST', False), ('POST', True)],
                             ids=['get-comma', 'post-comma', 'post-array'])
    @pytest.mark.parametrize('primary,secondary', [('asc', 'asc'), ('asc', 'desc'), ('desc', 'asc'), ('desc', 'desc')])
    def test_multifield_sort_and_complete_paging(self, mapi_search_api, mapi_search_data, method, array, primary, secondary):
        expressions = [f'firstPacket:{primary}', f'event.id:{secondary}']
        sort = expressions if array else ','.join(expressions)
        # Stable Python sorts compute an independent oracle, with the secondary
        # key applied first. The data contains two documents per timestamp.
        expected = sorted(mapi_search_data['documents'], key=lambda doc: doc['event_id'], reverse=secondary == 'desc')
        expected.sort(key=lambda doc: doc['timestamp'], reverse=primary == 'desc')
        received = []
        for offset in (0, 2, 4, 6):
            result = mapi_search_api(method, 'document', {
                **mapi_search_data['query'], 'sort': sort, 'offset': offset,
                'limit': 2, 'track_total_hits': True,
            })
            page = expected[offset:offset + 2]
            _assert_documents(result, expected_total=6, expected_count=len(page))
            assert [_identity(hit) for hit in result['results']] == [_identity(doc) for doc in page]
            assert [hit['sort'] for hit in result['results']] == [[doc['timestamp'], doc['event_id']] for doc in page]
            assert [hit['_source']['event']['id'] for hit in result['results']] == [doc['event_id'] for doc in page]
            received.extend(_identity(hit) for hit in result['results'])
        assert received == [_identity(doc) for doc in expected]
        assert len(set(received)) == 6

    @pytest.mark.parametrize('method', ['GET', 'POST'])
    @pytest.mark.parametrize('offset', [0, 1, 2])
    def test_single_document_offset_preserves_total(self, mapi_search_api, mapi_search_data, method, offset):
        doc = mapi_search_data['documents'][0]
        result = mapi_search_api(method, 'document', {
            **mapi_search_data['query'], 'filter': {'_index': doc['_index'], '_id': doc['_id']},
            'offset': offset, 'limit': 1, 'track_total_hits': True,
        })
        _assert_documents(result, expected_total=1, expected_count=1 if offset == 0 else 0)
        if offset == 0:
            assert _identity(result['results'][0]) == _identity(doc)

    @pytest.mark.parametrize('method', ['GET', 'POST'])
    @pytest.mark.parametrize('tracking', [True, ' TRUE ', 100, '100'], ids=['true', 'string-true', 'threshold', 'string-threshold'])
    def test_exact_count_without_hits(self, mapi_search_api, mapi_search_data, method, tracking):
        result = mapi_search_api(method, 'document', {
            **mapi_search_data['query'], 'limit': 0, 'track_total_hits': tracking,
        })
        _assert_documents(result, expected_total=6, expected_count=0)

    @pytest.mark.parametrize('method', ['GET', 'POST'])
    @pytest.mark.parametrize('tracking', [False, 'FALSE'], ids=['false', 'string-false'])
    def test_disabled_count(self, mapi_search_api, mapi_search_data, method, tracking):
        result = mapi_search_api(method, 'document', {
            **mapi_search_data['query'], 'limit': 1, 'track_total_hits': tracking,
        })
        _assert_documents(result, expected_count=1, counted=False)

    @pytest.mark.parametrize('method', ['GET', 'POST'])
    @pytest.mark.parametrize('threshold', [0, 1])
    def test_lower_bound_count(self, mapi_search_api, mapi_search_data, method, threshold):
        result = mapi_search_api(method, 'document', {
            **mapi_search_data['query'], 'limit': 0, 'track_total_hits': threshold,
        })
        _assert_documents(result, expected_count=0)
        assert result['total']['relation'] == 'gte'
        assert threshold <= result['total']['value'] <= 6
        if threshold == 0:
            assert result['total']['value'] == 0

    @pytest.mark.parametrize('method', ['GET', 'POST'])
    def test_integer_strings_and_whitespace(self, mapi_search_api, mapi_search_data, method):
        result = mapi_search_api(method, 'document', {
            **mapi_search_data['query'], 'limit': ' 0 ', 'offset': ' 0 ', 'track_total_hits': ' 100 ',
        })
        _assert_documents(result, expected_total=6, expected_count=0)

    def test_get_post_equivalence(self, mapi_search_api, mapi_search_data):
        query = {**mapi_search_data['query'], 'sort': 'firstPacket:asc,event.id:asc',
                 'limit': 6, 'track_total_hits': True}
        get = mapi_search_api('GET', 'document', query)
        post = mapi_search_api('POST', 'document', query)
        for result in (get, post):
            _assert_documents(result, expected_total=6, expected_count=6)
        for key in ('results', 'total', 'range', 'filter'):
            assert get[key] == post[key]

    @pytest.mark.parametrize('method', ['GET', 'POST'])
    def test_inclusive_time_bounds(self, mapi_search_api, mapi_search_data, method):
        instant = str(int(mapi_search_data['start'].timestamp()))
        result = mapi_search_api(method, 'document', {
            **mapi_search_data['query'], 'from': instant, 'to': instant,
        })
        _assert_documents(result, expected_total=2, expected_count=2)
        assert result['range'] == [int(instant), int(instant)]

    def test_legacy_till_is_ignored(self, mapi_search_api):
        before = int(datetime.now(UTC).timestamp())
        result = mapi_search_api('GET', 'agg', {'from': '0', 'till': '1'})
        after = int(datetime.now(UTC).timestamp())
        _assert_aggregation(result, ['event.provider'])
        assert result['range'][0] == 0
        # Allow modest client/server clock skew while ruling out till=1.
        assert before - 60 <= result['range'][1] <= after + 60

    @pytest.mark.parametrize('method', ['GET', 'POST'])
    @pytest.mark.parametrize('endpoint', ['document', 'agg'])
    def test_no_matches(self, mapi_search_api, mapi_search_data, method, endpoint):
        query = mapi_search_data['query']
        result = mapi_search_api(method, endpoint, {
            **query, 'filter': {**query['filter'], '!tags': mapi_search_data['token']},
        })
        if endpoint == 'document':
            _assert_documents(result, expected_total=0, expected_count=0)
        else:
            assert _assert_aggregation(result, ['event.provider']) == []

    @pytest.mark.parametrize('method', ['GET', 'POST'])
    def test_aggregation_exact_and_nested_counts(self, mapi_search_api, mapi_search_data, method):
        result = mapi_search_api(method, 'agg/event.provider,event.id', {
            **mapi_search_data['query'], 'limit': 10,
        })
        buckets = _assert_aggregation(result, ['event.provider', 'event.id'])
        assert len(buckets) == 1 and buckets[0]['key'] == 'malcolm' and buckets[0]['doc_count'] == 6
        nested = buckets[0]['event.id']['buckets']
        assert {bucket['key']: bucket['doc_count'] for bucket in nested} == {
            doc['event_id']: 1 for doc in mapi_search_data['documents']
        }
        assert result['filter'] == mapi_search_data['query']['filter']

    @pytest.mark.parametrize('method', ['GET', 'POST'])
    def test_aggregation_bucket_limit(self, mapi_search_api, mapi_search_data, method):
        result = mapi_search_api(method, 'agg/event.id', {**mapi_search_data['query'], 'limit': 1})
        buckets = _assert_aggregation(result, ['event.id'])
        assert len(buckets) == 1 and buckets[0]['doc_count'] == 1
        assert result['event.id']['sum_other_doc_count'] == 5

    @pytest.mark.parametrize('method', ['GET', 'POST'])
    @pytest.mark.parametrize('field', ['shards', 'timed_out', 'range', 'filter', 'fields', 'urls'])
    def test_aggregation_reserved_top_level_name(self, mapi_search_api, method, field):
        result = mapi_search_api(method, f'agg/{field}', expected_status=400)
        assert isinstance(result.get('error'), str) and result['error']

    @pytest.mark.parametrize('method', ['GET', 'POST'])
    def test_aggregation_nested_reserved_name(self, mapi_search_api, mapi_search_data, method):
        result = mapi_search_api(method, 'agg/event.provider,shards', mapi_search_data['query'])
        buckets = _assert_aggregation(result, ['event.provider', 'shards'])
        assert len(buckets) == 1 and buckets[0]['doc_count'] == 6
        assert isinstance(buckets[0]['shards']['buckets'], list)
        assert sum(bucket['doc_count'] for bucket in buckets[0]['shards']['buckets']) == 6

    @pytest.mark.parametrize('method', ['GET', 'POST'])
    @pytest.mark.parametrize('parameter', ['offset', 'limit'])
    @pytest.mark.parametrize('value', ['', '-1', '1.5', 'abc', 'true', '1e2'],
                             ids=['empty', 'negative', 'fraction', 'text', 'boolean-text', 'exponent'])
    def test_invalid_integer_strings(self, mapi_search_api, method, parameter, value):
        result = mapi_search_api(method, 'document', {parameter: value}, expected_status=400)
        assert isinstance(result.get('error'), str) and result['error']

    @pytest.mark.parametrize('parameter', ['offset', 'limit'])
    @pytest.mark.parametrize('value', [-1, 1.5, True, False, None, [], {}],
                             ids=['negative', 'fraction', 'true', 'false', 'null', 'array', 'object'])
    def test_invalid_integer_json_types(self, mapi_search_api, parameter, value):
        result = mapi_search_api('POST', 'document', {parameter: value}, expected_status=400)
        assert isinstance(result.get('error'), str) and result['error']

    @pytest.mark.parametrize('method', ['GET', 'POST'])
    @pytest.mark.parametrize('value', ['', '-', 'field:sideways', '-field:asc', 'field:asc:desc',
                                     'field,,other', 'field name', 'field:', ':asc', '+field'],
                             ids=['empty', 'minus-only', 'bad-direction', 'mixed-syntax', 'extra-colon',
                                  'empty-field', 'space-in-field', 'empty-direction', 'missing-field', 'plus-prefix'])
    def test_invalid_sort_strings(self, mapi_search_api, method, value):
        result = mapi_search_api(method, 'document', {'sort': value}, expected_status=400)
        assert isinstance(result.get('error'), str) and result['error']

    @pytest.mark.parametrize('value', [None, False, 1, {}, [], [None], [1], [''], ['field:asc', ''], ['field,other']],
                             ids=['null', 'boolean', 'number', 'object', 'empty-array', 'null-element',
                                  'number-element', 'empty-element', 'trailing-empty-element', 'comma-in-array-element'])
    def test_invalid_sort_json(self, mapi_search_api, value):
        result = mapi_search_api('POST', 'document', {'sort': value}, expected_status=400)
        assert isinstance(result.get('error'), str) and result['error']

    @pytest.mark.parametrize('method', ['GET', 'POST'])
    @pytest.mark.parametrize('value', ['', '-1', '1.5', 'yes', '1e3'],
                             ids=['empty', 'negative', 'fraction', 'yes', 'exponent'])
    def test_invalid_counting_strings(self, mapi_search_api, method, value):
        result = mapi_search_api(method, 'document', {'track_total_hits': value}, expected_status=400)
        assert isinstance(result.get('error'), str) and result['error']

    @pytest.mark.parametrize('value', [-1, 1.5, None, [], {}],
                             ids=['negative', 'fraction', 'null', 'array', 'object'])
    def test_invalid_counting_json(self, mapi_search_api, value):
        result = mapi_search_api('POST', 'document', {'track_total_hits': value}, expected_status=400)
        assert isinstance(result.get('error'), str) and result['error']

    @pytest.mark.parametrize('method', ['GET', 'POST'])
    @pytest.mark.parametrize('value', ['0', '-1', '1.5', 'abc', ''],
                             ids=['zero', 'negative', 'fraction', 'text', 'empty'])
    def test_invalid_aggregation_limit_strings(self, mapi_search_api, method, value):
        result = mapi_search_api(method, 'agg', {'limit': value}, expected_status=400)
        assert isinstance(result.get('error'), str) and result['error']

    @pytest.mark.parametrize('value', [0, -1, 1.5, True, False, None, [], {}],
                             ids=['zero', 'negative', 'fraction', 'true', 'false', 'null', 'array', 'object'])
    def test_invalid_aggregation_limit_json(self, mapi_search_api, value):
        result = mapi_search_api('POST', 'agg', {'limit': value}, expected_status=400)
        assert isinstance(result.get('error'), str) and result['error']

    @pytest.mark.opensearch
    def test_backend_result_window_error(self, mapi_search_api, mapi_search_data):
        """Read actual limits so the check works with nondefault index settings."""
        indices = mapi_search_api('GET', 'indices')
        pattern = indices['malcolm_network_index_pattern']
        settings = mapi_search_api('GET', f'opensearch/{quote(pattern, safe="*,")}/_settings', {
            'include_defaults': True, 'flat_settings': True,
        })
        assert settings, f'No index settings returned for {pattern}'
        limits = []
        for index, values in settings.items():
            limit = values.get('settings', {}).get('index.max_result_window')
            if limit is None:
                limit = values.get('defaults', {}).get('index.max_result_window')
            assert limit is not None, f'Missing result-window setting for {index}: {values}'
            limits.append(int(limit))
        # Exceed every selected index's window, avoiding a partial success when
        # different indexes have different limits. No cluster settings change.
        result = mapi_search_api('GET', 'document', {
            **mapi_search_data['query'], 'offset': max(limits), 'limit': 1,
        }, expected_status=500)
        assert result == {'error': 'Internal server error'}
