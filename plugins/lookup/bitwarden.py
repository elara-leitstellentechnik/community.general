# -*- coding: utf-8 -*-
# Copyright (c) 2022, Jonathan Lung <lungj@heresjono.com>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = """
    name: bitwarden
    author:
      - Jonathan Lung (@lungj) <lungj@heresjono.com>
    requirements:
      - bw (command line utility)
      - be logged into bitwarden
      - bitwarden vault unlocked
      - E(BW_SESSION) environment variable set
    short_description: Retrieve secrets from Bitwarden
    version_added: 5.4.0
    description:
      - Retrieve secrets from Bitwarden.
    options:
      _terms:
        description: Key(s) to fetch values for from login info.
        required: true
        type: list
        elements: str
      search:
        description:
          - Field to retrieve, for example V(name) or V(id).
          - If set to V(id), only zero or one element can be returned.
            Use the Jinja C(first) filter to get the only list element.
          - If set to V(None) or V(''), or if O(_terms) is empty, records are not filtered by fields.
        type: str
        default: name
        version_added: 5.7.0
      field:
        description: Field to fetch. Leave unset to fetch whole response.
        type: str
      collection_id:
        description:
          - Collection ID to filter results by collection. Leave unset to skip filtering.
          - O(collection_id) and O(collection_name) are mutually exclusive.
        type: str
        version_added: 6.3.0
      collection_name:
        description:
          - Collection name to filter results by collection. Leave unset to skip filtering.
          - O(collection_id) and O(collection_name) are mutually exclusive.
        type: str
        version_added: 10.4.0
      organization_id:
        description: Organization ID to filter results by organization. Leave unset to skip filtering.
        type: str
        version_added: 8.5.0
      bw_session:
        description: Pass session key instead of reading from env.
        type: str
        version_added: 8.4.0
        env:
          - name: BW_SESSION
      result_count:
        description:
          - Number of results expected for the lookup query. Task will fail if O(result_count)
            is set but does not match the number of query results. Leave empty to skip this check.
        type: int
        version_added: 10.4.0
      cache_results:
        description: Cache lookup results to reduce number of bitwarden-cli queries?
        type: bool
        version_added: 10.6.0
        env:
          - name: ANSIBLE_BITWARDEN_CACHE_RESULTS
        default: true
"""

EXAMPLES = """
- name: "Get 'password' from all Bitwarden records named 'a_test'"
  ansible.builtin.debug:
    msg: >-
      {{ lookup('community.general.bitwarden', 'a_test', field='password') }}

- name: "Get 'password' from Bitwarden record with ID 'bafba515-af11-47e6-abe3-af1200cd18b2'"
  ansible.builtin.debug:
    msg: >-
      {{ lookup('community.general.bitwarden', 'bafba515-af11-47e6-abe3-af1200cd18b2', search='id', field='password') | first }}

- name: "Get 'password' from all Bitwarden records named 'a_test' from collection"
  ansible.builtin.debug:
    msg: >-
      {{ lookup('community.general.bitwarden', 'a_test', field='password', collection_id='bafba515-af11-47e6-abe3-af1200cd18b2') }}

- name: "Get list of all full Bitwarden records named 'a_test'"
  ansible.builtin.debug:
    msg: >-
      {{ lookup('community.general.bitwarden', 'a_test') }}

- name: "Get custom field 'api_key' from all Bitwarden records named 'a_test'"
  ansible.builtin.debug:
    msg: >-
      {{ lookup('community.general.bitwarden', 'a_test', field='api_key') }}

- name: "Get 'password' from all Bitwarden records named 'a_test', using given session key"
  ansible.builtin.debug:
    msg: >-
      {{ lookup('community.general.bitwarden', 'a_test', field='password', bw_session='bXZ9B5TXi6...') }}

- name: "Get all Bitwarden records from collection"
  ansible.builtin.debug:
    msg: >-
      {{ lookup('community.general.bitwarden', None, collection_id='bafba515-af11-47e6-abe3-af1200cd18b2') }}

- name: "Get all Bitwarden records from collection"
  ansible.builtin.debug:
    msg: >-
      {{ lookup('community.general.bitwarden', None, collection_name='my_collections/test_collection') }}

- name: "Get Bitwarden record named 'a_test', ensure there is exactly one match"
  ansible.builtin.debug:
    msg: >-
      {{ lookup('community.general.bitwarden', 'a_test', result_count=1) }}
"""

RETURN = """
  _raw:
    description:
      - A one-element list that contains a list of requested fields or JSON objects of matches.
      - If you use C(query), you get a list of lists. If you use C(lookup) without C(wantlist=true),
        this always gets reduced to a list of field values or JSON objects.
    type: list
    elements: list
"""

import base64
import hashlib
import json
import os
import tempfile
import threading

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from filelock import FileLock
from subprocess import Popen, PIPE
from typing import Callable

from ansible.errors import AnsibleError, AnsibleOptionsError
from ansible.module_utils.common.text.converters import to_bytes, to_text
from ansible.utils.display import Display
from ansible.parsing.ajson import AnsibleJSONDecoder
from ansible.plugins.lookup import LookupBase

display = Display()


class BitwardenException(AnsibleError):
    pass


# TODO: cache expiry?
# TODO: document python deps
class BitwardenCache:
    _lock = threading.Lock()
    _instance = None
    _cache = {}
    _cache_file = os.path.join(tempfile.gettempdir(), "ansible-bitwarden-cache")
    _cache_file_lock = None
    _fernet = None

    def __new__(cls, session: str):
        if cls._instance is None:
            with cls._lock:
                # Another thread could have created the instance
                # before we acquired the lock. So check that the
                # instance is still nonexistent.
                if not cls._instance:
                    cls._instance = super().__new__(cls)
                    cls._cache_file_lock = FileLock(cls._cache_file + ".lock", thread_local=False)  # TODO: os.lockf?
                    cls._fernet = Fernet(
                        base64.urlsafe_b64encode(
                            PBKDF2HMAC(
                                algorithm=hashes.SHA256(),
                                length=32,
                                salt=b'',
                                iterations=1,
                            ).derive(session.encode())
                        )
                    )
                    cls._load_cache(cls._instance)

        return cls._instance

    def _load_cache(self):
        """
        Load cache from file
        """
        if os.path.exists(self._cache_file):
            display.vvv(msg=f"lookup(community.general.bitwarden): Found existing cache file: {self._cache_file}")
            with self._cache_file_lock:
                with open(self._cache_file) as cache_file:
                    try:
                        self._cache = json.loads(self._fernet.decrypt(cache_file.read()).decode('utf-8'))
                        display.vvv(
                            msg=f"lookup(community.general.bitwarden): Loaded cache entries: {self._cache.keys()}")
                    except InvalidToken:
                        display.vvv(msg=f"lookup(community.general.bitwarden): Failed to load cache file: InvalidToken "
                                        f"- This is probably caused by a new BW_SESSION. Cache file will be overridden")
                    except Exception as e:
                        display.vvv(msg=f"lookup(community.general.bitwarden): Failed to load cache file: "
                                        f"{type(e)} {e.args} - Cache file will be overridden")

        else:
            display.vvv(msg=f"lookup(community.general.bitwarden): Didn't find cache file: {self._cache_file}")

    def _dump_cache(self):
        """
        Dump cache to file
        """
        display.vvv(msg=f"lookup(community.general.bitwarden): Dumping cache to file")
        with self._cache_file_lock:
            with open(self._cache_file, "wb") as cache_file:
                try:
                    cache_file.write(self._fernet.encrypt(json.dumps(self._cache).encode('utf-8')))
                except Exception as e:
                    display.vvv(msg=f"lookup(community.general.bitwarden): Failed to write cache file: {e}")

    def cached_execution(self, func: Callable, **kwargs):
        """
        Will cache the results of func
        **kwargs will be passed to func as parameters

        :param func: func to cache results from
        :param kwargs: Parameters for func
        :return: Cached results of func
        """

        # use function and kwargs as cache key
        hash_inputs = kwargs.copy()
        hash_inputs.update({"_func": func.__name__})
        hash_inputs = repr(sorted(hash_inputs.items()))
        key = hashlib.sha256(hash_inputs.encode()).hexdigest()

        if not self._cache.get(key):
            with self._lock:
                with self._cache_file_lock:
                    # reload cache file since it might have been updated by another process
                    self._load_cache()

                    if not self._cache.get(key):
                        display.vvv(msg=f"lookup(community.general.bitwarden): not in cache: {hash_inputs} ({key})")
                        self._cache[key] = func(**kwargs)
                        self._dump_cache()
        else:
            display.vvv(msg=f"lookup(community.general.bitwarden): found in cache: {hash_inputs} ({key})")

        return self._cache.get(key)


class Bitwarden(object):

    def __init__(self, path='bw'):
        self._cli_path = path
        self._session = None

    @property
    def cli_path(self):
        return self._cli_path

    @property
    def session(self):
        return self._session

    @session.setter
    def session(self, value):
        self._session = value

    @property
    def unlocked(self):
        out, err = self._run(['status'], stdin="")
        decoded = AnsibleJSONDecoder().raw_decode(out)[0]
        return decoded['status'] == 'unlocked'

    def _run(self, args, stdin=None, expected_rc=0):
        if self.session:
            args += ['--session', self.session]

        p = Popen([self.cli_path] + args, stdout=PIPE, stderr=PIPE, stdin=PIPE)
        out, err = p.communicate(to_bytes(stdin))
        rc = p.wait()
        if rc != expected_rc:
            if len(args) > 2 and args[0] == 'get' and args[1] == 'item' and b'Not found.' in err:
                return 'null', ''
            raise BitwardenException(err)
        return to_text(out, errors='surrogate_or_strict'), to_text(err, errors='surrogate_or_strict')

    def _get_matches(self, search_value, search_field, collection_id=None, organization_id=None):
        """Return matching records whose search_field is equal to key.
        """

        # Prepare set of params for Bitwarden CLI
        if search_field == 'id':
            params = ['get', 'item', search_value]
        else:
            params = ['list', 'items']
            if search_value:
                params.extend(['--search', search_value])

        if collection_id:
            params.extend(['--collectionid', collection_id])
        if organization_id:
            params.extend(['--organizationid', organization_id])

        out, err = self._run(params)

        # This includes things that matched in different fields.
        initial_matches = AnsibleJSONDecoder().raw_decode(out)[0]

        if search_field == 'id':
            if initial_matches is None:
                initial_matches = []
            else:
                initial_matches = [initial_matches]

        # Filter to only include results from the right field, if a search is requested by value or field
        return [item for item in initial_matches
                if not search_value or not search_field or item.get(search_field) == search_value]

    def get_field(self, field, search_value, search_field="name", collection_id=None, organization_id=None):
        """Return a list of the specified field for records whose search_field match search_value
        and filtered by collection if collection has been provided.

        If field is None, return the whole record for each match.
        """
        matches = self._get_matches(search_value, search_field, collection_id, organization_id)
        if not field:
            return matches
        field_matches = []
        for match in matches:
            # if there are no custom fields, then `match` has no key 'fields'
            if 'fields' in match:
                custom_field_found = False
                for custom_field in match['fields']:
                    if field == custom_field['name']:
                        field_matches.append(custom_field['value'])
                        custom_field_found = True
                        break
                if custom_field_found:
                    continue
            if 'login' in match and field in match['login']:
                field_matches.append(match['login'][field])
                continue
            if field in match:
                field_matches.append(match[field])
                continue

        if matches and not field_matches:
            raise AnsibleError(f"field {field} does not exist in {search_value}")

        return field_matches

    def get_collection_ids(self, collection_name: str, organization_id=None) -> list[str]:
        """Return matching IDs of collections whose name is equal to collection_name."""

        # Prepare set of params for Bitwarden CLI
        params = ['list', 'collections', '--search', collection_name]

        if organization_id:
            params.extend(['--organizationid', organization_id])

        out, err = self._run(params)

        # This includes things that matched in different fields.
        initial_matches = AnsibleJSONDecoder().raw_decode(out)[0]

        # Filter to only return the ID of a collections with exactly matching name
        return [item['id'] for item in initial_matches
                if str(item.get('name')).lower() == collection_name.lower()]


class LookupModule(LookupBase):

    @staticmethod
    def _query_bwcli(terms, field, search_field, collection_id, collection_name, organization_id):
        if not _bitwarden.unlocked:
            raise AnsibleError("Bitwarden Vault locked. Run 'bw unlock'.")

        if collection_name and collection_id:
            raise AnsibleOptionsError("'collection_name' and 'collection_id' are mutually exclusive!")
        elif collection_name:
            collection_ids = _bitwarden.get_collection_ids(collection_name, organization_id)
            if not collection_ids:
                raise BitwardenException("No matching collections found!")
        else:
            collection_ids = [collection_id]

        return [
            _bitwarden.get_field(field, term, search_field, collection_id, organization_id)
            for collection_id in collection_ids
            for term in terms
        ]

    def run(self, terms=None, variables=None, **kwargs):
        self.set_options(var_options=variables, direct=kwargs)
        field = self.get_option('field')
        search_field = self.get_option('search')
        collection_id = self.get_option('collection_id')
        collection_name = self.get_option('collection_name')
        organization_id = self.get_option('organization_id')
        result_count = self.get_option('result_count')
        cache_results = self.get_option('cache_results')
        _bitwarden.session = self.get_option('bw_session')

        if not terms:
            terms = [None]

        display.vvv(
            msg=f"lookup(community.general.bitwarden): cache is " + ("enabled" if cache_results else "disabled"))

        query_args = dict(
            terms=terms,
            field=field,
            search_field=search_field,
            collection_id=collection_id,
            collection_name=collection_name,
            organization_id=organization_id
        )
        results = BitwardenCache(_bitwarden.session).cached_execution(self._query_bwcli, **query_args) \
            if cache_results else self._query_bwcli(**query_args)

        for result in results:
            if result_count is not None and len(result) != result_count:
                raise BitwardenException(
                    f"Number of results doesn't match result_count! ({len(result)} != {result_count})")

        return results


_bitwarden = Bitwarden()
