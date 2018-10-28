"""DNS Authenticator for Dreamhost DNS."""
import logging

import requests
import zope.interface

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)

ACCOUNT_URL = 'https://panel.dreamhost.com/?tree=home.api'


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Dreamhost

    This Authenticator uses the Dreamhost API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certificates using a DNS TXT record (if you are using Dreamhost for DNS).'
    ttl = 60

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=120)
        add('credentials', help='Dreamhost credentials INI file.')

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the Dreamhost API.'

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'Dreamhost credentials INI file',
            {
                'token': 'API token for Dreamhost account, obtained from {0}'.format(ACCOUNT_URL),
            }
        )

    def _perform(self, domain, validation_name, validation):
        self._get_dreamhost_client().add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        self._get_dreamhost_client().del_txt_record(domain, validation_name, validation)

    def _get_dreamhost_client(self):
        return _DreamhostDNSClient(self.credentials.conf('token'),
                                   self.ttl)


DEFAULTS = {
    'format': 'json',
}

class _DreamhostDNSClient(object):
    """
    Encapsulates all communication with the Dreamhost via Lexicon.
    """

    def __init__(self, token, ttl):
        self.session = requests.Session()
        self.token = token
        self.ttl = ttl

    @property
    def _base_args(self):
        args = {'key': self.token, "format": "json"}
        return args

    def add_txt_record(self, domain_name, record_name, record_content):
        resp = self.session.get('https://api.dreamhost.com/', params=dict(
            cmd="dns-add_record",
            type='txt',
            record=record_name,
            value=record_content,
            **self._base_args,
        ))

    def del_txt_record(self, domain_name, record_name, record_content):
        resp = self.session.get('https://api.dreamhost.com/', params=dict(
            cmd="dns-remove_record",
            type='txt',
            record=record_name,
            value=record_content,
            **self._base_args,
        ))

