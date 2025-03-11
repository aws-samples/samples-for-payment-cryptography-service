# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import binascii
import sys

import helpers.atalla_helper as atalla_helper
from asn1crypto import x509, keys, csr, pem, algos
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_der_public_key

def _writer(func):
    name = func.__name__
    return property(fget=lambda self: getattr(self, '_%s' % name), fset=func)


def pem_armor_csr(certification_request):
    """
    Encodes a CSR into PEM format

    :param certification_request:
        An asn1crypto.csr.CertificationRequest object of the CSR to armor.
        Typically this is obtained from CSRBuilder.build().

    :return:
        A byte string of the PEM-encoded CSR
    """

    return pem.armor(
        'CERTIFICATE REQUEST',
        certification_request.dump()
    )

class AtallaCSRBuilder(object):

    _subject = None
    _hash_algo = None
    _basic_constraints = None
    _subject_alt_name = None
    _key_usage = None
    _extended_key_usage = None
    _other_extensions = None

    _special_extensions = set([
        'basic_constraints',
        'subject_alt_name',
        'key_usage',
        'extended_key_usage',
    ])

    def __init__(self, subject):
        """
        Unless changed, CSRs will use SHA-256 for the signature

        :param subject:
            An asn1crypto.x509.Name object, or a dict - see the docstring
            for .subject for a list of valid options

        :param kms_arn:
            KMS Key Pair ARN with key usage SIGN_VERIFY
        """

        self.subject = subject
        self.ca = False

        self._hash_algo = 'sha256'
        self._other_extensions = {}

    @_writer
    def subject(self, value):
        is_dict = isinstance(value, dict)
        if is_dict:
            value = x509.Name.build(value)

        self._subject = value

    @property
    def ca(self):
        """
        None or a bool - if the request is for a CA cert. None indicates no
        basic constraints extension request.
        """

        if self._basic_constraints is None:
            return None

        return self._basic_constraints['ca'].native

    @ca.setter
    def ca(self, value):
        if value is None:
            self._basic_constraints = None
            return

        self._basic_constraints = x509.BasicConstraints({'ca': bool(value)})

        if value:
            self._key_usage = x509.KeyUsage(set(['key_cert_sign', 'crl_sign']))
            self._extended_key_usage = x509.ExtKeyUsageSyntax(['ocsp_signing'])
        else:
            self._key_usage = x509.KeyUsage(set(['digital_signature', 'key_encipherment']))
            self._extended_key_usage = x509.ExtKeyUsageSyntax(['server_auth', 'client_auth'])

    def _determine_critical(self, name):
        if name == 'subject_alt_name':
            return len(self._subject) == 0

        if name == 'basic_constraints':
            return self.ca is True

        return {
            'subject_directory_attributes': False,
            'key_usage': True,
            'issuer_alt_name': False,
            'name_constraints': True,
            # Based on example EV certificates, non-CA certs have this marked
            # as non-critical, most likely because existing browsers don't
            # seem to support policies or name constraints
            'certificate_policies': False,
            'policy_mappings': True,
            'policy_constraints': True,
            'extended_key_usage': False,
            'inhibit_any_policy': True,
            'subject_information_access': False,
            'tls_feature': False,
            'ocsp_no_check': False,
        }.get(name, False)

    def build_csr(self,priv_key,pub_key,atalla_address):
        """
        Validates the certificate information, constructs an X.509 certificate
        and then signs it

        :return:
            An asn1crypto.csr.CertificationRequest object of the request
        """
        def _make_extension(name, value):
            return {
                'extn_id': name,
                'critical': self._determine_critical(name),
                'extn_value': value
            }

        extensions = []
        for name in sorted(self._special_extensions):
            value = getattr(self, '_%s' % name)
            if value is not None:
                extensions.append(_make_extension(name, value))

        for name in sorted(self._other_extensions.keys()):
            extensions.append(_make_extension(name, self._other_extensions[name]))

        attributes = []
        if extensions:
            attributes.append({
                'type': 'extension_request',
                'values': [extensions]
            })

        self._subject_public_key = pub_key.asn1
        certification_request_info = csr.CertificationRequestInfo({
            'version': 'v1',
            'subject': self._subject,
            'subject_pk_info': self._subject_public_key,
            'attributes': attributes
        })
     
        signature = atalla_helper.sign139(priv_key,certification_request_info.dump(),atalla_address)
        signature_algorithm_id = algos.SignedDigestAlgorithm({
                    'algorithm': 'sha256_rsa',
                })
        csrRequest = csr.CertificationRequest({
            'certification_request_info': certification_request_info,
            'signature_algorithm': signature_algorithm_id,
            'signature': binascii.unhexlify(signature)
        })

        csrRequest = pem_armor_csr(csrRequest)

        return csrRequest