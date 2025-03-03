import re
import socket
import sys
import time

from import_export.utils.enums import (
    AsymmetricKeyUsage,
    EccKeyAlgorithm,
    RsaKeyAlgorithm,
    SymmetricKeyAlgorithm,
)

# Futurex Command tokens mapping
CT_TOKEN = {
    SymmetricKeyAlgorithm.TDES_2KEY: 2,
    SymmetricKeyAlgorithm.TDES_3KEY: 3,
    SymmetricKeyAlgorithm.AES_128: 4,
    SymmetricKeyAlgorithm.AES_192: 5,
    SymmetricKeyAlgorithm.AES_256: 6,
}
RA_TOKEN = {
    EccKeyAlgorithm.ECC_NIST_P256: 2,
    EccKeyAlgorithm.ECC_NIST_P384: 3,
}
RB_TOKEN = {
    RsaKeyAlgorithm.RSA_2048: 2048,
    RsaKeyAlgorithm.RSA_3072: 3072,
    RsaKeyAlgorithm.RSA_4096: 4096,
}
CZ_TOKEN = {
    AsymmetricKeyUsage.KEY_AGREEMENT_KEY: "X",
    AsymmetricKeyUsage.VERIFY: "V",
    AsymmetricKeyUsage.SIGN: "G",
}


class FuturexCommands:
    """
    Commands are assuming that it is using PMK. FS token will be set to 6.
    """

    def __init__(self, host, port):
        self.host = host
        self.port = port

    def gpgs_command(self, key_block_header: str, key_algorithm: SymmetricKeyAlgorithm):
        key_algorithm_token = CT_TOKEN[key_algorithm]
        command = f"[AOGPGS;FS6;CT{key_algorithm_token};AK{key_block_header};]"

        response = self._send_payload(command.encode())

        wrapped_key = self._get_response_token("BG", response)
        kcv = self._get_response_token("AE", response)
        return wrapped_key, kcv

    def gecc_command(self, key_algorithm: EccKeyAlgorithm, key_usage: AsymmetricKeyUsage):
        key_algorithm_token = RA_TOKEN[key_algorithm]
        mode_of_use_token = CZ_TOKEN[key_usage]
        command = f"[AOGECC;BJ6;RA{key_algorithm_token};KB1;CZ{mode_of_use_token};]"

        response = self._send_payload(command.encode())

        wrapped_private_key = self._get_response_token("RC", response)
        trusted_public_key = self._get_response_token("SD", response)
        clear_public_key = self._get_response_token("RD", response)
        return wrapped_private_key, trusted_public_key, clear_public_key

    def grsa_command(self, key_algorithm: RsaKeyAlgorithm, key_usage: AsymmetricKeyUsage):
        key_length_token = RB_TOKEN[key_algorithm]
        mode_of_use_token = CZ_TOKEN[key_usage]
        command = f"[AOGRSA;RB{key_length_token};CZ{mode_of_use_token};BJ6;RA10001;KB1;KF1;SP1;]"

        response = self._send_payload(command.encode())

        wrapped_private_key = self._get_response_token("RC", response)
        trusted_public_key = self._get_response_token("SD", response)
        clear_public_key = self._get_response_token("RD", response)
        return wrapped_private_key, trusted_public_key, clear_public_key

    def asgc_command(self, private_key: str):
        command = f"[AOASGC;RY3;XE1122;KUdigitalSignature,nonRepudiation,keyCertSign;AL6;AD1;BCCA:TRUE;RTKDH CA1;RSSelfSignedCertificate;SG10101;FS6;RC{private_key};]"
        response = self._send_payload(command.encode())

        certificate_der = self._get_response_token("RV", response)
        return certificate_der

    def asyr_command(self, private_key):
        command = f"[AOASYR;RG6;KUcritical,digitalSignature,keyEncipherment;RTPublicKey Cert;LA10201;FS6;RC{private_key};]"
        response = self._send_payload(command.encode())

        csr = self._get_response_token("RU", response)
        return csr

    def assr_command(self, csr, ca_wrapped_private_key, ca_certificate_der):
        command = f"[AOASSR;RY3;XE1122;AL6;KUdigitalSignature,nonRepudiation;RU{csr};SG20301;FS6;RH{ca_certificate_der};RC{ca_wrapped_private_key};RG1;]"
        response = self._send_payload(command.encode())

        certificate_der = self._get_response_token("RV", response)
        return certificate_der

    def avpc_command(self, certificate_der, ca_tpk=None):
        if ca_tpk is not None:
            command = f"[AOAVPC;FS6;RY3;KB1;CZX;SA{ca_tpk};RV{certificate_der};]"
        else:
            command = f"[AOAVPC;FS6;RY3;KB1;CZV;RV{certificate_der};]"

        response = self._send_payload(command.encode())
        certificate_tpk = self._get_response_token("RD", response)
        return certificate_tpk

    def trtp_command(
        self,
        kdh_certificate_der,
        kdh_private_key,
        krd_certificate_der,
        krd_ca_certificate_tpk,
        transport_key,
        nonce,
    ):
        command = f"[AOTRTP;ZA3;FS6;CT3;RV{kdh_certificate_der};RC{kdh_private_key};SJ{krd_certificate_der};SA{krd_ca_certificate_tpk};BG{transport_key};BJ{nonce};]"
        response = self._send_payload(command.encode())

        tr34_payload = self._get_response_token("SJ", response)
        return tr34_payload

    def twka_command(self, key_to_export, kek):
        command = f"[AOTWKA;FS6;AP{kek};BG{key_to_export};OFT;]"
        response = self._send_payload(command.encode())

        wrapped_key = self._get_response_token("BH", response)
        return wrapped_key

    def _send_payload(self, data: bytes, terminator=b"]"):
        output = b""
        try:
            connection = socket.create_connection((self.host, self.port), timeout=30)
            connection.sendall(data)

            end_time = time.time() + 30
            while end_time > time.time():
                try:
                    output += connection.recv(2**16)
                    if terminator and terminator in output:
                        break
                except socket.timeout:
                    print("Failed to send the payload to HSM.")
                    # connection.shutdown(socket.SHUT_RDWR)
                    # connection.close()
                    break
        finally:
            connection.shutdown(socket.SHUT_RDWR)
            connection.close()

        return output.decode()

    def _get_response_token(self, field: str, payload: str) -> str:
        pattern = r".*[\[;]" + field + r"(.*?);.*"
        matcher = re.match(pattern, payload)

        if not matcher:
            print(
                "Failed to find token in the command response : " + pattern + " in " + str(payload)
            )
            sys.exit(1)
        return matcher.group(1)
