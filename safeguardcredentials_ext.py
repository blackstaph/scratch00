# collection/oneidentity/safeguard/plugins/lookup/safeguardcredentials_ext.py
#
# DROP-IN FIX/EXTENSION:
# - Supports the original invocation style:
#     lookup('...safeguardcredentials_ext', <api_key>,
#            a2aconnection={spp_appliance, spp_certificate_file, spp_certificate_key,
#                           spp_tls_cert, spp_credential_type, spp_api_version, spp_validate_certs})
# - If the first positional term (api_key) is empty/false and (system, account) are provided,
#   the plugin derives the ApiKey via Core and then performs the A2A retrieval.
# - Uses pysafeguard exactly as the vendor plugin does.

from ansible.plugins.lookup import LookupBase
from ansible.errors import AnsibleError
import os
from pysafeguard import PySafeguardConnection, HttpMethods, Services, A2ATypes

DOCUMENTATION = r"""
lookup: oneidentity.safeguardcollection.safeguardcredentials_ext
author:
  - One Identity
  - Extended by You
short_description: Retrieve credentials from Safeguard A2A (API key positional or discovery via system/account)
description:
  - Compatible with the vendor plugin’s calling convention where the first positional term is the ApiKey.
  - Accepts a connection dictionary via C(a2aconnection) containing:
    C(spp_appliance), C(spp_certificate_file), C(spp_certificate_key), C(spp_tls_cert),
    C(spp_credential_type), C(spp_api_version), C(spp_validate_certs).
  - If the positional ApiKey is empty/false and both C(system) and C(account) are provided,
    the plugin discovers the ApiKey via Core (A2ARegistrations → RetrievableAccounts) using the same client certificate.
options:
  a2aconnection:
    description: Dictionary of connection parameters (same keys as the original plugin).
    type: dict
    required: true
    suboptions:
      spp_appliance:
        type: str
      spp_certificate_file:
        type: str
      spp_certificate_key:
        type: str
      spp_tls_cert:
        type: str
      spp_credential_type:
        type: str
        description: password or privatekey (case-insensitive)
      spp_api_version:
        type: str
        default: v4
      spp_validate_certs:
        type: bool
        default: true
  system:
    description: System (Asset) name used to derive ApiKey when positional ApiKey is empty.
    type: str
    required: false
  account:
    description: Account name used to derive ApiKey when positional ApiKey is empty.
    type: str
    required: false
  spp_registration_index:
    description: Zero-based index into Core /A2ARegistrations.
    type: int
    default: 0
notes:
  - Requires the pysafeguard Python package in the Execution Environment.
  - Private key must be unencrypted.
"""

EXAMPLES = r"""
# Original style: first term is the ApiKey; connection passed as a2aconnection
- set_fact:
    my_password: >-
      {{ lookup('oneidentity.safeguardcollection.safeguardcredentials_ext',
                spp_credential_apikey,
                a2aconnection={
                  'spp_appliance': host,
                  'spp_certificate_file': cert,
                  'spp_certificate_key': key,
                  'spp_tls_cert': cacert,
                  'spp_credential_type': 'password',
                  'spp_api_version': 'v4',
                  'spp_validate_certs': true
                }) }}

# Derive ApiKey when the first term is empty/false
- set_fact:
    my_password: >-
      {{ lookup('oneidentity.safeguardcollection.safeguardcredentials_ext',
                '',                             # no api key provided here
                a2aconnection={
                  'spp_appliance': host,
                  'spp_certificate_file': cert,
                  'spp_certificate_key': key,
                  'spp_tls_cert': cacert,
                  'spp_credential_type': 'password',
                  'spp_api_version': 'v4',
                  'spp_validate_certs': true
                },
                system=system_name,
                account=account_name,
                spp_registration_index=0) }}
"""

RETURN = r"""
_raw:
  description: The retrieved credential (password text or private-key material) as a string.
  type: str
"""

class LookupModule(LookupBase):
    def run(self, terms, variables=None, **kwargs):
        # --- positional ApiKey, per original plugin convention ---
        if terms is None or len(terms) == 0:
            raise AnsibleError("Positional ApiKey term is required (use '' if you want discovery via system/account).")
        positional_api_key = terms[0]

        # --- connection dict exactly as original ---
        conn = kwargs.get("a2aconnection") or kwargs.get("a2apasswordconnectioninfo")
        if not isinstance(conn, dict):
            raise AnsibleError("a2aconnection must be a dict with spp_* keys")

        spp_appliance        = conn.get("spp_appliance")
        spp_certificate_file = conn.get("spp_certificate_file")
        spp_certificate_key  = conn.get("spp_certificate_key")
        spp_tls_cert         = conn.get("spp_tls_cert")
        spp_credential_type  = conn.get("spp_credential_type", "password")
        spp_api_version      = conn.get("spp_api_version", "v4")
        spp_validate_certs   = conn.get("spp_validate_certs", True)

        if not spp_appliance:
            raise AnsibleError("Missing spp_appliance")
        if not spp_certificate_file or not spp_certificate_key:
            raise AnsibleError("spp_certificate_file and spp_certificate_key are required")

        cert_file = self._abs_ok(spp_certificate_file, "spp_certificate_file")
        key_file  = self._abs_ok(spp_certificate_key,  "spp_certificate_key")
        ca_bundle = None
        if spp_validate_certs:
            if not spp_tls_cert:
                raise AnsibleError("spp_tls_cert is required when spp_validate_certs is true")
            ca_bundle = self._abs_ok(spp_tls_cert, "spp_tls_cert")
        verify = (ca_bundle if spp_validate_certs else False)

        # --- resolve ApiKey: positional or discovery ---
        api_key = str(positional_api_key or "").strip()
        if not api_key:
            system  = kwargs.get("system")
            account = kwargs.get("account")
            if not (system and account):
                raise AnsibleError("Empty positional ApiKey: provide both system and account for discovery")
            reg_index = int(kwargs.get("spp_registration_index", 0))
            api_key = self._discover_api_key_via_core(
                spp_appliance, cert_file, key_file, verify, system, account, reg_index
            )

        # --- secret type mapping from spp_credential_type (original style) ---
        a2a_type = self._map_credential_type(spp_credential_type)

        # --- A2A retrieval via vendor API (Authorization: A2A <api_key>) ---
        try:
            secret = PySafeguardConnection.a2a_get_credential(
                spp_appliance, api_key, cert_file, key_file, verify, a2a_type, api_version=spp_api_version
            )
        except Exception as e:
            raise AnsibleError(f"A2A retrieval failed: {e}")

        return [secret if isinstance(secret, str) else str(secret)]

    # ---------------- helpers ----------------

    def _abs_ok(self, path, label):
        p = os.path.expanduser(os.path.expandvars(path or ""))
        if not (os.path.isfile(p) and os.path.getsize(p) > 0):
            raise AnsibleError(f"{label} not found or empty: {p!r}")
        return os.path.abspath(p)

    def _map_credential_type(self, t):
        s = str(t or "").strip().lower()
        if s in ("password", "pwd"):
            return A2ATypes.PASSWORD
        if s in ("privatekey", "private_key", "ssh_private_key", "key"):
            return A2ATypes.PRIVATE_KEY
        # default to password for backward compat if vendor plugin behaved that way
        return A2ATypes.PASSWORD

    def _discover_api_key_via_core(self, appliance, cert_file, key_file, verify,
                                   system, account, registration_index=0):
        """
        Core discovery using PySafeguard:
          1) GET /service/core/v4/A2ARegistrations
          2) reg_id = content[registration_index].Id
          3) GET /service/core/v4/A2ARegistrations/{reg_id}/RetrievableAccounts
          4) match (system, account) -> ApiKey
        """
        try:
            conn = PySafeguardConnection(appliance, verify=verify)
            conn.connect_certificate(cert_file, key_file)
        except Exception as e:
            raise AnsibleError(f"certificate connect failed: {e}")

        # Registrations
        try:
            r = conn.invoke(HttpMethods.GET, Services.CORE, "A2ARegistrations")
            regs = r.json()
        except Exception as e:
            raise AnsibleError(f"A2ARegistrations request failed: {e}")

        if not isinstance(regs, list) or not regs:
            raise AnsibleError("A2ARegistrations returned empty list")

        try:
            reg = regs[int(registration_index)]
        except Exception:
            raise AnsibleError(f"spp_registration_index {registration_index} out of range (len={len(regs)})")

        reg_id = reg.get("Id") or reg.get("ID")
        if reg_id is None:
            raise AnsibleError(f"registration missing Id: {reg}")

        # Retrievable accounts → find match
        page, limit = 0, 200
        while True:
            try:
                rr = conn.invoke(
                    HttpMethods.GET, Services.CORE,
                    f"A2ARegistrations/{reg_id}/RetrievableAccounts",
                    query={"page": page, "limit": limit}
                )
                ras = rr.json()
            except Exception as e:
                raise AnsibleError(f"RetrievableAccounts request failed (page {page}): {e}")

            if not isinstance(ras, list) or not ras:
                break

            for ra in ras:
                asset_nm   = ra.get("AssetName")   or (ra.get("Asset")   or {}).get("Name")
                account_nm = ra.get("AccountName") or (ra.get("Account") or {}).get("Name")
                if asset_nm == system and account_nm == account:
                    k = ra.get("ApiKey")
                    if not k:
                        raise AnsibleError(f"match found but ApiKey missing: {ra}")
                    return k
            page += 1

        raise AnsibleError(f"ApiKey not found for system='{system}', account='{account}' (registration_id={reg_id})")
