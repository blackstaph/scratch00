# collection/oneidentity/safeguard/plugins/lookup/safeguardcredentials.py
#
# DROP-IN EXTENSION OF VENDOR LOOKUP:
# - Positional term 0 is still the ApiKey ('' triggers discovery)
# - Connection dict still uses vendor spp_* keys
# - Discovery path:
#     GET /service/core/v4/A2ARegistrations  -> pick Id by spp_registration_index
#     GET /service/core/v4/A2ARegistrations/{Id}/RetrievableAccounts (paged)
#       → match AssetName==spp_systemname AND AccountName==spp_username → ApiKey
#     Use ApiKey to call PySafeguardConnection.a2a_get_credential(...)
#
# Requires: pysafeguard

from ansible.plugins.lookup import LookupBase
from ansible.errors import AnsibleError
import os
from json import JSONDecodeError
from pysafeguard import PySafeguardConnection, HttpMethods, Services, A2ATypes

DOCUMENTATION = r"""
lookup: oneidentity.safeguardcollection.safeguardcredentials
author:
  - One Identity
  - Extended by You
short_description: Retrieve a Safeguard secret; can discover ApiKey from system+username using cert auth
description:
  - Keeps vendor interface intact. If the first positional term (ApiKey) is empty,
    the plugin discovers the ApiKey by calling Core with the same client certificate
    to enumerate registrations and their retrievable accounts, then uses that ApiKey
    to retrieve the requested credential.
options:
  a2aconnection:
    type: dict
    required: true
    suboptions:
      spp_appliance:         {type: str}
      spp_certificate_file:  {type: str}
      spp_certificate_key:   {type: str}
      spp_tls_cert:          {type: str}
      spp_credential_type:   {type: str}
      spp_validate_certs:    {type: bool, default: true}
  spp_systemname:           {type: str, required: false}
  spp_username:             {type: str, required: false}
  spp_registration_index:   {type: int, default: 0}
notes:
  - First positional term remains the ApiKey (pass '' to enable discovery).
  - Private key file must be unencrypted.
"""

EXAMPLES = r"""
# Use provided ApiKey (original behavior)
- set_fact:
    my_password: >-
      {{ lookup('oneidentity.safeguardcollection.safeguardcredentials',
                spp_credential_apikey,
                a2aconnection={
                  'spp_appliance': host,
                  'spp_certificate_file': cert,
                  'spp_certificate_key': key,
                  'spp_tls_cert': cacert,
                  'spp_credential_type': 'password',
                  'spp_validate_certs': true
                }) }}

# Discover ApiKey from system+username, then fetch the password
- set_fact:
    my_password: >-
      {{ lookup('oneidentity.safeguardcollection.safeguardcredentials',
                '',
                a2aconnection={
                  'spp_appliance': host,
                  'spp_certificate_file': cert,
                  'spp_certificate_key': key,
                  'spp_tls_cert': cacert,
                  'spp_credential_type': 'password',
                  'spp_validate_certs': true
                },
                spp_systemname=system_name,
                spp_username=account_name,
                spp_registration_index=0) }}
"""

RETURN = r"""
_raw:
  description: The retrieved secret (password/private key) as a string.
  type: str
"""

class LookupModule(LookupBase):
    def run(self, terms, variables=None, **kwargs):
        if not terms:
            raise AnsibleError("First positional term must be the ApiKey (use '' to enable discovery).")
        api_key = str(terms[0] or "").strip()

        conn = kwargs.get("a2aconnection")
        if not isinstance(conn, dict):
            raise AnsibleError("a2aconnection must be a dict with spp_* keys")

        spp_appliance        = conn.get("spp_appliance")
        spp_certificate_file = conn.get("spp_certificate_file")
        spp_certificate_key  = conn.get("spp_certificate_key")
        spp_tls_cert         = conn.get("spp_tls_cert")
        spp_credential_type  = conn.get("spp_credential_type", "password").lower()
        spp_validate_certs   = conn.get("spp_validate_certs", True)

        if not spp_appliance:
            raise AnsibleError("Missing spp_appliance")
        if not spp_certificate_file or not spp_certificate_key:
            raise AnsibleError("spp_certificate_file and spp_certificate_key are required")

        cert_file = self._abs_ok(spp_certificate_file, "spp_certificate_file")
        key_file  = self._abs_ok(spp_certificate_key,  "spp_certificate_key")

        if spp_validate_certs:
            if not spp_tls_cert:
                raise AnsibleError("spp_tls_cert is required when spp_validate_certs is true")
            tls_cert = self._abs_ok(spp_tls_cert, "spp_tls_cert")
            verify = tls_cert
        else:
            verify = False

        # Discovery (ApiKey empty): use cert auth -> registrations -> retrievable accounts
        if not api_key:
            systemname = kwargs.get("spp_systemname")
            username   = kwargs.get("spp_username")
            if not (systemname and username):
                raise AnsibleError("Empty ApiKey: provide spp_systemname and spp_username to derive it")
            reg_index = int(kwargs.get("spp_registration_index", 0))
            api_key = self._discover_apikey(
                spp_appliance, cert_file, key_file, verify, systemname, username, reg_index
            )

        a2a_type = self._map_type(spp_credential_type)
        try:
            secret = PySafeguardConnection.a2a_get_credential(
                spp_appliance, api_key, cert_file, key_file, verify, a2a_type
            )
        except Exception as e:
            raise AnsibleError(f"A2A retrieval failed: {e}")

        return [secret if isinstance(secret, str) else str(secret)]

    # ---------- helpers ----------

    def _abs_ok(self, path, label):
        p = os.path.expanduser(os.path.expandvars(path or ""))
        if not (os.path.isfile(p) and os.path.getsize(p) > 0):
            raise AnsibleError(f"{label} not found or empty: {p!r}")
        return os.path.abspath(p)

    def _map_type(self, t):
        s = str(t or "").strip().lower()
        if s in ("password", "pwd"):
            return A2ATypes.PASSWORD
        if s in ("privatekey", "private_key", "ssh_private_key", "key"):
            return A2ATypes.PRIVATE_KEY
        raise AnsibleError(f"Unsupported spp_credential_type: {t!r}")

    def _json_strict(self, resp, context):
        if not getattr(resp, "status_code", None) or resp.status_code >= 400:
            body = ""
            try:
                body = resp.text or ""
            except Exception:
                pass
            snippet = (body or "").replace("\n", " ")[:300]
            raise AnsibleError(f"{context}: HTTP {getattr(resp,'status_code','???')} - {snippet}")
        try:
            return resp.json()
        except JSONDecodeError:
            snippet = (getattr(resp, "text", "") or "").replace("\n", " ")[:300]
            raise AnsibleError(f"{context}: Non-JSON response - {snippet}")

    def _discover_apikey(self, appliance, cert_file, key_file, verify,
                         systemname, username, registration_index=0):
        """
        1) GET /service/core/v4/A2ARegistrations → pick Id by index
        2) GET /service/core/v4/A2ARegistrations/{Id}/RetrievableAccounts (paged)
           → find AssetName==systemname and AccountName==username → ApiKey
        """
        try:
            conn = PySafeguardConnection(appliance, verify=verify)
            conn.connect_certificate(cert_file, key_file)
        except Exception as e:
            raise AnsibleError(f"certificate connect failed: {e}")

        headers = {"accept": "application/json"}

        # 1) Registrations
        try:
            r = conn.invoke(HttpMethods.GET, Services.CORE, "v4/A2ARegistrations", headers=headers)
            regs = self._json_strict(r, "A2ARegistrations")
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

        # 2) Retrievable accounts (paged)
        page, limit = 0, 200
        while True:
            try:
                rr = conn.invoke(
                    HttpMethods.GET, Services.CORE,
                    f"v4/A2ARegistrations/{reg_id}/RetrievableAccounts",
                    query={"page": page, "limit": limit},
                    headers=headers
                )
                ras = self._json_strict(rr, f"RetrievableAccounts page {page}")
            except Exception as e:
                raise AnsibleError(f"RetrievableAccounts request failed (page {page}): {e}")

            if not isinstance(ras, list) or not ras:
                break

            for ra in ras:
                asset_nm   = ra.get("AssetName")   or (ra.get("Asset")   or {}).get("Name")
                account_nm = ra.get("AccountName") or (ra.get("Account") or {}).get("Name")
                if asset_nm == systemname and account_nm == username:
                    k = ra.get("ApiKey")
                    if not k:
                        raise AnsibleError(f"match found but ApiKey missing: {ra}")
                    return k
            page += 1

        raise AnsibleError(f"ApiKey not found for system='{systemname}', account='{username}' (registration_id={reg_id})")
