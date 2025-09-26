# collection/oneidentity/safeguard/plugins/lookup/safeguardcredentials.py
#
# TRUE DROP-IN EXTENSION (no interface/dep changes):
# - First positional term is still the ApiKey ('' allowed to trigger discovery)
# - Connection dict is still 'a2aconnection' with the original spp_* keys
# - Uses pysafeguard and the original a2a_get_credential signature (NO api_version kwarg)
# - Only addition: if ApiKey is empty and spp_systemname+spp_username are provided,
#   derive the ApiKey via Core (A2ARegistrations → RetrievableAccounts) using the same cert+key.
# - Fix: handle paged-wrapped responses AND appliances that require explicit versioned paths (v4).

from ansible.plugins.lookup import LookupBase
from ansible.errors import AnsibleError
import os
from pysafeguard import PySafeguardConnection, HttpMethods, Services, A2ATypes

DOCUMENTATION = r"""
lookup: oneidentity.safeguardcollection.safeguardcredentials
author:
  - One Identity
  - Extended by You
short_description: Retrieve credentials from One Identity Safeguard A2A (drop-in extension)
description:
  - Keeps the vendor interface intact: the first positional term is the ApiKey; the connection dict is passed as C(a2aconnection) using C(spp_*) keys.
  - If the positional ApiKey is empty and both C(spp_systemname) and C(spp_username) are supplied, the ApiKey is discovered via Core using the same client certificate.
  - Uses the original C(pysafeguard) client and the original C(a2a_get_credential) signature (no extra kwargs).
options:
  a2aconnection:
    description: Connection parameters (original spp_* keys).
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
      spp_validate_certs:
        type: bool
        default: true
  spp_systemname:
    type: str
    required: false
  spp_username:
    type: str
    required: false
  spp_registration_index:
    type: int
    default: 0
notes:
  - Requires the pysafeguard Python package.
  - First positional term remains the ApiKey (use '' to enable discovery with spp_systemname + spp_username).
"""

EXAMPLES = r"""
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
  description: The retrieved credential (password text or private key material) as a string.
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
        spp_credential_type  = conn.get("spp_credential_type", "password")
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

    # -------- helpers --------
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

    def _unwrap(self, payload):
        """Handle paged wrapper objects like {'Data': [...]}, {'Items': [...]}, etc."""
        if isinstance(payload, dict):
            for k in ("Data", "data", "Items", "items", "Value", "value", "Results"):
                v = payload.get(k)
                if isinstance(v, list):
                    return v
        return payload

    def _get_core_list(self, conn, path_variants, query=None, what="list"):
        """Try multiple Core path variants (unversioned, v4, v3) and unwrap any paged envelope."""
        last_err = None
        for suffix in path_variants:
            try:
                r = conn.invoke(HttpMethods.GET, Services.CORE, suffix, query=query or {})
                data = self._unwrap(r.json())
                if isinstance(data, list) and data:
                    return data
                # allow empty list to fall through to try next variant
            except Exception as e:
                last_err = e
        # if we get here, either empty or errored on all variants
        if last_err:
            raise AnsibleError(f"{what} request failed: {last_err}")
        raise AnsibleError(f"{what} returned empty list")

    def _discover_apikey(self, appliance, cert_file, key_file, verify,
                         systemname, username, registration_index=0):
        """
        Discover ApiKey by:
          1) GET Core A2ARegistrations (try: 'A2ARegistrations', 'v4/A2ARegistrations', 'v3/A2ARegistrations')
          2) Pick registrations[registration_index].Id
          3) GET Core A2ARegistrations/{id}/RetrievableAccounts (try v4/unversioned/v3)
          4) Match (AssetName==systemname) and (AccountName==username) → ApiKey
        """
        try:
            conn = PySafeguardConnection(appliance, verify=verify)
            conn.connect_certificate(cert_file, key_file)
        except Exception as e:
            raise AnsibleError(f"certificate connect failed: {e}")

        regs = self._get_core_list(
            conn,
            ["A2ARegistrations", "v4/A2ARegistrations", "v3/A2ARegistrations"],
            what="A2ARegistrations"
        )

        try:
            reg = regs[int(registration_index)]
        except Exception:
            raise AnsibleError(f"spp_registration_index {registration_index} out of range (len={len(regs)})")

        reg_id = reg.get("Id") or reg.get("ID")
        if reg_id is None:
            raise AnsibleError(f"registration missing Id: {reg}")

        page, limit = 0, 200
        while True:
            ras = None
            # try path variants per page
            for suffix in (
                f"A2ARegistrations/{reg_id}/RetrievableAccounts",
                f"v4/A2ARegistrations/{reg_id}/RetrievableAccounts",
                f"v3/A2ARegistrations/{reg_id}/RetrievableAccounts",
            ):
                try:
                    rr = conn.invoke(
                        HttpMethods.GET, Services.CORE,
                        suffix, query={"page": page, "limit": limit}
                    )
                    ras = self._unwrap(rr.json())
                    break
                except Exception:
                    ras = None
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

