# collection/oneidentity/safeguard/plugins/lookup/safeguardcredentials.py
#
# DROP-IN EXTENSION (preserves ALL existing spp_* option names and PySafeguard usage)
# - If target_api_key is supplied: use it directly (unchanged vendor behavior)
# - Else, if system AND account are supplied: discover ApiKey via Core, then retrieve via A2A
# - First positional term remains the secret type: 'Password' or 'PrivateKey'
#
# NOTE: This file assumes the Execution Environment includes the 'pysafeguard' package.

from ansible.plugins.lookup import LookupBase
from ansible.errors import AnsibleError
import os
from pysafeguard import PySafeguardConnection, HttpMethods, Services, A2ATypes

DOCUMENTATION = r"""
lookup: oneidentity.safeguardcollection.safeguardcredentials
author:
  - One Identity
  - Extended by You
short_description: Retrieve credentials from One Identity Safeguard A2A (explicit ApiKey or discovery from system/account)
description:
  - Retrieves a credential secret (Password or PrivateKey) from One Identity Safeguard A2A using client certificate authentication.
  - If C(target_api_key) is provided, the plugin uses it directly (original behavior).
  - If C(target_api_key) is not provided and both C(system) and C(account) are provided,
    the plugin discovers the ApiKey by calling Safeguard Core (A2ARegistrations and RetrievableAccounts)
    using the same client certificate, then retrieves the secret via A2A.
  - All existing C(spp_*) option names are preserved for drop-in compatibility.
options:
  # Canonical, preserved names (do NOT change)
  spp_appliance:
    description: Safeguard appliance hostname or IP (no scheme).
    type: str
    required: false
  spp_certificate_file:
    description: Path to the client certificate file in PEM format.
    type: str
    required: false
  spp_key_file:
    description: Path to the unencrypted client private key in PEM format.
    type: str
    required: false
  spp_ca_bundle:
    description: Path to the CA bundle in PEM format; used when validating HTTPS.
    type: str
    required: false
  spp_api_version:
    description: A2A API version string (for example, v4).
    type: str
    default: v4
  spp_validate_certs:
    description: Whether to validate HTTPS certificates.
    type: bool
    default: true

  # Original parameter to provide an ApiKey explicitly
  target_api_key:
    description:
      - Explicit A2A ApiKey. When provided, the plugin uses it directly.
      - If omitted, provide C(system) and C(account) to derive the ApiKey via Core.
    type: str
    required: false

  # New optional inputs for ApiKey discovery (do NOT affect existing callers)
  system:
    description:
      - System (Asset) name used to locate the ApiKey during Core discovery.
      - Required only when C(target_api_key) is not provided.
    type: str
    required: false
  account:
    description:
      - Account name used to locate the ApiKey during Core discovery.
      - Required only when C(target_api_key) is not provided.
    type: str
    required: false
  spp_registration_index:
    description:
      - Zero-based index into the registrations list returned by Core A2ARegistrations.
      - The plugin selects content[spp_registration_index].Id before enumerating retrievable accounts.
    type: int
    default: 0
notes:
  - Requires the pysafeguard Python package in the Execution Environment.
  - The client private key file must be unencrypted (no passphrase).
  - The first positional term is the secret type and must be either Password or PrivateKey.
"""

EXAMPLES = r"""
# 1) Original behavior: explicit ApiKey with preserved spp_* options
- set_fact:
    safeguard_password: >-
      {{ lookup('oneidentity.safeguardcollection.safeguardcredentials',
                'Password',
                target_api_key=my_api_key,
                spp_appliance='spp.example.com',
                spp_certificate_file='/etc/spp/appcert.pem',
                spp_key_file='/etc/spp/appkey.pem',
                spp_ca_bundle='/etc/ssl/certs/ca-bundle.pem',
                spp_api_version='v4',
                spp_validate_certs=true) }}

# 2) New behavior: derive ApiKey from (system, account), then retrieve the secret
- set_fact:
    safeguard_password: >-
      {{ lookup('oneidentity.safeguardcollection.safeguardcredentials',
                'Password',
                system='WindowsAD01',
                account='svc.deploy',
                spp_appliance='spp.example.com',
                spp_certificate_file='/etc/spp/appcert.pem',
                spp_key_file='/etc/spp/appkey.pem',
                spp_ca_bundle='/etc/ssl/certs/ca-bundle.pem',
                spp_api_version='v4',
                spp_validate_certs=true,
                spp_registration_index=0) }}

# 3) Private key retrieval with explicit ApiKey (unchanged)
- set_fact:
    safeguard_private_key: >-
      {{ lookup('oneidentity.safeguardcollection.safeguardcredentials',
                'PrivateKey',
                target_api_key=my_api_key,
                spp_appliance='spp.example.com',
                spp_certificate_file='/etc/spp/appcert.pem',
                spp_key_file='/etc/spp/appkey.pem',
                spp_ca_bundle='/etc/ssl/certs/ca-bundle.pem',
                spp_api_version='v4',
                spp_validate_certs=true) }}
"""

RETURN = r"""
_raw:
  description: The retrieved credential as a string (password text or private key material).
  type: str
"""

class LookupModule(LookupBase):
    """
    Drop-in extension: preserves spp_* names and PySafeguard usage.
    Adds optional Core-based ApiKey discovery from (system, account) when target_api_key is not supplied.
    """

    def run(self, terms, variables=None, **kwargs):
        # 1) secret type (positional term, unchanged)
        if not terms:
            raise AnsibleError("usage: lookup('...safeguardcredentials', 'Password'|'PrivateKey', ...)")
        secret_type = str(terms[0]).strip()

        # 2) normalize preserved spp_* options (exact names preserved)
        spp_appliance = kwargs.get("spp_appliance")
        spp_certificate_file = kwargs.get("spp_certificate_file")
        spp_key_file = kwargs.get("spp_key_file")
        spp_ca_bundle = kwargs.get("spp_ca_bundle")
        spp_api_version = kwargs.get("spp_api_version", "v4")
        spp_validate_certs = kwargs.get("spp_validate_certs", True)

        if not spp_appliance:
            raise AnsibleError("Missing spp_appliance")
        if not spp_certificate_file or not spp_key_file:
            raise AnsibleError("spp_certificate_file and spp_key_file are required")

        # Resolve file paths and verify existence (unchanged expectation)
        spp_certificate_file = self._abs_ok(spp_certificate_file, "spp_certificate_file")
        spp_key_file = self._abs_ok(spp_key_file, "spp_key_file")
        if spp_validate_certs and spp_ca_bundle:
            spp_ca_bundle = self._abs_ok(spp_ca_bundle, "spp_ca_bundle")
        verify = (spp_ca_bundle if spp_validate_certs else False)

        # 3) resolve or derive ApiKey
        api_key = kwargs.get("target_api_key")
        if not api_key:
            system = kwargs.get("system")
            account = kwargs.get("account")
            if not (system and account):
                raise AnsibleError("Provide either target_api_key OR both system and account")
            reg_index = int(kwargs.get("spp_registration_index", 0))
            api_key = self._derive_api_key_via_core(
                appliance=spp_appliance,
                cert_file=spp_certificate_file,
                key_file=spp_key_file,
                verify=verify,
                system=system,
                account=account,
                registration_index=reg_index
            )

        # 4) A2A retrieval via PySafeguard (Authorization: A2A <api_key>)
        a2a_type = self._atype_from_secret(secret_type)
        try:
            secret = PySafeguardConnection.a2a_get_credential(
                spp_appliance,
                api_key,
                spp_certificate_file,
                spp_key_file,
                verify,
                a2a_type,
                api_version=spp_api_version
            )
        except Exception as e:
            raise AnsibleError(f"A2A retrieval failed: {e}")

        # Lookup plugins return a list
        return [secret if isinstance(secret, str) else str(secret)]

    # ---------------- helpers ----------------

    def _abs_ok(self, path, label):
        p = os.path.expanduser(os.path.expandvars(path or ""))
        if not (os.path.isfile(p) and os.path.getsize(p) > 0):
            raise AnsibleError(f"{label} not found or empty: {p!r}")
        return os.path.abspath(p)

    def _atype_from_secret(self, secret_type):
        s = str(secret_type).strip().lower()
        if s == "password":
            return A2ATypes.PASSWORD
        if s in ("privatekey", "private_key", "ssh_private_key"):
            return A2ATypes.PRIVATE_KEY
        raise AnsibleError(f"Unsupported secret type: {secret_type!r} (expected 'Password' or 'PrivateKey')")

    def _derive_api_key_via_core(self, appliance, cert_file, key_file, verify,
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

        # List registrations and select by index
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

        # Enumerate retrievable accounts and find the match
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
