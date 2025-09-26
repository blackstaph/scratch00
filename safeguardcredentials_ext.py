# lookup_plugins/safeguardcredentials.py
#
# Extended version that preserves the original architecture and dependency on
# PySafeguard while adding optional API-key discovery from (system, account).
#
# Behavior:
# - If 'target_api_key' is supplied, use it directly (existing behavior).
# - Else, if 'system' AND 'account' are supplied, discover the ApiKey via
#   Core (A2ARegistrations → RetrievableAccounts) using the same client
#   certificate, then use that ApiKey for the A2A retrieval.
# - Secret type is still taken from the first positional term:
#     'Password'  -> A2ATypes.PASSWORD
#     'PrivateKey'-> A2ATypes.PRIVATE_KEY
#
# NOTE: This file is a drop-in replacement for the plugin class; it keeps
#       PySafeguard and vendor-approved flows. Ensure 'pysafeguard' is
#       available in your Execution Environment.

from ansible.plugins.lookup import LookupBase
from ansible.errors import AnsibleError
import os
from pysafeguard import PySafeguardConnection, HttpMethods, Services, A2ATypes

DOCUMENTATION = r"""
lookup: oneidentity.safeguardcollection.safeguardcredentials
author:
  - One Identity
  - Extended by You
short_description: Retrieve credentials from One Identity Safeguard A2A, optionally discovering the ApiKey from (system, account)
description:
  - Retrieves a credential secret (e.g. Password, PrivateKey) from One Identity Safeguard A2A.
  - If C(target_api_key) is provided, the plugin uses it directly with the client certificate to call A2A.
  - If C(target_api_key) is omitted but C(system) and C(account) are provided, the plugin first calls Safeguard Core, discovers the matching ApiKey for the specified (system, account), and then retrieves the secret via A2A.
  - The first positional term determines the secret type and remains compatible with the original interface (C(Password) or C(PrivateKey)).
  - Uses the vendor library C(pysafeguard) for both Core discovery and A2A retrieval.
options:
  # ---- primary usage options (existing behavior retained) ----
  target_api_key:
    description:
      - The A2A ApiKey used to authorize the A2A retrieval.
      - If omitted, you may provide C(system) and C(account) to derive the ApiKey via Core.
    type: str
    required: false

  a2aconnection:
    description:
      - Dictionary of connection parameters for A2A/Core calls using client certificate authentication.
      - You may also specify these parameters in flat form at the top level for convenience.
    type: dict
    required: false
    suboptions:
      appliance:
        description: Safeguard appliance hostname or IP (no scheme).
        type: str
      appliance_address:
        description: Alternate key for the appliance hostname or IP.
        type: str
      certificate_file:
        description: Path to the client certificate in PEM.
        type: str
      key_file:
        description: Path to the unencrypted client private key in PEM.
        type: str
      ca_bundle:
        description: Path to CA bundle in PEM (required when validate_certs is true).
        type: str
      api_version:
        description: A2A API version path segment (e.g. C(v4)).
        type: str
        default: v4
      validate_certs:
        description: Whether to validate HTTPS certificates.
        type: bool
        default: true

  # ---- flat aliases for a2aconnection (kept for compatibility) ----
  appliance:
    description: Safeguard appliance hostname or IP (no scheme). Alias for C(a2aconnection.appliance).
    type: str
    required: false
  appliance_address:
    description: Alternate key for the appliance hostname or IP. Alias for C(a2aconnection.appliance_address).
    type: str
    required: false
  certificate_file:
    description: Path to the client certificate in PEM. Alias for C(a2aconnection.certificate_file).
    type: str
    required: false
  key_file:
    description: Path to the unencrypted client private key in PEM. Alias for C(a2aconnection.key_file).
    type: str
    required: false
  ca_bundle:
    description: Path to CA bundle in PEM. Alias for C(a2aconnection.ca_bundle).
    type: str
    required: false
  api_version:
    description: A2A API version (e.g. C(v4)). Alias for C(a2aconnection.api_version).
    type: str
    required: false
  validate_certs:
    description: Whether to validate HTTPS certificates. Alias for C(a2aconnection.validate_certs).
    type: bool
    required: false

  # ---- new optional discovery inputs ----
  system:
    description:
      - System (Asset) name to match during Core discovery of ApiKey.
      - Required if C(target_api_key) is not provided.
    type: str
    required: false
  account:
    description:
      - Account name to match during Core discovery of ApiKey.
      - Required if C(target_api_key) is not provided.
    type: str
    required: false
  registration_index:
    description:
      - Zero-based index into the registrations list returned by Core C(/A2ARegistrations).
      - The plugin selects C(content[registration_index].Id) before enumerating retrievable accounts.
    type: int
    default: 0
notes:
  - This plugin requires the C(pysafeguard) Python package in the Execution Environment.
  - The private key file must be unencrypted (no passphrase), as C(pysafeguard) does not prompt for key passwords.
  - The first positional term must be the secret type, typically C(Password) or C(PrivateKey).
"""

EXAMPLES = r"""
# Using a known ApiKey (original behavior)
- set_fact:
    spp_password: >-
      {{ lookup('oneidentity.safeguardcollection.safeguardcredentials',
                'Password',
                target_api_key=my_api_key,
                a2aconnection={
                  'appliance': 'spp.example.com',
                  'certificate_file': '/etc/spp/appcert.pem',
                  'key_file': '/etc/spp/appkey.pem',
                  'ca_bundle': '/etc/ssl/certs/ca-bundle.pem',
                  'api_version': 'v4',
                  'validate_certs': true
                }) }}

# Derive ApiKey from (system, account), then retrieve the Password
- set_fact:
    spp_password: >-
      {{ lookup('oneidentity.safeguardcollection.safeguardcredentials',
                'Password',
                system='WindowsAD01',
                account='svc.deploy',
                a2aconnection={
                  'appliance': 'spp.example.com',
                  'certificate_file': '/etc/spp/appcert.pem',
                  'key_file': '/etc/spp/appkey.pem',
                  'ca_bundle': '/etc/ssl/certs/ca-bundle.pem',
                  'api_version': 'v4',
                  'validate_certs': true
                },
                registration_index=0) }}

# Flat-arg aliases for a2aconnection (kept for compatibility)
- set_fact:
    spp_private_key: >-
      {{ lookup('oneidentity.safeguardcollection.safeguardcredentials',
                'PrivateKey',
                target_api_key=my_api_key,
                appliance='spp.example.com',
                certificate_file='/etc/spp/appcert.pem',
                key_file='/etc/spp/appkey.pem',
                ca_bundle='/etc/ssl/certs/ca-bundle.pem',
                api_version='v4',
                validate_certs=true) }}
"""

RETURN = r"""
_raw:
  description: The retrieved credential secret as a string (password text or private key material).
  type: str
"""

class LookupModule(LookupBase):
    """
    Extended LookupModule:
      - Keeps original interface: first term is secret type; supports a2aconnection and flat args.
      - Adds optional Core-based ApiKey discovery via (system, account) when target_api_key not provided.
      - Uses PySafeguard both for Core discovery and for A2A retrieval (Authorization: A2A <api_key>).
    """

    def run(self, terms, variables=None, **kwargs):
        # ---- 1) secret type from _terms (original contract) ----
        if not terms:
            raise AnsibleError("usage: lookup('...safeguardcredentials', 'Password'|'PrivateKey', ...)")
        secret_type = str(terms[0])

        # ---- 2) normalize connection args (support dict and/or flat aliases) ----
        a2a = kwargs.get("a2aconnection") or {}
        appliance = (
            kwargs.get("appliance")
            or kwargs.get("appliance_address")
            or a2a.get("appliance")
            or a2a.get("appliance_address")
        )
        cert_file   = kwargs.get("certificate_file") or a2a.get("certificate_file")
        key_file    = kwargs.get("key_file")         or a2a.get("key_file")
        ca_bundle   = kwargs.get("ca_bundle")        or a2a.get("ca_bundle")
        api_version = kwargs.get("api_version")      or a2a.get("api_version") or "v4"
        validate    = a2a.get("validate_certs") if "validate_certs" in a2a else kwargs.get("validate_certs", True)

        if not appliance:
            raise AnsibleError("Missing appliance/appliance_address")
        if not cert_file or not key_file:
            raise AnsibleError("certificate_file and key_file are required")

        # Resolve on-disk paths early (match original expectations)
        cert_file = self._abs_ok(cert_file, "certificate_file")
        key_file  = self._abs_ok(key_file,  "key_file")
        if validate and ca_bundle:
            ca_bundle = self._abs_ok(ca_bundle, "ca_bundle")
        verify = (ca_bundle if validate else False)

        # ---- 3) resolve api_key: prefer provided, else derive from (system, account) ----
        api_key = kwargs.get("target_api_key")
        if not api_key:
            system  = kwargs.get("system")
            account = kwargs.get("account")
            if not (system and account):
                raise AnsibleError("Provide either target_api_key OR both system and account")
            reg_idx = int(kwargs.get("registration_index", 0))
            api_key = self._derive_api_key_via_core(
                appliance=appliance,
                cert_file=cert_file,
                key_file=key_file,
                verify=verify,
                system=system,
                account=account,
                registration_index=reg_idx
            )

        # ---- 4) A2A retrieval via PySafeguard (Authorization: A2A <api_key>) ----
        atype = self._atype_from_secret(secret_type)
        try:
            secret = PySafeguardConnection.a2a_get_credential(
                appliance,
                api_key,
                cert_file,
                key_file,
                verify,
                atype,
                api_version=api_version
            )
        except Exception as e:
            raise AnsibleError(f"A2A retrieval failed: {e}")

        # lookup returns a list (Ansible unwraps in scalar contexts)
        return [secret if isinstance(secret, str) else str(secret)]

    # ---------------- helpers ----------------

    def _abs_ok(self, p, name):
        p = os.path.expanduser(os.path.expandvars(p or ""))
        if not (os.path.isfile(p) and os.path.getsize(p) > 0):
            raise AnsibleError(f"{name} not found or empty: {p!r}")
        return os.path.abspath(p)

    def _atype_from_secret(self, secret_type):
        st = str(secret_type).strip()
        if st.lower() == "password":
            return A2ATypes.PASSWORD
        if st.lower() in ("privatekey", "private_key", "ssh_private_key"):
            return A2ATypes.PRIVATE_KEY
        raise AnsibleError(f"Unsupported secret type: {secret_type!r} (expected 'Password' or 'PrivateKey')")

    def _derive_api_key_via_core(self, appliance, cert_file, key_file, verify,
                                 system, account, registration_index=0):
        """
        Core discovery flow using PySafeguard:
          1) GET /service/core/v4/A2ARegistrations
          2) reg_id = content[registration_index].Id
          3) GET /service/core/v4/A2ARegistrations/{reg_id}/RetrievableAccounts
          4) match (system, account) → ApiKey
        """
        try:
            conn = PySafeguardConnection(appliance, verify=verify)
            conn.connect_certificate(cert_file, key_file)
        except Exception as e:
            raise AnsibleError(f"certificate connect failed: {e}")

        # List registrations (no filters) and select by index
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
            raise AnsibleError(f"registration_index {registration_index} out of range (len={len(regs)})")

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
                    api_key = ra.get("ApiKey")
                    if not api_key:
                        raise AnsibleError(f"match found but ApiKey missing: {ra}")
                    return api_key
            page += 1

        raise AnsibleError(f"ApiKey not found for system='{system}', account='{account}' (registration_id={reg_id})")
