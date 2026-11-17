"""
Signature and digest algorithm selection for the ``sign`` pipe.

The XML-DSig ``SignatureMethod`` must match the type of the signing key. This
module maps pybergshamra key types (``Key.algorithm_name``, e.g. ``RSA``,
``EC-P384``, ``Ed25519``, ``ML-DSA-65``) to a default signature method, and
resolves user supplied ``signature_method`` / ``digest_method`` overrides
given either as a short name (``ecdsa-sha256``) or as an algorithm URI.
"""

from typing import Optional

import pybergshamra

from pyff.pipes import PipeException

_A = pybergshamra.Algorithm

_PQ_ML_DSA = ("44", "65", "87")
_PQ_SLH_DSA = ("128s", "128f", "192s", "192f", "256s", "256f")

#: short name -> signature method URI
SIGNATURE_METHODS: dict[str, str] = {
    "rsa-sha256": _A.RSA_SHA256,
    "rsa-sha384": _A.RSA_SHA384,
    "rsa-sha512": _A.RSA_SHA512,
    "rsa-pss-sha256": _A.RSA_PSS_SHA256,
    "rsa-pss-sha384": _A.RSA_PSS_SHA384,
    "rsa-pss-sha512": _A.RSA_PSS_SHA512,
    "ecdsa-sha256": _A.ECDSA_SHA256,
    "ecdsa-sha384": _A.ECDSA_SHA384,
    "ecdsa-sha512": _A.ECDSA_SHA512,
    "eddsa-ed25519": _A.EDDSA_ED25519,
}
for _level in _PQ_ML_DSA:
    SIGNATURE_METHODS[f"ml-dsa-{_level}"] = getattr(_A, f"ML_DSA_{_level}_W3C")
    SIGNATURE_METHODS[f"ml-dsa-{_level}-xmlsec"] = getattr(_A, f"ML_DSA_{_level}")
for _param in _PQ_SLH_DSA:
    SIGNATURE_METHODS[f"slh-dsa-sha2-{_param}"] = getattr(_A, f"SLH_DSA_SHA2_{_param.upper()}_W3C")
    SIGNATURE_METHODS[f"slh-dsa-sha2-{_param}-xmlsec"] = getattr(_A, f"SLH_DSA_SHA2_{_param.upper()}")

#: short name -> digest method URI
DIGEST_METHODS: dict[str, str] = {
    "sha256": _A.SHA256,
    "sha384": _A.SHA384,
    "sha512": _A.SHA512,
    "sha3-256": _A.SHA3_256,
    "sha3-384": _A.SHA3_384,
    "sha3-512": _A.SHA3_512,
}

DEFAULT_DIGEST_METHOD = _A.SHA256

#: key family of every supported signature method URI
_METHOD_FAMILY: dict[str, str] = {}
for _name, _uri in SIGNATURE_METHODS.items():
    if _name.startswith(("ml-dsa", "slh-dsa")):
        _METHOD_FAMILY[_uri] = _name[: _name.index("-dsa") + 4]
    else:
        _METHOD_FAMILY[_uri] = _name.split("-")[0]

_EC_CURVES = {"EC-P256": "P-256", "EC-P384": "P-384", "EC-P521": "P-521"}
_EC_DEFAULTS = {"EC-P256": _A.ECDSA_SHA256, "EC-P384": _A.ECDSA_SHA384, "EC-P521": _A.ECDSA_SHA512}

# Signature methods the PKCS#11 signer in pybergshamra can produce.
_PKCS11_FAMILIES = {"rsa", "ecdsa", "eddsa"}


def _resolve(value: object, table: dict[str, str], what: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PipeException(f"The sign pipe {what} argument must be a non-empty string")
    value = value.strip()
    short = table.get(value.lower())
    if short is not None:
        return short
    if value in table.values():
        return value
    raise PipeException(f"Unsupported {what} {value!r}; use one of: {', '.join(sorted(table))} or the matching URI")


def resolve_signature_method(value: object) -> str:
    """Resolve a short name or URI to a supported signature method URI."""
    return _resolve(value, SIGNATURE_METHODS, "signature_method")


def resolve_digest_method(value: object) -> str:
    """Resolve a short name or URI to a supported digest method URI."""
    return _resolve(value, DIGEST_METHODS, "digest_method")


def key_family(algorithm_name: str) -> Optional[str]:
    """The family (rsa, ecdsa, eddsa, ml-dsa, slh-dsa) of a pybergshamra key type, or None."""
    if algorithm_name == "RSA":
        return "rsa"
    if algorithm_name in _EC_CURVES:
        return "ecdsa"
    if algorithm_name == "Ed25519":
        return "eddsa"
    if algorithm_name.startswith("ML-DSA-"):
        return "ml-dsa"
    if algorithm_name.startswith("SLH-DSA-"):
        return "slh-dsa"
    return None


def method_family(uri: str) -> Optional[str]:
    """The key family a signature method URI requires, or None if unknown."""
    return _METHOD_FAMILY.get(uri)


def default_signature_method(algorithm_name: str) -> str:
    """The signature method used for a key type when no override is given."""
    if algorithm_name == "RSA":
        return _A.RSA_SHA256
    if algorithm_name in _EC_DEFAULTS:
        return _EC_DEFAULTS[algorithm_name]
    if algorithm_name == "Ed25519":
        return _A.EDDSA_ED25519
    family = key_family(algorithm_name)
    if family in ("ml-dsa", "slh-dsa"):
        # "ML-DSA-65" -> ML_DSA_65_W3C, "SLH-DSA-SHA2-128s" -> SLH_DSA_SHA2_128S_W3C
        uri = getattr(_A, algorithm_name.upper().replace("-", "_") + "_W3C", None)
        if uri is not None:
            return uri
    raise PipeException(f"No default signature method for {algorithm_name} keys; set signature_method in the sign pipe")


def ec_curve_for(algorithm_name: str) -> Optional[str]:
    """The curve name ("P-256", ...) Pkcs11Signer expects for an EC key type, or None."""
    return _EC_CURVES.get(algorithm_name)


def check_compatible(signature_method: str, algorithm_name: str) -> None:
    """Fail early if ``signature_method`` cannot be produced with a key of ``algorithm_name``."""
    want = method_family(signature_method)
    have = key_family(algorithm_name)
    if want is None or have is None:
        return
    if want != have:
        raise PipeException(f"signature_method {signature_method} does not match the {algorithm_name} signing key")
    if want in ("ml-dsa", "slh-dsa"):
        # ML-DSA-65 needs ml-dsa-65, not ml-dsa-44; the parameter set is in the URI suffix.
        if not signature_method.lower().endswith(algorithm_name.lower()[len(want) :]):
            raise PipeException(f"signature_method {signature_method} does not match the {algorithm_name} signing key")


def pkcs11_supported(signature_method: str) -> bool:
    """Whether pybergshamra's PKCS#11 signer supports ``signature_method``."""
    return method_family(signature_method) in _PKCS11_FAMILIES
