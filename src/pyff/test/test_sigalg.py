"""Tests for signing with non-RSA keys (EC, Ed25519, RSA-PSS, ML-DSA, SLH-DSA)."""

import base64
import datetime
import os
import re
import shutil
import subprocess
from unittest.mock import MagicMock, patch

import pybergshamra
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID
from pyuppsala import etree

from pyff import builtins, sigalg
from pyff.constants import NS
from pyff.pipes import PipeException, Plumbing
from pyff.repo import MDRepository
from pyff.utils import cert_info, check_signature

A = pybergshamra.Algorithm
KEYS_DIR = os.path.join(os.path.dirname(__file__), "data", "keys")

AGGREGATE = (
    '<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" ID="agg">'
    '<md:EntityDescriptor entityID="https://sp.example.org/sp" ID="sp">'
    '<md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/></md:EntityDescriptor>'
    '<md:EntityDescriptor entityID="https://idp.example.org/idp" ID="idp">'
    '<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/></md:EntityDescriptor>'
    "</md:EntitiesDescriptor>"
)


def _self_signed(private_key, cn="pyff-test", days=3650, public_key=None, issuer_key=None):
    """A PEM certificate for ``public_key`` (default: the private key's own)."""
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    signer = issuer_key or private_key
    algorithm = None if isinstance(signer, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(public_key or private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=days))
        .sign(signer, algorithm)
    )
    return cert.public_bytes(ser.Encoding.PEM).decode()


def _write_key_pair(directory, name, private_key):
    key_path = os.path.join(directory, f"{name}.key")
    cert_path = os.path.join(directory, f"{name}.crt")
    with open(key_path, "wb") as fd:
        fd.write(private_key.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()))
    with open(cert_path, "w") as fd:
        fd.write(_self_signed(private_key, cn=name))
    return key_path, cert_path


@pytest.fixture(scope="module")
def key_pairs(tmp_path_factory):
    """name -> (key path, cert path) for every supported on-disk key type."""
    directory = str(tmp_path_factory.mktemp("keys"))
    pairs = {
        "rsa": _write_key_pair(directory, "rsa", rsa.generate_private_key(65537, 2048)),
        "ec-p256": _write_key_pair(directory, "ec-p256", ec.generate_private_key(ec.SECP256R1())),
        "ec-p384": _write_key_pair(directory, "ec-p384", ec.generate_private_key(ec.SECP384R1())),
        "ec-p521": _write_key_pair(directory, "ec-p521", ec.generate_private_key(ec.SECP521R1())),
        "ed25519": _write_key_pair(directory, "ed25519", ed25519.Ed25519PrivateKey.generate()),
    }
    for name in ("ml-dsa-65", "slh-dsa-sha2-128s"):
        pairs[name] = (os.path.join(KEYS_DIR, f"{name}-key.pem"), os.path.join(KEYS_DIR, f"{name}-cert.pem"))
    return pairs


def _request(xml, args, t=None):
    return Plumbing.Request(
        Plumbing([], pid="sigalg-test"),
        MDRepository(),
        t=t if t is not None else etree.fromstring(xml),
        args=args,
    )


def _methods(tree):
    xml = etree.tostring(tree, encoding="unicode")
    return (
        re.findall(r'SignatureMethod Algorithm="([^"]+)"', xml),
        re.findall(r'DigestMethod Algorithm="([^"]+)"', xml),
    )


# --- algorithm resolution ---------------------------------------------------


@pytest.mark.parametrize(
    "value, expected",
    [
        ("ecdsa-sha256", A.ECDSA_SHA256),
        ("ECDSA-SHA384", A.ECDSA_SHA384),
        (" rsa-pss-sha256 ", A.RSA_PSS_SHA256),
        ("eddsa-ed25519", A.EDDSA_ED25519),
        ("ml-dsa-65", A.ML_DSA_65_W3C),
        ("ml-dsa-65-xmlsec", A.ML_DSA_65),
        ("slh-dsa-sha2-128s", A.SLH_DSA_SHA2_128S_W3C),
        (A.ECDSA_SHA512, A.ECDSA_SHA512),
        (A.ML_DSA_87, A.ML_DSA_87),
    ],
)
def test_resolve_signature_method(value, expected):
    assert sigalg.resolve_signature_method(value) == expected


@pytest.mark.parametrize("value", ["rsa-md5", "hmac-sha256", A.HMAC_SHA256, A.RSA_SHA1, "", 42, None])
def test_resolve_signature_method_rejects(value):
    with pytest.raises(PipeException):
        sigalg.resolve_signature_method(value)


@pytest.mark.parametrize(
    "value, expected", [("sha256", A.SHA256), ("SHA512", A.SHA512), ("sha3-384", A.SHA3_384), (A.SHA384, A.SHA384)]
)
def test_resolve_digest_method(value, expected):
    assert sigalg.resolve_digest_method(value) == expected


@pytest.mark.parametrize("value", ["sha1", "md5", A.SHA1, ""])
def test_resolve_digest_method_rejects(value):
    with pytest.raises(PipeException):
        sigalg.resolve_digest_method(value)


@pytest.mark.parametrize(
    "algorithm_name, expected",
    [
        ("RSA", A.RSA_SHA256),
        ("EC-P256", A.ECDSA_SHA256),
        ("EC-P384", A.ECDSA_SHA384),
        ("EC-P521", A.ECDSA_SHA512),
        ("Ed25519", A.EDDSA_ED25519),
        ("ML-DSA-44", A.ML_DSA_44_W3C),
        ("ML-DSA-65", A.ML_DSA_65_W3C),
        ("ML-DSA-87", A.ML_DSA_87_W3C),
        ("SLH-DSA-SHA2-128s", A.SLH_DSA_SHA2_128S_W3C),
        ("SLH-DSA-SHA2-256f", A.SLH_DSA_SHA2_256F_W3C),
    ],
)
def test_default_signature_method(algorithm_name, expected):
    assert sigalg.default_signature_method(algorithm_name) == expected


@pytest.mark.parametrize("algorithm_name", ["DSA", "HMAC", "X25519", "AES-128"])
def test_default_signature_method_unknown(algorithm_name):
    with pytest.raises(PipeException, match="set signature_method"):
        sigalg.default_signature_method(algorithm_name)


@pytest.mark.parametrize(
    "method, algorithm_name",
    [
        (A.RSA_SHA512, "RSA"),
        (A.RSA_PSS_SHA256, "RSA"),
        (A.ECDSA_SHA512, "EC-P256"),
        (A.EDDSA_ED25519, "Ed25519"),
        (A.ML_DSA_65, "ML-DSA-65"),
        (A.ML_DSA_65_W3C, "ML-DSA-65"),
        (A.SLH_DSA_SHA2_128S_W3C, "SLH-DSA-SHA2-128s"),
    ],
)
def test_check_compatible(method, algorithm_name):
    sigalg.check_compatible(method, algorithm_name)


@pytest.mark.parametrize(
    "method, algorithm_name",
    [
        (A.ECDSA_SHA256, "RSA"),
        (A.RSA_SHA256, "EC-P256"),
        (A.RSA_PSS_SHA256, "Ed25519"),
        (A.ML_DSA_44_W3C, "ML-DSA-65"),
        (A.SLH_DSA_SHA2_128F_W3C, "SLH-DSA-SHA2-128s"),
        (A.ML_DSA_65_W3C, "SLH-DSA-SHA2-128s"),
    ],
)
def test_check_compatible_mismatch(method, algorithm_name):
    with pytest.raises(PipeException, match="does not match"):
        sigalg.check_compatible(method, algorithm_name)


# --- on-disk keys -----------------------------------------------------------


@pytest.mark.parametrize(
    "name, expected",
    [
        ("rsa", A.RSA_SHA256),
        ("ec-p256", A.ECDSA_SHA256),
        ("ec-p384", A.ECDSA_SHA384),
        ("ec-p521", A.ECDSA_SHA512),
        ("ed25519", A.EDDSA_ED25519),
        ("ml-dsa-65", A.ML_DSA_65_W3C),
        ("slh-dsa-sha2-128s", A.SLH_DSA_SHA2_128S_W3C),
    ],
)
def test_sign_document_root_with_key_type(key_pairs, name, expected):
    """The aggregate (document root) path picks the method from the key type."""
    key, cert = key_pairs[name]
    t = builtins.sign(_request(AGGREGATE, {"key": key, "cert": cert}))
    assert _methods(t) == ([expected], [A.SHA256])
    check_signature(t, cert, only_one_signature=True)


@pytest.mark.parametrize("name", ["ec-p384", "ed25519", "ml-dsa-65"])
def test_sign_subtree_with_key_type(key_pairs, name):
    """The subtree path (an entity still inside its aggregate, as after `first`)."""
    key, cert = key_pairs[name]
    aggregate = etree.fromstring(AGGREGATE)
    entity = aggregate.find("{{{}}}EntityDescriptor".format(NS["md"]))
    t = builtins.sign(_request(None, {"key": key, "cert": cert}, t=entity))
    assert t.get("entityID") == "https://sp.example.org/sp"
    assert _methods(t)[0] == [sigalg.default_signature_method(pybergshamra.load_key_file(key).algorithm_name)]
    check_signature(t, cert, only_one_signature=True)


@pytest.mark.parametrize(
    "name, signature_method, digest_method, expected_method, expected_digest",
    [
        ("rsa", "rsa-pss-sha256", None, A.RSA_PSS_SHA256, A.SHA256),
        ("rsa", "rsa-sha512", "sha512", A.RSA_SHA512, A.SHA512),
        ("ec-p256", "ecdsa-sha384", "sha384", A.ECDSA_SHA384, A.SHA384),
        ("ec-p384", A.ECDSA_SHA256, "sha3-256", A.ECDSA_SHA256, A.SHA3_256),
        ("ml-dsa-65", "ml-dsa-65-xmlsec", None, A.ML_DSA_65, A.SHA256),
    ],
)
def test_sign_with_overrides(key_pairs, name, signature_method, digest_method, expected_method, expected_digest):
    key, cert = key_pairs[name]
    args = {"key": key, "cert": cert, "signature_method": signature_method}
    if digest_method is not None:
        args["digest_method"] = digest_method
    t = builtins.sign(_request(AGGREGATE, args))
    assert _methods(t) == ([expected_method], [expected_digest])
    check_signature(t, cert, only_one_signature=True)


def test_sign_override_mismatch(key_pairs):
    key, cert = key_pairs["rsa"]
    with pytest.raises(PipeException, match="does not match the RSA signing key"):
        builtins.sign(_request(AGGREGATE, {"key": key, "cert": cert, "signature_method": "ecdsa-sha256"}))


def test_sign_unknown_override(key_pairs):
    key, cert = key_pairs["ec-p256"]
    with pytest.raises(PipeException, match="Unsupported signature_method"):
        builtins.sign(_request(AGGREGATE, {"key": key, "cert": cert, "signature_method": "ecdsa-md5"}))


def test_sign_ec_pipeline(key_pairs, tmp_path):
    """End to end through a YAML pipeline: load, select, sign with EC, publish, verify."""
    import yaml

    key, cert = key_pairs["ec-p256"]
    metadata = os.path.join(os.path.dirname(__file__), "data", "metadata", "test01.xml")
    output = tmp_path / "signed.xml"
    pipeline = yaml.safe_load(
        f"""
- load:
    - {metadata}
- select
- finalize:
    Name: https://md.example.org
- sign:
    key: {key}
    cert: {cert}
- publish:
    output: {output}
"""
    )
    Plumbing(pipeline, pid="ec-pipeline").process(MDRepository(), state={"batch": True, "stats": {}})
    published = etree.fromstring(output.read_bytes())
    assert _methods(published)[0] == [A.ECDSA_SHA256]
    check_signature(published, cert, only_one_signature=True)


# --- PKCS#11 algorithm selection (mocked token) -----------------------------


def _pkcs11_sign(args, cert_pem=None, tmp_path=None):
    """Run the sign pipe against a mocked token; return the Pkcs11Signer and sign_enveloped mocks."""
    args = {"key": "pkcs11:///usr/lib/libmocked-pkcs11.so/signer", **args}
    if cert_pem is not None:
        cert_path = tmp_path / "token.crt"
        cert_path.write_text(cert_pem)
        args["cert"] = str(cert_path)
    signer_type = MagicMock()
    with (
        patch.dict(os.environ, {"PYKCS11PIN": "secret"}),
        patch.object(builtins, "_pkcs11_provider_cache", {}),
        patch.object(builtins.pybergshamra, "Pkcs11Provider", MagicMock()),
        patch.object(builtins.pybergshamra, "Pkcs11Signer", signer_type),
        patch.object(builtins.pybergshamra, "DsigContext", MagicMock()),
        patch.object(
            builtins.pybergshamra, "sign_enveloped", side_effect=lambda _ctx, value, **_kw: value
        ) as sign_enveloped,
    ):
        builtins.sign(_request(AGGREGATE, args))
    return signer_type, sign_enveloped


@pytest.mark.parametrize(
    "private_key, args, method, curve",
    [
        (None, {}, A.RSA_SHA256, None),  # no cert, no override: unchanged default
        (rsa.generate_private_key(65537, 2048), {}, A.RSA_SHA256, None),
        (ec.generate_private_key(ec.SECP256R1()), {}, A.ECDSA_SHA256, "P-256"),
        (ec.generate_private_key(ec.SECP384R1()), {}, A.ECDSA_SHA384, "P-384"),
        (ec.generate_private_key(ec.SECP384R1()), {"signature_method": "ecdsa-sha512"}, A.ECDSA_SHA512, "P-384"),
        (ed25519.Ed25519PrivateKey.generate(), {}, A.EDDSA_ED25519, None),
        (None, {"signature_method": "ecdsa-sha256", "ec_curve": "p-521"}, A.ECDSA_SHA256, "P-521"),
        (None, {"signature_method": "rsa-pss-sha384", "digest_method": "sha384"}, A.RSA_PSS_SHA384, None),
    ],
)
def test_pkcs11_signature_method(tmp_path, private_key, args, method, curve):
    cert_pem = _self_signed(private_key) if private_key is not None else None
    signer_type, sign_enveloped = _pkcs11_sign(args, cert_pem, tmp_path)
    signer_type.assert_called_once()
    assert signer_type.call_args.args[2] == method
    assert signer_type.call_args.kwargs["ec_curve"] == curve
    assert sign_enveloped.call_args.kwargs["signature_method"] == method
    expected_digest = sigalg.resolve_digest_method(args.get("digest_method", "sha256"))
    assert sign_enveloped.call_args.kwargs["digest_method"] == expected_digest


@pytest.mark.parametrize(
    "private_key, args, message",
    [
        (None, {"signature_method": "ecdsa-sha256"}, "needs a cert or the ec_curve"),
        (None, {"signature_method": "ecdsa-sha256", "ec_curve": "P-192"}, "Unsupported ec_curve"),
        (ec.generate_private_key(ec.SECP256R1()), {"ec_curve": "P-384"}, "does not match"),
        (ec.generate_private_key(ec.SECP256R1()), {"signature_method": "rsa-sha256"}, "does not match"),
        (None, {"signature_method": "ml-dsa-65"}, "not supported by the PKCS#11 signer"),
    ],
)
def test_pkcs11_signature_method_errors(tmp_path, private_key, args, message):
    cert_pem = _self_signed(private_key) if private_key is not None else None
    with pytest.raises(PipeException, match=message):
        _pkcs11_sign(args, cert_pem, tmp_path)


def test_pkcs11_pq_cert_rejected(tmp_path):
    with open(os.path.join(KEYS_DIR, "ml-dsa-65-cert.pem")) as fd:
        cert_pem = fd.read()
    with pytest.raises(PipeException, match="not supported by the PKCS#11 signer"):
        _pkcs11_sign({}, cert_pem, tmp_path)


def test_pkcs11_bad_override_fails_before_login(tmp_path):
    """A typo in signature_method must not cost a token login."""
    provider_type = MagicMock()
    with (
        patch.dict(os.environ, {"PYKCS11PIN": "secret"}),
        patch.object(builtins, "_pkcs11_provider_cache", {}),
        patch.object(builtins.pybergshamra, "Pkcs11Provider", provider_type),
        pytest.raises(PipeException, match="Unsupported signature_method"),
    ):
        builtins.sign(
            _request(
                AGGREGATE,
                {"key": "pkcs11:///usr/lib/libmocked-pkcs11.so/signer", "signature_method": "nope"},
            )
        )
    provider_type.assert_not_called()


# --- PKCS#11 against a real SoftHSM2 token ----------------------------------

SOFTHSM_MODULE = next(
    (
        path
        for path in (
            "/usr/lib/softhsm/libsofthsm2.so",
            "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
            "/usr/local/lib/softhsm/libsofthsm2.so",
            "/opt/homebrew/lib/softhsm/libsofthsm2.so",
        )
        if os.path.exists(path)
    ),
    None,
)


# CI sets PYFF_REQUIRE_SOFTHSM=1 so a missing SoftHSM2 or a failing key type
# fails the run instead of being skipped silently.
REQUIRE_SOFTHSM = os.environ.get("PYFF_REQUIRE_SOFTHSM", "").strip().lower() in ("1", "true", "yes")


def _softhsm_unavailable(reason):
    if REQUIRE_SOFTHSM:
        pytest.fail(f"{reason} (PYFF_REQUIRE_SOFTHSM is set)")
    pytest.skip(reason)


@pytest.fixture(scope="module")
def softhsm_token(tmp_path_factory):
    """An initialized SoftHSM2 token; keys are created per test by ``_softhsm_key``."""
    if SOFTHSM_MODULE is None or not shutil.which("softhsm2-util") or not shutil.which("pkcs11-tool"):
        _softhsm_unavailable("SoftHSM2 and pkcs11-tool are required")

    directory = tmp_path_factory.mktemp("softhsm")
    (directory / "tokens").mkdir()
    conf = directory / "softhsm2.conf"
    conf.write_text(f"directories.tokendir = {directory / 'tokens'}\nobjectstore.backend = file\n")
    env = {**os.environ, "SOFTHSM2_CONF": str(conf)}
    pin, label = "1234", "pyff-sigalg"
    try:
        subprocess.run(
            ("softhsm2-util", "--init-token", "--free", "--label", label, "--pin", pin, "--so-pin", "5678"),
            check=True,
            env=env,
            capture_output=True,
        )
    except subprocess.CalledProcessError as ex:
        _softhsm_unavailable(f"Unable to initialize a SoftHSM2 token: {ex.stderr!r}")

    return {
        "directory": directory,
        "env": env,
        "pin": pin,
        "label": label,
        "ca": ec.generate_private_key(ec.SECP256R1()),
        "certs": {},
    }


def _softhsm_key(token, key_label, key_type):
    """Generate ``key_type`` on the token once and return the path of a cert for it.

    A key type the installed SoftHSM2 / pkcs11-tool cannot generate skips only
    the tests for that type (or fails them when PYFF_REQUIRE_SOFTHSM is set).
    """
    if key_label in token["certs"]:
        return token["certs"][key_label]

    directory = token["directory"]
    pkcs11 = ("pkcs11-tool", "--module", SOFTHSM_MODULE, "--token-label", token["label"])
    pub_path = directory / f"{key_label}.pub"
    try:
        for args in (
            ("--login", "--pin", token["pin"], "--keypairgen", "--key-type", key_type, "--label", key_label),
            ("--read-object", "--type", "pubkey", "--label", key_label, "-o", str(pub_path)),
        ):
            subprocess.run((*pkcs11, *args), check=True, env=token["env"], capture_output=True)
    except subprocess.CalledProcessError as ex:
        _softhsm_unavailable(f"Unable to create a {key_type} key on SoftHSM2: {ex.stderr!r}")

    raw = pub_path.read_bytes()
    # pkcs11-tool writes EdDSA public keys as PEM even when asked for DER.
    public_key = ser.load_pem_public_key(raw) if raw.startswith(b"-----") else ser.load_der_public_key(raw)
    cert_path = directory / f"{key_label}.crt"
    cert_path.write_text(_self_signed(None, cn=key_label, public_key=public_key, issuer_key=token["ca"]))
    token["certs"][key_label] = str(cert_path)
    return token["certs"][key_label]


@pytest.mark.parametrize(
    "key_label, key_type, expected",
    [
        ("rsa", "rsa:2048", A.RSA_SHA256),
        ("ec", "EC:prime256v1", A.ECDSA_SHA256),
        ("ed", "EC:edwards25519", A.EDDSA_ED25519),
    ],
)
def test_softhsm_sign(softhsm_token, key_label, key_type, expected):
    cert = _softhsm_key(softhsm_token, key_label, key_type)
    args = {
        "key": f"pkcs11://{SOFTHSM_MODULE}/{key_label}",
        "token_label": softhsm_token["label"],
        "cert": cert,
    }
    with (
        patch.dict(
            os.environ, {"SOFTHSM2_CONF": softhsm_token["env"]["SOFTHSM2_CONF"], "PYKCS11PIN": softhsm_token["pin"]}
        ),
        patch.object(builtins, "_pkcs11_provider_cache", {}),
    ):
        t = builtins.sign(_request(AGGREGATE, args))
    assert _methods(t) == ([expected], [A.SHA256])
    check_signature(t, cert, only_one_signature=True)


# --- certreport ---------------------------------------------------------------


def _entity_with_cert(cert_pem):
    body = "".join(line for line in cert_pem.splitlines() if not line.startswith("-----"))
    return etree.fromstring(
        f'<md:EntitiesDescriptor xmlns:md="{NS["md"]}" xmlns:ds="{NS["ds"]}">'
        '<md:EntityDescriptor entityID="https://sp.example.org/sp"><md:SPSSODescriptor '
        'protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor><ds:KeyInfo>'
        f"<ds:X509Data><ds:X509Certificate>{body}</ds:X509Certificate></ds:X509Data>"
        "</ds:KeyInfo></md:KeyDescriptor></md:SPSSODescriptor></md:EntityDescriptor></md:EntitiesDescriptor>"
    )


def _certreport(cert_pem, args=None):
    req = Plumbing.Request(
        Plumbing([], pid="certreport"), MDRepository(), t=_entity_with_cert(cert_pem), args=args, store=MagicMock()
    )
    with patch.object(builtins, "annotate_entity") as annotate:
        builtins.certreport(req)
    return [(call.args[1], call.args[2]) for call in annotate.call_args_list]


@pytest.mark.parametrize(
    "private_key, expected",
    [
        (rsa.generate_private_key(65537, 2048), []),
        (rsa.generate_private_key(65537, 1024), [("certificate-warning", "keysize small")]),
        (ec.generate_private_key(ec.SECP256R1()), []),
        (ec.generate_private_key(ec.SECP384R1()), []),
        (ec.generate_private_key(ec.SECP224R1()), [("certificate-warning", "keysize small")]),
        (ec.generate_private_key(ec.SECP192R1()), [("certificate-error", "keysize too small")]),
        (ed25519.Ed25519PrivateKey.generate(), []),
    ],
)
def test_certreport_key_sizes(private_key, expected):
    assert _certreport(_self_signed(private_key)) == expected


def test_certreport_ec_limits_configurable():
    cert_pem = _self_signed(ec.generate_private_key(ec.SECP256R1()))
    assert _certreport(cert_pem, {"ec_warning_bits": 384}) == [("certificate-warning", "keysize small")]


@pytest.mark.parametrize("name, family", [("ml-dsa-65", "ml-dsa"), ("slh-dsa-sha2-128s", "slh-dsa")])
def test_certreport_pq_certs(name, family):
    """PQ certs are not size checked, and an unloadable key type still gets the expiry check."""
    with open(os.path.join(KEYS_DIR, f"{name}-cert.pem")) as fd:
        cert_pem = fd.read()
    body = "".join(line for line in cert_pem.splitlines() if not line.startswith("-----"))
    info = cert_info(body)
    assert info.key_family == family
    assert info.not_after is not None
    assert _certreport(cert_pem) == []
    with patch.object(builtins, "utc_now", return_value=info.not_after + datetime.timedelta(days=1)):
        assert _certreport(cert_pem) == [("certificate-error", "certificate has expired")]


@pytest.mark.parametrize(
    "private_key, family",
    [
        (rsa.generate_private_key(65537, 2048), "rsa"),
        (ec.generate_private_key(ec.SECP256R1()), "ec"),
        (ed25519.Ed25519PrivateKey.generate(), "ed25519"),
    ],
)
def test_cert_info_key_family(private_key, family):
    pem = _self_signed(private_key)
    der = x509.load_pem_x509_certificate(pem.encode()).public_bytes(ser.Encoding.DER)
    assert cert_info(base64.b64encode(der).decode()).key_family == family
