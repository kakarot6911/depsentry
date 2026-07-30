"""Seed the local advisory corpus.

IMPORTANT (academic integrity, SOP Annexure-A clause 13):
These advisories are SYNTHETIC. They carry `DEPS-` identifiers, not `CVE-`
identifiers, and they are not claims about real defects in the named packages.
They are modelled on the *structure* and *severity distribution* of real OSV
advisories so the reachability experiment has a realistic corpus to run against
without requiring network access or asserting unverified facts about real CVEs.

To run DepSentry against genuine advisory data, export from osv.dev and load it
with `VulnerabilityDB.import_osv()` -- the pipeline needs no other change.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from depsentry.models import Vulnerability  # noqa: E402
from depsentry.vulndb import DEFAULT_DB, VulnerabilityDB  # noqa: E402


def _v(
    vuln_id: str,
    package: str,
    introduced: str,
    fixed: str | None,
    cvss: float,
    summary: str,
    symbols: tuple[str, ...],
    cwe: tuple[str, ...],
    *,
    exploit_known: bool = False,
    network_exposed: bool = False,
    vector: str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
) -> Vulnerability:
    return Vulnerability(
        vuln_id=vuln_id,
        package=package,
        ecosystem="PyPI",
        introduced=introduced,
        fixed=fixed,
        cvss_score=cvss,
        cvss_vector=vector,
        summary=summary,
        affected_symbols=symbols,
        cwe=cwe,
        published="2026-01-15",
        exploit_known=exploit_known,
        network_exposed=network_exposed,
    )


# The corpus deliberately spans the full severity range and, critically, mixes
# advisories on symbols an application typically calls (requests.get) with ones
# on symbols it almost never calls (yaml.load, pickle paths, admin-only helpers).
# That mix is what makes the reachability result non-trivial.
ADVISORIES: list[Vulnerability] = [
    _v("DEPS-2026-0001", "requests", "0", "2.32.0", 7.5,
       "Proxy-Authorization header leaked on cross-origin redirect.",
       ("requests.get", "requests.post", "requests.Session.request", "requests.api.request"),
       ("CWE-200",), network_exposed=True, exploit_known=True),

    _v("DEPS-2026-0002", "requests", "0", "2.31.0", 5.3,
       "Certificate verification bypass when verify is passed a non-bool truthy value.",
       ("requests.Session.merge_environment_settings",), ("CWE-295",), network_exposed=True),

    _v("DEPS-2026-0003", "urllib3", "0", "2.2.2", 6.5,
       "Redirect handling discloses Authorization header to a different host.",
       ("urllib3.PoolManager.urlopen", "urllib3.request"), ("CWE-200",), network_exposed=True),

    _v("DEPS-2026-0004", "urllib3", "0", "1.26.19", 4.3,
       "Chunked transfer-encoding request smuggling under a specific proxy config.",
       ("urllib3.connection.HTTPConnection.request_chunked",), ("CWE-444",)),

    _v("DEPS-2026-0005", "jinja2", "0", "3.1.4", 8.8,
       "Sandbox escape in the template environment allows attribute traversal.",
       ("jinja2.sandbox.SandboxedEnvironment.call_binop", "jinja2.Environment.from_string"),
       ("CWE-693",), exploit_known=True, network_exposed=True),

    _v("DEPS-2026-0006", "jinja2", "0", "3.1.3", 5.4,
       "XSS via the xmlattr filter accepting keys containing whitespace.",
       ("jinja2.filters.do_xmlattr",), ("CWE-79",), network_exposed=True),

    _v("DEPS-2026-0007", "pyyaml", "0", "6.0.2", 9.8,
       "Arbitrary code execution when untrusted input reaches the unsafe loader.",
       ("yaml.load", "yaml.unsafe_load", "yaml.full_load"),
       ("CWE-502",), exploit_known=True, network_exposed=True,
       vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),

    _v("DEPS-2026-0008", "pillow", "0", "10.3.0", 7.8,
       "Heap buffer overflow parsing a malformed ICC profile.",
       ("PIL.Image.open", "PIL.ImageCms.profileToProfile"), ("CWE-787",)),

    _v("DEPS-2026-0009", "pillow", "0", "10.2.0", 6.2,
       "Denial of service through decompression bomb in TIFF handling.",
       ("PIL.TiffImagePlugin.TiffImageFile.load",), ("CWE-400",)),

    _v("DEPS-2026-0010", "cryptography", "0", "42.0.4", 7.5,
       "NULL pointer dereference when loading a malformed PKCS7 certificate.",
       ("cryptography.hazmat.primitives.serialization.pkcs7.load_der_pkcs7_certificates",),
       ("CWE-476",)),

    _v("DEPS-2026-0011", "cryptography", "0", "41.0.6", 5.9,
       "Timing side channel in RSA PKCS#1 v1.5 decryption.",
       ("cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15",), ("CWE-208",)),

    _v("DEPS-2026-0012", "flask", "0", "2.3.3", 6.1,
       "Session cookie set without the Secure attribute behind a TLS-terminating proxy.",
       ("flask.sessions.SecureCookieSessionInterface.save_session",),
       ("CWE-614",), network_exposed=True),

    _v("DEPS-2026-0013", "werkzeug", "0", "3.0.3", 7.5,
       "Resource exhaustion parsing multipart form data with many small parts.",
       ("werkzeug.formparser.MultiPartParser.parse",), ("CWE-400",), network_exposed=True),

    _v("DEPS-2026-0014", "werkzeug", "0", "3.0.1", 8.1,
       "Path traversal in the development static file server on Windows.",
       ("werkzeug.security.safe_join", "werkzeug.serving.run_simple"), ("CWE-22",)),

    _v("DEPS-2026-0015", "numpy", "0", "1.26.0", 5.5,
       "Buffer over-read in the legacy binary .npy loader.",
       ("numpy.load", "numpy.lib.format.read_array"), ("CWE-125",)),

    _v("DEPS-2026-0016", "pandas", "0", "2.2.0", 7.8,
       "Deserialisation of untrusted pickle data in read_pickle.",
       ("pandas.read_pickle",), ("CWE-502",), exploit_known=True),

    _v("DEPS-2026-0017", "sqlalchemy", "0", "2.0.30", 6.5,
       "SQL injection when a limit/offset clause is built from unsanitised input.",
       ("sqlalchemy.orm.Query.limit", "sqlalchemy.text"), ("CWE-89",), network_exposed=True),

    _v("DEPS-2026-0018", "certifi", "0", "2024.7.4", 6.8,
       "Root store retains a CA whose trust was withdrawn.",
       ("certifi.where",), ("CWE-295",), network_exposed=True),

    _v("DEPS-2026-0019", "idna", "0", "3.7", 4.3,
       "Quadratic complexity decoding a crafted internationalised domain name.",
       ("idna.encode", "idna.decode"), ("CWE-407",)),

    _v("DEPS-2026-0020", "setuptools", "0", "70.0.0", 8.8,
       "Remote code execution via a crafted package index URL during easy_install.",
       ("setuptools.package_index.PackageIndex.download",),
       ("CWE-94",), exploit_known=True),

    _v("DEPS-2026-0021", "click", "0", "8.1.7", 3.3,
       "Terminal escape sequence injection in echo output.",
       ("click.echo",), ("CWE-150",)),

    _v("DEPS-2026-0022", "starlette", "0", "0.37.2", 7.5,
       "Unbounded memory growth handling large multipart uploads.",
       ("starlette.requests.Request.form",), ("CWE-770",), network_exposed=True),

    _v("DEPS-2026-0023", "fastapi", "0", "0.109.1", 5.3,
       "Content-Type confusion permits form parsing on a JSON-only endpoint.",
       ("fastapi.routing.APIRoute.get_route_handler",), ("CWE-843",), network_exposed=True),

    _v("DEPS-2026-0024", "pydantic", "0", "2.6.0", 4.9,
       "Regular expression denial of service in the email validator.",
       ("pydantic.networks.validate_email",), ("CWE-1333",)),

    _v("DEPS-2026-0025", "joblib", "0", "1.4.0", 8.4,
       "Arbitrary code execution loading an untrusted serialised object.",
       ("joblib.load",), ("CWE-502",), exploit_known=True),

    _v("DEPS-2026-0026", "scikit-learn", "0", "1.5.0", 5.5,
       "Sensitive training data retained in a fitted vectoriser's stop-word list.",
       ("sklearn.feature_extraction.text.TfidfVectorizer",), ("CWE-212",)),

    _v("DEPS-2026-0027", "matplotlib", "0", "3.9.0", 3.7,
       "Temporary file created with predictable name during font cache rebuild.",
       ("matplotlib.font_manager.FontManager",), ("CWE-377",)),

    _v("DEPS-2026-0028", "typing-extensions", "0", None, 2.0,
       "Informational: unmaintained backport path retained for legacy runtimes.",
       ("typing_extensions.deprecated",), ("CWE-1104",)),

    _v("DEPS-2026-0029", "anyio", "0", "4.4.0", 4.0,
       "Race condition in task group cancellation may drop an exception.",
       ("anyio.create_task_group",), ("CWE-362",)),

    _v("DEPS-2026-0030", "h11", "0", "0.14.1", 6.5,
       "Lenient chunked-encoding parsing enables request smuggling behind a proxy.",
       ("h11.Connection.receive_data",), ("CWE-444",), network_exposed=True),
]


def seed(db_path: str | Path = DEFAULT_DB, *, reset: bool = True) -> int:
    path = Path(db_path)
    if reset and path.exists():
        path.unlink()

    with VulnerabilityDB(path) as db:
        db.add_many(ADVISORIES)
        total = db.count()

    print(f"Seeded {total} advisories into {path}")
    return total


if __name__ == "__main__":
    seed()
