import pytest
from app.gateway import check_tool_call, check_url, normalize_path, check_redirect
from app.policy import Policy


def strict() -> Policy:
    return Policy(
        read_prefixes=["/workspace/docs", "/workspace/data"],
        deny_path_globs=["*/.env", "*.pem"],
        fetch_allowed_hosts=["intranet.corp", "docs.example.test"],
        fetch_denied_hosts=["evil.test"],
        email_allowed_domains=["corp.test"],
    )


# ----- paths -----
@pytest.mark.parametrize("raw", [
    "../etc/passwd", "/etc/passwd", "docs/../../etc/passwd", "/workspace/../etc/passwd",
    "docs\\..\\..\\etc\\passwd", "/workspace/docs/%2e%2e/secret", "a\x00b", "", None, 123,
])
def test_path_escape_rejected(raw):
    assert normalize_path(raw) is None


def test_path_normalizes_inside_root():
    assert normalize_path("docs/./a//b.txt") == "/workspace/docs/a/b.txt"
    assert normalize_path("/workspace/docs/../data/x") == "/workspace/data/x"


def test_read_allowed_and_denied():
    p = strict()
    assert check_tool_call(p, "read_file", {"path": "docs/a.txt"}).allowed
    assert not check_tool_call(p, "read_file", {"path": "docs/.env"}).allowed       # deny glob
    assert not check_tool_call(p, "read_file", {"path": "docs/../.env"}).allowed    # outside prefix
    assert not check_tool_call(p, "read_file", {"path": "docs/../../etc/passwd"}).allowed
    assert not check_tool_call(p, "read_file", {"path": "docs/key.PEM".replace("PEM", "pem")}).allowed


def test_write_scope():
    p = Policy()
    assert check_tool_call(p, "write_file", {"path": "out/r.txt", "content": "x"}).allowed
    assert not check_tool_call(p, "write_file", {"path": "docs/r.txt", "content": "x"}).allowed
    assert not check_tool_call(p, "write_file", {"path": "out/../../tmp/x", "content": "x"}).allowed


# ----- urls -----
@pytest.mark.parametrize("url", [
    "http://intranet.corp@evil.test/x",          # H3 userinfo trick
    "https://intranet.corp:pw@evil.test/",
    "https://intranet.corp.evil.test/",           # subdomain spoof
    "https://evilintranet.corp/",                 # suffix spoof
    "https://evil.test/",
    "https://sub.evil.test/",                     # denied host covers subdomains
    "https://docs.example.test.evil.test/",
    "file:///workspace/.env", "ftp://intranet.corp/", "javascript:alert(1)",
    "https://intranet.corp:8080/",                # port not allowed
    "http://127.0.0.1/", "http://169.254.169.254/latest/meta-data", "http://10.0.0.5/",
    "https://intranet.corp /x", "https://intranet.corp\\@evil.test/", "", "   ",
])
def test_url_blocked(url):
    assert not check_url(strict(), url).allowed, url


@pytest.mark.parametrize("url", [
    "https://intranet.corp/page", "http://docs.example.test/a?b=c",
    "https://INTRANET.CORP./page", "https://intranet.corp:443/",
])
def test_url_allowed(url):
    assert check_url(strict(), url).allowed, url


def test_permissive_baseline_allows_unknown_host():
    assert check_url(Policy(), "https://anything.example/").allowed


def test_redirect_is_revalidated():
    assert not check_redirect(strict(), "https://evil.test/collect").allowed
    assert check_redirect(strict(), "https://intranet.corp/next").allowed


# ----- email -----
def test_email():
    p = strict()
    assert check_tool_call(p, "send_email", {"to": "a@corp.test", "body": "hi"}).allowed
    assert not check_tool_call(p, "send_email", {"to": "a@evil.test", "body": "hi"}).allowed
    assert not check_tool_call(p, "send_email", {"to": "a@corp.test,b@evil.test", "body": "x"}).allowed
    assert not check_tool_call(p, "send_email", {"to": "a@corp.test@evil.test", "body": "x"}).allowed
    assert not check_tool_call(p, "send_email", {"to": "a@corp.test\nbcc:b@evil.test", "body": "x"}).allowed


# ----- misc -----
def test_arg_length_cap():
    p = Policy(max_arg_len={"send_email": 10})
    assert not check_tool_call(p, "send_email", {"to": "a@b.c", "body": "x" * 11}).allowed


def test_unknown_tool_denied():
    assert not check_tool_call(Policy(), "rm_rf", {}).allowed
