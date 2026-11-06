import pytest
from app.gateway import check_tool_call
from app.patches import Patch, PatchError, apply_patch, is_narrowing
from app.policy import Policy


def test_add_deny_host_blocks_subdomains_and_bumps_version():
    p = apply_patch(Policy(), Patch(op="ADD_DENY", field="fetch_denied_hosts", value="Evil.Test."))
    assert p.version == 1 and p.fetch_denied_hosts == ["evil.test"]
    assert not check_tool_call(p, "fetch_url", {"url": "https://x.evil.test/"}).allowed
    assert check_tool_call(p, "fetch_url", {"url": "https://ok.example/"}).allowed


def test_add_deny_path_glob_blocks_env():
    p = apply_patch(Policy(), Patch(op="ADD_DENY", field="deny_path_globs", value="*/.env"))
    assert not check_tool_call(p, "read_file", {"path": "x/.env"}).allowed


def test_add_deny_rejects_bad_field_and_bad_host():
    with pytest.raises(PatchError):
        apply_patch(Policy(), Patch(op="ADD_DENY", field="read_prefixes", value="/x"))
    with pytest.raises(PatchError):
        apply_patch(Policy(), Patch(op="ADD_DENY", field="fetch_denied_hosts", value="a@b"))


def test_remove_wildcard_with_replacement():
    p = apply_patch(Policy(), Patch(op="REMOVE_ALLOWED_VALUE", field="fetch_allowed_hosts", value="*",
                                    replace_with=["Intranet.Corp"]))
    assert p.fetch_allowed_hosts == ["intranet.corp"]
    assert check_tool_call(p, "fetch_url", {"url": "https://intranet.corp/"}).allowed
    assert not check_tool_call(p, "fetch_url", {"url": "https://evil.test/"}).allowed


def test_remove_missing_value_fails():
    with pytest.raises(PatchError):
        apply_patch(Policy(), Patch(op="REMOVE_ALLOWED_VALUE", field="fetch_allowed_hosts", value="nope.test"))


def test_replace_with_wildcard_rejected():
    with pytest.raises(PatchError):
        apply_patch(Policy(), Patch(op="REMOVE_ALLOWED_VALUE", field="fetch_allowed_hosts", value="*",
                                    replace_with=["*"]))


def test_remove_port():
    p = apply_patch(Policy(), Patch(op="REMOVE_ALLOWED_VALUE", field="allowed_ports", value=80))
    assert p.allowed_ports == [443]


def test_tighten_prefix():
    p = apply_patch(Policy(), Patch(op="TIGHTEN_PREFIX", field="read_prefixes", value="/workspace",
                                    new_value="/workspace/docs"))
    assert p.read_prefixes == ["/workspace/docs"]
    assert not check_tool_call(p, "read_file", {"path": "secrets/.env"}).allowed
    assert check_tool_call(p, "read_file", {"path": "docs/a.txt"}).allowed


@pytest.mark.parametrize("new_value", ["/workspace", "/etc", "/workspace/../etc", "/workspacex", "/"])
def test_tighten_prefix_cannot_widen_or_escape(new_value):
    with pytest.raises(PatchError):
        apply_patch(Policy(), Patch(op="TIGHTEN_PREFIX", field="read_prefixes", value="/workspace",
                                    new_value=new_value))


def test_arg_constraint_blocks_encoded_exfil():
    p = apply_patch(Policy(), Patch(op="ADD_ARG_CONSTRAINT", tool="fetch_url", pattern=r"[?&]\w+=[A-Za-z0-9+/=]{40,}"))
    blob = "A" * 60
    assert not check_tool_call(p, "fetch_url", {"url": f"https://ok.example/c?d={blob}"}).allowed
    assert check_tool_call(p, "fetch_url", {"url": "https://ok.example/c?d=1"}).allowed


def test_arg_constraint_rejects_bad_regex_and_unknown_tool():
    with pytest.raises(PatchError):
        apply_patch(Policy(), Patch(op="ADD_ARG_CONSTRAINT", tool="fetch_url", pattern="("))
    with pytest.raises(PatchError):
        apply_patch(Policy(), Patch(op="ADD_ARG_CONSTRAINT", tool="nope", pattern="x"))
    with pytest.raises(PatchError):
        apply_patch(Policy(), Patch(op="ADD_ARG_CONSTRAINT", tool="fetch_url", pattern="x" * 201))


def test_cap_arg_length_only_lowers():
    p = apply_patch(Policy(), Patch(op="CAP_ARG_LENGTH", tool="send_email", max_len=500))
    assert p.max_arg_len["send_email"] == 500
    with pytest.raises(PatchError):
        apply_patch(p, Patch(op="CAP_ARG_LENGTH", tool="send_email", max_len=500))
    with pytest.raises(PatchError):
        apply_patch(p, Patch(op="CAP_ARG_LENGTH", tool="send_email", max_len=9999))
    with pytest.raises(PatchError):
        apply_patch(Policy(), Patch(op="CAP_ARG_LENGTH", tool="send_email", max_len=0))


def test_is_narrowing_catches_widening():
    base = Policy(fetch_allowed_hosts=["a.test"], read_prefixes=["/workspace/docs"])
    assert is_narrowing(base, base)[0]
    assert not is_narrowing(base, base.model_copy(update={"fetch_allowed_hosts": ["a.test", "b.test"]}))[0]
    assert not is_narrowing(base, base.model_copy(update={"fetch_allowed_hosts": ["*"]}))[0]
    assert not is_narrowing(base, base.model_copy(update={"read_prefixes": ["/workspace"]}))[0]
    assert not is_narrowing(base, base.model_copy(update={"block_private_ips": False}))[0]
    assert not is_narrowing(base, base.model_copy(update={"max_arg_len": {}}))[0]
    wide = Policy(fetch_allowed_hosts=["*"])
    assert is_narrowing(wide, wide.model_copy(update={"fetch_allowed_hosts": ["x.test"]}))[0]


def test_is_narrowing_catches_removed_denies():
    base = Policy(fetch_denied_hosts=["evil.test"])
    assert not is_narrowing(base, base.model_copy(update={"fetch_denied_hosts": []}))[0]


def test_original_policy_not_mutated():
    p0 = Policy()
    apply_patch(p0, Patch(op="ADD_DENY", field="fetch_denied_hosts", value="evil.test"))
    assert p0.fetch_denied_hosts == [] and p0.version == 0
