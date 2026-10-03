"""DNS subtree matching semantics."""

from certaudit.audit import _dns_matches


def test_bare_subtree_matches_self_and_label_boundary_subdomains():
    assert _dns_matches("example.com", "example.com")
    assert _dns_matches("example.com", "www.example.com")
    assert _dns_matches("example.com", "a.b.example.com")


def test_bare_subtree_rejects_non_boundary_suffixes():
    assert not _dns_matches("example.com", "badexample.com")
    assert not _dns_matches("example.com", "example.com.evil.org")
    assert not _dns_matches("example.com", "example.co")


def test_dotted_subtree_matches_only_proper_subdomains():
    assert _dns_matches(".example.com", "www.example.com")
    assert _dns_matches(".example.com", "a.b.example.com")
    assert not _dns_matches(".example.com", "example.com")
    assert not _dns_matches(".example.com", "badexample.com")


def test_matching_ignores_case():
    assert _dns_matches("example.com", "WWW.EXAMPLE.COM")
    assert _dns_matches("EXAMPLE.com", "www.example.COM")
    assert _dns_matches(".Example.COM", "WWW.example.com")
