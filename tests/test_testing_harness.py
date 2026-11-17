"""
Tests for the shared backend test harness itself.

These verify the guardrail added for deletion semantics: a backend that
reports "missing credential" and "deletion failed" with the same exception
type (differing only by message) MUST fail the harness, and a backend that
distinguishes them by type MUST pass it.
"""

import pytest

from keyring import backend, errors
from keyring.testing.backend import BackendBasicTests


class InMemoryKeyring(backend.KeyringBackend):
    """A correct backend: absence is a distinct type."""

    priority = 1

    def __init__(self):
        super().__init__()
        self._store = {}

    def get_password(self, service, username):
        return self._store.get((service, username))

    def set_password(self, service, username, password):
        self._store[(service, username)] = password

    def delete_password(self, service, username):
        try:
            del self._store[(service, username)]
        except KeyError:
            raise errors.PasswordNotFound(service=service, username=username) from None


class TwoFacedKeyring(InMemoryKeyring):
    """
    A backend that uses a single exception type for both semantics.

    The only difference between "not found" and "failed" is the message,
    which is exactly what the guardrail must reject.
    """

    priority = 1

    def delete_password(self, service, username):
        try:
            del self._store[(service, username)]
        except KeyError:
            raise errors.PasswordDeleteError("Password not found") from None


class LegacyTwoFacedKeyring(InMemoryKeyring):
    """
    A pre-existing third-party style backend: only the legacy
    PasswordDeleteError exists, so both semantics share it.
    """

    priority = 1

    def delete_password(self, service, username):
        if (service, username) not in self._store:
            raise errors.PasswordDeleteError("No such password!")
        del self._store[(service, username)]


class _Harness(BackendBasicTests):
    """BackendBasicTests bound to a concrete in-memory backend."""

    __test__ = False  # invoked explicitly below, not collected

    backend_factory = InMemoryKeyring

    def init_keyring(self):
        return self.backend_factory()


class _TwoFacedHarness(_Harness):
    backend_factory = TwoFacedKeyring


class _LegacyTwoFacedHarness(_Harness):
    backend_factory = LegacyTwoFacedKeyring


class TestHarnessGuardrail:
    """
    Drive the real ``BackendBasicTests`` deletion tests against in-memory
    backends: the two-faced ones must turn red, the correct one green.
    """

    @staticmethod
    def _run(harness_cls):
        # Bypass the autouse fixture (which needs a pytest request object) by
        # supplying the same state it would; we exercise only the deletion
        # tests, so no real store or cleanup is involved.
        harness = harness_cls()
        harness.keyring = harness.init_keyring()
        harness.credentials_created = set()
        return harness

    def test_correct_backend_passes_not_found_test(self):
        self._run(_Harness).test_delete_not_present()

    def test_correct_backend_passes_idempotent_delete_test(self):
        self._run(_Harness).test_delete_twice_is_idempotent()

    def test_two_faced_backend_fails_not_found_test(self):
        with pytest.raises(AssertionError, match='PasswordNotFound'):
            self._run(_TwoFacedHarness).test_delete_not_present()

    def test_legacy_two_faced_backend_fails_not_found_test(self):
        with pytest.raises(AssertionError, match='PasswordNotFound'):
            self._run(_LegacyTwoFacedHarness).test_delete_not_present()

    def test_two_faced_backend_fails_idempotent_delete_test(self):
        # The second deletion must be reported as NOT_FOUND; a two-faced
        # backend raises plain PasswordDeleteError, which is FAILED.
        with pytest.raises(AssertionError, match='PasswordNotFound'):
            self._run(_TwoFacedHarness).test_delete_twice_is_idempotent()

    def test_legacy_backend_message_does_not_confuse_classifier(self):
        keyring_ = LegacyTwoFacedKeyring()
        with pytest.raises(errors.PasswordDeleteError) as exc_info:
            keyring_.delete_password('svc', 'user')
        # Even though the message says "No such password!", classification
        # must not trust it.
        assert (
            errors.classify_delete_error(exc_info.value) is errors.DeleteOutcome.FAILED
        )

    def test_assert_delete_not_found_accepts_correct_backend(self):
        from keyring.testing.backend import assert_delete_not_found

        assert_delete_not_found(InMemoryKeyring(), 'svc', 'user')


class TestBackendBasicTestsAreWired:
    def test_guardrail_tests_present(self):
        names = {
            name for name in dir(BackendBasicTests) if name.startswith('test_delete')
        }
        assert 'test_delete_not_present' in names
        assert 'test_delete_twice_is_idempotent' in names
