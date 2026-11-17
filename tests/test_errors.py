import sys
from unittest import mock

import pytest

from keyring import errors


class DeletionDetector:
    def __init__(self, state):
        self.state = state
        self.state.deleted = False

    def __del__(self):
        self.state.deleted = True


class TestExceptionInfo:
    @pytest.mark.skipif(
        '__pypy__' in sys.builtin_module_names,
        reason="pypy garbage collection defers deletion",
    )
    def test_traceback_not_referenced(self):
        """
        Ensure that an ExceptionInfo does not keep a reference
        to the traceback, as doing so can create unintended
        side effects. See #386 for more info.
        """
        state = mock.MagicMock()
        _ = errors.ExceptionInfo(None, None, DeletionDetector(state))
        assert state.deleted


class TestDeleteErrorHierarchy:
    """
    The three deletion semantics must be distinguishable at the type level
    while remaining compatible with pre-existing ``PasswordDeleteError``
    handlers.
    """

    def test_not_found_is_a_delete_error(self):
        # Backwards compatibility: existing handlers keep catching it.
        assert issubclass(errors.PasswordNotFound, errors.PasswordDeleteError)
        assert issubclass(errors.PasswordNotFound, errors.KeyringError)

    def test_not_found_and_failure_are_different_types(self):
        assert not issubclass(errors.PasswordDeleteError, errors.PasswordNotFound)
        assert not issubclass(errors.PasswordNotFound, errors.PasswordStoreUnavailable)
        assert type(errors.PasswordNotFound("x")) is not type(
            errors.PasswordDeleteError("x")
        )

    def test_not_found_and_unavailable_are_different_types(self):
        assert not issubclass(errors.PasswordNotFound, errors.PasswordStoreUnavailable)
        assert not issubclass(errors.PasswordStoreUnavailable, errors.PasswordNotFound)

    def test_unavailable_is_both_delete_error_and_locked(self):
        exc = errors.PasswordStoreUnavailable("locked")
        assert isinstance(exc, errors.PasswordDeleteError)
        assert isinstance(exc, errors.KeyringLocked)

    def test_existing_exception_types_still_importable(self):
        # Third-party backends import these names directly.
        for name in (
            'KeyringError',
            'PasswordSetError',
            'PasswordDeleteError',
            'InitError',
            'KeyringLocked',
            'NoKeyringError',
        ):
            assert isinstance(getattr(errors, name), type)
            assert issubclass(getattr(errors, name), errors.KeyringError)

    def test_kind_attribute_matches_classification(self):
        cases = [
            (errors.PasswordNotFound("x"), errors.DeleteOutcome.NOT_FOUND),
            (errors.PasswordDeleteError("x"), errors.DeleteOutcome.FAILED),
            (errors.PasswordStoreUnavailable("x"), errors.DeleteOutcome.UNAVAILABLE),
        ]
        for exc, expected in cases:
            assert exc.kind is expected
            assert errors.classify_delete_error(exc) is expected

    def test_default_messages_identify_service_and_username(self):
        not_found = errors.PasswordNotFound(service='svc', username='user')
        failure = errors.PasswordDeleteError(service='svc', username='user')
        unavailable = errors.PasswordStoreUnavailable(service='svc', username='user')
        for exc in (not_found, failure, unavailable):
            assert 'svc' in str(exc)
            assert 'user' in str(exc)

    def test_explicit_message_is_preserved(self):
        assert str(errors.PasswordNotFound("custom")) == "custom"
        assert str(errors.PasswordDeleteError("custom")) == "custom"


class TestClassifyDeleteError:
    def test_classifies_recognized_types(self):
        assert (
            errors.classify_delete_error(errors.PasswordNotFound("x"))
            is errors.DeleteOutcome.NOT_FOUND
        )
        assert (
            errors.classify_delete_error(errors.PasswordDeleteError("x"))
            is errors.DeleteOutcome.FAILED
        )
        assert (
            errors.classify_delete_error(errors.PasswordStoreUnavailable("x"))
            is errors.DeleteOutcome.UNAVAILABLE
        )

    def test_plain_locked_counts_as_unavailable(self):
        # Backends may still raise the legacy KeyringLocked for a locked store.
        assert (
            errors.classify_delete_error(errors.KeyringLocked("locked"))
            is errors.DeleteOutcome.UNAVAILABLE
        )
        assert (
            errors.classify_delete_error(errors.InitError("no store"))
            is errors.DeleteOutcome.UNAVAILABLE
        )
        assert (
            errors.classify_delete_error(errors.NoKeyringError("no backend"))
            is errors.DeleteOutcome.UNAVAILABLE
        )

    def test_unknown_keyring_error_is_conservatively_failed(self):
        class Custom(errors.KeyringError):
            pass

        # A third-party error type we don't know about must never be mistaken
        # for "not found"; that would skip a deletion that may be needed.
        assert (
            errors.classify_delete_error(Custom("boom")) is errors.DeleteOutcome.FAILED
        )

    def test_two_faced_backend_is_not_found_free(self):
        """
        A backend deriving not-found and failure from one type (differing
        only in message) must not slip through as NOT_FOUND.
        """

        class TwoFaced(errors.PasswordDeleteError):
            pass

        missing = TwoFaced("Password not found")
        real_failure = TwoFaced("Could not remove entry")
        assert type(missing) is type(real_failure)
        assert errors.classify_delete_error(missing) is errors.DeleteOutcome.FAILED

    def test_non_keyring_error_is_rejected(self):
        with pytest.raises(TypeError):
            errors.classify_delete_error(ValueError("nope"))
