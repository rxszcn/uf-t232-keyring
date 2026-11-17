import pytest

import keyring.backends.chainer
from keyring import backend, errors


@pytest.fixture
def two_keyrings(monkeypatch):
    def get_two():
        class Keyring1(backend.KeyringBackend):
            priority = 1

            def get_password(self, system, user):
                return f'ring1-{system}-{user}'

            def set_password(self, system, user, password):
                pass

        class Keyring2(backend.KeyringBackend):
            priority = 2

            def get_password(self, system, user):
                return f'ring2-{system}-{user}'

            def set_password(self, system, user, password):
                raise NotImplementedError()

        return Keyring1(), Keyring2()

    monkeypatch.setattr('keyring.backend.get_all_keyring', get_two)


class TestChainer:
    def test_chainer_gets_from_highest_priority(self, two_keyrings):
        chainer = keyring.backends.chainer.ChainerBackend()
        pw = chainer.get_password('alpha', 'bravo')
        assert pw == 'ring2-alpha-bravo'

    def test_chainer_defers_to_fail(self, monkeypatch):
        """
        The Chainer backend should defer to the Fail backend when there are
        no backends to be chained.
        """
        monkeypatch.setattr('keyring.backend.get_all_keyring', tuple)
        assert keyring.backend.by_priority(
            keyring.backends.chainer.ChainerBackend
        ) < keyring.backend.by_priority(keyring.backends.fail.Keyring)


def make_delete_backend(priority, exc):
    """Build a backend whose delete_password always raises *exc* (or None)."""

    class DeleteOnly(backend.KeyringBackend):
        def get_password(self, service, username):
            return None

        def set_password(self, service, username, password):
            pass

        def delete_password(self, service, username):
            if exc is None:
                return
            raise exc

    DeleteOnly.priority = priority
    return DeleteOnly()


class TestChainerDeleteSemantics:
    def _chainer(self, monkeypatch, *backends):
        chainer = keyring.backends.chainer.ChainerBackend()
        monkeypatch.setattr(
            type(chainer), 'backends', property(lambda self: list(backends))
        )
        return chainer

    def test_all_missing_is_not_found(self, monkeypatch):
        b1 = make_delete_backend(1, errors.PasswordNotFound("one"))
        b2 = make_delete_backend(2, errors.PasswordNotFound("two"))
        chainer = self._chainer(monkeypatch, b1, b2)
        with pytest.raises(errors.PasswordNotFound):
            chainer.delete_password('svc', 'user')

    def test_locked_backend_is_not_downgraded_to_not_found(self, monkeypatch):
        missing = make_delete_backend(1, errors.PasswordNotFound("one"))
        locked = make_delete_backend(2, errors.PasswordStoreUnavailable("locked"))
        chainer = self._chainer(monkeypatch, missing, locked)
        with pytest.raises(errors.PasswordStoreUnavailable):
            chainer.delete_password('svc', 'user')

    def test_failure_is_not_downgraded_to_not_found(self, monkeypatch):
        missing = make_delete_backend(1, errors.PasswordNotFound("one"))
        failed = make_delete_backend(2, errors.PasswordDeleteError("boom"))
        chainer = self._chainer(monkeypatch, missing, failed)
        with pytest.raises(errors.PasswordDeleteError) as exc_info:
            chainer.delete_password('svc', 'user')
        assert not isinstance(exc_info.value, errors.PasswordNotFound)
        assert (
            errors.classify_delete_error(exc_info.value) is errors.DeleteOutcome.FAILED
        )

    def test_unavailable_beats_plain_failure(self, monkeypatch):
        failed = make_delete_backend(1, errors.PasswordDeleteError("boom"))
        locked = make_delete_backend(2, errors.KeyringLocked("locked"))
        chainer = self._chainer(monkeypatch, failed, locked)
        with pytest.raises(errors.KeyringLocked):
            chainer.delete_password('svc', 'user')

    def test_absence_does_not_stop_later_backends(self, monkeypatch):
        # A lower-priority backend holding the credential must still be
        # consulted after a higher-priority one reports absence.
        deleted = []

        def make(priority, outcome):
            b = make_delete_backend(priority, None)

            def delete(service, username):
                deleted.append(priority)
                if isinstance(outcome, Exception):
                    raise outcome

            b.delete_password = delete
            return b

        missing = make(2, errors.PasswordNotFound("gone"))
        holder = make(1, None)
        chainer = self._chainer(monkeypatch, missing, holder)
        chainer.delete_password('svc', 'user')
        assert deleted == [2, 1]
