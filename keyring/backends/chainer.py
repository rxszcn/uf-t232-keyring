"""
Keyring Chainer - iterates over other viable backends to
discover passwords in each.
"""

from .. import backend, errors
from ..compat import properties
from . import fail


class ChainerBackend(backend.KeyringBackend):
    """
    >>> ChainerBackend()
    <keyring.backends.chainer.ChainerBackend object at ...>
    """

    # override viability as 'priority' cannot be determined
    # until other backends have been constructed
    viable = True

    @properties.classproperty
    def priority(cls) -> float:
        """
        If there are backends to chain, high priority
        Otherwise very low priority since our operation when empty
        is the same as null.
        """
        return 10 if len(cls.backends) > 1 else (fail.Keyring.priority - 1)

    @properties.classproperty
    def backends(cls):
        """
        Discover all keyrings for chaining.
        """

        def allow(keyring):
            limit = backend._limit or bool
            return (
                not isinstance(keyring, ChainerBackend)
                and limit(keyring)
                and keyring.priority > 0
            )

        allowed = filter(allow, backend.get_all_keyring())
        return sorted(allowed, key=backend.by_priority, reverse=True)

    def get_password(self, service, username):
        for keyring in self.backends:
            password = keyring.get_password(service, username)
            if password is not None:
                return password

    def set_password(self, service, username, password):
        for keyring in self.backends:
            try:
                return keyring.set_password(service, username, password)
            except NotImplementedError:
                pass

    def delete_password(self, service, username):
        """
        Delete the password from the first backend that holds it.

        A backend reporting absence does not stop the search, so a credential
        stored in a lower-priority backend is still deleted. If no backend
        holds the credential, the aggregated error preserves the deletion
        semantics: the most severe failure seen is re-raised (a locked or
        failing store is never downgraded to "not found"), and only when no
        backend reported a failure is ``PasswordNotFound`` raised.
        """
        deferred = None
        for keyring in self.backends:
            try:
                return keyring.delete_password(service, username)
            except NotImplementedError:
                pass
            except errors.KeyringError as exc:
                outcome = errors.classify_delete_error(exc)
                if outcome is errors.DeleteOutcome.NOT_FOUND:
                    # Absence here doesn't mean absence everywhere; keep
                    # looking so a lower-priority backend still gets cleaned.
                    continue
                if deferred is None or self._severity(exc) > self._severity(deferred):
                    deferred = exc
        if deferred is not None:
            raise deferred
        raise errors.PasswordNotFound(service=service, username=username)

    @staticmethod
    def _severity(exc: BaseException) -> int:
        outcome = errors.classify_delete_error(exc)
        return {
            errors.DeleteOutcome.NOT_FOUND: 0,
            errors.DeleteOutcome.FAILED: 1,
            errors.DeleteOutcome.UNAVAILABLE: 2,
        }[outcome]

    def get_credential(self, service, username):
        for keyring in self.backends:
            credential = keyring.get_credential(service, username)
            if credential is not None:
                return credential
