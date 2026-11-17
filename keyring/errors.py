import enum
import sys
import warnings


class KeyringError(Exception):
    """Base class for exceptions in keyring"""


class PasswordSetError(KeyringError):
    """Raised when the password can't be set."""


class DeleteOutcome(enum.Enum):
    """
    Classified outcomes of a failed ``delete_password``.

    Callers such as credential-rotation pipelines select retry and alerting
    behaviour from this value rather than from the exception type or its
    message:

    * :attr:`NOT_FOUND` -- nothing to delete. Deletion is idempotent; do not
      retry, and do not page anyone.
    * :attr:`FAILED` -- the credential could not be deleted although it may
      still exist. Retrying is reasonable; raise a normal alert.
    * :attr:`UNAVAILABLE` -- the credential store itself could not be opened
      or unlocked. Raise the highest alert; retrying blindly (or reporting
      cleanup as successful) is wrong.
    """

    NOT_FOUND = 'not-found'
    """The credential did not exist; deletion is idempotent."""

    FAILED = 'failed'
    """The credential exists (or may exist) but could not be deleted."""

    UNAVAILABLE = 'keyring-unavailable'
    """The credential store could not be opened or unlocked."""


class PasswordDeleteError(KeyringError):
    """
    Raised when the password can't be deleted.

    This remains the base type of every deletion failure, for backwards
    compatibility. Callers that need to distinguish "there was nothing to
    delete" from "deletion failed" should test the type (:class:`PasswordNotFound`,
    :class:`PasswordStoreUnavailable`) or use :func:`classify_delete_error`;
    the message is intended for humans and must not be parsed.

    ``kind`` is the machine-readable classification and is readable straight
    off the exception instance.
    """

    kind = DeleteOutcome.FAILED

    _default_message = (
        "Failed to delete password for service {service!r} and username {username!r}"
    )

    def __init__(self, message=None, *, service=None, username=None):
        if message is None:
            message = self._default_message.format(service=service, username=username)
        super().__init__(message)


class PasswordNotFound(PasswordDeleteError):
    """
    Raised when the password to delete does not exist.

    Deleting an absent credential is a no-op in every backend, so callers
    should treat this as success (or at most an informational event) and must
    not retry it indefinitely.

    This subclasses :class:`PasswordDeleteError`, so existing
    ``except PasswordDeleteError`` handlers keep working unchanged. It is the
    *only* type classified as :attr:`DeleteOutcome.NOT_FOUND`; see
    :func:`classify_delete_error` for the compatibility policy applied to
    third-party backends.
    """

    kind = DeleteOutcome.NOT_FOUND

    _default_message = (
        "No password found for service {service!r} and username {username!r}"
    )


class InitError(KeyringError):
    """Raised when the keyring could not be initialised"""


class KeyringLocked(KeyringError):
    """Raised when the keyring failed unlocking"""


class NoKeyringError(KeyringError, RuntimeError):
    """Raised when there is no keyring backend"""


class PasswordStoreUnavailable(PasswordDeleteError, KeyringLocked):
    """
    Raised when a deletion cannot even be attempted because the credential
    store is locked, cannot be opened, or is otherwise unavailable.

    This is the highest-alert deletion failure. It deliberately subclasses
    both :class:`PasswordDeleteError` and :class:`KeyringLocked`, so existing
    handlers for either type keep working. The important part is that it is
    *not* confused with "the password was not there", which must never be
    reported as a store failure (nor the reverse).
    """

    kind = DeleteOutcome.UNAVAILABLE

    _default_message = (
        "The keyring is unavailable; cannot delete password for service "
        "{service!r} and username {username!r}"
    )


def classify_delete_error(exc: BaseException) -> DeleteOutcome:
    """
    Classify an exception raised by ``delete_password``.

    This is the canonical discriminator for deletion failures, and the one
    callers should branch on. It exists in addition to the exception
    hierarchy because "the store is unavailable" is also signalled by
    :class:`KeyringLocked`/:class:`InitError`/:class:`NoKeyringError`, which
    are not :class:`PasswordDeleteError` subclasses.

    Compatibility policy for third-party backends:

    * :class:`PasswordNotFound` is the *only* signal classified as
      :attr:`DeleteOutcome.NOT_FOUND`. A backend that predates this type and
      raises a plain :class:`PasswordDeleteError` for a missing credential is
      deliberately classified as :attr:`DeleteOutcome.FAILED`: guessing from
      the message could silently turn a real failure into a skipped deletion,
      which is the unsafe direction for a rotation pipeline. Such backends
      must be updated to raise :class:`PasswordNotFound` (the shared test
      harness fails them until they do).
    * Any other :class:`KeyringError` subclass is classified as
      :attr:`DeleteOutcome.FAILED`, again conservatively.
    * Exceptions that are not :class:`KeyringError` are programming errors
      (e.g. ``TypeError``) rather than deletion semantics, so they are not
      classified: ``TypeError`` is raised.

    >>> classify_delete_error(PasswordNotFound(service='svc', username='u'))
    <DeleteOutcome.NOT_FOUND: 'not-found'>
    >>> classify_delete_error(PasswordDeleteError('boom'))
    <DeleteOutcome.FAILED: 'failed'>
    >>> classify_delete_error(KeyringLocked('locked'))
    <DeleteOutcome.UNAVAILABLE: 'keyring-unavailable'>
    """
    if isinstance(exc, PasswordNotFound):
        return DeleteOutcome.NOT_FOUND
    if isinstance(
        exc, (PasswordStoreUnavailable, KeyringLocked, InitError, NoKeyringError)
    ):
        return DeleteOutcome.UNAVAILABLE
    if isinstance(exc, KeyringError):
        return DeleteOutcome.FAILED
    raise TypeError(
        "classify_delete_error expects a keyring error, "
        f"not {type(exc).__name__}: {exc}"
    )


class ExceptionRaisedContext:
    """
    An exception-trapping context that indicates whether an exception was
    raised.
    """

    def __init__(self, ExpectedException=Exception):
        warnings.warn(
            "ExceptionRaisedContext is deprecated; use `jaraco.context.ExceptionTrap`",
            DeprecationWarning,
            stacklevel=2,
        )
        self.ExpectedException = ExpectedException
        self.exc_info = None

    def __enter__(self):
        self.exc_info = object.__new__(ExceptionInfo)
        return self.exc_info

    def __exit__(self, *exc_info):
        self.exc_info.__init__(*exc_info)
        return self.exc_info.type and issubclass(
            self.exc_info.type, self.ExpectedException
        )


class ExceptionInfo:
    def __init__(self, *info):
        if not info:
            info = sys.exc_info()
        self.type, self.value, _ = info

    def __bool__(self):
        """
        Return True if an exception occurred
        """
        return bool(self.type)

    __nonzero__ = __bool__
