import sys

import pytest

import keyring.backends.Windows
from keyring import errors
from keyring.backends.Windows import DecodingCredential
from keyring.testing.backend import UNICODE_CHARS, BackendBasicTests


@pytest.mark.skipif(
    not keyring.backends.Windows.WinVaultKeyring.viable, reason="Needs Windows"
)
class TestWinVaultKeyring(BackendBasicTests):
    def tearDown(self):
        # clean up any credentials created
        for cred in self.credentials_created:
            try:
                self.keyring.delete_password(*cred)
            except Exception as e:  # noqa: BLE001
                print(e, file=sys.stderr)

    def init_keyring(self):
        return keyring.backends.Windows.WinVaultKeyring()

    def set_utf8_password(self, service, username, password):
        """
        Write a UTF-8 encoded password using win32ctypes primitives
        """
        from ctypes import c_char, cast, create_string_buffer, sizeof

        from win32ctypes.core import _authentication as auth
        from win32ctypes.core.ctypes._common import LPBYTE

        credential = dict(
            Type=1,
            TargetName=service,
            UserName=username,
            CredentialBlob=password,
            Comment="Stored using python-keyring",
            Persist=3,
        )

        c_cred = auth.CREDENTIAL.fromdict(credential, 0)
        blob_data = create_string_buffer(password.encode("utf-8"))
        c_cred.CredentialBlobSize = sizeof(blob_data) - sizeof(c_char)
        c_cred.CredentialBlob = cast(blob_data, LPBYTE)
        c_cred_pointer = auth.PCREDENTIAL(c_cred)
        auth._CredWrite(c_cred_pointer, 0)

        self.credentials_created.add((service, username))

    def test_long_password_nice_error(self):
        self.keyring.set_password('system', 'user', 'x' * 512 * 2)

    def test_read_utf8_password(self):
        """
        Write a UTF-8 encoded credential and make sure it can be read back correctly.
        """
        service = "keyring-utf8-test"
        username = "keyring"
        password = "utf8-test" + UNICODE_CHARS

        self.set_utf8_password(service, username, password)
        assert self.keyring.get_password(service, username) == password


@pytest.mark.skipif('sys.platform != "win32"')
def test_winvault_always_viable():
    """
    The WinVault backend should always be viable on Windows.
    """
    assert keyring.backends.Windows.WinVaultKeyring.viable


class FakeWinError(Exception):
    """Stand-in for pywintypes.error with the attributes the backend reads."""

    def __init__(self, winerror, funcname, message=''):
        super().__init__(winerror, funcname, message)
        self.winerror = winerror
        self.funcname = funcname


class FakeCredVault:
    """
    Minimal in-memory stand-in for win32cred (no Windows APIs involved).

    This lets the deletion-path contract be tested on every platform.
    """

    CRED_TYPE_GENERIC = 1

    def __init__(self, credentials=None):
        self.credentials = dict(credentials or {})
        self.read_errors = {}
        self.delete_errors = {}

    @staticmethod
    def _cred(username, password):
        return DecodingCredential(
            UserName=username, CredentialBlob=password.encode('utf-16')
        )

    def CredRead(self, Type, TargetName):
        if TargetName in self.read_errors:
            raise self.read_errors[TargetName]
        if TargetName not in self.credentials:
            raise FakeWinError(1168, 'CredRead', 'Element not found')
        return self.credentials[TargetName]

    def CredDelete(self, Type, TargetName):
        if TargetName in self.delete_errors:
            raise self.delete_errors[TargetName]
        if TargetName not in self.credentials:
            raise FakeWinError(1168, 'CredDelete', 'Element not found')
        del self.credentials[TargetName]

    def CredWrite(self, credential, flags):
        self.credentials[credential['TargetName']] = self._cred(
            credential['UserName'], credential['CredentialBlob']
        )


@pytest.fixture
def fake_vault(monkeypatch):
    vault = FakeCredVault()
    monkeypatch.setattr(keyring.backends.Windows, 'win32cred', vault, raising=False)
    monkeypatch.setattr(
        keyring.backends.Windows,
        'pywintypes',
        type('FakePywintypes', (), {'error': FakeWinError}),
        raising=False,
    )
    return vault


class TestWinVaultDeletePath:
    """
    The Windows deletion path must distinguish "not found" from
    "could not delete" without invoking the real Credential Manager.
    """

    def test_delete_missing_raises_not_found(self, fake_vault):
        keyring_ = keyring.backends.Windows.WinVaultKeyring()
        with pytest.raises(errors.PasswordNotFound) as exc_info:
            keyring_.delete_password('svc', 'user')
        assert (
            errors.classify_delete_error(exc_info.value)
            is errors.DeleteOutcome.NOT_FOUND
        )

    def test_delete_missing_is_not_typed_as_failure(self, fake_vault):
        keyring_ = keyring.backends.Windows.WinVaultKeyring()
        with pytest.raises(errors.PasswordNotFound) as exc_info:
            keyring_.delete_password('svc', 'user')
        assert type(exc_info.value) is not errors.PasswordDeleteError
        assert exc_info.value.kind is errors.DeleteOutcome.NOT_FOUND

    def test_delete_missing_leaves_other_users_credential(self, fake_vault):
        fake_vault.credentials['svc'] = fake_vault._cred('someone-else', 'pw')
        keyring_ = keyring.backends.Windows.WinVaultKeyring()
        with pytest.raises(errors.PasswordNotFound):
            keyring_.delete_password('svc', 'user')
        assert 'svc' in fake_vault.credentials

    def test_delete_present(self, fake_vault):
        fake_vault.credentials['svc'] = fake_vault._cred('user', 'pw')
        keyring_ = keyring.backends.Windows.WinVaultKeyring()
        keyring_.delete_password('svc', 'user')
        assert 'svc' not in fake_vault.credentials

    def test_delete_compound_target(self, fake_vault):
        fake_vault.credentials['user@svc'] = fake_vault._cred('user', 'pw')
        keyring_ = keyring.backends.Windows.WinVaultKeyring()
        keyring_.delete_password('svc', 'user')
        assert 'user@svc' not in fake_vault.credentials

    def test_delete_twice_is_idempotent(self, fake_vault):
        fake_vault.credentials['svc'] = fake_vault._cred('user', 'pw')
        keyring_ = keyring.backends.Windows.WinVaultKeyring()
        keyring_.delete_password('svc', 'user')
        with pytest.raises(errors.PasswordNotFound):
            keyring_.delete_password('svc', 'user')

    def test_read_access_denied_is_store_unavailable(self, fake_vault):
        fake_vault.read_errors['svc'] = FakeWinError(5, 'CredRead', 'Access denied')
        fake_vault.read_errors['user@svc'] = FakeWinError(
            5, 'CredRead', 'Access denied'
        )
        keyring_ = keyring.backends.Windows.WinVaultKeyring()
        with pytest.raises(errors.PasswordStoreUnavailable) as exc_info:
            keyring_.delete_password('svc', 'user')
        assert (
            errors.classify_delete_error(exc_info.value)
            is errors.DeleteOutcome.UNAVAILABLE
        )

    def test_delete_failure_is_store_unavailable(self, fake_vault):
        fake_vault.credentials['svc'] = fake_vault._cred('user', 'pw')
        fake_vault.delete_errors['svc'] = FakeWinError(5, 'CredDelete', 'Access denied')
        keyring_ = keyring.backends.Windows.WinVaultKeyring()
        with pytest.raises(errors.PasswordStoreUnavailable):
            keyring_.delete_password('svc', 'user')

    def test_delete_race_treated_as_success(self, fake_vault):
        """
        The credential vanishing between read and delete (winerror 1168 on
        CredDelete) is the intended outcome, not a failure.
        """
        fake_vault.credentials['svc'] = fake_vault._cred('user', 'pw')
        fake_vault.delete_errors['svc'] = FakeWinError(
            1168, 'CredDelete', 'Element not found'
        )
        keyring_ = keyring.backends.Windows.WinVaultKeyring()
        keyring_.delete_password('svc', 'user')
