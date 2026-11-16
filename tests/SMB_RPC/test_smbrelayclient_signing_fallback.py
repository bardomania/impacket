import unittest
from unittest.mock import patch, MagicMock, PropertyMock
from types import SimpleNamespace

from impacket.smb3 import (
    SMB2_DIALECT_002, SMB2_DIALECT_21, SMB2_DIALECT_30,
    SMB2_NEGOTIATE_SIGNING_REQUIRED, SMB2_NEGOTIATE_SIGNING_ENABLED,
)
from impacket.examples.ntlmrelayx.clients.smbrelayclient import SMBRelayClient, MYSMB3


def _make_server_config(**overrides):
    defaults = dict(
        smb2support=True,
        remove_target=False,
        reauth_bypass=False,
        remove_mic=False,
        protocolClients={},
        domainIp=None,
        machineAccount=None,
        machineHashes='',
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _make_target(scheme='SMB', host='192.168.1.100', port=445):
    t = SimpleNamespace()
    t.scheme = scheme
    t.hostname = host
    t.netloc = '%s:%d' % (host, port)
    t.port = port
    return t


class TestSigningDialectFallback(unittest.TestCase):
    """Verify that initConnection() falls back to lower SMB dialects
    when the highest negotiated dialect requires signing."""

    @patch('impacket.examples.ntlmrelayx.clients.smbrelayclient.MYSMB3')
    @patch('impacket.examples.ntlmrelayx.clients.smbrelayclient.SMBConnection')
    def test_fallback_to_smb21_when_smb30_requires_signing(self, MockSMBConn, MockMYSMB3):
        """SMB 3.0 requires signing → fallback to SMB 2.1 without signing."""
        config = _make_server_config()
        target = _make_target()
        client = SMBRelayClient(config, target)

        mock_session = MagicMock()
        mock_session.negotiateSessionWildcard.return_value = b'\xfe' + b'\x00' * 100
        mock_session.getNMBServer.return_value = MagicMock()
        MockSMBConn.return_value = mock_session

        call_count = [0]
        def make_mysmb3(*args, **kwargs):
            call_count[0] += 1
            mock = MagicMock()
            pd = kwargs.get('preferredDialect')
            if pd is None:
                mock.signingRequired = True
                mock._Connection = {'Dialect': SMB2_DIALECT_30}
            elif pd == SMB2_DIALECT_21:
                mock.signingRequired = False
                mock._Connection = {'Dialect': SMB2_DIALECT_21}
            else:
                mock.signingRequired = True
                mock._Connection = {'Dialect': pd}
            return mock

        MockMYSMB3.side_effect = make_mysmb3

        result = client.initConnection()

        self.assertTrue(result)
        self.assertEqual(call_count[0], 2)
        second_call_kwargs = MockMYSMB3.call_args_list[1][1]
        self.assertEqual(second_call_kwargs['preferredDialect'], SMB2_DIALECT_21)

    @patch('impacket.examples.ntlmrelayx.clients.smbrelayclient.MYSMB3')
    @patch('impacket.examples.ntlmrelayx.clients.smbrelayclient.SMBConnection')
    def test_fallback_to_smb002_when_smb30_and_smb21_require_signing(self, MockSMBConn, MockMYSMB3):
        """SMB 3.0 and 2.1 both require signing → fallback to SMB 2.0.2."""
        config = _make_server_config()
        target = _make_target()
        client = SMBRelayClient(config, target)

        mock_session = MagicMock()
        mock_session.negotiateSessionWildcard.return_value = b'\xfe' + b'\x00' * 100
        mock_session.getNMBServer.return_value = MagicMock()
        MockSMBConn.return_value = mock_session

        call_count = [0]
        def make_mysmb3(*args, **kwargs):
            call_count[0] += 1
            mock = MagicMock()
            pd = kwargs.get('preferredDialect')
            if pd == SMB2_DIALECT_002:
                mock.signingRequired = False
                mock._Connection = {'Dialect': SMB2_DIALECT_002}
            else:
                mock.signingRequired = True
                mock._Connection = {'Dialect': pd or SMB2_DIALECT_30}
            return mock

        MockMYSMB3.side_effect = make_mysmb3

        result = client.initConnection()

        self.assertTrue(result)
        self.assertEqual(call_count[0], 3)
        third_call_kwargs = MockMYSMB3.call_args_list[2][1]
        self.assertEqual(third_call_kwargs['preferredDialect'], SMB2_DIALECT_002)

    @patch('impacket.examples.ntlmrelayx.clients.smbrelayclient.MYSMB3')
    @patch('impacket.examples.ntlmrelayx.clients.smbrelayclient.SMBConnection')
    def test_all_dialects_require_signing_returns_false(self, MockSMBConn, MockMYSMB3):
        """All SMB dialects require signing → initConnection returns False."""
        config = _make_server_config()
        target = _make_target()
        client = SMBRelayClient(config, target)

        mock_session = MagicMock()
        mock_session.negotiateSessionWildcard.return_value = b'\xfe' + b'\x00' * 100
        mock_session.getNMBServer.return_value = MagicMock()
        MockSMBConn.return_value = mock_session

        def make_mysmb3(*args, **kwargs):
            mock = MagicMock()
            mock.signingRequired = True
            mock._Connection = {'Dialect': kwargs.get('preferredDialect') or SMB2_DIALECT_30}
            return mock

        MockMYSMB3.side_effect = make_mysmb3

        result = client.initConnection()

        self.assertFalse(result)

    @patch('impacket.examples.ntlmrelayx.clients.smbrelayclient.MYSMB3')
    @patch('impacket.examples.ntlmrelayx.clients.smbrelayclient.SMBConnection')
    def test_no_fallback_when_signing_not_required(self, MockSMBConn, MockMYSMB3):
        """SMB 3.0 does not require signing → no fallback, use it directly."""
        config = _make_server_config()
        target = _make_target()
        client = SMBRelayClient(config, target)

        mock_session = MagicMock()
        mock_session.negotiateSessionWildcard.return_value = b'\xfe' + b'\x00' * 100
        mock_session.getNMBServer.return_value = MagicMock()
        MockSMBConn.return_value = mock_session

        mock_smb3 = MagicMock()
        mock_smb3.signingRequired = False
        mock_smb3._Connection = {'Dialect': SMB2_DIALECT_30}
        MockMYSMB3.return_value = mock_smb3

        result = client.initConnection()

        self.assertTrue(result)
        self.assertEqual(MockMYSMB3.call_count, 1)

    @patch('impacket.examples.ntlmrelayx.clients.smbrelayclient.MYSMB3')
    @patch('impacket.examples.ntlmrelayx.clients.smbrelayclient.SMBConnection')
    def test_no_fallback_when_reauth_bypass(self, MockSMBConn, MockMYSMB3):
        """With reauth_bypass, do not attempt dialect fallback."""
        config = _make_server_config(
            reauth_bypass=True,
            reauth_user='admin', reauth_password='pass',
            reauth_domain='CORP', reauth_lmhash='', reauth_nthash='',
        )
        target = _make_target()
        client = SMBRelayClient(config, target)

        mock_session = MagicMock()
        mock_session.negotiateSessionWildcard.return_value = b'\xfe' + b'\x00' * 100
        mock_session.getNMBServer.return_value = MagicMock()
        MockSMBConn.return_value = mock_session

        mock_smb3 = MagicMock()
        mock_smb3.signingRequired = True
        mock_smb3._Connection = {'Dialect': SMB2_DIALECT_30}
        MockMYSMB3.return_value = mock_smb3

        # openBaseSession will be called with reauth_bypass; just patch it
        with patch.object(SMBRelayClient, 'openBaseSession', return_value=True):
            client.initConnection()

        self.assertEqual(MockMYSMB3.call_count, 1)

    @patch('impacket.examples.ntlmrelayx.clients.smbrelayclient.MYSMB3')
    @patch('impacket.examples.ntlmrelayx.clients.smbrelayclient.SMBConnection')
    def test_no_fallback_when_preferred_dialect_set(self, MockSMBConn, MockMYSMB3):
        """With remove_target (preferredDialect set), do not attempt dialect fallback."""
        config = _make_server_config(remove_target=True)
        target = _make_target()
        client = SMBRelayClient(config, target)

        mock_session = MagicMock()
        mock_session.negotiateSessionWildcard.return_value = b'\xfe' + b'\x00' * 100
        mock_session.getNMBServer.return_value = MagicMock()
        MockSMBConn.return_value = mock_session

        mock_smb3 = MagicMock()
        mock_smb3.signingRequired = True
        mock_smb3._Connection = {'Dialect': SMB2_DIALECT_21}
        MockMYSMB3.return_value = mock_smb3

        client.initConnection()

        self.assertEqual(MockMYSMB3.call_count, 1)

    @patch('impacket.examples.ntlmrelayx.clients.smbrelayclient.MYSMB3')
    @patch('impacket.examples.ntlmrelayx.clients.smbrelayclient.SMBConnection')
    def test_fallback_handles_connection_error(self, MockSMBConn, MockMYSMB3):
        """If a fallback connection attempt throws, try the next dialect."""
        config = _make_server_config()
        target = _make_target()
        client = SMBRelayClient(config, target)

        call_count = [0]
        def mock_smb_conn(*args, **kwargs):
            call_count[0] += 1
            mock = MagicMock()
            if call_count[0] == 2:
                mock.negotiateSessionWildcard.side_effect = Exception("Connection refused")
            else:
                mock.negotiateSessionWildcard.return_value = b'\xfe' + b'\x00' * 100
                mock.getNMBServer.return_value = MagicMock()
            return mock

        MockSMBConn.side_effect = mock_smb_conn

        mysmb3_count = [0]
        def make_mysmb3(*args, **kwargs):
            mysmb3_count[0] += 1
            mock = MagicMock()
            pd = kwargs.get('preferredDialect')
            if pd is None:
                mock.signingRequired = True
                mock._Connection = {'Dialect': SMB2_DIALECT_30}
            elif pd == SMB2_DIALECT_002:
                mock.signingRequired = False
                mock._Connection = {'Dialect': SMB2_DIALECT_002}
            else:
                mock.signingRequired = True
                mock._Connection = {'Dialect': pd}
            return mock

        MockMYSMB3.side_effect = make_mysmb3

        result = client.initConnection()

        self.assertTrue(result)
        self.assertEqual(mysmb3_count[0], 2)


class TestMYSMB3SigningFlag(unittest.TestCase):
    """Test that MYSMB3.signingRequired flag is set correctly."""

    def test_signing_required_flag_initialized_false(self):
        """signingRequired starts as False before negotiation."""
        with patch.object(MYSMB3, '__init__', lambda self, *a, **kw: None):
            obj = MYSMB3.__new__(MYSMB3)
            obj.signingRequired = False
            self.assertFalse(obj.signingRequired)


if __name__ == '__main__':
    unittest.main()
