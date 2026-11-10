"""Isolated tests; no production tokens or Supervisor required."""
import importlib
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

PROJECT = str(Path(__file__).resolve().parents[1] / "rootfs" / "app" / "agent")
sys.path.insert(0, PROJECT)

agent = types.ModuleType('lna0_agent')
agent.__path__ = [str(Path(PROJECT) / 'lna0_agent')]
http = types.ModuleType('lna0_agent.http_client')
http.signed_request = lambda **kwargs: {}
http.post_json = lambda *args, **kwargs: {}
state = types.ModuleType('lna0_agent.state')
state.load_state = lambda path: {}
state.save_state = lambda path, data: None
sys.modules['lna0_agent'] = agent
sys.modules['lna0_agent.http_client'] = http
sys.modules['lna0_agent.state'] = state
remote = importlib.import_module('lna0_agent.remote_provision')

HOST = 'a' * 32 + '.remote.55projects.com'

class FakeSupervisor:
    token = 'dummy-supervisor-token'
    base_url = 'http://supervisor'
    def __init__(self, installed=True, stdin=True, state='stopped', options=None):
        self.installed = installed
        self.stdin = stdin
        self.state = state
        self.options = options if options is not None else {'public_hostname': ''}
        self.calls = []
    def get(self, path):
        self.calls.append(('GET', path))
        if path == '/addons':
            return {'data': {'addons': ([{'slug': 'ab12_lna0_remote_access'}] if self.installed else [])}}
        return {'data': {'stdin': self.stdin, 'state': self.state, 'options': self.options}}
    def post(self, path, data):
        self.calls.append(('POST', path, data))
        if path.endswith('/options'):
            self.options['public_hostname'] = data['options']['public_hostname']
        if path.endswith('/start'):
            self.state = 'started'
        return {'result': 'ok'}

class Config:
    control_plane_url = 'https://lna01.leinahome.com'
    control_plane_ca_pem = None
    allow_insecure_dev_http = False
    node_id = 'LNA0-N-000001'
    state_path = Path('/fake/state')

class ProvisionTests(unittest.TestCase):
    def test_send_stdin_via_supervisor_keeps_node_secret_private(self):
        sent=[]
        class Response:
            status=200
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self, n): return b'{"result":"ok"}'
        def fake_open(req, timeout):
            sent.append(req)
            return Response()
        sup = FakeSupervisor()
        with patch.object(remote.request,'urlopen',fake_open):
            remote._send_ephemeral_stdin(sup, 'ab12_lna0_remote_access', {'hostname': HOST})
        self.assertEqual(len(sent),1)
        self.assertNotIn('node-secret', sent[0].data.decode())
        command = json.loads(sent[0].data)
        self.assertEqual(command['type'],remote._STDIN_COMMAND)
        self.assertTrue(sent[0].data.endswith(b'\n'))

    def test_selects_only_unique_remote_app(self):
        sup=FakeSupervisor()
        self.assertEqual(remote._discover_addon(sup),'ab12_lna0_remote_access')
        self.assertIsNone(remote._discover_addon(FakeSupervisor(installed=False)))

    def test_public_hostname_config_and_start(self):
        sup=FakeSupervisor()
        self.assertTrue(remote._ensure_addon_ready(sup,'ab12_lna0_remote_access',HOST))
        self.assertEqual(sup.options['public_hostname'],HOST)
        self.assertIn(('POST','/addons/ab12_lna0_remote_access/start',{}),sup.calls)

    def test_does_not_send_to_older_app_or_different_house(self):
        self.assertFalse(remote._ensure_addon_ready(FakeSupervisor(stdin=False),'id_lna0_remote_access',HOST))
        with self.assertRaises(RuntimeError):
            remote._ensure_addon_ready(FakeSupervisor(options={'public_hostname':'b'*32+'.remote.55projects.com'}), 'id_lna0_remote_access', HOST)

    def test_disabling_house_stops_only_matching_remote_app(self):
        sup = FakeSupervisor(state='started', options={'public_hostname': HOST})
        with patch.object(remote, 'signed_request', return_value={
            'status': 'disabled', 'hostname': HOST, 'node_id': Config.node_id
        }):
            self.assertEqual(remote.provision_remote_access(Config, sup, 'node-secret'),
                             'stopped_on_disable')
        self.assertIn(('POST', '/addons/ab12_lna0_remote_access/stop', {}), sup.calls)
        other = FakeSupervisor(state='started', options={
            'public_hostname': 'b' * 32 + '.remote.55projects.com'
        })
        with patch.object(remote, 'signed_request', return_value={
            'status': 'disabled', 'hostname': HOST, 'node_id': Config.node_id
        }):
            self.assertEqual(remote.provision_remote_access(Config, other, 'node-secret'),
                             'not_requested')
        self.assertFalse(any('/stop' in call[1] for call in other.calls))

    def test_full_grant_redemption_and_schedule(self):
        sup=FakeSupervisor()
        saved={}
        calls=[]
        def signed_request(**kw):
            calls.append(kw['url'])
            if kw['method']=='GET':
                return {'hostname':HOST,'status':'requested','node_id':Config.node_id}
            return {'grant':'token'}
        def post_json(*a, **kw):
            self.assertEqual(a[1]['grant'],'token')
            return {'hostname':HOST,'fernet_token':'dummy'}
        with (patch.object(remote,'signed_request',side_effect=signed_request),
              patch.object(remote,'post_json',side_effect=post_json),
              patch.object(remote,'_send_ephemeral_stdin',side_effect=lambda sup,slug,cred: calls.append('delivered')),
              patch.object(remote,'load_state',side_effect=lambda _: saved.copy()),
              patch.object(remote,'save_state',side_effect=lambda _,data: saved.update(data))):
            self.assertEqual(remote.provision_remote_access(Config,sup,'node-secret'),'delivered')
            self.assertEqual(remote.provision_remote_access(Config,sup,'node-secret'),'current')
        self.assertEqual(calls.count('delivered'),1)
        self.assertNotIn('node-secret',str(saved))

if __name__=='__main__':
    unittest.main()
