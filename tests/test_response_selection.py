"""Real selection-owner methods with synthetic configuration and backends."""

import threading
import types
import unittest
from unittest import mock

import config
import companion_manager as manager_module
from companion_manager import CompanionManager
from ai.response_selection import (
    ProviderIdentity, ResponseSelection, SelectionChangedError,
    require_selected_model, require_unchanged_selection,
)


class SelectionHost:
    _response_identity = staticmethod(CompanionManager._response_identity)
    _response_selection_locked = CompanionManager._response_selection_locked
    _response_selection = CompanionManager._response_selection
    _acquire_response_dispatch = CompanionManager._acquire_response_dispatch
    _get_llm = CompanionManager._get_llm
    set_active_provider = CompanionManager.set_active_provider
    set_model = CompanionManager.set_model
    set_ollama_model = CompanionManager.set_ollama_model

    def __init__(self):
        self._selection_lock = threading.RLock()
        self._selection_revision = 0
        self._selection_identity = self._llm_identity = None
        self._current_model = "model-a"
        self._llm = None
        self._create_llm = mock.Mock(side_effect=lambda _: object())
        self.sig_error = mock.Mock()
        self.refresh_ollama_models = mock.Mock()


class ResponseSelectionTests(unittest.TestCase):
    def setUp(self):
        self.cfg = config.Config(active_llm="openai", openai_api_key="dummy",
                                 openrouter_api_key="dummy-router", openai_default_model="model-a")
        self.cfg.available_llm_providers = lambda: ["openai", "openrouter", "ollama", "lmstudio", "claude"]
        self.host = SelectionHost()
        for patcher in (
            mock.patch.object(manager_module, "cfg", self.cfg),
            mock.patch.object(config, "_save_preferences"),
            mock.patch("ai.model_registry.cache_is_stale", return_value=False),
            mock.patch("ai.model_registry.cached_models", return_value=[
                {"id": "model-a", "vision": True}, {"id": "model-b", "vision": False},
            ]),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_pure_token_checks_every_identity_component_and_revision(self):
        original = ResponseSelection(ProviderIdentity("openai", "http://router/v1"), "model-a", 2)
        require_unchanged_selection(original, original)
        for changed in (
            ResponseSelection(ProviderIdentity("openrouter", "http://router/v1"), "model-a", 2),
            ResponseSelection(ProviderIdentity("openai", "http://other/v1"), "model-a", 2),
            ResponseSelection(original.identity, "model-b", 2),
            ResponseSelection(original.identity, "model-a", 3),
        ):
            with self.subTest(changed=changed), self.assertRaises(SelectionChangedError):
                require_unchanged_selection(original, changed)
        with self.assertRaises(SelectionChangedError):
            require_selected_model(ResponseSelection(original.identity, None, 2))

    def test_failed_saves_retain_config_model_cache_and_revision(self):
        before = self.host._acquire_response_dispatch()
        with mock.patch.object(config, "_save_preferences", side_effect=OSError("synthetic failure")):
            self.assertFalse(self.host.set_active_provider("openrouter"))
            self.assertFalse(self.host.set_model("model-b"))
            self.assertFalse(self.host.set_ollama_model("vision", "other-local"))
        after = self.host._acquire_response_dispatch()
        self.assertEqual(after.selection, before.selection)
        self.assertIs(after.backend, before.backend)
        self.assertEqual(self.cfg.active_llm, "openai")
        self.assertEqual(self.cfg.openai_default_model, "model-a")
        self.assertNotEqual(self.cfg.ollama_vision_model, "other-local")

    def test_successful_switch_publishes_no_model_then_selected_model(self):
        before = self.host._acquire_response_dispatch()
        self.assertTrue(self.host.set_active_provider("openrouter"))
        current = self.host._response_selection()
        self.assertEqual(current.identity.provider_id, "openrouter")
        self.assertIsNone(current.model_id)
        with self.assertRaises(SelectionChangedError):
            self.host._acquire_response_dispatch()
        self.assertTrue(self.host.set_model("model-b"))
        after = self.host._acquire_response_dispatch()
        self.assertEqual(after.selection.model_id, "model-b")
        self.assertGreater(after.selection.revision, before.selection.revision)
        self.assertIsNot(after.backend, before.backend)

    def test_publication_excludes_reader_between_save_and_cache_update(self):
        before = self.host._acquire_response_dispatch()
        saving, release, read_done = threading.Event(), threading.Event(), threading.Event()
        observed = []
        def save(**_updates):
            saving.set()
            self.assertTrue(release.wait(2))
        def read():
            observed.append(self.host._response_selection())
            read_done.set()
        with mock.patch.object(config, "_save_preferences", side_effect=save):
            writer = threading.Thread(target=self.host.set_active_provider, args=("openrouter",))
            writer.start()
            self.assertTrue(saving.wait(2))
            reader = threading.Thread(target=read)
            reader.start()
            try:
                self.assertFalse(read_done.wait(0.05))
            finally:
                release.set()
                writer.join(2)
                reader.join(2)
        self.assertFalse(writer.is_alive() or reader.is_alive())
        self.assertEqual(observed[0].identity.provider_id, "openrouter")
        self.assertIsNone(observed[0].model_id)
        self.assertIsNone(self.host._llm)
        self.assertNotEqual(observed[0], before.selection)

    def test_cold_construction_switch_rejects_candidate_without_request(self):
        accepted = self.host._response_selection()
        candidate = mock.Mock()
        def create(_provider):
            # A second thread can publish while construction is in progress.
            done = threading.Event()
            def switch():
                self.host.set_active_provider("openrouter")
                done.set()
            thread = threading.Thread(target=switch)
            thread.start()
            self.assertTrue(done.wait(2), "construction held the selection lock")
            thread.join(2)
            return candidate
        self.host._create_llm.side_effect = create
        with self.assertRaises(SelectionChangedError):
            self.host._acquire_response_dispatch(accepted)
        self.assertIsNone(self.host._llm)
        candidate.stream_response.assert_not_called()

    def test_endpoint_change_invalidates_cached_client_and_accepted_request(self):
        before = self.host._acquire_response_dispatch()
        self.cfg.openai_base_url = "http://127.0.0.1:9876/custom/v1"
        with self.assertRaises(SelectionChangedError):
            self.host._acquire_response_dispatch(before.selection)
        after = self.host._acquire_response_dispatch()
        self.assertEqual(after.selection.identity.endpoint, self.cfg.openai_base_url)
        self.assertIsNot(after.backend, before.backend)

    def test_change_back_stays_stale_and_acquired_dispatch_stays_immutable(self):
        accepted = self.host._acquire_response_dispatch()
        self.host.set_active_provider("openrouter")
        self.host.set_active_provider("openai")
        self.host.set_model("model-a")
        with self.assertRaises(SelectionChangedError):
            self.host._acquire_response_dispatch(accepted.selection)
        self.assertEqual(accepted.selection.identity.provider_id, "openai")
        self.assertEqual(accepted.selection.model_id, "model-a")

    def test_local_slot_publication_invalidates_active_cache(self):
        self.host.set_active_provider("ollama")
        self.host.set_model("local-model")
        before = self.host._acquire_response_dispatch()
        self.assertTrue(self.host.set_ollama_model("text", "updated-local"))
        self.assertEqual(self.cfg.ollama_text_model, "updated-local")
        with self.assertRaises(SelectionChangedError):
            self.host._acquire_response_dispatch(before.selection)


class SelectionUITests(unittest.TestCase):
    def test_failed_selection_restores_without_emitting_or_announcing_success(self):
        from PyQt6.QtCore import QObject, pyqtSignal
        import main
        class Panel(QObject):
            changed = pyqtSignal(str)
            model_selection_notice = ""
            def refresh_for_provider(self, provider):
                self.changed.emit(provider)
        panel = Panel()
        changed = mock.Mock()
        panel.changed.connect(changed)
        manager = types.SimpleNamespace(set_model=mock.Mock(return_value=False),
                                        set_active_provider=mock.Mock(return_value=False))
        tray = mock.Mock()
        with mock.patch.object(main.cfg, "llm_provider", return_value="openai"):
            self.assertFalse(main._select_response_model(manager, panel, "model-b"))
            self.assertFalse(main._switch_response_provider(manager, panel, tray, "openrouter"))
        changed.assert_not_called()
        tray.show_notification.assert_not_called()
        manager.set_model.assert_called_once()
