import json
import pytest
from common.models import NormalizedEvent
from correlation.pipeline import analyze
from agents.deepseek import build_packet, review_trace, evidence_digest, load_review


def sample():
    event = NormalizedEvent(event_id='evt_test', task_id='task_test', timestamp='2026-09-10T00:00:00Z',
        source_type='host_log', source='windows', host_id='officepc01', action='login_success',
        user='SECRET_USER', raw_event={'password': 'SECRET_PASSWORD'}, src_ip='192.168.70.20')
    return analyze('task_test', [event])


def test_packet_does_not_send_raw_details():
    events, alerts, _, _ = sample()
    encoded = json.dumps(build_packet(events, alerts))
    for secret in ['SECRET_USER', 'SECRET_PASSWORD', '192.168.70.20', 'officepc01']:
        assert secret not in encoded
    assert 'evt_test' not in encoded
    assert 'evt_0000' in encoded


def test_two_roles_keep_original_results():
    events, alerts, _, trace = sample()
    calls = []
    def ask(role, packet):
        calls.append(role)
        return {'findings': [{'text': 'Observed login; compromise not established.', 'event_ids': ['evt_0000']}]}
    result = review_trace(events, alerts, trace, ask, 'test-model')
    assert calls == ['analyst', 'reviewer']
    assert result.attribution['llm_used'] is True
    assert result.attack_chain == trace.attack_chain
    assert trace.attribution['llm_used'] is False
    assert result.attribution['llm_review']['findings'][0]['event_ids'] == ['evt_test']


def test_unknown_evidence_rejected():
    events, alerts, _, trace = sample()
    with pytest.raises(ValueError):
        review_trace(events, alerts, trace, lambda *a: {'findings': [{'text': 'bad', 'event_ids': ['evt_fake']}]}, 'test')


def test_stale_or_corrupt_cache_ignored(tmp_path):
    events, alerts, _, trace = sample()
    path = tmp_path / 'review.json'
    path.write_text(json.dumps({'digest': 'stale', 'trace': trace.model_dump(mode='json')}))
    assert load_review(path, events, trace) == trace
    path.write_text('invalid')
    assert load_review(path, events, trace) == trace


def test_digest_stable_and_sensitive():
    events, _, _, _ = sample()
    before = evidence_digest(events)
    assert before == evidence_digest(list(reversed(events)))
    events[0].action = 'login_failure'
    assert before != evidence_digest(events)


def test_valid_cache_preserves_current_baseline(tmp_path):
    events, alerts, _, trace = sample()
    result = review_trace(events, alerts, trace, lambda *a: {'findings': []}, 'test')
    path = tmp_path / 'review.json'
    path.write_text(json.dumps({'digest': evidence_digest(events), 'trace': result.model_dump(mode='json')}))
    loaded = load_review(path, events, trace)
    assert loaded.attribution['llm_used'] is True
    assert loaded.generated_at == trace.generated_at
    result.suspected_c2_entity_ids = ['fabricated']
    path.write_text(json.dumps({'digest': evidence_digest(events), 'trace': result.model_dump(mode='json')}))
    assert load_review(path, events, trace) == trace


def test_sensitive_event_id_is_only_local():
    events, alerts, _, trace = sample()
    events[0].event_id = 'evt_SECRET_USER_192.168.70.20'
    packet = json.dumps(build_packet(events, alerts))
    assert 'SECRET_USER' not in packet
    assert '192.168.70.20' not in packet


def test_api_reads_review_without_model_call(tmp_path, monkeypatch):
    import backend.main as backend
    from fastapi.testclient import TestClient
    from agents.deepseek import DeepSeekClient
    events, alerts, _, baseline = sample()
    reviewed = review_trace(events, alerts, baseline, lambda *a: {'findings': []}, 'test')
    path = tmp_path / 'review.json'
    path.write_text(json.dumps({'digest': evidence_digest(events), 'trace': reviewed.model_dump(mode='json')}))
    monkeypatch.delenv('ATS_EVENTS_FILE', raising=False)
    monkeypatch.setenv('ATS_LLM_REVIEW_FILE', str(path))
    for name in ('_alert_store', '_graph_store', '_trace_store', '_task_store'):
        monkeypatch.setattr(backend, name, {})
    monkeypatch.setattr(backend, '_event_store', [])
    def forbidden(*args, **kwargs):
        pytest.fail('GET must not call model')
    monkeypatch.setattr(DeepSeekClient, '__call__', forbidden)
    with TestClient(backend.app) as client:
        assert client.post('/api/events', json=[e.model_dump(mode='json') for e in events]).status_code == 200
        for _ in range(2):
            response = client.get('/api/trace/task_test')
            assert response.json()['data']['attribution']['llm_used'] is True
        path.write_text('broken')
        assert client.get('/api/trace/task_test').json()['data']['attribution']['llm_used'] is False
