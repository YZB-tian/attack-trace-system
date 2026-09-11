"""Run two explicit model requests over a minimized local evidence packet."""
import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from common.models import NormalizedEvent
from correlation.pipeline import analyze
from agents.deepseek import DeepSeekClient, review_trace, evidence_digest
from detection.attack_stix import AttackKnowledge


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--events', type=Path, required=True)
    parser.add_argument('--task-id', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--stix', type=Path,
                        help='official enterprise-attack bundle so the baseline keeps ATT&CK mappings')
    args = parser.parse_args()
    config = {}
    env = ROOT / '.env'
    if env.exists():
        for line in env.read_text(encoding='utf-8-sig').splitlines():
            if line.strip() and not line.lstrip().startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                config[key.strip()] = value.strip()
    key = os.environ.get('LLM_API_KEY') or config.get('LLM_API_KEY')
    model = os.environ.get('LLM_MODEL') or config.get('LLM_MODEL', 'deepseek-flash')
    events = [NormalizedEvent.model_validate(e) for e in json.loads(args.events.read_text(encoding='utf-8-sig')) if e['task_id'] == args.task_id]
    knowledge = AttackKnowledge(args.stix) if args.stix else None
    _, alerts, _, baseline = analyze(args.task_id, events, knowledge=knowledge)
    client = DeepSeekClient(key, model)
    result = review_trace(events, alerts, baseline, client, model)
    from jsonschema import Draft202012Validator, FormatChecker
    Draft202012Validator(json.loads((ROOT / 'schemas/trace_result.schema.json').read_text()),
        format_checker=FormatChecker()).validate(result.model_dump(mode='json'))
    payload = {'digest': evidence_digest(events), 'trace': result.model_dump(mode='json'), 'usage': client.usage}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    name = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=args.output.parent, delete=False) as stream:
            name = stream.name
            json.dump(payload, stream, ensure_ascii=False, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, args.output)
    finally:
        if name and os.path.exists(name):
            os.unlink(name)
    print(json.dumps({'task_id': args.task_id, 'model': model, 'calls': len(client.usage),
        'total_tokens': sum(u.get('total_tokens', 0) for u in client.usage), 'output': str(args.output)}))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Model review failed. Original analysis and existing output are preserved.', file=sys.stderr)
        sys.exit(1)
