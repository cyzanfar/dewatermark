import hashlib
import sys
from contextlib import AbstractContextManager
from types import SimpleNamespace

import schemes


def test_public_key_partition_ids_are_random_labels_not_key_digests():
    ids = {scheme["manifest"]["key_fingerprint"] for scheme in schemes.SCHEMES.values()}
    assert len(ids) == len(schemes.SCHEMES)
    assert all(len(value) == 64 and set(value) <= set("0123456789abcdef") for value in ids)
    derived = {
        hashlib.sha256(str(secret).encode()).hexdigest()
        for secret in (schemes.kgw.HASH_KEY, schemes.UNIGRAM_KEY, schemes.EXP_KEY)
    }
    assert ids.isdisjoint(derived)


def test_sample_seed_is_deterministic_portable_63_bit_identity():
    first = schemes.sample_seed(7, "EXP", "positive-test", 128, 3)
    assert first == schemes.sample_seed(7, "EXP", "positive-test", 128, 3)
    assert 0 <= first < 2**63

    seeds = {schemes.sample_seed(7, "sample", index) for index in range(10_000)}
    assert len(seeds) == 10_000
    assert max(seeds) >= 2**31


class _NoGrad(AbstractContextManager):
    def __exit__(self, *_args):
        return None


class _Inputs:
    shape = (1, 2)


class _Tokenizer:
    eos_token_id = 99

    def apply_chat_template(self, messages, **kwargs):
        assert messages == [{"role": "user", "content": "prompt"}]
        assert kwargs == {"add_generation_prompt": True, "return_tensors": "pt"}
        return _Inputs()

    def decode(self, token_ids, *, skip_special_tokens):
        assert token_ids == [3, 4]
        assert skip_special_tokens is True
        return "decoded"


class _Model:
    def __init__(self):
        self.calls = []

    def generate(self, inputs, **kwargs):
        assert isinstance(inputs, _Inputs)
        self.calls.append(kwargs)
        return [[1, 2, 3, 4]]


def test_exp_matched_control_changes_only_watermark_processor(monkeypatch):
    fake_torch = SimpleNamespace(no_grad=lambda: _NoGrad())
    fake_transformers = SimpleNamespace(LogitsProcessorList=lambda items: list(items))
    monkeypatch.setitem(sys.modules, "torch", fake_torch)
    monkeypatch.setitem(sys.modules, "transformers", fake_transformers)
    seeds = []
    monkeypatch.setattr(schemes, "seed_everything", seeds.append)

    model = _Model()
    tokenizer = _Tokenizer()
    assert schemes.exp_generate("prompt", tokenizer, model, 20, 123, True) == "decoded"
    assert schemes.exp_generate("prompt", tokenizer, model, 20, 123, False) == "decoded"

    watermarked_args, plain_args = (dict(call) for call in model.calls)
    watermarked_processor = watermarked_args.pop("logits_processor")
    plain_processor = plain_args.pop("logits_processor")
    assert len(watermarked_processor) == 1
    assert isinstance(watermarked_processor[0], schemes._EXPProcessor)
    assert plain_processor is None
    assert watermarked_args == plain_args
    assert seeds == [123, 123]

    matched = schemes.SCHEMES["EXP"]["manifest"]["matched_control"]
    assert matched["generation_arguments"] == schemes.EXP_DECODING
    assert matched["only_difference"] == "logits_processor"
