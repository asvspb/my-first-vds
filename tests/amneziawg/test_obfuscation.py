"""Unit-тесты генератора/валидатора обфускации AmneziaWG (SPEC §6, ADR-005)."""

import random

import pytest

from src.amneziawg.config import (
    _JC_MAX,
    _JC_MIN,
    _JMAX_LIMIT,
    gen_obfuscation_params,
    validate_obfuscation,
)


def _valid_obf() -> dict:
    return {
        "Jc": 5, "Jmin": 64, "Jmax": 256, "S1": 88, "S2": 128,
        "H1": 2149340781, "H2": 1934967624, "H3": 1242853139, "H4": 881236702,
    }


class TestGenObfuscationParams:
    def test_seed_determinism(self) -> None:
        assert gen_obfuscation_params(random.Random(42)) == gen_obfuscation_params(
            random.Random(42)
        )

    def test_different_seeds_differ(self) -> None:
        # уникальность на «установку»: разные seed → разные наборы
        assert gen_obfuscation_params(random.Random(1)) != gen_obfuscation_params(
            random.Random(2)
        )

    def test_generated_set_passes_validation(self) -> None:
        obf = gen_obfuscation_params(random.Random(7))
        validate_obfuscation(obf)  # не поднимает

    def test_generated_set_is_exact_15_keys(self) -> None:
        obf = gen_obfuscation_params(random.Random(7))
        assert set(obf) == {"Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"}

    def test_jc_in_range(self) -> None:
        for seed in range(50):
            assert _JC_MIN <= gen_obfuscation_params(random.Random(seed))["Jc"] <= _JC_MAX

    def test_jmin_lt_jmax_lt_limit(self) -> None:
        for seed in range(50):
            obf = gen_obfuscation_params(random.Random(seed))
            assert obf["Jmin"] < obf["Jmax"] < _JMAX_LIMIT


class TestValidateObfuscation:
    def test_valid_set_ok(self) -> None:
        validate_obfuscation(_valid_obf())

    def test_jmin_ge_jmax_rejected(self) -> None:
        obf = _valid_obf()
        obf["Jmin"] = obf["Jmax"]  # 256 >= 256
        with pytest.raises(ValueError, match="Jmin.*меньше Jmax"):
            validate_obfuscation(obf)

    def test_jmax_ge_mtu_minus_128_rejected(self) -> None:
        obf = _valid_obf()
        obf["Jmax"] = _JMAX_LIMIT  # не строго меньше предела
        with pytest.raises(ValueError, match="MTU-128"):
            validate_obfuscation(obf)

    def test_duplicate_h_rejected(self) -> None:
        obf = _valid_obf()
        obf["H3"] = obf["H1"]
        with pytest.raises(ValueError, match="H3"):
            validate_obfuscation(obf)

    @pytest.mark.parametrize("key", ["H1", "H2", "H3", "H4"])
    def test_h_out_of_uint32_rejected(self, key: str) -> None:
        obf = _valid_obf()
        obf[key] = 2**32  # > uint32
        with pytest.raises(ValueError, match=f"{key}.*uint32"):
            validate_obfuscation(obf)

    def test_negative_h_rejected(self) -> None:
        obf = _valid_obf()
        obf["H2"] = -1
        with pytest.raises(ValueError, match="H2.*uint32"):
            validate_obfuscation(obf)

    @pytest.mark.parametrize(
        "param", ["S3", "S4", "H1_MIN", "H1_MAX", "HEADER_PROTECTION_KEY"]
    )
    def test_awg_20_params_rejected_with_adr_reference(self, param: str) -> None:
        obf = _valid_obf()
        obf[param] = 42
        with pytest.raises(ValueError, match="не поддерживается \\(ADR-005: линия 1.5\\)"):
            validate_obfuscation(obf)

    def test_missing_key_rejected(self) -> None:
        obf = _valid_obf()
        del obf["S2"]
        with pytest.raises(ValueError, match="S2"):
            validate_obfuscation(obf)

    def test_unknown_key_rejected(self) -> None:
        obf = _valid_obf()
        obf["Foo"] = 1
        with pytest.raises(ValueError, match="Foo"):
            validate_obfuscation(obf)
