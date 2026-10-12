"""Bonus: policy Rego (OPA) cho cùng quyết định với agent/policy.py."""
from __future__ import annotations

import shutil

import pytest

from agent.policy import check
from bonus.opa_parity import CASES, opa_decide

pytestmark = pytest.mark.skipif(shutil.which("opa") is None, reason="cần binary opa trong PATH")


@pytest.mark.parametrize("name,context", CASES, ids=[name for name, _ in CASES])
def test_opa_matches_python_policy(name, context):
    py_allow, _ = check(context)
    opa_allow, opa_reason = opa_decide(context)
    assert opa_allow == py_allow, f"{name}: python={py_allow} opa={opa_allow} ({opa_reason})"
    assert opa_reason, "OPA cũng phải luôn trả reason"
