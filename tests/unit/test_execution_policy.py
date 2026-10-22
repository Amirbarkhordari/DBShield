"""Unit tests for ExecutionPolicy and ExecutionBudgetTracker (Phase 6)."""

from dbshield.execution.policy import ExecutionBudgetTracker, ExecutionPolicy


def test_execution_policy_defaults() -> None:
    """Verify default policy configuration values."""
    policy = ExecutionPolicy()
    assert policy.max_total_requests == 50
    assert policy.max_requests_per_parameter == 8
    assert policy.max_payloads_per_parameter == 6
    assert policy.timeout_seconds == 10.0
    assert policy.enable_differential is True
    assert policy.stop_on_first_indicator is False


def test_evaluate_parameter_eligibility_sensitive_exclusion() -> None:
    """Verify sensitive parameters are rejected for payload delivery."""
    policy = ExecutionPolicy()

    # Disallowed patterns
    sensitive_names = [
        "password",
        "user_password",
        "auth_token",
        "csrf_token",
        "session",
        "user.secret",
        "account.pwd",
    ]
    for name in sensitive_names:
        allowed, reason = policy.evaluate_parameter_eligibility(name)
        assert allowed is False
        assert reason is not None
        assert "sensitive security control pattern" in reason

    # Allowed parameters
    safe_names = ["id", "username", "category", "search", "filter.category_id", "email"]
    for name in safe_names:
        allowed, reason = policy.evaluate_parameter_eligibility(name)
        assert allowed is True
        assert reason is None


def test_budget_tracker_records_requests() -> None:
    """Verify tracker records per-parameter and total request counts."""
    policy = ExecutionPolicy(max_total_requests=20, max_requests_per_parameter=5)
    tracker = ExecutionBudgetTracker(policy)

    assert tracker.total_requests == 0
    assert tracker.get_parameter_requests("id") == 0

    tracker.record_dispatch("id", count=1)
    assert tracker.total_requests == 1
    assert tracker.get_parameter_requests("id") == 1

    tracker.record_dispatch("id", count=2)
    assert tracker.total_requests == 3
    assert tracker.get_parameter_requests("id") == 3


def test_budget_tracker_enforces_per_param_limit() -> None:
    """Verify tracker stops dispatch when per-parameter request budget is exceeded."""
    policy = ExecutionPolicy(max_total_requests=20, max_requests_per_parameter=3)
    tracker = ExecutionBudgetTracker(policy)

    can_dispatch, _ = tracker.can_dispatch_test("param_a", estimated_requests=2)
    assert can_dispatch is True
    tracker.record_dispatch("param_a", count=2)

    # 2 dispatched, limit is 3. Estimated requests = 2 would make 4 > 3 -> reject
    can_dispatch, reason = tracker.can_dispatch_test("param_a", estimated_requests=2)
    assert can_dispatch is False
    assert "Parameter request budget reached" in (reason or "")

    # But another parameter is still eligible
    can_dispatch_b, _ = tracker.can_dispatch_test("param_b", estimated_requests=2)
    assert can_dispatch_b is True


def test_budget_tracker_enforces_global_limit() -> None:
    """Verify tracker stops dispatch when global request budget is reached."""
    policy = ExecutionPolicy(max_total_requests=5, max_requests_per_parameter=5)
    tracker = ExecutionBudgetTracker(policy)

    tracker.record_dispatch("p1", count=4)
    assert tracker.total_requests == 4

    # Estimated 2 would make 6 > 5 -> reject
    can_dispatch, reason = tracker.can_dispatch_test("p2", estimated_requests=2)
    assert can_dispatch is False
    assert "Global request budget reached" in (reason or "")


def test_budget_tracker_cancellation() -> None:
    """Verify cancellation aborts future dispatch."""
    policy = ExecutionPolicy()
    tracker = ExecutionBudgetTracker(policy)

    assert tracker.is_cancelled is False
    can_dispatch, _ = tracker.can_dispatch_test("id", estimated_requests=1)
    assert can_dispatch is True

    tracker.cancel("Terminated by user signal.")
    assert tracker.is_cancelled is True
    assert tracker.cancel_reason == "Terminated by user signal."

    can_dispatch_after, reason = tracker.can_dispatch_test("id", estimated_requests=1)
    assert can_dispatch_after is False
    assert "Run cancelled: Terminated by user signal." in (reason or "")
