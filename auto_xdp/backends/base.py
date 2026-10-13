"""Abstract backend interface."""
from __future__ import annotations

from dataclasses import dataclass, field

from auto_xdp.config import ConfigSnapshot, snapshot_config
from auto_xdp.state import ApplyResult, AppliedState, DesiredState, ObservedState, ReconcilePlan, compute_reconcile_plan, project_endpoint_policies


@dataclass
class BackendStatus:
    name: str
    available: bool
    reason: str = ""
    details: dict[str, str] = field(default_factory=dict)
    checks: dict[str, bool] = field(default_factory=dict)

    @property
    def failed_checks(self) -> list[str]:
        return [name for name, passed in self.checks.items() if not passed]

    def format_message(self) -> str:
        parts: list[str] = []
        if self.reason:
            parts.append(self.reason)
        if self.failed_checks:
            parts.append(f"failed checks: {', '.join(self.failed_checks)}")
        if self.details:
            parts.append(", ".join(f"{key}={value}" for key, value in self.details.items()))
        if parts:
            return "; ".join(parts)
        return "available" if self.available else "unavailable"


class PortBackend:
    name = "backend"
    last_apply_result: ApplyResult | None = None

    @property
    def config(self) -> ConfigSnapshot:
        return getattr(self, "_config", None) or snapshot_config()

    @classmethod
    def probe(cls) -> BackendStatus:
        return BackendStatus(name=cls.name, available=True)

    def get_applied_state(self) -> AppliedState:
        raise NotImplementedError

    def build_reconcile_plan(self, desired_state: DesiredState, applied_state: AppliedState) -> ReconcilePlan:
        return compute_reconcile_plan(desired_state, applied_state)

    def apply_reconcile_plan(
        self,
        plan: ReconcilePlan,
        dry_run: bool,
        desired_state: DesiredState,
        observed_state: ObservedState | None = None,
    ) -> ApplyResult | None:
        raise NotImplementedError

    def reconcile(
        self,
        desired_state: DesiredState,
        dry_run: bool,
        observed_state: ObservedState | None = None,
    ) -> ApplyResult:
        applied_state = self.get_applied_state()
        projection, blocked = project_endpoint_policies(desired_state)
        plan = self.build_reconcile_plan(projection, applied_state)
        plan.target = desired_state
        result = self.apply_reconcile_plan(plan, dry_run, projection, observed_state)
        if result is not None:
            result.blocked_endpoints.update(blocked)
        return result if result is not None else ApplyResult(
            dry_run=dry_run, plan=plan, applied=self.get_applied_state(),
            unconfirmed={"backend": "adapter returned no execution result"},
        )

    def close(self) -> None:
        return None

    def __enter__(self) -> "PortBackend":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
