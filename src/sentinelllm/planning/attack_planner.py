"""Attack planner boundary and registry-backed implementation."""

from abc import ABC, abstractmethod

from sentinelllm.core.models import AttackPlan, ScanConfiguration, TargetProfile
from sentinelllm.planning.strategies import StrategyRegistry, build_default_registry


class AttackPlanner(ABC):
    """Selects and structures applicable, authorized security tests."""

    @abstractmethod
    async def plan(
        self, profile: TargetProfile, configuration: ScanConfiguration
    ) -> tuple[AttackPlan, ...]:
        """Return plans without executing them."""
        raise NotImplementedError


class DefaultAttackPlanner(AttackPlanner):
    """Select applicable OWASP strategies from the registry."""

    def __init__(self, registry: StrategyRegistry | None = None) -> None:
        self.registry = registry or build_default_registry()

    async def plan(
        self, profile: TargetProfile, configuration: ScanConfiguration
    ) -> tuple[AttackPlan, ...]:
        """Create initial plans without executing or communicating with the target."""
        categories = configuration.enabled_attack_categories or tuple(
            type(next(iter(self.registry.all())).category)
        )
        plans: list[AttackPlan] = []
        writable_endpoints = [
            item
            for item in profile.endpoint_profiles
            if item.method in configuration.allowed_methods and item.method != "GET"
        ]
        selected_endpoint = writable_endpoints[0] if writable_endpoints else None
        for category in categories:
            ranked = self.registry.rank(category, profile)
            if not ranked:
                continue
            strategy = ranked[0]
            plans.append(
                AttackPlan(
                    attack_id=f"AT-{configuration.scan_id[:8]}-{len(plans) + 1:02d}",
                    category=category,
                    owasp_mapping=f"LLM{list(type(category)).index(category) + 1:02d}:2026",
                    objective=strategy.objective,
                    preconditions=("target is in scope",),
                    strategy=strategy.name,
                    expected_indicators=strategy.expected_signals,
                    risk_level=strategy.risk_level,
                    strategy_id=strategy.strategy_id,
                    description=strategy.description,
                    success_criteria=strategy.success_criteria,
                    stop_conditions=strategy.stop_conditions,
                    remediation_guidance=strategy.remediation_guidance,
                    endpoint=selected_endpoint.url
                    if selected_endpoint
                    else configuration.target_url,
                    method=selected_endpoint.method if selected_endpoint else "POST",
                    parameter=(
                        selected_endpoint.parameters[0]
                        if selected_endpoint and selected_endpoint.parameters
                        else "prompt"
                    ),
                )
            )
        return tuple(plans)
