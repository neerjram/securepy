"""Rule Registry for SecurePy.

Maintains the catalog of registered security analysis rules and supports
dynamic registration of custom rules.
"""

from __future__ import annotations

from typing import Optional, Type

from backend.engine.rules.base_rule import BaseRule
from backend.engine.rules.command_injection import CommandInjectionRule
from backend.engine.rules.credentials import HardcodedCredentialsRule
from backend.engine.rules.dangerous_functions import DangerousFunctionsRule
from backend.engine.rules.deserialization import InsecureDeserializationRule
from backend.engine.rules.sql_injection import SQLInjectionRule


class RuleRegistry:
    """Manages active security rules for the analysis engine."""

    def __init__(self, load_defaults: bool = True) -> None:
        self._rules: dict[str, BaseRule] = {}
        if load_defaults:
            self._register_default_rules()

    def _register_default_rules(self) -> None:
        """Register the built-in core rules."""
        self.register(HardcodedCredentialsRule())
        self.register(DangerousFunctionsRule())
        self.register(CommandInjectionRule())
        self.register(SQLInjectionRule())
        self.register(InsecureDeserializationRule())

    def register(self, rule: BaseRule | Type[BaseRule]) -> None:
        """Register a new rule instance or rule class."""
        instance = rule() if isinstance(rule, type) else rule
        self._rules[instance.rule_id] = instance

    def unregister(self, rule_id: str) -> bool:
        """Remove a rule from the registry."""
        if rule_id in self._rules:
            del self._rules[rule_id]
            return True
        return False

    def get_rule(self, rule_id: str) -> Optional[BaseRule]:
        """Retrieve a rule by its ID."""
        return self._rules.get(rule_id)

    def get_all_rules(self) -> list[BaseRule]:
        """Return all registered rules."""
        return list(self._rules.values())

    def __len__(self) -> int:
        return len(self._rules)


# Shared default registry instance
default_registry = RuleRegistry(load_defaults=True)
