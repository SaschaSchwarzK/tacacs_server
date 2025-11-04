"""
Advanced Command Authorization System
Implements fine-grained command authorization with regex patterns and privilege levels
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from re import Pattern

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from tacacs_server.web.web import (
    get_command_engine,
)
from tacacs_server.web.web import (
    get_config as monitoring_get_config,
)


class ActionType(Enum):
    PERMIT = "permit"
    DENY = "deny"


class CommandMatchType(Enum):
    EXACT = "exact"
    PREFIX = "prefix"
    REGEX = "regex"
    WILDCARD = "wildcard"


@dataclass
class CommandRule:
    """Command authorization rule"""

    id: int
    action: ActionType
    match_type: CommandMatchType
    pattern: str
    min_privilege: int = 0
    max_privilege: int = 15
    description: str | None = None
    user_groups: list[str] | None = None
    device_groups: list[str] | None = None
    # Optional per-rule response mode: "pass_add" or "pass_repl"
    response_mode: str | None = None
    # Optional attributes to include on permit decisions
    attrs: dict[str, str] | None = None

    # Compiled pattern cache (for regex/wildcard), None otherwise
    _compiled_pattern: Pattern[str] | None = field(init=False, default=None)

    def __post_init__(self):
        """Compile regex patterns for efficiency"""
        if self.match_type == CommandMatchType.REGEX:
            self._compiled_pattern = re.compile(self.pattern)
        elif self.match_type == CommandMatchType.WILDCARD:
            # Convert wildcard to regex
            regex_pattern = self.pattern.replace("*", ".*").replace("?", ".")
            self._compiled_pattern = re.compile(f"^{regex_pattern}$")
        else:
            self._compiled_pattern = None

    def matches(
        self,
        command: str,
        privilege_level: int = 15,
        user_groups: list[str] | None = None,
        device_group: str | None = None,
    ) -> bool:
        """Check if this rule matches the command"""
        # Check privilege level
        if not (self.min_privilege <= privilege_level <= self.max_privilege):
            return False

        # Check user groups
        if self.user_groups and user_groups:
            if not any(ug in self.user_groups for ug in user_groups):
                return False

        # Check device group
        if self.device_groups and device_group:
            if device_group not in self.device_groups:
                return False

        # Check command match
        if self.match_type == CommandMatchType.EXACT:
            return command == self.pattern
        elif self.match_type == CommandMatchType.PREFIX:
            return command.startswith(self.pattern)
        elif self.match_type in (CommandMatchType.REGEX, CommandMatchType.WILDCARD):
            pat = self._compiled_pattern
            return bool(pat is not None and pat.match(command))

        return False


class CommandAuthorizationEngine:
    """
    Command authorization engine with rule evaluation
    Implements a firewall-like rule system for command authorization
    """

    def __init__(self):
        self.rules: list[CommandRule] = []
        self.default_action = ActionType.DENY
        self._rule_id_counter = 1

    def add_rule(
        self,
        action: ActionType,
        match_type: CommandMatchType,
        pattern: str,
        min_privilege: int = 0,
        max_privilege: int = 15,
        description: str | None = None,
        user_groups: list[str] | None = None,
        device_groups: list[str] | None = None,
        *,
        response_mode: str | None = None,
        attrs: dict[str, str] | None = None,
    ) -> CommandRule:
        """Add authorization rule"""
        rule = CommandRule(
            id=self._rule_id_counter,
            action=action,
            match_type=match_type,
            pattern=pattern,
            min_privilege=min_privilege,
            max_privilege=max_privilege,
            description=description,
            user_groups=user_groups,
            device_groups=device_groups,
            response_mode=response_mode,
            attrs=attrs,
        )
        self.rules.append(rule)
        self._rule_id_counter += 1
        return rule

    def remove_rule(self, rule_id: int) -> bool:
        """Remove rule by ID"""
        for i, rule in enumerate(self.rules):
            if rule.id == rule_id:
                self.rules.pop(i)
                return True
        return False

    def authorize_command(
        self,
        command: str,
        privilege_level: int = 15,
        user_groups: list[str] | None = None,
        device_group: str | None = None,
    ) -> tuple[bool, str | None, dict[str, str] | None, str | None]:
        """
        Authorize command execution
        Returns: (authorized: bool, reason: str)
        """
        # Evaluate rules in order
        for rule in self.rules:
            if rule.matches(command, privilege_level, user_groups, device_group):
                authorized = rule.action == ActionType.PERMIT
                reason = rule.description or f"Rule {rule.id}: {rule.action.value}"
                # Normalize response_mode
                resp_mode = None
                if isinstance(rule.response_mode, str):
                    rm = rule.response_mode.strip().lower()
                    if rm in ("pass_add", "pass_repl"):
                        resp_mode = rm
                attrs = dict(rule.attrs) if isinstance(rule.attrs, dict) else None
                return authorized, reason, attrs, resp_mode

        # No matching rule, use default action
        authorized = self.default_action == ActionType.PERMIT
        reason = f"Default action: {self.default_action.value}"
        return authorized, reason, None, None

    def get_allowed_commands(
        self,
        privilege_level: int = 15,
        user_groups: list[str] | None = None,
        device_group: str | None = None,
    ) -> list[str]:
        """Get list of explicitly allowed command patterns"""
        allowed = []
        for rule in self.rules:
            if rule.action == ActionType.PERMIT:
                # Check if rule applies to this context
                if rule.min_privilege <= privilege_level <= rule.max_privilege:
                    if not rule.user_groups or (
                        user_groups
                        and any(ug in rule.user_groups for ug in user_groups)
                    ):
                        if not rule.device_groups or (
                            device_group and device_group in rule.device_groups
                        ):
                            allowed.append(rule.pattern)
        return allowed

    def load_from_config(self, config: list[dict]):
        """Load rules from configuration"""
        self.rules.clear()

        def _parse_action(val) -> ActionType:
            if isinstance(val, ActionType):
                return val
            try:
                s = str(val).strip().lower()
                return ActionType.PERMIT if s == "permit" else ActionType.DENY
            except Exception:
                return ActionType.DENY

        def _parse_match_type(val) -> CommandMatchType:
            if isinstance(val, CommandMatchType):
                return val
            try:
                s = str(val).strip().lower()
                if s == "exact":
                    return CommandMatchType.EXACT
                if s == "prefix":
                    return CommandMatchType.PREFIX
                if s == "regex":
                    return CommandMatchType.REGEX
                if s == "wildcard":
                    return CommandMatchType.WILDCARD
            except Exception:
                pass
            return CommandMatchType.EXACT

        for rule_config in config:
            try:
                self.add_rule(
                    action=_parse_action(rule_config.get("action")),
                    match_type=_parse_match_type(rule_config.get("match_type")),
                    pattern=str(rule_config.get("pattern", "")),
                    min_privilege=rule_config.get("min_privilege", 0),
                    max_privilege=rule_config.get("max_privilege", 15),
                    description=rule_config.get("description"),
                    user_groups=rule_config.get("user_groups"),
                    device_groups=rule_config.get("device_groups"),
                    response_mode=rule_config.get("response_mode"),
                    attrs=rule_config.get("attrs"),
                )
            except Exception:
                # Skip invalid rule entries gracefully
                continue

    def export_config(self) -> list[dict]:
        """Export rules to configuration format"""
        return [
            {
                "id": rule.id,
                "action": rule.action.value,
                "match_type": rule.match_type.value,
                "pattern": rule.pattern,
                "min_privilege": rule.min_privilege,
                "max_privilege": rule.max_privilege,
                "description": rule.description,
                "user_groups": rule.user_groups,
                "device_groups": rule.device_groups,
                "response_mode": rule.response_mode,
                "attrs": rule.attrs,
            }
            for rule in self.rules
        ]


# Predefined rule templates for common scenarios


class CommandRuleTemplates:
    """Common command authorization rule templates"""

    @staticmethod
    def cisco_read_only() -> list[dict]:
        """Cisco read-only commands (show, ping, traceroute)"""
        return [
            {
                "action": "permit",
                "match_type": "prefix",
                "pattern": "show ",
                "min_privilege": 1,
                "description": "Allow all show commands",
            },
            {
                "action": "permit",
                "match_type": "exact",
                "pattern": "show",
                "min_privilege": 1,
                "description": "Allow show command",
            },
            {
                "action": "permit",
                "match_type": "prefix",
                "pattern": "ping ",
                "min_privilege": 1,
                "description": "Allow ping",
            },
            {
                "action": "permit",
                "match_type": "prefix",
                "pattern": "traceroute ",
                "min_privilege": 1,
                "description": "Allow traceroute",
            },
        ]

    @staticmethod
    def cisco_network_admin() -> list[dict]:
        """Cisco network admin commands"""
        return [
            *CommandRuleTemplates.cisco_read_only(),
            {
                "action": "permit",
                "match_type": "prefix",
                "pattern": "configure ",
                "min_privilege": 15,
                "description": "Allow configuration mode",
            },
            {
                "action": "permit",
                "match_type": "regex",
                "pattern": r"^interface .*",
                "min_privilege": 15,
                "description": "Allow interface configuration",
            },
            {
                "action": "deny",
                "match_type": "regex",
                "pattern": r"^(reload|reboot|shutdown).*",
                "min_privilege": 0,
                "max_privilege": 15,
                "description": "Deny system restart commands",
            },
        ]

    @staticmethod
    def juniper_read_only() -> list[dict]:
        """Juniper read-only commands"""
        return [
            {
                "action": "permit",
                "match_type": "prefix",
                "pattern": "show ",
                "min_privilege": 1,
                "description": "Allow all show commands",
            },
            {
                "action": "permit",
                "match_type": "prefix",
                "pattern": "monitor ",
                "min_privilege": 1,
                "description": "Allow monitoring commands",
            },
        ]

    @staticmethod
    def linux_user() -> list[dict]:
        """Linux user commands"""
        return [
            {
                "action": "permit",
                "match_type": "regex",
                "pattern": r"^ls.*",
                "description": "Allow ls",
            },
            {
                "action": "permit",
                "match_type": "regex",
                "pattern": r"^cat .*",
                "description": "Allow cat",
            },
            {
                "action": "permit",
                "match_type": "regex",
                "pattern": r"^grep .*",
                "description": "Allow grep",
            },
            {
                "action": "deny",
                "match_type": "regex",
                "pattern": r"^(rm|mv|cp|chmod|chown).*",
                "description": "Deny file modification",
            },
            {
                "action": "deny",
                "match_type": "prefix",
                "pattern": "sudo ",
                "description": "Deny sudo",
            },
        ]


# Integration with existing authorization system


class EnhancedAuthorizationService:
    """Enhanced authorization service with command authorization"""

    def __init__(self, command_engine: CommandAuthorizationEngine):
        self.command_engine = command_engine

    def authorize_tacacs_command(
        self,
        username: str,
        command: str,
        privilege_level: int,
        user_groups: list[str],
        device_group: str,
    ) -> dict:
        """
        Authorize TACACS+ command with enhanced rules
        Returns TACACS+ authorization response attributes
        """
        authorized, reason, _attrs, _mode = self.command_engine.authorize_command(
            command, privilege_level, user_groups, device_group
        )

        if authorized:
            # Return successful authorization with optional modifications
            return {
                "status": "PASS_ADD",
                "priv-lvl": str(privilege_level),
                "cmd": command,
                "reason": reason,
            }
        else:
            # Return denial
            return {"status": "FAIL", "reason": reason}

    def get_available_commands(
        self,
        username: str,
        privilege_level: int,
        user_groups: list[str],
        device_group: str,
    ) -> list[str]:
        """Get list of available commands for user"""
        return self.command_engine.get_allowed_commands(
            privilege_level, user_groups, device_group
        )


# FastAPI integration

router = APIRouter(
    prefix="/api/command-authorization", tags=["Authorization"], include_in_schema=True
)


class CommandAuthRequest(BaseModel):
    command: str
    privilege_level: int = 15
    user_groups: list[str] | None = None
    device_group: str | None = None


class CommandAuthResponse(BaseModel):
    authorized: bool
    reason: str
    command: str


class CommandAuthSettings(BaseModel):
    default_action: str


class CommandRuleCreate(BaseModel):
    action: str
    match_type: str
    pattern: str
    min_privilege: int = 0
    max_privilege: int = 15
    description: str | None = None
    user_groups: list[str] | None = None
    device_groups: list[str] | None = None


async def _admin_guard_dep(request: Request):
    # Enforce cookie-based admin session; do not consume body
    import logging

    from tacacs_server.utils import config_utils

    try:
        logging.getLogger("tacacs.command_auth").info(
            "command_auth.admin_guard: path=%s method=%s has_cookie=%s",
            getattr(request.url, "path", ""),
            getattr(request, "method", ""),
            bool(request.cookies.get("admin_session")),
        )
    except Exception:
        pass

    token = request.cookies.get("admin_session")
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    mgr = config_utils.get_admin_session_manager()
    if not mgr:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE)
    if not mgr.validate_session(token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)


@router.post(
    "/check",
    response_model=CommandAuthResponse,
    dependencies=[Depends(_admin_guard_dep)],
)
async def check_command_authorization(request: CommandAuthRequest):
    """Check if command is authorized"""
    # Get command engine from app state
    engine = get_command_engine()
    if engine is None:
        raise HTTPException(
            status_code=503, detail="Command authorization engine not initialized"
        )

    authorized, reason, _, _ = engine.authorize_command(
        request.command,
        request.privilege_level,
        request.user_groups,
        request.device_group,
    )

    return CommandAuthResponse(
        authorized=authorized, reason=reason, command=request.command
    )


@router.get("/rules", dependencies=[Depends(_admin_guard_dep)])
async def list_command_rules():
    """List all command authorization rules"""
    # Get engine from app state
    engine = get_command_engine()
    if engine is None:
        engine = CommandAuthorizationEngine()
    return {"rules": engine.export_config()}


@router.get(
    "/settings",
    response_model=CommandAuthSettings,
    dependencies=[Depends(_admin_guard_dep)],
)
async def get_settings():
    engine = get_command_engine()
    default_action = "deny"
    if engine is not None and getattr(engine, "default_action", None) is not None:
        default_action = (
            engine.default_action.value
            if hasattr(engine.default_action, "value")
            else str(engine.default_action)
        )
    return CommandAuthSettings(default_action=default_action)


@router.put(
    "/settings",
    response_model=CommandAuthSettings,
    dependencies=[Depends(_admin_guard_dep)],
)
async def update_settings(settings: CommandAuthSettings):
    engine = get_command_engine()
    if engine is None:
        engine = CommandAuthorizationEngine()
    try:
        action = ActionType(settings.default_action)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid default_action")
    engine.default_action = action
    # Persist
    try:
        cfg = monitoring_get_config()
        if cfg is not None:
            cfg.update_command_authorization_config(
                default_action=settings.default_action
            )
    except Exception:
        pass
    return CommandAuthSettings(default_action=settings.default_action)


@router.post("/rules", dependencies=[Depends(_admin_guard_dep)])
async def create_command_rule(rule: CommandRuleCreate):
    """Create new command authorization rule"""
    # Get engine from app state
    engine = get_command_engine()
    if engine is None:
        engine = CommandAuthorizationEngine()

    new_rule = engine.add_rule(
        action=ActionType(rule.action),
        match_type=CommandMatchType(rule.match_type),
        pattern=rule.pattern,
        min_privilege=rule.min_privilege,
        max_privilege=rule.max_privilege,
        description=rule.description,
        user_groups=rule.user_groups,
        device_groups=rule.device_groups,
    )
    # Persist to config
    try:
        cfg = monitoring_get_config()
        if cfg is not None:
            cfg.update_command_authorization_config(rules=engine.export_config())
    except Exception:
        # Non-fatal: keep runtime updated even if persistence fails
        pass

    return {"rule_id": new_rule.id, "message": "Rule created"}


@router.delete("/rules/{rule_id}", dependencies=[Depends(_admin_guard_dep)])
async def delete_command_rule(rule_id: int):
    """Delete command authorization rule"""
    # Get engine from app state
    engine = get_command_engine()
    if engine is None:
        engine = CommandAuthorizationEngine()

    if engine.remove_rule(rule_id):
        # Persist to config
        try:
            cfg = monitoring_get_config()
            if cfg is not None:
                cfg.update_command_authorization_config(rules=engine.export_config())
        except Exception:
            pass
        return {"message": "Rule deleted"}
    else:
        raise HTTPException(status_code=404, detail="Rule not found")


@router.get("/templates", dependencies=[Depends(_admin_guard_dep)])
async def list_rule_templates():
    """List available rule templates"""
    return {
        "templates": {
            "cisco_read_only": CommandRuleTemplates.cisco_read_only(),
            "cisco_network_admin": CommandRuleTemplates.cisco_network_admin(),
            "juniper_read_only": CommandRuleTemplates.juniper_read_only(),
            "linux_user": CommandRuleTemplates.linux_user(),
        }
    }


@router.post(
    "/templates/{template_name}/apply", dependencies=[Depends(_admin_guard_dep)]
)
async def apply_rule_template(template_name: str):
    """Apply a rule template"""
    templates = {
        "cisco_read_only": CommandRuleTemplates.cisco_read_only,
        "cisco_network_admin": CommandRuleTemplates.cisco_network_admin,
        "juniper_read_only": CommandRuleTemplates.juniper_read_only,
        "linux_user": CommandRuleTemplates.linux_user,
    }

    if template_name not in templates:
        raise HTTPException(status_code=404, detail="Template not found")

    # Get engine from app state
    engine = get_command_engine()
    if engine is None:
        engine = CommandAuthorizationEngine()

    rules = templates[template_name]()
    engine.load_from_config(rules)
    # Persist to config
    try:
        cfg = monitoring_get_config()
        if cfg is not None:
            cfg.update_command_authorization_config(rules=engine.export_config())
    except Exception:
        pass

    return {"message": f"Applied template: {template_name}", "rules_count": len(rules)}
