# rbac.py

ROLE_PERMISSIONS = {
    "admin@Super": [
        "view_dashboard", "view_agents", "view_logs",
        "run_commands", "run_shell", "disconnect_agent",
        "approve_tamper", "deploy_agent", "manage_users",
        "view_audit", "export_reports"
    ],
    "admin@SOC": [
        "view_dashboard", "view_agents", "view_logs",
        "run_commands", "run_shell", "disconnect_agent",
        "approve_tamper", "deploy_agent", "view_audit"
    ],
    "analyst@SOC": [
        "view_dashboard", "view_agents", "view_logs",
        "run_commands"
    ],
    "complaince": [
        "view_dashboard", "view_agents", "view_logs",
        "view_audit", "export_reports"
    ],
    "viewer": [
        "view_dashboard"
    ]
}

def has_permission(roles: list, permission: str) -> bool:
    for role in roles:
        if permission in ROLE_PERMISSIONS.get(role, []):
            return True
    return False