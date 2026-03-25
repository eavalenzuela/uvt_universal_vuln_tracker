def rule_json(rule):
    return {
        "id": rule.id,
        "name": rule.name,
        "is_enabled": rule.is_enabled,
        "delivery_adapter": rule.delivery_adapter,
        "delivery_config": rule.delivery_config or {},
        "severity_threshold": rule.severity_threshold,
        "notify_on_status_change": rule.notify_on_status_change,
        "notify_on_assignment_change": rule.notify_on_assignment_change,
        "product_scope": rule.product_scope or [],
        "frequency_days": rule.frequency_days,
        "escalation_after_days": rule.escalation_after_days,
        "channels": rule.channels or [],
        "recipients": rule.recipients or [],
        "created_by": rule.created_by,
        "created_at": rule.created_at.isoformat() if rule.created_at else None,
        "updated_at": rule.updated_at.isoformat() if rule.updated_at else None,
    }
