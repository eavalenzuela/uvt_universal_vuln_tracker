def serialize_template(template):
    owner = template.owner
    return {
        "id": template.id,
        "name": template.name,
        "report_type": template.report_type,
        "fields": template.fields_json or [],
        "filters": template.filters_json or {},
        "format": template.export_format,
        "delivery_channel": template.delivery_channel,
        "recipients": template.recipients_json or [],
        "delivery_preferences": template.delivery_preferences_json or {},
        "visibility": template.visibility,
        "owner": {
            "id": owner.id if owner else None,
            "username": owner.username if owner else None,
        },
        "created_at": template.created_at.isoformat() if template.created_at else None,
        "updated_at": template.updated_at.isoformat() if template.updated_at else None,
    }
