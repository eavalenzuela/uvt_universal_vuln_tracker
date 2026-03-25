def control_json(control):
    return {
        "id": control.id,
        "name": control.name,
        "framework": control.framework,
        "description": control.description,
        "created_at": control.created_at.isoformat(),
        "updated_at": control.updated_at.isoformat(),
    }
