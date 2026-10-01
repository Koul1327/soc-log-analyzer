def get_username(message):
    parts = message.split()

    if parts[:3] != ["Failed", "password", "for"]:
        return None

    if len(parts) < 4:
        return None

    if parts[3:5] == ["invalid", "user"]:
        if len(parts) < 6:
            return None
        return parts[5]
    return parts[3]
