from xml.sax.saxutils import escape


def entries(value):
    return [] if value is None else value if isinstance(value, list) else [value]


def named_removals(old, new, tag, namespace):
    def names(values):
        return {item.get("name") if isinstance(item, dict) else item for item in entries(values)}
    removed = names(old) - names(new)
    return "".join(
        f'<{tag} xmlns:nc="{namespace}" nc:operation="remove"><name>{escape(name)}</name></{tag}>'
        for name in sorted(name for name in removed if isinstance(name, str) and name)
    )
