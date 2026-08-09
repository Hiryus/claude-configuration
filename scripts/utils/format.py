from models.parsing import Access, Reference


def describe_refs(refs: list[Reference]) -> str:
    """
    Return a human readable description of the references (path + access type).
    """
    accesses = []
    for file in sorted(r.text for r in refs if r.access is Access.READ):
        accesses.append(f"reads {format_references([file])}")
    for file in sorted(r.text for r in refs if r.access is Access.WRITE):
        accesses.append(f"writes {format_references([file])}")
    return ", ".join(accesses)

def format_references(paths: list[str]) -> str:
    # Wrap each path in backticks: a bare path is parsed as markdown when shown to the user, which strips backslashes as escape characters.
    return ", ".join(f"`{path}`" for path in paths)
