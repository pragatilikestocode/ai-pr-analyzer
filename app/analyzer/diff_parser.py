def extract_added_lines(patch: str) -> list[str]:
    if not patch:
        return []

    return [
        line[1:]  # remove leading "+"
        for line in patch.split("\n")
        if line.startswith("+") and not line.startswith("+++")
    ]


def diff_position_for_added_line(patch: str, added_line_number: int) -> int | None:
    if not patch:
        return None

    try:
        target_added_line = int(added_line_number)
    except (TypeError, ValueError):
        return None

    if target_added_line < 1:
        return None

    added_line = 0

    for position, line in enumerate(patch.splitlines(), start=1):
        if line.startswith("+") and not line.startswith("+++"):
            added_line += 1

            if added_line == target_added_line:
                return position

    return None


def new_file_line_for_added_line(patch: str, added_line_number: int) -> int | None:
    if not patch:
        return None

    try:
        target_added_line = int(added_line_number)
    except (TypeError, ValueError):
        return None

    if target_added_line < 1:
        return None

    added_line = 0
    in_hunk = False
    new_line_number = 0

    for line in patch.splitlines():
        if line.startswith("@@"):
            in_hunk = True
            parts = line.split(" ")
            if len(parts) < 3:
                return None

            # hunk format: @@ -old_start,old_count +new_start,new_count @@
            try:
                new_part = parts[2]  # e.g. "+10,5"
                new_start = new_part[1:].split(",", 1)[0]
                new_line_number = int(new_start)
            except (ValueError, IndexError):
                return None
            continue

        if not in_hunk:
            continue

        if not line:
            continue

        prefix = line[0]
        if prefix == "+" and not line.startswith("+++"):
            added_line += 1
            if added_line == target_added_line:
                return new_line_number
            new_line_number += 1
        elif prefix == " ":
            new_line_number += 1
        elif prefix == "-":
            continue

    return None
