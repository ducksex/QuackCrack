def is_printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    printable = sum(c.isprintable() for c in text)
    return printable / len(text)
