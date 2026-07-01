def save_results(path, header, lines, summary):
    with open(path, "w", encoding="utf-8") as f:
        f.write(header + "\n")
        f.write(f"{'─' * 50}\n")
        for line in lines:
            f.write(line + "\n")
        f.write(summary + "\n")
