import os
import tempfile

def write_file(content_list, filename, path=None):
    path = path if path else tempfile.gettempdir()
    with open(os.path.join(path, filename), "w") as f:
        written = f.write("\n".join(content_list))
        print(f"{written} chars written to {f.name}")

