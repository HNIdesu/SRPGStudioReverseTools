import PyInstaller.__main__

specs = [
    "extract.spec",
    "extract_key.spec",
    "pack.spec",
    "unpack.spec",
]

for spec in specs:
    print(f"Building {spec} ...")
    PyInstaller.__main__.run([spec])
