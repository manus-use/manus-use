import_results = {}
packages_to_test = [
    "docker",
    "pydantic",
    "strands",
    "toml",
    "rich",
    "markdownify",
    "duckduckgo_search",
    "nest_asyncio",
]

for package in packages_to_test:
    try:
        __import__(package)
        import_results[package] = "Successfully imported"
    except ImportError as e:
        import_results[package] = f"Failed to import: {e}"
    except Exception as e:
        import_results[package] = f"An unexpected error occurred: {e}"

for package, result in import_results.items():
    print(f"{package}: {result}")
