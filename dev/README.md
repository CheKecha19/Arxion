# Development

Python environment: .venv/. Shared sources remain in ../src, configuration in ../pyproject.toml.
Build intermediates: build/. Recreate the environment using uv sync --python 3.14 --all-groups --locked
with UV_PROJECT_ENVIRONMENT set to this directory's .venv.
