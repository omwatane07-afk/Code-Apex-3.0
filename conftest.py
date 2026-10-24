import sys
import os

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "Code-Apex-3.0-main"))
if not os.path.exists(repo_root):
    repo_root = os.path.abspath(os.path.dirname(__file__))

backend_src = os.path.join(repo_root, "backend", "src")
backend_tests = os.path.join(repo_root, "backend", "tests")

for p in [repo_root, backend_src, backend_tests]:
    if p not in sys.path:
        sys.path.insert(0, p)

os.environ["CYBERQ_DATABASE_URL"] = "sqlite:///:memory:"
os.environ["CYBERQ_ENV"] = "demo"
os.environ["CYBERQ_AUDIT_SIGNING_SEED"] = (
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)
