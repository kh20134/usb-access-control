"""USB storage access control for Windows.

The pure policy core (whitelist matching, plans, password hashes, audit logs)
runs anywhere. Changing HKLM or device nodes is a separate Windows administrator
path. See the package README for what user mode can and cannot do.
"""

__version__ = "1.0.0"
