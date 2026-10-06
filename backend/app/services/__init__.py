"""Services package init.

Service layer sits between API endpoints and infrastructure (DB, future
collectors / engines). Security-sensitive operations must live behind
service interfaces like this one so later integrations stay isolated.
"""
