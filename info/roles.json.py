
import json
import os

# roles.json is from https://admin.microsoft.com/admin/api/rbac/roles
# seems to be an internal API - extract via https://admin.microsoft.com/#/rbac/directory

BASE_DIR = os.path.realpath(os.path.dirname(__file__))

with open(os.path.join(BASE_DIR, "roles.graph.json")) as of:
    roles = json.load(of)

outfile = open(os.path.join(BASE_DIR, "roles.md"), "w")
outfile.write("# AAD Built-In Role Permissions\n\n")

outfile.write("## Permissions by Role\n\n")
outfile.write("| Role | Permission |\n| ---- | ---------- |\n")

permissions = {}

for role in sorted(roles["value"], key=lambda r: r['displayName']):
    display_name = role['displayName']
    for perm in role["rolePermissions"]:
        for action in sorted(perm["allowedResourceActions"]):
            outfile.write(f"| {display_name} | {action} |\n")

            if action not in permissions.keys():
                permissions[action] = []
            permissions[action].append(display_name)

outfile.write("\n\n## Roles by Permission\n\n")
outfile.write("| Permission | Roles |\n| ---------- | ----- |\n")

for action in sorted(permissions.keys()):
    roles = ", ".join(sorted(permissions[action]))
    outfile.write(f"| {action} | {roles} |\n")

outfile.close()
