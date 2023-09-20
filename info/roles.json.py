
import json

# roles.json is from https://admin.microsoft.com/admin/api/rbac/roles
# seems to be an internal API - extract via https://admin.microsoft.com/#/rbac/directory

with open("roles.json") as of:
    roles = json.load(of)

outfile = open("roles.md", "w")
outfile.write("# AAD Built-In Role Permissions\n\n")

outfile.write("## Permissions by Role\n\n")
outfile.write("| Role | Permission |\n| ---- | ---------- |\n")

permissions = {}

for role in sorted(roles["Roles"], key=lambda r: r['DisplayName']):
    display_name = role['DisplayName']
    for perm in role["RolePermissions"]:
        for action in sorted(perm["ResourceActions"]["AllowedResourceActions"]):
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
