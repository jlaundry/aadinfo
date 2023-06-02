
import json

with open("roles.json") as of:
    roles = json.load(of)

outfile = open("roles.md", "w")
outfile.write("# AAD Built-In Role Permissions\n\n")

outfile.write("## Permissions by Role\n\n")
outfile.write("| Role | Permission |\n| ---- | ---------- |\n")

permissions = {}

for role in roles["Roles"]:
    display_name = role['DisplayName']
    for perm in role["RolePermissions"]:
        for action in sorted(perm["ResourceActions"]["AllowedResourceActions"]):
            outfile.write(f"| {display_name} | {action} |\n")

            if action not in permissions.keys():
                permissions[action] = []
            permissions[action].append(display_name)

outfile.write("\n\n## Roles by Permission\n\n")
outfile.write("| Permission | Roles |\n| ---------- | ----- |\n")

for action in permissions.keys():
    roles = ", ".join(sorted(permissions[action]))
    outfile.write(f"| {action} | {roles} |\n")

outfile.close()
