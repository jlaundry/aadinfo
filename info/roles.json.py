
import json

with open("roles.json") as of:
    roles = json.load(of)

outfile = open("roles.md", "w")
outfile.write("# AAD Built-In Role Permissions\n\n")

outfile.write("| Role | Permission |\n| ---- | ---------- |\n")

for role in roles["Roles"]:
    display_name = role['DisplayName']
    for perm in role["RolePermissions"]:
        for action in sorted(perm["ResourceActions"]["AllowedResourceActions"]):
            outfile.write(f"| {display_name} | {action} |\n")

outfile.close()
