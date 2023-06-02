
import json

with open("roles.json") as of:
    roles = json.load(of)

outfile = open("roles.md", "w")
outfile.write(f"# AAD Built-In Role Permissions\n\n")

for role in roles["Roles"]:
    display_name = role['DisplayName']
    for perm in role["RolePermissions"]:
        for action in sorted(perm["ResourceActions"]["AllowedResourceActions"]):
            outfile.write(f"| {display_name} | {action} |\n")

outfile.close()
