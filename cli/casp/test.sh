LAST_TAG=$(git describe --tags --abbrev=0)
VERSION=${LAST_TAG#v}
TIMESTAMP=$(date +%s)

# Set version to <last_tag>.<timestamp> (e.g., 1.0.0.1701234567)
sed -i "s/^version = \".*\"/version = \"$VERSION.$TIMESTAMP\"/" pyproject.toml