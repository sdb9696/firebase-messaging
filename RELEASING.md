# Releasing

## Requirements
* [github client](https://github.com/cli/cli#installation)
* [gitchub_changelog_generator](https://github.com/github-changelog-generator)
* [github access token](https://github.com/github-changelog-generator/github-changelog-generator#github-token)

## Export changelog token

```bash
export CHANGELOG_GITHUB_TOKEN=token
```

## Set release information

```bash
export NEW_RELEASE=x.x.x
```

## Normal releases from main

### Create a branch for the release

```bash
git checkout main
git fetch origin main
git rebase origin/main
git checkout -b release/$NEW_RELEASE
```

### Update the version number

```bash
sed -i "0,/version = /{s/version = .*/version = \"${NEW_RELEASE}\"/}" pyproject.toml
```

### Update dependencies

```bash
uv sync --all-extras
uv lock --upgrade
```

### Run pre-commit and tests

```bash
uv run pre-commit run --all-files
uv run pytest
```

### Create release summary (skip for dev releases)

Write a short and understandable summary for the release.  Can include images.

#### Create $NEW_RELEASE milestone in github

If not already created

#### Create new issue linked to the milestone

```bash
gh issue create --label "release-summary" --milestone $NEW_RELEASE --title "$NEW_RELEASE Release Summary" --body "**Release highlights:**"
```

You can exclude the --body option to get an interactive editor or go into the issue on github and edit there.

#### Close the issue

Either via github or:

```bash
gh issue close ISSUE_NUMBER
```

### Generate changelog

Configuration settings are in `.github_changelog_generator`

#### For pre-release

EXCLUDE_TAGS will exclude all dev tags except for the current release dev tags.

Regex should be something like this `^((?!0\.9\.0)(.*dev\d))+`. The first match group negative matches on the current release and the second matches on releases ending with dev.

```bash
EXCLUDE_TAGS=${NEW_RELEASE%.dev*}; EXCLUDE_TAGS=${EXCLUDE_TAGS//"."/"\."}; EXCLUDE_TAGS="^((?!"$EXCLUDE_TAGS")(.*dev\d))+"
echo "$EXCLUDE_TAGS"
github_changelog_generator --future-release $NEW_RELEASE --exclude-tags-regex "$EXCLUDE_TAGS"
```

#### For production

```bash
github_changelog_generator --future-release $NEW_RELEASE --exclude-tags-regex 'dev\d$'
```

You can ignore warnings about missing PR commits like below as these relate to PRs to branches other than main:
```
Warning: PR 111 merge commit was not found in the release branch or tagged git history and no rebased SHA comment was found
```


### Export new release notes to variable

```bash
export RELEASE_NOTES=$(grep -Poz '(?<=\# Changelog\n\n)(.|\n)+?(?=\#\#)' CHANGELOG.md | tr '\0' '\n' )
echo "$RELEASE_NOTES"  # Check the output and copy paste if necessary
```

### Commit and push the changed files

```bash
git commit --all --verbose -m "Prepare $NEW_RELEASE"
git push origin release/$NEW_RELEASE -u
```

### Create a PR for the release, merge it, and re-fetch the main

#### Create the PR
```
gh pr create --title "Prepare $NEW_RELEASE" --body "$RELEASE_NOTES" --label release-prep --base main
```

#### Merge the PR once the CI passes

Create a squash commit and add the markdown from the PR description to the commit description.

```bash
gh pr merge --squash --body "$RELEASE_NOTES"
```

### Rebase local main

```bash
git checkout main
git fetch origin main
git rebase origin/main
```

### Create a release tag

Note, add changelog release notes as the tag commit message so `gh release create --notes-from-tag` can be used to create a release draft.

```bash
git tag --annotate $NEW_RELEASE -m "$RELEASE_NOTES"  # to create a signed tag replace --annotate with --sign
git push origin $NEW_RELEASE
```

### Approve the release workflow

This will automatically deploy to pypi


## Updating protobuf version

Skip this part under normal circumstances.
Only required if protobuf minimum dependency is updated.

### Update protobuf version

```bash
export PROTOBUF_VERSION=x.x.x
IFS='.' read -r PROTOBUF_MAJOR PROTOBUF_MINOR PROTOBUF_PATCH <<< "$PROTOBUF_VERSION"
PROTOBUF_NEXT="$((PROTOBUF_MAJOR + 2))"
PROTOBUF_CONSTRAINT=">=$PROTOBUF_VERSION,<$PROTOBUF_NEXT"
uv add "protobuf$PROTOBUF_CONSTRAINT"
uv add --dev "types-protobuf$PROTOBUF_CONSTRAINT"
```

### Download and unzip latest protoc compiler

Replace download url with correct version/platform

```bash
sudo rm -r .protoc
mkdir .protoc
wget -P .protoc/ "https://github.com/protocolbuffers/protobuf/releases/download/v$PROTOBUF_MINOR.$PROTOBUF_PATCH/protoc-$PROTOBUF_MINOR.$PROTOBUF_PATCH-linux-x86_64.zip"
unzip .protoc/protoc-$PROTOBUF_MINOR.$PROTOBUF_PATCH-linux-x86_64.zip -d .protoc/
.protoc/bin/protoc --version # check version as expected
```

### Update generated python files

```bash
export PROTO_DIR="firebase_messaging/proto"
.protoc/bin/protoc --proto_path=$PROTO_DIR --python_out=$PROTO_DIR $PROTO_DIR/android_checkin.proto $PROTO_DIR/checkin.proto $PROTO_DIR/mcs.proto
.protoc/bin/protoc --proto_path=$PROTO_DIR --pyi_out=$PROTO_DIR $PROTO_DIR/android_checkin.proto $PROTO_DIR/checkin.proto $PROTO_DIR/mcs.proto
```

### Fix relative import

`protoc` doesn't do relative imports https://github.com/protocolbuffers/protobuf/issues/1491

In `checkin_pb2.py` and `checkin_pb2.pyi` put `from . ` in front of `import android_checkin_pb2 ...`
