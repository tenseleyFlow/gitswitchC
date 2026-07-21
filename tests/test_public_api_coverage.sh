#!/bin/sh
# AR-11 L4: prove that the public-API link registry is exhaustive in both
# production and GITSWITCH_TESTING header profiles.

set -eu
LC_ALL=C
export LC_ALL

fail() {
    printf 'public API coverage: ERROR: %s\n' "$*" >&2
    exit 1
}

if [ "$#" -ne 1 ]; then
    fail "usage: $0 REPOSITORY_ROOT"
fi

root=$(CDPATH='' cd -- "$1" && pwd -P) || fail "cannot enter repository root"
cc_command=${PUBLIC_API_CC:-cc}

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/gitswitch-public-api.XXXXXX") ||
    fail "cannot create temporary directory"
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM

header_input=$tmp_dir/headers.c
for header in "$root"/src/*.h; do
    [ -f "$header" ] || fail "no project headers found"
    header_name=${header##*/}
    printf '#include "%s"\n' "$header_name"
done >"$header_input"
set -f

extract_header_declarations() {
    profile=$1
    output=$2
    preprocessed=$tmp_dir/$profile.headers.preprocessed
    parsed=$tmp_dir/$profile.headers.parsed

    if [ "$profile" = testing ]; then
        # PUBLIC_API_CC deliberately follows Make's compiler selection. Word
        # splitting permits the same launcher-plus-compiler form as CC.
        # shellcheck disable=SC2086
        $cc_command -std=gnu11 -E -DGITSWITCH_TESTING \
            -I"$root/src" "$header_input" >"$preprocessed" ||
            fail "$profile header preprocessing failed"
    else
        # shellcheck disable=SC2086
        $cc_command -std=gnu11 -E -I"$root/src" "$header_input" \
            >"$preprocessed" ||
            fail "$profile header preprocessing failed"
    fi

    awk -v header_dir="$root/src" '
        function finish_statement(    before, count, fields, name) {
            gsub(/[[:space:]]+/, " ", statement)
            sub(/^ /, "", statement)
            if (statement !~ /^typedef / && statement ~ /\(/) {
                before = statement
                sub(/\(.*/, "", before)
                gsub(/\*/, " ", before)
                count = split(before, fields, /[[:space:]]+/)
                name = fields[count]
                if (name ~ /^[A-Za-z_][A-Za-z0-9_]*$/)
                    print name
            }
            statement = ""
        }

        /^#[[:space:]]*[0-9]+[[:space:]]+"/ {
            marker = $0
            sub(/^#[[:space:]]*[0-9]+[[:space:]]+"/, "", marker)
            sub(/".*$/, "", marker)
            project = (index(marker, header_dir "/") == 1 &&
                       marker ~ /\.h$/)
            next
        }

        !project { next }

        {
            line = $0
            for (i = 1; i <= length(line); i++) {
                character = substr(line, i, 1)
                if (character == "{")
                    depth++
                if (depth == 0)
                    statement = statement character
                if (character == "}") {
                    depth--
                    if (depth == 0)
                        statement = statement "}"
                }
                if (character == ";" && depth == 0)
                    finish_statement()
            }
            if (depth == 0 && statement != "")
                statement = statement " "
        }
    ' "$preprocessed" >"$parsed" || fail "$profile header parsing failed"
    sort -u "$parsed" >"$output" || fail "$profile header sorting failed"

    [ -s "$output" ] || fail "$profile header scan found no declarations"
}

extract_registry() {
    profile=$1
    output=$2
    preprocessed=$tmp_dir/$profile.registry.preprocessed

    if [ "$profile" = testing ]; then
        # shellcheck disable=SC2086
        $cc_command -std=gnu11 -E -P -DGITSWITCH_TESTING \
            -DGITSWITCH_PUBLIC_API_REGISTRY_ONLY \
            -I"$root/src" -I"$root/tests" "$root/tests/test_public_api.c" \
            >"$preprocessed" || fail "$profile registry preprocessing failed"
    else
        # shellcheck disable=SC2086
        $cc_command -std=gnu11 -E -P \
            -DGITSWITCH_PUBLIC_API_REGISTRY_ONLY \
            -I"$root/src" -I"$root/tests" "$root/tests/test_public_api.c" \
            >"$preprocessed" || fail "$profile registry preprocessing failed"
    fi

    awk '
        {
            line = $0
            while (match(line,
                         /GITSWITCH_PUBLIC_API_REGISTRY\([A-Za-z_][A-Za-z0-9_]*\)/)) {
                token = substr(line, RSTART, RLENGTH)
                sub(/^GITSWITCH_PUBLIC_API_REGISTRY\(/, "", token)
                sub(/\)$/, "", token)
                print token
                line = substr(line, RSTART + RLENGTH)
            }
        }
    ' "$preprocessed" >"$output.raw" || fail "$profile registry parsing failed"

    sort "$output.raw" >"$output.sorted" || fail "$profile registry sorting failed"
    uniq -d "$output.sorted" >"$output.duplicates" ||
        fail "$profile duplicate scan failed"
    if [ -s "$output.duplicates" ]; then
        while IFS= read -r symbol; do
            printf 'public API coverage: ERROR: %s registry repeats %s\n' \
                "$profile" "$symbol" >&2
        done <"$output.duplicates"
        exit 1
    fi

    uniq "$output.sorted" >"$output" || fail "$profile registry deduplication failed"
    [ -s "$output" ] || fail "$profile registry is empty"
}

check_profile() {
    profile=$1
    declarations=$tmp_dir/$profile.declarations
    registry=$tmp_dir/$profile.registry
    missing=$tmp_dir/$profile.missing
    extra=$tmp_dir/$profile.extra

    extract_header_declarations "$profile" "$declarations"
    extract_registry "$profile" "$registry"
    comm -23 "$declarations" "$registry" >"$missing" ||
        fail "$profile missing-symbol comparison failed"
    comm -13 "$declarations" "$registry" >"$extra" ||
        fail "$profile extra-symbol comparison failed"

    if [ -s "$missing" ]; then
        while IFS= read -r symbol; do
            printf 'public API coverage: ERROR: %s registry omits %s\n' \
                "$profile" "$symbol" >&2
        done <"$missing"
    fi
    if [ -s "$extra" ]; then
        while IFS= read -r symbol; do
            printf 'public API coverage: ERROR: %s registry has undeclared %s\n' \
                "$profile" "$symbol" >&2
        done <"$extra"
    fi
    [ ! -s "$missing" ] && [ ! -s "$extra" ] || exit 1

    count=$(awk 'END { print NR }' "$registry") ||
        fail "$profile registry count failed"
    printf 'public API coverage: %s profile covers %s declarations\n' \
        "$profile" "$count"
}

check_profile production
check_profile testing
