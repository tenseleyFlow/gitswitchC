#!/bin/sh
# Build RPMs inside one invocation-private namespace, then publish only the
# validated package leaves through the descriptor-pinned release publisher.
# ShellCheck 0.9 misclassifies deliberate fail-closed assertion chains.
# shellcheck disable=SC2015

set -u
umask 077
LC_ALL=C
export LC_ALL

rpm_fail()
{
    printf 'release-rpm: ERROR: %s\n' "$*" >&2
    exit 1
}

[ "$#" -eq 6 ] ||
    rpm_fail "usage: $0 ROOT ARCHIVE ARCHIVE_NAME DIST_ROOT PACKAGE PUBLISHER"

rpm_root=$1
rpm_archive=$2
rpm_archive_name=$3
rpm_dist_root=$4
rpm_package=$5
rpm_publisher=$6
rpm_topdir=
rpm_topdir_identity=
rpm_topdir_device=
rpm_topdir_inode=
rpm_home_physical=
rpm_sha256_tool=

# Fixed release descriptors are an internal ABI.  Discard any caller-owned
# generations before commands can inherit them, then assign each slot below.
exec 3<&-
exec 4<&-
exec 5<&-
exec 6<&-
exec 7<&-
exec 8<&-
exec 9<&-

rpm_path_identity()
{
    case $rpm_host_os in
        Linux) stat -L -c '%d:%i' "$1" ;;
        Darwin|FreeBSD) stat -L -f '%d:%i' "$1" ;;
        *) return 1 ;;
    esac
}

rpm_regular_path_identity()
{
    case $rpm_host_os in
        Linux) stat -L -c '%d:%i:%s' "$1" ;;
        Darwin|FreeBSD) stat -L -f '%d:%i:%z' "$1" ;;
        *) return 1 ;;
    esac
}

rpm_regular_fd_identity()
{
    rpm_regular_identity_fd=$1
    "$rpm_publisher" --internal-regular-fd-identity-v1 \
        "$rpm_regular_identity_fd"
}

rpm_sha256_fd()
{
    rpm_hash_fd=$1
    case $rpm_hash_fd in
        6)
            exec 3<&- 4<&- 5<&- 7<&- 8<&- 9<&-
            ;;
        8)
            exec 3<&- 4<&- 5<&- 6<&- 7<&- 9<&-
            ;;
        9)
            exec 3<&- 4<&- 5<&- 6<&- 7<&- 8<&-
            ;;
        *) return 1 ;;
    esac
    case $rpm_sha256_tool in
        sha256sum)
            rpm_hash_output=$(sha256sum "/dev/fd/$rpm_hash_fd") ||
                return 1
            rpm_hash_output=${rpm_hash_output%% *}
            ;;
        shasum)
            rpm_hash_output=$(shasum -a 256 "/dev/fd/$rpm_hash_fd") ||
                return 1
            rpm_hash_output=${rpm_hash_output%% *}
            ;;
        sha256)
            rpm_hash_output=$(sha256 -q "/dev/fd/$rpm_hash_fd") ||
                return 1
            ;;
        *) return 1 ;;
    esac
    [ "${#rpm_hash_output}" -eq 64 ] || return 1
    case $rpm_hash_output in
        *[!0-9a-fA-F]*) return 1 ;;
    esac
    printf '%s\n' "$rpm_hash_output"
}

rpm_open_archive()
{
    exec 6<&-
    exec 6<"$rpm_archive" || return 1
    [ "$(rpm_regular_fd_identity 6)" = \
        "$rpm_archive_identity" ]
}

rpm_open_source()
{
    exec 8<&-
    exec 8<"$rpm_source" || return 1
    [ "$(rpm_regular_fd_identity 8)" = "$rpm_source_identity" ]
}

rpm_normalize_private_acl()
{
    rpm_acl_path=$1
    case $rpm_host_os in
        Linux) ;;
        Darwin) chmod -N "$rpm_acl_path" || return 1 ;;
        FreeBSD)
            rpm_acl_nfs4=$(getconf ACL_NFS4 "$rpm_acl_path" 2>/dev/null) ||
                return 1
            rpm_acl_extended=$(getconf ACL_EXTENDED "$rpm_acl_path" \
                2>/dev/null) || return 1
            case $rpm_acl_nfs4:$rpm_acl_extended in
                1:0|1:1) setfacl -b "$rpm_acl_path" || return 1 ;;
                0:1)
                    setfacl -b "$rpm_acl_path" &&
                        setfacl -k "$rpm_acl_path" || return 1
                    ;;
                0:0) ;;
                *) return 1 ;;
            esac
            ;;
        *) return 1 ;;
    esac
    chmod 0700 "$rpm_acl_path"
}

rpm_private_name_is_safe()
{
    rpm_safe_path=$1
    [ -n "$rpm_home_physical" ] || return 1
    [ "${rpm_safe_path%/*}" = "$rpm_home_physical" ] || return 1
    rpm_safe_name=${rpm_safe_path##*/}
    case $rpm_safe_name in
        .gitswitch-rpmbuild.??????) ;;
        *) return 1 ;;
    esac
    rpm_safe_suffix=${rpm_safe_name#.gitswitch-rpmbuild.}
    case $rpm_safe_suffix in
        *[!A-Za-z0-9]*) return 1 ;;
    esac
    [ "${#rpm_safe_suffix}" -eq 6 ]
}

rpm_directory_is_exact()
{
    rpm_exact_path=$1
    [ -d "$rpm_exact_path" ] && [ ! -L "$rpm_exact_path" ] || return 1
    rpm_exact_physical=$(CDPATH='' cd "$rpm_exact_path" && pwd -P) || return 1
    [ "$rpm_exact_physical" = "$rpm_exact_path" ] || return 1
    rpm_exact_mode=$(find "$rpm_exact_path" -prune -type d -perm 0700 \
        -print 2>/dev/null) || return 1
    [ "$rpm_exact_mode" = "$rpm_exact_path" ]
}

rpm_cleanup()
{
    rpm_cleanup_status=$?
    # AR-12 M8: on a signal path $? is the last command's status (usually 0);
    # the signal handler pins the conventional 128+N status here so an
    # aborted build can never report success.
    if [ -n "${rpm_cleanup_forced-}" ]; then
        rpm_cleanup_status=$rpm_cleanup_forced
    fi
    trap - 0 1 2 3 15
    exec 3<&-
    exec 4<&-
    exec 5<&-
    exec 6<&-
    exec 7<&-
    exec 8<&-
    exec 9<&-
    rpm_cleanup_failed=0
    if [ -n "$rpm_topdir" ]; then
        if [ ! -e "$rpm_topdir" ] && [ ! -L "$rpm_topdir" ]; then
            :
        elif [ -n "$rpm_topdir_device" ] && [ -n "$rpm_topdir_inode" ] &&
             rpm_private_name_is_safe "$rpm_topdir"; then
            "$rpm_publisher" --internal-retire-tree-v1 \
                "$rpm_home_physical" "${rpm_topdir##*/}" \
                "$rpm_topdir_device" "$rpm_topdir_inode"
            rpm_retire_status=$?
            case $rpm_retire_status in
                0)
                    if [ -e "$rpm_topdir" ] || [ -L "$rpm_topdir" ]; then
                        printf '%s\n' \
                            'release-rpm: ERROR: descriptor-retired namespace name was recreated; replacement retained' \
                            >&2
                        rpm_cleanup_failed=1
                    fi
                    ;;
                2)
                    if rpm_directory_is_exact "$rpm_topdir" &&
                       [ "$(rpm_path_identity "$rpm_topdir")" = \
                           "$rpm_topdir_identity" ]; then
                        printf 'release-rpm: WARNING: private namespace safely retained because this platform lacks descriptor-conditioned directory removal: %s\n' \
                            "$rpm_topdir" >&2
                    else
                        printf '%s\n' \
                            'release-rpm: ERROR: safely-retained namespace changed identity after retirement refusal' \
                            >&2
                        rpm_cleanup_failed=1
                    fi
                    ;;
                *)
                    printf '%s\n' \
                        'release-rpm: ERROR: descriptor-pinned private namespace cleanup failed; replacement retained' \
                        >&2
                    rpm_cleanup_failed=1
                    ;;
            esac
        else
            printf '%s\n' \
                'release-rpm: ERROR: descriptor-pinned private namespace cleanup failed; replacement retained' \
                >&2
            rpm_cleanup_failed=1
        fi
    fi
    if [ "$rpm_cleanup_status" -eq 0 ] && [ "$rpm_cleanup_failed" -ne 0 ]; then
        rpm_cleanup_status=1
    fi
    exit "$rpm_cleanup_status"
}

rpm_host_os=$(uname -s 2>/dev/null) || rpm_fail "cannot identify host platform"
case $rpm_host_os in
    Linux|Darwin|FreeBSD) ;;
    *) rpm_fail "unsupported host platform: $rpm_host_os" ;;
esac
case $rpm_host_os in
    Linux)
        command -v sha256sum >/dev/null 2>&1 ||
            rpm_fail "sha256sum is unavailable"
        rpm_sha256_tool=sha256sum
        ;;
    Darwin)
        command -v shasum >/dev/null 2>&1 ||
            rpm_fail "shasum is unavailable"
        rpm_sha256_tool=shasum
        ;;
    FreeBSD)
        command -v sha256 >/dev/null 2>&1 ||
            rpm_fail "sha256 is unavailable"
        rpm_sha256_tool=sha256
        ;;
esac

case $rpm_root in
    /*) ;;
    *) rpm_fail "release root is not absolute" ;;
esac
[ -d "$rpm_root" ] && [ ! -L "$rpm_root" ] ||
    rpm_fail "release root is not a real directory"
rpm_root_physical=$(CDPATH='' cd "$rpm_root" && pwd -P) ||
    rpm_fail "cannot resolve release root"
[ "$rpm_root_physical" = "$rpm_root" ] ||
    rpm_fail "release root changed physical identity"

case $rpm_archive_name in
    ''|.|..|*/*) rpm_fail "archive name is not a single component" ;;
esac
[ "$rpm_archive" = "$rpm_root/build/dist/$rpm_archive_name" ] ||
    rpm_fail "archive is outside the canonical release directory"
[ -s "$rpm_archive" ] && [ -f "$rpm_archive" ] && [ ! -L "$rpm_archive" ] ||
    rpm_fail "canonical release archive is not a nonempty regular file"
rpm_archive_identity=$(rpm_regular_path_identity "$rpm_archive") ||
    rpm_fail "cannot identify canonical release archive"
[ -x "$rpm_publisher" ] && [ -f "$rpm_publisher" ] && [ ! -L "$rpm_publisher" ] ||
    rpm_fail "release publisher is not an executable regular file"
command -v rpmbuild >/dev/null 2>&1 ||
    rpm_fail "rpmbuild disappeared before the private build began"

rpm_home=${HOME-}
case $rpm_home in
    /*) ;;
    *) rpm_fail "HOME must be a nonempty absolute path" ;;
esac
case $rpm_home in
    *'
'*) rpm_fail "HOME must not contain a newline" ;;
esac
case $rpm_home in
    *%*) rpm_fail "HOME must not contain RPM macro expansion syntax (%)" ;;
esac
[ -d "$rpm_home" ] && [ ! -L "$rpm_home" ] ||
    rpm_fail "HOME is not a real directory"
rpm_home_physical=$(CDPATH='' cd "$rpm_home" && pwd -P) ||
    rpm_fail "cannot resolve HOME"
[ "$rpm_home_physical" = "$rpm_home" ] ||
    rpm_fail "HOME is not its exact physical path"

# AR-13 L10: arm signal/EXIT cleanup BEFORE mktemp, so a signal in the window
# between creating the private namespace and installing the handler can no
# longer leak it. rpm_cleanup guards on an empty rpm_topdir (still unset here),
# and the cleanup path repeats the strict parent/name/type/physical-identity
# checks before it removes anything, so an unsafe value is rejected rather than
# acted upon. AR-12 M8: signals must pin a nonzero exit status before cleanup
# runs — a single shared EXIT/signal handler read $? as 0 on the signal path
# and made an aborted `make rpm` report success (matching Makefile install and
# release_publish_lock.sh, which already pass explicit statuses).
rpm_cleanup_signal()
{
    rpm_cleanup_forced=$1
    rpm_cleanup
}
trap rpm_cleanup 0
trap 'rpm_cleanup_signal 129' 1
trap 'rpm_cleanup_signal 130' 2
trap 'rpm_cleanup_signal 131' 3
trap 'rpm_cleanup_signal 143' 15
rpm_topdir=$(mktemp -d "$rpm_home_physical/.gitswitch-rpmbuild.XXXXXX") ||
    rpm_fail "cannot create private RPM namespace"
rpm_normalize_private_acl "$rpm_topdir" ||
    rpm_fail "cannot secure private RPM namespace ACL"
if ! rpm_private_name_is_safe "$rpm_topdir" ||
   ! rpm_directory_is_exact "$rpm_topdir"; then
    rpm_fail "mktemp returned an unsafe private RPM namespace"
fi
rpm_topdir_identity=$(rpm_path_identity "$rpm_topdir") ||
    rpm_fail "cannot identify private RPM namespace"
rpm_topdir_device=${rpm_topdir_identity%%:*}
rpm_topdir_inode=${rpm_topdir_identity#*:}
case $rpm_topdir_device in
    ''|*[!0-9]*) rpm_fail "private RPM namespace device is invalid" ;;
esac
case $rpm_topdir_inode in
    ''|*[!0-9]*) rpm_fail "private RPM namespace inode is invalid" ;;
esac

for rpm_component in BUILD BUILDROOT RPMS SOURCES SPECS SRPMS TMP PUBLISH; do
    mkdir -m 0700 "$rpm_topdir/$rpm_component" ||
        rpm_fail "cannot create private $rpm_component directory"
    rpm_normalize_private_acl "$rpm_topdir/$rpm_component" ||
        rpm_fail "cannot secure private $rpm_component directory ACL"
    rpm_directory_is_exact "$rpm_topdir/$rpm_component" ||
        rpm_fail "private $rpm_component directory is not exact mode 0700"
done
rpm_rpms_identity=$(rpm_path_identity "$rpm_topdir/RPMS") ||
    rpm_fail "cannot identify private RPMS directory"
rpm_srpms_identity=$(rpm_path_identity "$rpm_topdir/SRPMS") ||
    rpm_fail "cannot identify private SRPMS directory"
rpm_publish_identity=$(rpm_path_identity "$rpm_topdir/PUBLISH") ||
    rpm_fail "cannot identify private PUBLISH directory"
rpm_rpms_device=${rpm_rpms_identity%%:*}
rpm_rpms_inode=${rpm_rpms_identity#*:}
rpm_srpms_device=${rpm_srpms_identity%%:*}
rpm_srpms_inode=${rpm_srpms_identity#*:}
rpm_publish_device=${rpm_publish_identity%%:*}
rpm_publish_inode=${rpm_publish_identity#*:}
for rpm_directory_identity_part in \
    "$rpm_rpms_device" "$rpm_rpms_inode" \
    "$rpm_srpms_device" "$rpm_srpms_inode" \
    "$rpm_publish_device" "$rpm_publish_inode"; do
    case $rpm_directory_identity_part in
        ''|*[!0-9]*) rpm_fail "private RPM directory identity is invalid" ;;
    esac
done

exec 3<"$rpm_topdir/RPMS" ||
    rpm_fail "cannot pin private RPMS directory"
exec 4<"$rpm_topdir/SRPMS" ||
    rpm_fail "cannot pin private SRPMS directory"
exec 5<"$rpm_topdir/PUBLISH" ||
    rpm_fail "cannot pin private PUBLISH directory"
rpm_open_archive ||
    rpm_fail "cannot pin canonical release archive"
rpm_archive_digest=$(rpm_sha256_fd 6) ||
    rpm_fail "cannot hash canonical release archive"
rpm_open_archive ||
    rpm_fail "canonical release archive changed identity before copying"
rpm_source=$rpm_topdir/SOURCES/$rpm_archive_name
(
    exec 3<&- 4<&- 5<&- 7<&- 8<&- 9<&-
    /bin/cat /dev/fd/6
) >"$rpm_source" ||
    rpm_fail "cannot copy private RPM source from descriptor"
exec 8<"$rpm_source" || rpm_fail "cannot open private RPM source"
rpm_source_identity=$(rpm_regular_fd_identity 8) ||
    rpm_fail "cannot identify private RPM source descriptor"
# The versioned C identity ABI has already fstat-verified a nonempty regular
# file. Do not repeat that proof through /dev/fd: FreeBSD stat predicates see
# the fdescfs node rather than the opened file.
chmod 0400 /dev/fd/8 || rpm_fail "cannot seal private RPM source"
rpm_source_digest=$(rpm_sha256_fd 8) ||
    rpm_fail "cannot hash private RPM source"
[ "$rpm_source_digest" = "$rpm_archive_digest" ] ||
    rpm_fail "private RPM source copy changed bytes"

rpm_spec=$rpm_topdir/SPECS/$rpm_package.spec
rpm_open_source ||
    rpm_fail "private RPM source changed identity before spec extraction"
(
    exec 3<&- 4<&- 5<&- 6<&- 7<&- 9<&-
    tar -xOf /dev/fd/8 "$rpm_dist_root/$rpm_package.spec"
) >"$rpm_spec" ||
    rpm_fail "cannot extract the archive-embedded RPM spec"
exec 9<"$rpm_spec" ||
    rpm_fail "cannot open archive-embedded RPM spec"
rpm_spec_identity=$(rpm_regular_fd_identity 9) ||
    rpm_fail "cannot identify archive-embedded RPM spec"
# As above, the C helper owns the portable regular/nonempty proof.
chmod 0400 /dev/fd/9 || rpm_fail "cannot seal private RPM spec"
rpm_spec_digest=$(rpm_sha256_fd 9) ||
    rpm_fail "cannot hash archive-embedded RPM spec"
exec 9<&-
exec 9<"$rpm_spec" ||
    rpm_fail "cannot reopen archive-embedded RPM spec"
[ "$(rpm_regular_fd_identity 9)" = "$rpm_spec_identity" ] ||
    rpm_fail "archive-embedded RPM spec changed identity before rpmbuild"
exec 6<&-
exec 8<&-

printf '%s\n' 'Building RPM packages in a private rpmbuild namespace...'
(
    exec 3<&-
    exec 4<&-
    exec 5<&-
    exec 6<&-
    exec 7<&-
    exec 8<&-
    rpmbuild \
        --define "_topdir $rpm_topdir" \
        --define "_builddir $rpm_topdir/BUILD" \
        --define "_buildrootdir $rpm_topdir/BUILDROOT" \
        --define "_rpmdir $rpm_topdir/RPMS" \
        --define "_sourcedir $rpm_topdir/SOURCES" \
        --define "_specdir $rpm_topdir/SPECS" \
        --define "_srcrpmdir $rpm_topdir/SRPMS" \
        --define "_tmppath $rpm_topdir/TMP" \
        --define '_rpmfilename %{ARCH}/%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}.rpm' \
        -ba /dev/fd/9
) || rpm_fail "rpmbuild failed"

rpm_open_source ||
    rpm_fail "private RPM source changed identity during rpmbuild"
rpm_postbuild_source_digest=$(rpm_sha256_fd 8) ||
    rpm_fail "cannot hash private RPM source after rpmbuild"
[ "$rpm_postbuild_source_digest" = "$rpm_source_digest" ] ||
    rpm_fail "private RPM source changed bytes during rpmbuild"
exec 9<&-
exec 9<"$rpm_spec" ||
    rpm_fail "cannot reopen archive-embedded RPM spec after rpmbuild"
[ "$(rpm_regular_fd_identity 9)" = "$rpm_spec_identity" ] ||
    rpm_fail "archive-embedded RPM spec changed identity during rpmbuild"
rpm_postbuild_spec_digest=$(rpm_sha256_fd 9) ||
    rpm_fail "cannot hash archive-embedded RPM spec after rpmbuild"
[ "$rpm_postbuild_spec_digest" = "$rpm_spec_digest" ] ||
    rpm_fail "archive-embedded RPM spec changed bytes during rpmbuild"

rpm_directory_is_exact "$rpm_topdir" &&
[ "$(rpm_path_identity "$rpm_topdir")" = "$rpm_topdir_identity" ] ||
    rpm_fail "private RPM namespace changed identity"
rpm_directory_is_exact "$rpm_topdir/RPMS" &&
[ "$(rpm_path_identity "$rpm_topdir/RPMS")" = "$rpm_rpms_identity" ] ||
    rpm_fail "private RPMS directory changed identity"
rpm_directory_is_exact "$rpm_topdir/SRPMS" &&
[ "$(rpm_path_identity "$rpm_topdir/SRPMS")" = "$rpm_srpms_identity" ] ||
    rpm_fail "private SRPMS directory changed identity"
rpm_directory_is_exact "$rpm_topdir/PUBLISH" &&
[ "$(rpm_path_identity "$rpm_topdir/PUBLISH")" = "$rpm_publish_identity" ] ||
    rpm_fail "private PUBLISH directory changed identity"

exec 6<&-
exec 7<&-
exec 8<&-
exec 9<&-
rpm_stage_records=$(
    exec 6<&-
    exec 7<&-
    exec 8<&-
    exec 9<&-
    "$rpm_publisher" --internal-rpm-stage-v1 3 "$rpm_rpms_device" \
        "$rpm_rpms_inode" \
        4 "$rpm_srpms_device" "$rpm_srpms_inode" \
        5 "$rpm_publish_device" "$rpm_publish_inode"
) ||
    rpm_fail "cannot validate and stage the complete RPM output set"
[ -n "$rpm_stage_records" ] ||
    rpm_fail "RPM staging helper returned no package records"
rpm_record_newline='
'
rpm_saved_ifs=$IFS
case $- in
    *f*) rpm_globbing_was_disabled=true ;;
    *) rpm_globbing_was_disabled=false ;;
esac
set -f
IFS=$rpm_record_newline
# The C helper rejects whitespace and glob metacharacters in names and bounds
# record count/length; disabled globbing leaves newline as the sole separator.
# shellcheck disable=SC2086
set -- $rpm_stage_records
IFS=$rpm_saved_ifs
if [ "$rpm_globbing_was_disabled" = false ]; then
    set +f
fi
[ "$#" -ge 1 ] && [ "$#" -le 1024 ] ||
    rpm_fail "RPM staging helper returned an invalid record count"
# Publication is atomic per leaf, not across the whole package set.  Rolling
# back a leaf after the publisher reports a post-publication durability error
# could destroy the only completed artifact.  Failures therefore retain every
# possibly durable leaf under its no-replace name and give an exact, bounded
# recovery set; the next invocation refuses those names until the operator has
# inspected the exact expected digests and resolved only matching outputs.
rpm_report_incomplete_set()
{
    printf '%s\n' \
        'release-rpm: ERROR: RPM set publication is incomplete; validated leaves may remain in build/dist' \
        'release-rpm: ERROR: inspect these exact no-replace outputs before retry; remove a leaf only after its digest matches:' \
        >&2
    for rpm_recovery_record do
        rpm_validate_record "$rpm_recovery_record"
        printf '  build/dist/%s (expected sha256 %s; inspect before removal)\n' \
            "$rpm_name" "$rpm_recorded_digest" >&2
    done
}

rpm_validate_record()
{
    rpm_record=$1
    rpm_name=${rpm_record%%,*}
    rpm_recorded_remainder=${rpm_record#*,}
    rpm_recorded_identity=${rpm_recorded_remainder%%,*}
    rpm_recorded_digest=${rpm_recorded_remainder#*,}
    [ "$rpm_recorded_remainder" != "$rpm_record" ] &&
    [ "$rpm_recorded_digest" != "$rpm_recorded_remainder" ] ||
        rpm_fail "private RPM record contains incomplete fields"
    case $rpm_recorded_digest in
        *,*) rpm_fail "private RPM record contains excess fields" ;;
    esac
    case $rpm_name in
        ''|*[!A-Za-z0-9._+~-]*)
            rpm_fail "private RPM record contains an unsafe name"
            ;;
    esac
    case $rpm_name in
        *.rpm) ;;
        *) rpm_fail "private RPM record contains a non-RPM name" ;;
    esac
    rpm_recorded_device=${rpm_recorded_identity%%:*}
    rpm_recorded_remainder=${rpm_recorded_identity#*:}
    rpm_recorded_inode=${rpm_recorded_remainder%%:*}
    rpm_recorded_size=${rpm_recorded_remainder#*:}
    [ "$rpm_recorded_remainder" != "$rpm_recorded_identity" ] &&
    [ "$rpm_recorded_size" != "$rpm_recorded_remainder" ] &&
    [ "${rpm_recorded_size%%:*}" = "$rpm_recorded_size" ] ||
        rpm_fail "private RPM record contains an incomplete identity"
    for rpm_identity_part in \
        "$rpm_recorded_device" "$rpm_recorded_inode" "$rpm_recorded_size"; do
        case $rpm_identity_part in
            ''|*[!0-9]*) rpm_fail "private RPM record identity is invalid" ;;
        esac
    done
    [ "$rpm_recorded_size" -gt 0 ] ||
        rpm_fail "private RPM record contains an empty leaf"
    [ "${#rpm_recorded_digest}" -eq 64 ] ||
        rpm_fail "private RPM record digest has the wrong length"
    case $rpm_recorded_digest in
        *[!0-9a-f]*) rpm_fail "private RPM record digest is invalid" ;;
    esac
}

rpm_directory_is_exact "$rpm_topdir/PUBLISH" &&
[ "$(rpm_path_identity "$rpm_topdir/PUBLISH")" = "$rpm_publish_identity" ] ||
    rpm_fail "private PUBLISH directory changed during staging"

# Reject every known collision before publishing the first leaf.  The C helper
# repeats this check atomically and owns final identity plus durability.  A
# prior interrupted invocation gets the same exact recovery inventory.
rpm_record_count=0
for rpm_record do
    rpm_validate_record "$rpm_record"
    if [ -e "$rpm_root/build/dist/$rpm_name" ] ||
       [ -L "$rpm_root/build/dist/$rpm_name" ]; then
        rpm_failed_name=$rpm_name
        rpm_report_incomplete_set "$@"
        rpm_fail "release output already exists: build/dist/$rpm_failed_name"
    fi
    rpm_record_count=$((rpm_record_count + 1))
done
[ "$rpm_record_count" -eq "$#" ] ||
    rpm_fail "private RPM record validation count changed"

for rpm_record do
    rpm_validate_record "$rpm_record"
    if ! (
        exec 3<&-
        exec 4<&-
        exec 6<&-
        exec 7<&-
        exec 8<&-
        exec 9<&-
        "$rpm_publisher" --internal-release-tree-from-dir-v1 \
            "$rpm_root" build dist "$rpm_name" 5 \
            "$rpm_publish_device" "$rpm_publish_inode" \
            "$rpm_recorded_device" "$rpm_recorded_inode" \
            "$rpm_recorded_size" "$rpm_recorded_digest"
    ); then
        rpm_failed_name=$rpm_name
        rpm_report_incomplete_set "$@"
        rpm_fail "cannot publish RPM without replacement: $rpm_failed_name"
    fi
done

printf '%s\n' 'RPM packages created in build/dist/'
