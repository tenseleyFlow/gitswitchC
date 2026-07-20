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

rpm_path_identity()
{
    case $rpm_host_os in
        Linux) stat -c '%d:%i' "$1" ;;
        Darwin|FreeBSD) stat -f '%d:%i' "$1" ;;
        *) return 1 ;;
    esac
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
    trap - 0 1 2 3 15
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
                    if [ "$rpm_host_os" != FreeBSD ] &&
                       rpm_directory_is_exact "$rpm_topdir" &&
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

rpm_topdir=$(mktemp -d "$rpm_home_physical/.gitswitch-rpmbuild.XXXXXX") ||
    rpm_fail "cannot create private RPM namespace"
# Install cleanup before trusting mktemp's output.  The cleanup path repeats
# the strict parent/name/type/physical-identity checks before it removes
# anything, so an unsafe return value is rejected rather than acted upon.
trap rpm_cleanup 0 1 2 3 15
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

rpm_source=$rpm_topdir/SOURCES/$rpm_archive_name
cp "$rpm_archive" "$rpm_source" || rpm_fail "cannot copy private RPM source"
chmod 0600 "$rpm_source" || rpm_fail "cannot secure private RPM source"
if [ ! -f "$rpm_source" ] || [ -L "$rpm_source" ] ||
   ! cmp -s "$rpm_archive" "$rpm_source"; then
    rpm_fail "private RPM source copy changed bytes"
fi

rpm_spec=$rpm_topdir/SPECS/$rpm_package.spec
tar -xOf "$rpm_source" "$rpm_dist_root/$rpm_package.spec" >"$rpm_spec" ||
    rpm_fail "cannot extract the archive-embedded RPM spec"
chmod 0600 "$rpm_spec" || rpm_fail "cannot secure private RPM spec"
[ -s "$rpm_spec" ] && [ -f "$rpm_spec" ] && [ ! -L "$rpm_spec" ] ||
    rpm_fail "archive-embedded RPM spec is not a nonempty regular file"

printf '%s\n' 'Building RPM packages in a private rpmbuild namespace...'
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
    -ba "$rpm_spec" || rpm_fail "rpmbuild failed"

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

rpm_binary_count=0
for rpm_arch_dir in "$rpm_topdir"/RPMS/*; do
    if [ ! -e "$rpm_arch_dir" ] && [ ! -L "$rpm_arch_dir" ]; then
        continue
    fi
    [ ! -L "$rpm_arch_dir" ] ||
        rpm_fail "rpmbuild produced a symlinked binary RPM directory"
    if [ ! -d "$rpm_arch_dir" ]; then
        continue
    fi
    rpm_directory_is_exact "$rpm_arch_dir" ||
        rpm_fail "rpmbuild produced an unsafe binary RPM directory"
    rpm_normalize_private_acl "$rpm_arch_dir" ||
        rpm_fail "cannot secure binary RPM directory ACL"
    rpm_directory_is_exact "$rpm_arch_dir" ||
        rpm_fail "binary RPM directory changed during ACL normalization"
    case $rpm_arch_dir in
        "$rpm_topdir/RPMS/"*) ;;
        *) rpm_fail "binary RPM directory escaped the private namespace" ;;
    esac
    for rpm_file in "$rpm_arch_dir"/*.rpm; do
        if [ ! -e "$rpm_file" ] && [ ! -L "$rpm_file" ]; then
            continue
        fi
        [ -s "$rpm_file" ] && [ -f "$rpm_file" ] && [ ! -L "$rpm_file" ] ||
            rpm_fail "rpmbuild produced an unsafe or empty binary RPM"
        rpm_name=${rpm_file##*/}
        [ ! -e "$rpm_topdir/PUBLISH/$rpm_name" ] &&
        [ ! -L "$rpm_topdir/PUBLISH/$rpm_name" ] ||
            rpm_fail "rpmbuild produced a duplicate RPM name: $rpm_name"
        cp "$rpm_file" "$rpm_topdir/PUBLISH/$rpm_name" ||
            rpm_fail "cannot stage binary RPM: $rpm_name"
        chmod 0400 "$rpm_topdir/PUBLISH/$rpm_name" ||
            rpm_fail "cannot seal staged binary RPM: $rpm_name"
        cmp -s "$rpm_file" "$rpm_topdir/PUBLISH/$rpm_name" ||
            rpm_fail "staged binary RPM changed bytes: $rpm_name"
        rpm_binary_count=$((rpm_binary_count + 1))
    done
done

rpm_source_count=0
for rpm_file in "$rpm_topdir"/SRPMS/*.src.rpm; do
    if [ ! -e "$rpm_file" ] && [ ! -L "$rpm_file" ]; then
        continue
    fi
    [ -s "$rpm_file" ] && [ -f "$rpm_file" ] && [ ! -L "$rpm_file" ] ||
        rpm_fail "rpmbuild produced an unsafe or empty source RPM"
    rpm_name=${rpm_file##*/}
    [ ! -e "$rpm_topdir/PUBLISH/$rpm_name" ] &&
    [ ! -L "$rpm_topdir/PUBLISH/$rpm_name" ] ||
        rpm_fail "rpmbuild produced a duplicate RPM name: $rpm_name"
    cp "$rpm_file" "$rpm_topdir/PUBLISH/$rpm_name" ||
        rpm_fail "cannot stage source RPM: $rpm_name"
    chmod 0400 "$rpm_topdir/PUBLISH/$rpm_name" ||
        rpm_fail "cannot seal staged source RPM: $rpm_name"
    cmp -s "$rpm_file" "$rpm_topdir/PUBLISH/$rpm_name" ||
        rpm_fail "staged source RPM changed bytes: $rpm_name"
    rpm_source_count=$((rpm_source_count + 1))
done

[ "$rpm_binary_count" -gt 0 ] ||
    rpm_fail "rpmbuild produced no regular binary RPM"
[ "$rpm_source_count" -gt 0 ] ||
    rpm_fail "rpmbuild produced no regular source RPM"
# Publication is atomic per leaf, not across the whole package set.  Rolling
# back a leaf after the publisher reports a post-publication durability error
# could destroy the only completed artifact.  Failures therefore retain every
# possibly durable leaf under its no-replace name and give an exact, bounded
# recovery set; the next invocation refuses those names until the operator has
# inspected and removed only these release outputs.
rpm_report_incomplete_set()
{
    printf '%s\n' \
        'release-rpm: ERROR: RPM set publication is incomplete; validated leaves may remain in build/dist' \
        'release-rpm: ERROR: inspect and remove only these exact no-replace outputs before retry:' \
        >&2
    for rpm_recovery_file in "$rpm_topdir"/PUBLISH/*.rpm; do
        printf '  build/dist/%s\n' "${rpm_recovery_file##*/}" >&2
    done
}

rpm_directory_is_exact "$rpm_topdir/PUBLISH" &&
[ "$(rpm_path_identity "$rpm_topdir/PUBLISH")" = "$rpm_publish_identity" ] ||
    rpm_fail "private PUBLISH directory changed during staging"

# Reject every known collision before publishing the first leaf.  The C helper
# repeats this check atomically and owns final identity plus durability.  A
# prior interrupted invocation gets the same exact recovery inventory.
for rpm_private_file in "$rpm_topdir"/PUBLISH/*.rpm; do
    rpm_name=${rpm_private_file##*/}
    [ -s "$rpm_private_file" ] && [ -f "$rpm_private_file" ] &&
    [ ! -L "$rpm_private_file" ] ||
        rpm_fail "private RPM staging contains an unsafe output"
    if [ -e "$rpm_root/build/dist/$rpm_name" ] ||
       [ -L "$rpm_root/build/dist/$rpm_name" ]; then
        rpm_report_incomplete_set
        rpm_fail "release output already exists: build/dist/$rpm_name"
    fi
done

for rpm_private_file in "$rpm_topdir"/PUBLISH/*.rpm; do
    rpm_name=${rpm_private_file##*/}
    if ! "$rpm_publisher" --internal-release-tree-v1 \
            "$rpm_root" build dist "$rpm_name" -- \
            /bin/cat "$rpm_private_file"; then
        rpm_report_incomplete_set
        rpm_fail "cannot publish RPM without replacement: $rpm_name"
    fi
    if [ ! -s "$rpm_root/build/dist/$rpm_name" ] ||
       [ ! -f "$rpm_root/build/dist/$rpm_name" ] ||
       [ -L "$rpm_root/build/dist/$rpm_name" ] ||
       ! cmp -s "$rpm_private_file" "$rpm_root/build/dist/$rpm_name"; then
        rpm_report_incomplete_set
        rpm_fail "published RPM changed bytes: $rpm_name"
    fi
done

printf '%s\n' 'RPM packages created in build/dist/'
