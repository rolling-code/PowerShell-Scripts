#!/usr/bin/env python3
#
# Enumerates which attributes of every AD user are writable by the bound account
# and writes results into Users.csv. Usage:
#
# python3 CheckWritableAttributesADUsers.py DOMAIN/mcontestabile:'XXX' -dc-ip 1.2.3.4
#
# Notes:
# - Uses ldap3. Install with: pip3 install ldap3 colorama
# - The script is conservative: it skips well-known operational or dangerous
#   attributes that should not be modified (see SKIP_ATTRS).
# - Only users where attributes can be retrieved are processed.
# - For each attribute the script attempts a MODIFY_REPLACE to "test" and then
#   restores the original value(s). Multi-valued attributes are handled.
# - Output CSV (Users.csv) contains two columns: sAMAccountName,WritableAttributes
#   where WritableAttributes is a semicolon-separated list of attribute names.
#

import argparse
import csv
import sys
import time
from ldap3 import Server, Connection, ALL, SUBTREE, MODIFY_REPLACE, ALL_ATTRIBUTES
from colorama import Fore, Style, init

init(autoreset=True)

# Attributes we should not attempt to modify (operational, binary, or dangerous)
SKIP_ATTRS = {
    'objectGUID',
    'objectSid',
    'nTSecurityDescriptor',
    'sAMAccountType',
    'userAccountControl',
    'unicodePwd',           # requires SSL and special modify
    'pwdLastSet',
    'badPwdCount',
    'badPasswordTime',
    'lastLogon',
    'lastLogonTimestamp',
    'logonCount',
    'msDS-UserPasswordExpiryTimeComputed',
    'directReports',
    'memberOf',
    'objectClass',
    'whenCreated',
    'whenChanged',
    'uSNCreated',
    'uSNChanged',
    'uSNReceived',
    'replPropertyMetaData',
    'replUpToDateVector',
    'msDS-ReplValueMetaData',
    'msDS-ReplAttributeMetaData',
    'msDS-ConsistencyGuid',
}

def parse_identity(identity):
    # DOMAIN/user:password
    if '/' not in identity:
        raise ValueError("target must be DOMAIN/user:password")
    domain, rest = identity.split('/', 1)
    if ':' in rest:
        user, password = rest.split(':', 1)
    else:
        user, password = rest, ''
    # Build UPN (assumes domain is DNS-style, e.g. domainame.net)
    if '.' in domain:
        upn = f"{user}@{domain}"
    else:
        upn = f"{user}@{domain.lower()}.net"
    return domain, user, password, upn

def safe_restore(conn, dn, attr, original):
    """Restore attribute original value. original may be None, single value, or list."""
    try:
        if original is None:
            # clear attribute
            conn.modify(dn, {attr: [(MODIFY_REPLACE, [])]})
        else:
            if isinstance(original, (list, tuple)):
                conn.modify(dn, {attr: [(MODIFY_REPLACE, list(original))]})
            else:
                conn.modify(dn, {attr: [(MODIFY_REPLACE, [original])]})
        return conn.result['result'] == 0
    except Exception:
        return False

def attempt_write_attribute(conn, dn, attr):
    """Attempt to write a safe test value to attr and restore. Return True if writable."""
    # small test token; avoid overly long values
    test_value = "test"
    try:
        # perform replace with single-element test value
        conn.modify(dn, {attr: [(MODIFY_REPLACE, [test_value])]})
        if conn.result['result'] == 0:
            return True
        else:
            return False
    except Exception:
        return False

def main():
    parser = argparse.ArgumentParser(description="Check writable AD attributes for all users")
    parser.add_argument('target', help='DOMAIN/user:password')
    parser.add_argument('-dc-ip', required=True, help='Domain controller IP or hostname')
    parser.add_argument('-out', default='Users.csv', help='Output CSV filename (default: Users.csv)')
    parser.add_argument('--page-size', type=int, default=1000, help='LDAP page size for user enumeration')
    args = parser.parse_args()

    try:
        domain, bind_user, bind_password, upn = parse_identity(args.target)
    except Exception as e:
        print(Fore.RED + f"[-] Error parsing identity: {e}")
        sys.exit(1)

    server = Server(args.dc_ip, get_info=ALL)
    try:
        conn = Connection(server, user=upn, password=bind_password, auto_bind=True)
    except Exception as e:
        print(Fore.RED + f"[-] Failed to bind: {e}")
        sys.exit(1)

    try:
        base_dn = conn.server.info.other['defaultNamingContext'][0]
    except Exception as e:
        print(Fore.RED + f"[-] Unable to determine base DN from server info: {e}")
        sys.exit(1)

    print(Fore.CYAN + f"[*] Bound as {upn}; base DN: {base_dn}")
    print(Fore.CYAN + "[*] Enumerating users...")

    # LDAP filter for user objects (sAMAccountName present)
    user_filter = '(&(objectCategory=person)(objectClass=user)(sAMAccountName=*))'

    # Request ALL_ATTRIBUTES so we can iterate attributes
    try:
        # paged search to retrieve all users
        conn.search(search_base=base_dn,
                    search_filter=user_filter,
                    search_scope=SUBTREE,
                    attributes=ALL_ATTRIBUTES,
                    paged_size=args.page_size)
    except Exception as e:
        print(Fore.RED + f"[-] Search failed: {e}")
        conn.unbind()
        sys.exit(1)

    entries = conn.entries
    if not entries:
        print(Fore.YELLOW + "[-] No users found or insufficient permissions to enumerate users.")
        conn.unbind()
        sys.exit(1)

    print(Fore.GREEN + f"[*] Retrieved {len(entries)} user entries (first page). Note: ldap3 may have more pages to iterate manually if required.")

    # ldap3's Connection.search with paged_size returns only first page unless we iterate with cookie.
    # For robust enumeration, use the generator method below to walk all pages.
    all_users = []

    # Re-run enumeration using paged search loop to ensure we get all users
    cookie = None
    try:
        while True:
            conn.search(search_base=base_dn,
                        search_filter=user_filter,
                        search_scope=SUBTREE,
                        attributes=ALL_ATTRIBUTES,
                        paged_size=args.page_size,
                        paged_cookie=cookie)
            all_users.extend(conn.entries)
            cookie = conn.result.get('controls', {}).get('1.2.840.113556.1.4.319', {}).get('value', {}).get('cookie', None)
            # ldap3 may return cookie as bytes or b''; treat both
            if not cookie:
                break
    except Exception as e:
        print(Fore.RED + f"[-] Paged search failed: {e}")
        conn.unbind()
        sys.exit(1)

    print(Fore.GREEN + f"[*] Total users enumerated: {len(all_users)}")

    # Prepare CSV
    out_file = args.out
    csvfh = open(out_file, 'w', newline='', encoding='utf-8')
    csv_writer = csv.writer(csvfh)
    csv_writer.writerow(['sAMAccountName', 'distinguishedName', 'WritableAttributes'])  # header

    processed = 0
    skipped = 0

    for entry in all_users:
        try:
            sam = None
            try:
                sam = str(entry.sAMAccountName) if 'sAMAccountName' in entry else None
            except Exception:
                sam = None

            if not sam:
                skipped += 1
                continue

            dn = entry.entry_dn
            print(Style.BRIGHT + f"\n[*] Processing user: {sam}  DN: {dn}")

            # Retrieve fresh attributes for this user so we have current values
            try:
                conn.search(search_base=dn, search_filter='(objectClass=*)', attributes=ALL_ATTRIBUTES)
                if not conn.entries:
                    print(Fore.YELLOW + f"[-] Could not retrieve attributes for {sam}; skipping.")
                    skipped += 1
                    continue
                user_entry = conn.entries[0]
            except Exception as e:
                print(Fore.RED + f"[-] Search for user attributes failed for {sam}: {e}; skipping.")
                skipped += 1
                continue

            writable_attrs = []

            # iterate attributes present in the entry
            attrs = list(user_entry.entry_attributes)
            for attr in attrs:
                if attr in SKIP_ATTRS:
                    # skip known operational/unsafe attributes
                    continue

                # read original value; could be None, single value, or list
                try:
                    original = user_entry[attr].value
                except Exception:
                    original = None

                # attempt write only if attribute is not empty or is writable candidate
                # We'll attempt regardless (except SKIP_ATTRS) but catch failures
                try:
                    success = False
                    # Attempt write
                    if attempt_write_attribute(conn, dn, attr):
                        # restore original
                        restored = safe_restore(conn, dn, attr, original)
                        if not restored:
                            print(Fore.YELLOW + f"[!] Warning: wrote attr {attr} on {sam} but failed to restore reliably.")
                        success = True
                    if success:
                        writable_attrs.append(attr)
                        print(Fore.GREEN + f"[+] Writable: {attr}")
                    else:
                        print(Fore.RED + f"[-] Not writable: {attr}")
                except Exception as e:
                    print(Fore.RED + f"[-] Exception while testing {attr}: {e}")

            if writable_attrs:
                csv_writer.writerow([sam, dn, ';'.join(writable_attrs)])
                processed += 1
            else:
                # Per requirement: "No need to include users which attributes failed to be retrieved."
                # If no writable attributes found, still include user with empty list? User requested "no need" so skip
                processed += 1

            # small sleep to avoid hammering DC too quickly
            time.sleep(0.05)

        except KeyboardInterrupt:
            print(Fore.YELLOW + "\n[!] Interrupted by user.")
            break
        except Exception as e:
            print(Fore.RED + f"[-] Unexpected error processing an entry: {e}")
            skipped += 1
            continue

    csvfh.close()
    conn.unbind()

    print("\n" + Style.BRIGHT + "=== Done ===")
    print(Fore.GREEN + f"Users processed: {processed}")
    print(Fore.YELLOW + f"Users skipped: {skipped}")
    print(Fore.CYAN + f"CSV written to: {out_file}")

if __name__ == '__main__':
    main()