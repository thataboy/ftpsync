from datetime import datetime, timedelta
import argparse
from config_loader import load_config
import sys
import os


def parse_time_string(time_string):
    unit = time_string[-1].lower()
    value = int(time_string[:-1])
    if unit == 'd':
        return timedelta(days=value)
    elif unit == 'h':
        return timedelta(hours=value)
    elif unit == 'm':
        return timedelta(minutes=value)
    elif unit == 's':
        return timedelta(seconds=value)
    else:
        raise ValueError("Invalid time unit. Use 'd' for days, 'h' for hours, 'm' for minutes, 's' for seconds'.")


def load_settings():
    """return dict of profiles to monitor or sync
       args.modified is None (monitor) or timedelta (manual sync)
       args.execute is bool True = perform sync, otherwise preview only
    """
    parser = argparse.ArgumentParser(description="FTP Sync Tool")
    parser.add_argument('profiles', nargs='+',
                        help='Profile(s) to monitor or sync. Or all = all profiles; '
                             'ALL = all profiles, including disabled ones')
    parser.add_argument("-m", "--modified",
                        help="Sync files modified within <integer><time_unit> (e.g.: 30d | 12h | 15m | 30s)")
    parser.add_argument("-x", "--execute", action="store_true", help="Execute sync (by default, only show a preview)")

    args = parser.parse_args()

    if ('all' in args.profiles or 'ALL' in args.profiles) and len(args.profiles) > 1:
        print('all, ALL, and profile(s) may not be used together.')
        sys.exit(1)

    if args.execute and not args.modified:
        print("-x (--execute) requires the -m (--modified) option. Please specify a time range.")
        sys.exit(1)

    ini_path = os.path.join(os.path.dirname(__file__), 'ftpsync.ini')

    if not os.path.exists(ini_path):
        print(f'{ini_path} does not exist.')
        sys.exit(1)

    profiles = load_config(ini_path, args.profiles)

    if not profiles:
        print('No valid profiles enabled. Nothing to do.')
        sys.exit(1)

    if args.modified:
        try:
            time_delta = parse_time_string(args.modified)
            args.modified = datetime.now() - time_delta
        except Exception as e:
            print(f"-m Parse error: {e}")
            sys.exit(1)

    return (profiles, args)
