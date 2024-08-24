import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from ftplib import FTP_TLS, error_perm
import time
import sys
from queue import Queue, Empty
from threading import Thread, Event
from crypty import decrypt
from config_loader import load_config, ENCRYPT_PASSWORD
from datetime import datetime, timedelta
import argparse
from collections import defaultdict
import logging
from enum import Enum

SYNC_FILE_DELETION = True
SYNC_FOLDER_DELETION = True
SYNC_FILE_MOVE = True
SYNC_FOLDER_MOVE = True
MAX_RETRIES = 3
RETRY_DELAY = 3  # seconds
SHOW_FULL_PATH = False

# Set up logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s [%(levelname)s]%(name)s%(message)s',
                    datefmt='%H:%M:%S')

logger = logging.getLogger(' ')


class FtpError(Enum):
    NO_AUTHENTICATION = 1
    NO_SUCH_FILE_OR_DIR = 2
    OTHER = 9


class FileOperation:
    def __init__(self, operation, src_path, dest_path=None, batch_id=0):
        self.operation = operation
        self.src_path = src_path
        self.dest_path = dest_path
        self.batch_id = batch_id
        self.timestamp = time.time()


class FileMonitorHandler(FileSystemEventHandler):
    def __init__(self, queue, ftps_handler):
        self.queue = queue
        self.ftps_handler = ftps_handler

        # FileSystemEvents are low level file operations, like "dir created" or "file modified"
        # rather than "copy folder A to B"
        # FileMonitorHandler tries to group them into batches in order to show
        # meaningful summaries like nnn files uploaded
        # It does this by looking at the time when the event is fired and other heuristics
        self.batch_id = 0  # each batch is given an id
        self.base_dir = None  # dir name of the first src_path in the batch
        self.last_operation = None
        self.last_operation_time = None
        self.time_threshold = 1.0
        self.short_time_threshold = 0.05
        self.long_time_threshold = 10.0
        # operation(s) that may be expected to follow a given operation
        self.compatible_operations = {
            'mkdir': ['mkdir', 'upload'],
            'upload': ['upload', 'mkdir'],
            'delete': ['delete', 'rmdir'],
            'rmdir': ['rmdir', 'delete'],
            'rename': ['rename'],
            'move': ['mkdir', 'move']  # not sure about this one?
        }

    def is_new_batch(self, operation, src_path, current_time):
        if self.last_operation is None:
            return True
        diff = current_time - self.last_operation_time
        if diff <= self.short_time_threshold:
            return False
        if operation not in self.compatible_operations.get(self.last_operation, []):
            return True
        if diff >= self.long_time_threshold:
            return True
        if diff >= self.time_threshold and self.base_dir not in src_path:
            return True
        return False

    def queue_operation(self, operation, src_path, dest_path=None):
        if not self.is_active:
            return
        current_time = time.time()
        if self.is_new_batch(operation, src_path, current_time):
            self.base_dir = os.path.dirname(src_path)
            self.batch_id += 1

        self.last_operation = operation
        self.last_operation_time = current_time

        self.queue.put(FileOperation(operation, src_path, dest_path, batch_id=self.batch_id))

    def on_modified(self, event):
        if not event.is_directory:
            self.queue_operation('upload', event.src_path)

    def on_created(self, event):
        # there seems no need to check for file created event
        # since it will be followed by file modified. This simplifies things
        if event.is_directory:
            self.queue_operation('mkdir', event.src_path)

    def on_deleted(self, event):
        if not SYNC_FOLDER_DELETION and event.is_directory or \
           not SYNC_FILE_DELETION and not event.is_directory:
            return
        op = 'rmdir' if event.is_directory else 'delete'
        self.queue_operation(op, event.src_path)

    def on_moved(self, event):
        if not SYNC_FOLDER_MOVE and event.is_directory or \
           not SYNC_FILE_MOVE and not event.is_directory:
            return
        # check if parent dir still exist,
        # in case system is generating a moved event for child items
        if not os.path.exists(os.path.dirname(event.src_path)):
            return
        op = 'rename' if os.path.dirname(event.src_path) == os.path.dirname(event.dest_path) else 'move'
        self.queue_operation(op, event.src_path, event.dest_path)

    @property
    def is_active(self):
        return self.ftps_handler.is_active


class FTPSHandler:
    def __init__(self, profile, logger):
        self.ftp_host = profile['host']
        self.ftp_user = profile['user']
        self.ftp_pwd = decrypt(profile['pwd']) if ENCRYPT_PASSWORD else profile['password']
        self.remote_dir = profile['remote']
        self.local_folder = profile['local']
        self.ftps = None
        self.errors = set()
        self.max_retries = MAX_RETRIES
        self.retry_delay = RETRY_DELAY
        self.is_active = True
        self.logger = logger

    def __del__(self):
        self.disconnect()

    def connect(self):
        if not self.is_active:
            return False
        if self.ftps:
            return True

        def do_connect():
            try:
                self.ftps = FTP_TLS(self.ftp_host)
                self.ftps.login(self.ftp_user, self.ftp_pwd)
                self.ftps.prot_p()
                return True
            except error_perm as e:
                self.errors.add(FtpError.NO_AUTHENTICATION)
                self.logger.error(f"Cannot connect to {self.ftp_host}: {e}")
                self.logger.critical("Authentication failed. Stopping this profile.")
                self.is_active = False
                return False

        return self.do_op(do_connect, 'connect')

    def disconnect(self):
        if self.ftps:
            try:
                self.ftps.quit()
            except Exception:
                pass
            finally:
                self.ftps = None

    def do_op(self, func, op_name, *args, **kwargs):
        if FtpError.NO_AUTHENTICATION in self.errors:
            return False

        for attempt in range(self.max_retries):
            if op_name != 'connect' and not self.connect():
                return False
            try:
                return func(*args, **kwargs)
            except (error_perm, Exception) as e:
                if len(args) > 1:
                    txt = f"{args[0]} -> {args[1]}"
                elif len(args) == 1:
                    txt = args[0]
                else:
                    txt = ''
                perm = isinstance(e, error_perm)
                if perm or attempt >= self.max_retries - 1:
                    quit = '' if perm else f'Gave up after {self.max_retries} attempts.'
                    self.logger.error(f"Failed to {op_name} {txt}: {e}. {quit}")
                    return False
                self.logger.warning(f"Unable to {op_name} {txt}: {e}. Retrying in {self.retry_delay} seconds...")
                self.disconnect()
                time.sleep(self.retry_delay)

    def get_remote_path(self, src_path):
        relative_path = os.path.relpath(src_path, start=self.local_folder)
        relative_path = os.path.normpath(relative_path).replace(os.sep, '/')
        return f'{self.remote_dir}/{relative_path}'

    def upload(self, src_path):
        def do_upload(src_path, remote_path):
            try:
                with open(src_path, 'rb') as f:
                    self.ftps.storbinary(f'STOR {remote_path}', f)
                    self.logger.info(f"Uploaded: {src_path} -> {remote_path}")
                    return True
            except error_perm:
                if self.make_dir(os.path.dirname(src_path)):
                    return do_upload(src_path, remote_path)
                else:
                    return False
            except (FileNotFoundError, PermissionError, OSError) as e:
                self.logger.error(f"File error: {e}")
                return False

        remote_path = self.get_remote_path(src_path)
        return self.do_op(do_upload, 'upload', src_path, remote_path)

    def delete_file(self, src_path):
        def do_delete_file(remote_path):
            self.ftps.delete(remote_path)
            self.logger.info(f"Deleted: {remote_path}")
            return True

        remote_path = self.get_remote_path(src_path)
        return self.do_op(do_delete_file, 'delete', remote_path)

    def rename(self, src_path, dest_path, op='rename'):
        def do_rename(remote_path, remote_dest_path):
            self.ftps.rename(remote_path, remote_dest_path)
            self.logger.info(f"{op.capitalize()}d: {remote_path} -> {remote_dest_path}")
            return True

        remote_path = self.get_remote_path(src_path)
        remote_dest_path = self.get_remote_path(dest_path)
        return self.do_op(do_rename, op, remote_path, remote_dest_path)

    def move(self, src_path, dest_path):
        if self.make_dir(os.path.dirname(dest_path)):
            return self.rename(src_path, dest_path, op='move')
        else:
            return False

    def make_dir(self, src_path):
        def do_make_dir(remote_path):
            self.ftps.cwd(self.remote_dir)
            relative_path = os.path.relpath(remote_path, start=self.remote_dir)
            dirs = relative_path.split('/')
            for dir in dirs:
                if dir:
                    try:
                        self.ftps.cwd(dir)
                    except Exception:
                        self.ftps.mkd(dir)
                        self.logger.info(f"Created: {os.path.join(self.remote_dir, relative_path)}")
                        self.ftps.cwd(dir)
            return True

        remote_path = self.get_remote_path(src_path)
        return self.do_op(do_make_dir, 'mkdir', remote_path)

    def delete_dir(self, src_path):
        def do_delete_dir(path):
            counts = defaultdict(lambda: {'success': 0, 'failure': 0, 'ignored': 0})

            try:
                listing = self.ftps.mlsd(path, facts=['type'])
                for (item, fact) in listing:
                    if item in ['.', '..']:
                        continue
                    full_path = f"{path}/{item}"
                    if fact['type'] == 'dir':
                        subdir_counts = do_delete_dir(full_path)
                        for op in ['delete', 'rmdir']:
                            counts[op]['success'] += subdir_counts[op]['success']
                            counts[op]['failure'] += subdir_counts[op]['failure']
                    elif fact['type'] == 'file':
                        try:
                            self.ftps.delete(full_path)
                            counts['delete']['success'] += 1
                            self.logger.info(f"Deleted: {full_path}")
                        except Exception as e:
                            counts['delete']['failure'] += 1
                            self.logger.error(f"Unable to delete {full_path}: {e}")

                self.ftps.rmd(path)
                counts['rmdir']['success'] += 1
                self.logger.info(f"Removed: {path}")
            except error_perm as e:
                counts['rmdir']['failure'] += 1
                self.logger.error(f"Unable to delete {path}: {e}")

            return counts

        remote_path = self.get_remote_path(src_path)
        return self.do_op(do_delete_dir, 'rmdir', remote_path)


class BatchTracker:
    def __init__(self, logger):
        self.counts = defaultdict(lambda: {'success': 0, 'failure': 0, 'ignored': 0})
        self.start_time = time.time()
        self.logger = logger

    def record(self, operation, success):
        if isinstance(success, bool):
            self.counts[operation]['success' if success else 'failure'] += 1
            self.counts['total']['success' if success else 'failure'] += 1
        elif isinstance(success, dict):
            # rather than a single bool, operation 'rmdir' returns a dict of count of
            # successful or failed 'rmdir' and 'delete' operations
            for op, counts in success.items():
                for res in ['success', 'failure']:
                    self.counts[op][res] += counts[res]
                    self.counts['total'][res] += counts[res]
        elif success is None:
            self.counts[operation]['ignored'] += 1
            self.counts['total']['ignored'] += 1

    def report(self):
        if self.counts['total']['success'] + self.counts['total']['failure'] > 1:
            print()
            self.logger.info("Batch Summary:")
            total = self.counts.pop('total')
            for op, counts in self.counts.items():
                self.logger.info(f"{op.capitalize()}: {counts['success']} successful, "
                                 f"{counts['failure']} failed, {counts['ignored']} ignored")
            self.logger.info(f"Total: {total['success']} successful, "
                             f"{total['failure']} failed, {total['ignored']} ignored")

            duration = time.time() - self.start_time
            self.logger.info(f"Batch duration: {duration:.2f} seconds")


class QueueHandler:
    def __init__(self, queue, ftps_handler, ignore_regex, logger):
        self.queue = queue
        self.ftps_handler = ftps_handler
        self.stop_event = Event()
        self.current_batch_id = None
        self.batch_tracker = None
        self.ignore_regex = ignore_regex
        self.thread = None
        self.logger = logger

    def should_process(self, src_path):
        return self.ignore_regex is None or self.ignore_regex.search(src_path) is None

    def start(self):
        self.thread = Thread(target=self.process_queue)
        self.thread.daemon = True
        self.thread.start()

    def process_queue(self):
        while not self.stop_event.is_set() and self.is_active:
            try:
                operation = self.queue.get(timeout=1)

                if self.current_batch_id != operation.batch_id:
                    if self.batch_tracker:
                        self.batch_tracker.report()
                    self.current_batch_id = operation.batch_id
                    self.batch_tracker = BatchTracker(self.logger)
                    print()

                if self.should_process(operation.src_path):
                    success = self.process_operation(operation)
                else:
                    success = None
                self.batch_tracker.record(operation.operation, success)

                self.queue.task_done()

            except Empty:
                if self.batch_tracker:
                    self.batch_tracker.report()
                    self.batch_tracker = None
                self.current_batch_id = None
                continue

    def process_operation(self, operation):
        success = False
        if operation.operation == 'upload':
            success = self.ftps_handler.upload(operation.src_path)
        elif operation.operation == 'delete':
            success = self.ftps_handler.delete_file(operation.src_path)
        elif operation.operation == 'mkdir':
            success = self.ftps_handler.make_dir(operation.src_path)
        elif operation.operation == 'rmdir':
            success = self.ftps_handler.delete_dir(operation.src_path)
        elif operation.operation == 'rename':
            success = self.ftps_handler.rename(operation.src_path, operation.dest_path)
        elif operation.operation == 'move':
            success = self.ftps_handler.move(operation.src_path, operation.dest_path)
        return success

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=2)
        if self.batch_tracker:
            self.batch_tracker.report()

    @property
    def is_active(self):
        return self.ftps_handler.is_active


class SyncManager:
    def __init__(self, profile):
        self.name = profile['name']
        self.local_folder = profile['local']
        self.remote_folder = profile['remote']
        self.ignore_regex = profile.get('ignore_regex')
        self.logger = logging.getLogger(f' {profile['name']} ')

        self.queue = Queue()
        self.ftps_handler = FTPSHandler(profile, self.logger)
        self.queue_handler = QueueHandler(self.queue, self.ftps_handler, self.ignore_regex, self.logger)
        self.event_handler = FileMonitorHandler(self.queue, self.ftps_handler)

        self.observer = Observer()
        self.observer.schedule(self.event_handler, self.local_folder, recursive=True)

    def start(self):
        self.observer.start()
        self.queue_handler.start()
        self.logger.info(f"Monitoring: {self.local_folder} -> {self.remote_folder}")

    def stop(self):
        self.observer.stop()
        self.observer.join(timeout=2)
        self.queue_handler.stop()
        self.ftps_handler.disconnect()
        self.logger.info(f"Stopped monitoring")

    @property
    def is_active(self):
        return self.ftps_handler.is_active


def start_monitor(profiles):
    sync_managers = []

    for profile in profiles.values():
        sync_manager = SyncManager(profile)
        try:
            sync_manager.start()
            sync_managers.append(sync_manager)
        except Exception as e:
            logger.error(f'Cannot monitor {profile['name']} due to error: {e}')
            continue

    return sync_managers


def clean_up(sync_managers):
    logger.info('Cleaning up')
    for sync_manager in sync_managers:
        sync_manager.stop()
    logger.info('Cleanup completed')


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


def get_files_to_sync(local_folder, modified_since, ignore_regex):
    files_to_sync = []
    for root, _, files in os.walk(local_folder):
        for file in files:
            file_path = os.path.join(root, file)
            if os.path.getmtime(file_path) > modified_since.timestamp() and \
               (ignore_regex is None or ignore_regex.search(file_path) is None):
                files_to_sync.append(file_path)
    return files_to_sync


def manual_sync(profiles, modified_since, execute=False):
    for profile in profiles.values():
        print()
        files_to_sync = get_files_to_sync(profile['local'], modified_since, profile['ignore_regex'])

        if not files_to_sync:
            print(f"{profile['name']}: Nothing to sync.")
            continue

        if not execute:
            print(f"Preview for {profile['name']}:")
            for file in files_to_sync:
                print(f"  {file}")
            continue

        sync_manager = SyncManager(profile)
        logger.info(f"Syncing profile {profile['name']}: {profile['local']} -> {profile['remote']}")
        for file_path in files_to_sync:
            sync_manager.queue.put(FileOperation('upload', file_path, batch_id=1))

        sync_manager.queue_handler.start()
        sync_manager.queue.join()  # Wait for all tasks to be processed
        sync_manager.queue_handler.stop()
        sync_manager.ftps_handler.disconnect()


def monitor_profiles(profiles):
    sync_managers = start_monitor(profiles)

    try:
        while sync_managers:
            time.sleep(1)
            for sm in sync_managers:
                if not sm.is_active:
                    sm.stop()

            sync_managers = [sm for sm in sync_managers if sm.is_active]
            if not sync_managers:
                logger.critical("All profiles have stopped. Exiting the program.")
                break

    except KeyboardInterrupt:
        logger.info("Script interrupted")
    finally:
        clean_up(sync_managers)


if __name__ == "__main__":
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
            modified_since = datetime.now() - time_delta
        except Exception as e:
            print(f"{e}")
            sys.exit(1)
        manual_sync(profiles, modified_since, args.execute)
    else:
        print()
        monitor_profiles(profiles)
