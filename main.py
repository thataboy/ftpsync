import os
from os.path import basename
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

from enum import Enum

SYNC_FILE_DELETION = True
SYNC_FOLDER_DELETION = True
SYNC_FILE_MOVE = True
SYNC_FOLDER_MOVE = True
MAX_RETRIES = 3
RETRY_DELAY = 3  # seconds
SHOW_FULL_PATH = False


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
    def __init__(self, queue):
        self.queue = queue

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


class FTPSHandler:
    def __init__(self, profile):
        self.ftp_host = profile['host']
        self.ftp_user = profile['user']
        self.ftp_pwd = decrypt(profile['pwd']) if ENCRYPT_PASSWORD else profile['password']
        self.remote_dir = profile['remote']
        self.local_folder = profile['local']
        self.profile_name = profile['name']
        self.ftps = None
        self.errors = set()
        self.max_retries = MAX_RETRIES
        self.retry_delay = RETRY_DELAY

    def __del__(self):
        self.disconnect()

    def connect(self):
        if self.ftps:
            return True

        def perform_connect():
            self.ftps = FTP_TLS(self.ftp_host)
            self.ftps.login(self.ftp_user, self.ftp_pwd)
            self.ftps.prot_p()
            return True

        return self.do_op(perform_connect, 'connect')

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
                if perm and op_name == 'connect':
                    self.errors.add(FtpError.NO_AUTHENTICATION)
                    self.log(f"Cannot connect to {self.ftp_host}: {e}.")
                    self.log(f"Dave, this conversation can serve no purpose anymore. Goodbye.")
                    return False
                if perm or attempt >= self.max_retries - 1:
                    quit = '' if perm else f'Gave up after {self.max_retries} attempts.'
                    self.log(f"Failed to {op_name} {txt}: {e}. {quit}")
                    return False
                self.log(f"Unable to {op_name} {txt}: {e}. Retrying in {self.retry_delay} seconds...")
                self.disconnect()
                time.sleep(self.retry_delay)

    def get_remote_path(self, src_path):
        relative_path = os.path.relpath(src_path, start=self.local_folder)
        relative_path = os.path.normpath(relative_path).replace(os.sep, '/')
        return f'{self.remote_dir}/{relative_path}'

    def log(self, txt):
        now = datetime.now().strftime("%H:%M:%S.%f")[:-4]
        print(f"{self.profile_name} {now} {txt}")

    def log_op(self, operation, path1, path2=None):

        def abbrev_path(path, root):
            root_length = len(root.split(os.sep))
            path_length = len(path.split(os.sep))
            if path_length - 3 > root_length:
                return f'{root}/.../{basename(path)}'
            else:
                return path

        if 'ploaded' in operation:
            src = path1 if SHOW_FULL_PATH else os.path.relpath(path1, start=self.local_folder)
        else:
            src = path1 if SHOW_FULL_PATH else os.path.relpath(path1, start=self.remote_dir)
        if path2:
            dest = path2 if SHOW_FULL_PATH else os.path.relpath(path2, start=self.remote_dir)
            # abbrev_path(path2, self.remote_dir)
            txt = f"{src} -> {dest}"
        else:
            txt = f"{src}"
        # now = datetime.now().strftime("%d %b %H:%M:%S.%f")[:-4]
        self.log(f"{operation}: {txt}")

    def upload(self, src_path):
        def do_upload(src_path, remote_path):
            try:
                with open(src_path, 'rb') as f:
                    self.ftps.storbinary(f'STOR {remote_path}', f)
                    self.log_op("Uploaded", src_path, remote_path)
                    return True
            except error_perm:
                if self.make_dir(os.path.dirname(src_path)):
                    return do_upload(src_path, remote_path)
                else:
                    return False
            except (FileNotFoundError, PermissionError, OSError) as e:
                self.log(f"File error: {e}")
                return False

        remote_path = self.get_remote_path(src_path)
        return self.do_op(do_upload, 'upload', src_path, remote_path)

    def delete_file(self, src_path):
        def do_delete_file(remote_path):
            self.ftps.delete(remote_path)
            self.log_op("Deleted", remote_path)
            return True

        remote_path = self.get_remote_path(src_path)
        return self.do_op(do_delete_file, 'delete', remote_path)

    def rename(self, src_path, dest_path, op='rename'):
        def do_rename(remote_path, remote_dest_path):
            self.ftps.rename(remote_path, remote_dest_path)
            self.log_op(f"{op.capitalize()}d", remote_path, remote_dest_path)
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
                        self.log_op("Created", os.path.join(self.remote_dir, relative_path))
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
                            self.log_op("Deleted", os.path.join(self.remote_dir, os.path.relpath(full_path, start=self.remote_dir)))
                        except Exception as e:
                            counts['delete']['failure'] += 1
                            self.log(f"Unable to delete {full_path}: {e}")

                self.ftps.rmd(path)
                counts['rmdir']['success'] += 1
                self.log_op("Removed", path)
            except error_perm as e:
                counts['rmdir']['failure'] += 1
                self.log(f"Unable to delete {path}: {e}")

            return counts

        remote_path = self.get_remote_path(src_path)
        return self.do_op(do_delete_dir, 'rmdir', remote_path)


class BatchTracker:
    def __init__(self):
        self.counts = defaultdict(lambda: {'success': 0, 'failure': 0, 'ignored': 0})
        self.start_time = time.time()

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
            print("\nBatch Summary:")
            total = self.counts.pop('total')
            for op, counts in self.counts.items():
                print(f"{op.capitalize()}: {counts['success']} successful, "
                      f"{counts['failure']} failed, {counts['ignored']} ignored")
            print(f"Total: {total['success']} successful, {total['failure']} failed, {total['ignored']} ignored")

            duration = time.time() - self.start_time
            print(f"Batch duration: {duration:.2f} seconds")


class QueueHandler:
    def __init__(self, queue, ftps_handler, ignore_regex):
        self.queue = queue
        self.ftps_handler = ftps_handler
        self.stop_event = Event()
        self.current_batch_id = None
        self.batch_tracker = None
        self.ignore_regex = ignore_regex

    def should_process(self, src_path):
        return self.ignore_regex is None or self.ignore_regex.search(src_path) is None

    def process_queue(self):
        while not self.stop_event.is_set():
            try:
                operation = self.queue.get(timeout=1)

                if self.current_batch_id != operation.batch_id:
                    if self.batch_tracker:
                        self.batch_tracker.report()
                    self.current_batch_id = operation.batch_id
                    self.batch_tracker = BatchTracker()
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
        if self.batch_tracker:
            self.batch_tracker.report()


def start_monitor(profiles):
    observers = []
    queue_handlers = []

    for profile in profiles.values():

        ignore_regex = profile.get('ignore_regex')

        queue = Queue()
        ftps_handler = FTPSHandler(profile)
        event_handler = FileMonitorHandler(queue)

        queue_handler = QueueHandler(queue, ftps_handler, ignore_regex)
        queue_thread = Thread(target=queue_handler.process_queue)
        queue_thread.daemon = True
        queue_thread.start()

        observer = Observer()
        observer.schedule(event_handler, profile['local'], recursive=True)
        observer.start()
        observers.append((observer, ftps_handler))
        queue_handlers.append((queue_handler, queue_thread, queue))

        print(f"Monitoring {profile['name']}: {profile['local']} -> {profile['remote']}")
    return (observers, queue_handlers)


def clean_up(observers, queue_handlers):
    print('Cleaning up')
    # Stop all observers
    for observer, _ in observers:
        observer.stop()

    # Wait for observers to finish (with timeout)
    for observer, _ in observers:
        observer.join(timeout=2)  # Wait for up to 2 seconds
        if observer.is_alive():
            print("Warning: An observer didn't stop cleanly and may still be running.")

    # Stop all queue handlers and wait for queues to finish
    for queue_handler, _, _ in queue_handlers:
        queue_handler.stop()

    # Wait for queue threads to finish (with timeout)
    for _, queue_thread, _ in queue_handlers:
        queue_thread.join(timeout=2)  # Wait for up to 2 seconds
        if queue_thread.is_alive():
            print("Warning: A queue thread didn't stop cleanly and may still be running.")

    # Close all FTP connections
    for _, handler in observers:
        try:
            handler.disconnect()
        except Exception:
            continue

    print('Cleanup completed')


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


def get_files_to_sync(profile, modified_since):
    files_to_sync = []
    for root, _, files in os.walk(profile['local']):
        for file in files:
            file_path = os.path.join(root, file)
            if os.path.getmtime(file_path) > modified_since:
                files_to_sync.append(file_path)
    return files_to_sync


def manual_sync(profile, modified_since, execute=False):
    files_to_sync = get_files_to_sync(profile, modified_since)

    if not execute:
        print(f"Files that would be uploaded:")
        for file in files_to_sync:
            if profile['ignore_regex'] is None or profile['ignore_regex'].search(file) is None:
                print(f"  {file}")
            else:
                print(f"  Ignored: {file}")
        return

    queue = Queue()
    ftps_handler = FTPSHandler(profile)

    for file_path in files_to_sync:
        queue.put(FileOperation('upload', file_path, batch_id=1))

    queue_handler = QueueHandler(queue, ftps_handler, profile.get('ignore_regex'))
    queue_thread = Thread(target=queue_handler.process_queue)
    queue_thread.daemon = True
    queue_thread.start()

    queue.join()  # Wait for all tasks to be processed
    queue_handler.stop()
    queue_thread.join()
    ftps_handler.disconnect()


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
        print(f'all, ALL, and profile(s) may not be used together.')
        sys.exit(1)

    if args.execute and not args.modified:
        print("-x (--execute) requires the -m (--modified) option. Please specify a time range.")
        sys.exit(1)

    ini_path = os.path.join(os.path.dirname(__file__), 'ftpsync.ini')

    if not os.path.exists(ini_path):
        print(f'{ini_path} does not exist.')
        sys.exit(1)

    profiles = load_config(ini_path, args.profiles)
    if len(profiles) == 0:
        print('No valid profiles enabled. Nothing to do.')
        sys.exit(1)

    if args.modified:
        try:
            time_delta = parse_time_string(args.modified)
            modified_since = datetime.now() - time_delta
            for profile in profiles.values():
                mode = 'Manually syncing' if args.execute else 'Previewing'
                print(f"\n{mode} profile {profile['name']}: {profile['local']} -> {profile['remote']}")
                manual_sync(profile, modified_since.timestamp(), args.execute)
        except Exception as e:
            print(f"{e}")
            sys.exit(1)
    else:
        print()
        (observers, queue_handlers) = start_monitor(profiles)

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nScript interrupted")
        finally:
            clean_up(observers, queue_handlers)
