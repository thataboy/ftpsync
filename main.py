import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from ftplib import FTP_TLS, error_perm
from socket import gaierror
import time
from queue import Queue, Empty
from threading import Thread, Event
from crypty import decrypt
from start_up import load_settings
from constants import *
from collections import defaultdict
import logging
import colorama


# Initialize colorama
colorama.init(autoreset=True)


# Custom ColoredFormatter
class ColoredFormatter(logging.Formatter):
    COLORS = {
        'DEBUG': colorama.Fore.BLUE,
        'INFO': colorama.Fore.WHITE,
        'WARNING': colorama.Fore.YELLOW,
        'ERROR': colorama.Fore.RED,
        'CRITICAL': colorama.Fore.RED
    }

    def format(self, record):
        return (f"{colorama.Style.DIM}{self.formatTime(record, self.datefmt)}{colorama.Style.RESET_ALL} "
                f"{self.COLORS.get(record.levelname, '')}{record.levelname}{colorama.Style.RESET_ALL} "
                f"{colorama.Fore.MAGENTA}{record.name if record.name != 'root' else '>'} "
                f"{colorama.Style.RESET_ALL}{record.msg}")


# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()
handler = logging.StreamHandler()
formatter = ColoredFormatter(fmt='[%(levelname)s] %(name)s%(message)s', datefmt='%H:%M:%S')
handler.setFormatter(formatter)
logger.handlers = [handler]


def colorize_path(path, base):
    relative_path = os.path.relpath(path, start=base)
    dirname, basename = os.path.split(relative_path)
    return (f"{colorama.Style.DIM}{base}{os.path.sep if base else ''}{colorama.Style.RESET_ALL}"
            f"{colorama.Fore.LIGHTCYAN_EX}{dirname}{os.path.sep if dirname else ''}"
            f"{colorama.Fore.LIGHTMAGENTA_EX}{basename}{colorama.Style.RESET_ALL}")


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
        self.last_operation_src = None
        self.last_operation_time = None
        self.time_threshold = 1.0
        self.micro_time_threshold = 0.02
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
        self.last_operation_src = src_path
        self.last_operation_time = current_time

        self.queue.put(FileOperation(operation, src_path, dest_path, batch_id=self.batch_id))

    def on_created(self, event):
        op = 'mkdir' if event.is_directory else 'upload'
        self.queue_operation(op, event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            # check for file modified event right after file created event
            # to avoid duplicate uploads. This seems to happen when
            # user duplicates file(s) in Finder
            if self.last_operation_time and \
               self.last_operation != 'upload' and \
               self.last_operation_src != event.src_path and \
               time.time() - self.last_operation_time > self.micro_time_threshold:
                self.queue_operation('upload', event.src_path)

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
        self.ftps = FTP_TLS()
        self.errors = set()
        self.is_connected = False
        self.is_active = True  # set to False on permanent connect error. It's dead, Jim
        self.logger = logger

    def __del__(self):
        self.disconnect()

    def log_success(self, operation, *paths):
        (path, *rest) = paths
        base = self.local_folder if operation == 'Uploaded' else self.remote_dir
        path = colorize_path(path, base)
        path2 = colorize_path(rest[0], self.remote_dir) if rest else None
        txt = f'{path} -> {path2}' if path2 else path
        self.logger.info(f"{colorama.Fore.GREEN}{operation}{colorama.Style.RESET_ALL}: {txt}")

    def connect(self):
        if not self.is_active:
            return False
        if self.is_connected:
            return True

        def do_connect(name):
            self.logger.info(f'Connecting to {name}..')
            self.ftps.connect(self.ftp_host)
            self.ftps.login(self.ftp_user, self.ftp_pwd)
            self.ftps.prot_p()
            self.is_connected = True
            return True

        name = f'{self.ftp_user}@{self.ftp_host}'
        return self.do_op(do_connect, 'connect', name, log_success=False)

    def disconnect(self):
        if self.is_connected:
            try:
                self.ftps.quit()
            except Exception:
                pass
            finally:
                self.is_connected = False

    def do_op(self, func, op_name, *args, log_success=True, **kwargs):
        if not self.is_active:
            return False

        for attempt in range(FTP_MAX_RETRIES):

            if op_name != 'connect' and not self.connect():
                return False

            if len(args) > 1:
                args_str = f"{args[0]} -> {args[1]}"
            elif len(args) == 1:
                args_str = args[0]
            else:
                args_str = ''
            try:
                res = func(*args, **kwargs)
                if res and log_success:
                    verb = f"{op_name.capitalize()}{'d' if op_name.endswith('e') else 'ed'}"
                    self.log_success(verb, *args)
                return res
            except Exception as e:
                perm = isinstance(e, (error_perm, gaierror))
                if perm and op_name == 'connect':
                    self.logger.error(f"Failed to connect to {args_str}: {e}")
                    self.logger.critical("Permanent error. Stopping this profile.")
                    self.is_active = False
                    return False
                if perm or attempt >= FTP_MAX_RETRIES - 1:
                    quit = '' if perm else f'Gave up after {FTP_MAX_RETRIES} attempts.'
                    self.logger.error(f"Failed to {op_name} {args_str}: {e}. {quit}")
                    return False
                self.logger.warning(f"Unable to {op_name} {args_str}: {e}. Retrying in {FTP_RETRY_DELAY} seconds...")
                self.disconnect()
                time.sleep(FTP_RETRY_DELAY)

    def get_remote_path(self, src_path):
        relative_path = os.path.relpath(src_path, start=self.local_folder)
        relative_path = os.path.normpath(relative_path).replace(os.sep, '/')
        return f'{self.remote_dir}/{relative_path}'

    def upload(self, src_path):
        def do_upload(src_path, remote_path):
            try:
                with open(src_path, 'rb') as f:
                    self.ftps.storbinary(f'STOR {remote_path}', f)
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
            return True

        remote_path = self.get_remote_path(src_path)
        return self.do_op(do_delete_file, 'delete', remote_path)

    def rename(self, src_path, dest_path, op='rename'):
        def do_rename(remote_path, remote_dest_path):
            self.ftps.rename(remote_path, remote_dest_path)
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
                        self.log_success('Created', os.path.join(self.remote_dir, relative_path))
                        self.ftps.cwd(dir)
            return True

        remote_path = self.get_remote_path(src_path)
        return self.do_op(do_make_dir, 'mkdir', remote_path, log_success=False)

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
                            self.log_success('Deleted', full_path)
                        except Exception as e:
                            counts['delete']['failure'] += 1
                            self.logger.error(f"Unable to delete {full_path}: {e}")

                self.ftps.rmd(path)
                counts['rmdir']['success'] += 1
                self.log_success('Removed', path)
            except error_perm as e:
                counts['rmdir']['failure'] += 1
                self.logger.error(f"Unable to delete {path}: {e}")

            return counts

        remote_path = self.get_remote_path(src_path)
        return self.do_op(do_delete_dir, 'rmdir', remote_path, log_success=False)


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
            self.logger.info(f"{colorama.Fore.CYAN}Batch Summary:{colorama.Style.RESET_ALL}")
            total = self.counts.pop('total')
            for op, counts in self.counts.items():
                self.logger.info(f"{colorama.Fore.CYAN}{op.capitalize()}{colorama.Style.RESET_ALL}: "
                                 f"{colorama.Fore.GREEN}{counts['success']} successful{colorama.Style.RESET_ALL}, "
                                 f"{colorama.Fore.RED}{counts['failure']} failed{colorama.Style.RESET_ALL}, "
                                 f"{colorama.Fore.YELLOW}{counts['ignored']} ignored{colorama.Style.RESET_ALL}")
            self.logger.info(f"{colorama.Fore.CYAN}Total{colorama.Style.RESET_ALL}: "
                             f"{colorama.Fore.GREEN}{total['success']} successful{colorama.Style.RESET_ALL}, "
                             f"{colorama.Fore.RED}{total['failure']} failed{colorama.Style.RESET_ALL}, "
                             f"{colorama.Fore.YELLOW}{total['ignored']} ignored{colorama.Style.RESET_ALL}")

            duration = time.time() - self.start_time
            self.logger.info(f"{colorama.Fore.CYAN}Batch duration:{colorama.Style.RESET_ALL} {duration:.2f} seconds")


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
                if self.batch_tracker:
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
        self.logger = logging.getLogger(self.name)

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
        self.logger.info("Stopped monitoring")

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
        files_to_sync = get_files_to_sync(profile['local'], modified_since, profile['ignore_regex'])

        if not files_to_sync:
            print(f"{profile['name']}: Nothing to sync.")
            continue

        if not execute:
            print(f"Preview for {profile['name']}:")
            for file in files_to_sync:
                print(f"  {colorize_path(file, profile['local'])}")
            continue

        sync_manager = SyncManager(profile)
        logger.info(f"Syncing profile {profile['name']}: {profile['local']} -> {profile['remote']}")
        for file_path in files_to_sync:
            sync_manager.queue.put(FileOperation('upload', file_path, batch_id=1))

        sync_manager.queue_handler.start()
        sync_manager.queue.join()  # Wait for all tasks to be processed
        sync_manager.queue_handler.stop()
        sync_manager.ftps_handler.disconnect()
        print()


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
        print()
        logger.info("Script interrupted")
    finally:
        clean_up(sync_managers)


if __name__ == "__main__":

    (profiles, args) = load_settings()

    if args.modified:
        manual_sync(profiles, args.modified, args.execute)
    else:
        monitor_profiles(profiles)
