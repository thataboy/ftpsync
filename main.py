import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from ftplib import FTP_TLS, error_perm, error_temp
import time
import sys
from queue import Queue, Empty
from threading import Thread, Event
from crypty import decrypt
from config_loader import load_config, ENCRYPT_PASSWORD

from enum import Enum

SYNC_FILE_DELETION = True
SYNC_FOLDER_DELETION = True
SYNC_FILE_MOVE = True
SYNC_FOLDER_MOVE = True
MAX_RETRIES = 3
RETRY_DELAY = 3  # seconds


class FtpError(Enum):
    NO_AUTHENTICATION = 1
    NO_SUCH_FILE_OR_DIR = 2
    OTHER = 9


class FileOperation:
    def __init__(self, operation, src_path, dest_path=None):
        self.operation = operation
        self.src_path = src_path
        self.dest_path = dest_path


class FileMonitorHandler(FileSystemEventHandler):

    def __init__(self, queue, ignore_regex):
        self.queue = queue
        self.ignore_regex = ignore_regex

    def should_process(self, src_path):
        return self.ignore_regex is None or self.ignore_regex.search(src_path) is None

    def on_modified(self, event):
        # print(f'{event}')
        if not event.is_directory and self.should_process(event.src_path):
            # when you duplicate a file, Mac generates a FileCreatedEvent
            # and FileModifiedEvent in quick succession, causing duplicate upload
            stat_result = os.stat(event.src_path)
            ctime = stat_result.st_ctime
            mtime = stat_result.st_mtime
            if mtime - ctime > 0.05:
                self.queue.put(FileOperation('upload', event.src_path))

    def on_created(self, event):
        # print(f'{event}')
        if self.should_process(event.src_path):
            op = 'mkdir' if event.is_directory else 'upload'
            self.queue.put(FileOperation(op, event.src_path))

    def on_deleted(self, event):
        # print(f'{event}')
        if not SYNC_FOLDER_DELETION and event.is_directory or \
           not SYNC_FILE_DELETION and not event.is_directory or \
           not self.should_process(event.src_path):
            return
        op = 'rmdir' if event.is_directory else 'delete'
        self.queue.put(FileOperation(op, event.src_path))

    def on_moved(self, event):
        if not SYNC_FOLDER_MOVE and event.is_directory or \
           not SYNC_FILE_MOVE and not event.is_directory or \
           not self.should_process(event.src_path):
            return
        # when you rename/move a folder, Mac seems to send a DirMovedEvent
        # followed by a FileMovedEvent for all the files in the folder, too
        # so we have to check to see if parent folder is still there
        # to prevent lots of errors when moving non existent files on server
        if not os.path.exists(os.path.dirname(event.src_path)):
            return
        # moving to same folder => renaming
        op = 'rename' if os.path.dirname(event.src_path) == os.path.dirname(event.dest_path) else 'move'
        self.queue.put(FileOperation(op, event.src_path, event.dest_path))


class FTPSHandler:
    def __init__(self, profile):
        self.ftp_host = profile['host']
        self.ftp_user = profile['user']
        self.ftp_pwd = decrypt(profile['pwd']) if ENCRYPT_PASSWORD else profile['password']
        self.remote_dir = profile['remote']
        self.local_folder = profile['local']
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

        return self._perform_operation(perform_connect, 'connect')

    def disconnect(self):
        if self.ftps:
            try:
                self.ftps.quit()
            except Exception:
                pass
            finally:
                self.ftps = None

    def _perform_operation(self, func, operation, *args, **kwargs):
        """
        The main retry and exception handling loop for FTPSHandler

        Args:
            func (callable): The function (FTP operation) to call.
                func should return boolean to indicate succesful operation,
                or causes an Exception
            operation (str): The name of the operation (for logging purposes).
            *args, **kwargs: args and kwargs to pass to func

        Returns:
            (boolean) whether operation was successful.

        Notes:
            This method will retry the operation up to self.max_retries times if it fails,
            waiting self.retry_delay seconds between retries.
        """

        # don't bother if previously got authentication error
        if FtpError.NO_AUTHENTICATION in self.errors:
            return False

        for attempt in range(self.max_retries):
            if operation != 'connect' and not self.connect():
                return False
            try:
                return func(*args)
            except (error_perm, Exception) as e:
                if len(args) > 1:
                    txt = f"{args[0]} -> {args[1]}"
                elif len(args) == 1:
                    txt = args[0]
                else:
                    txt = ''
                perm = isinstance(e, error_perm)
                if perm and operation == 'connect':
                    self.errors.add(FtpError.NO_AUTHENTICATION)
                    print(f"Cannot connect to {self.ftp_host}: {e}.")
                    print(f"Dave, this conversation can serve no purpose anymore. Goodbye.")
                    return False
                if perm or attempt >= self.max_retries - 1:
                    quit = '' if perm else f'Gave up after {self.max_retries} attempts.'
                    print(f"Failed to {operation} {txt}: {e}. {quit}")
                    return False
                print(f"Unable to {operation} {txt}: {e}. Retrying in {self.retry_delay} seconds...")
                self.disconnect()
                time.sleep(self.retry_delay)

    def get_remote_path(self, src_path):
        """
        Translate local to remote path based on the `local` and `remote` root folders in config
        """
        relative_path = os.path.relpath(src_path, start=self.local_folder)
        # normalize path so Windows path becomes Unix path
        relative_path = os.path.normpath(relative_path).replace(os.sep, '/')
        return f'{self.remote_dir}/{relative_path}'

    def upload(self, src_path):

        def upload_operation(src_path, remote_path):

            def do_upload(src_path, remote_path):
                with open(src_path, 'rb') as f:
                    self.ftps.storbinary(f'STOR {remote_path}', f)
                print(f"Uploaded: {src_path} -> {remote_path} at {time.ctime()}")
                return True

            try:
                # just upload the file, don't bother checking if remote dir exists
                return do_upload(src_path, remote_path)
            except error_perm:
                # oops, guess it doesn't exist, better make it
                remote_dir = os.path.dirname(remote_path)
                print(f'mkdir {remote_dir}')
                if self.do_make_dir(remote_dir):
                    return do_upload(src_path, remote_path)

        remote_path = self.get_remote_path(src_path)
        return self._perform_operation(upload_operation, 'upload', src_path, remote_path)

    def delete_file(self, src_path):

        def delete_operation(remote_path):
            self.ftps.delete(remote_path)
            print(f"Deleted: {remote_path} at {time.ctime()}")
            return True

        remote_path = self.get_remote_path(src_path)
        self._perform_operation(delete_operation, 'delete', remote_path)

    def rename(self, src_path, dest_path, op='rename'):

        def rename_operation(remote_path, remote_dest_path):
            self.ftps.rename(remote_path, remote_dest_path)
            print(f"{op.capitalize()}d: {remote_path} to {remote_dest_path} at {time.ctime()}")
            return True

        remote_path = self.get_remote_path(src_path)
        remote_dest_path = self.get_remote_path(dest_path)
        return self._perform_operation(rename_operation, op, remote_path, remote_dest_path)

    def move(self, src_path, dest_path):
        """move file or dir"""
        if self.make_dir(os.path.dirname(dest_path)):
            self.rename(src_path, dest_path, op='move')

    def make_dir(self, src_path):

        def make_dir_operation(remote_path):
            self.ftps.cwd(self.remote_dir)  # change to root folder
            relative_path = os.path.relpath(remote_path, start=self.remote_dir)
            dirs = relative_path.split('/')
            for dir in dirs:
                if dir:
                    try:
                        self.ftps.cwd(dir)
                        return True
                    except Exception:
                        print(f"Creating directory {dir}.")
                        self.ftps.mkd(dir)
                        self.ftps.cwd(dir)
                        return True
            return False

        remote_path = self.get_remote_path(src_path)
        return self._perform_operation(make_dir_operation, 'mkdir', remote_path)

    def delete_dir(self, src_path):

        def delete_dir_operation(remote_path):
            return self.do_delete_dir(remote_path)

        remote_path = self.get_remote_path(src_path)
        return self._perform_operation(delete_dir_operation, 'rmdir', remote_path)

    def do_delete_dir(self, path):
        try:
            listing = self.ftps.mlsd(path, facts=['type'])
            for (item, fact) in listing:
                if item in ['.', '..']:
                    continue
                full_path = f"{path}/{item}"
                if fact['type'] == 'dir':
                    self.do_delete_dir(full_path)
                elif fact['type'] == 'file':
                    try:
                        self.ftps.delete(full_path)
                        print(f'Deleted: {full_path}')
                    except Exception as e:
                        print(f"Unable to delete {full_path} {e}.")
            self.ftps.rmd(path)
            print(f'Removed: {path}')
            return True
        except error_perm as e:
            print(f"{path} does not seem to exist on server. {e}")
        return False

    def do_make_dir(self, remote_path):
        self.ftps.cwd(self.remote_dir)  # change to root folder
        relative_path = os.path.relpath(remote_path, start=self.remote_dir)
        # ASSume FTP uses unix path
        dirs = relative_path.split('/')
        for dir in dirs:
            if dir:
                try:
                    self.ftps.cwd(dir)
                except Exception:
                    print(f"Creating directory {dir}.")
                    self.ftps.mkd(dir)
                    self.ftps.cwd(dir)
        return True


class QueueHandler:
    def __init__(self, queue, ftps_handler):
        self.queue = queue
        self.ftps_handler = ftps_handler
        self.stop_event = Event()

    def process_queue(self):
        while not self.stop_event.is_set():
            try:
                operation = self.queue.get(timeout=1)  # Wait for 1 second
                # print(operation.operation, operation.src_path, operation.dest_path)
                if operation.operation == 'upload':
                    self.ftps_handler.upload(operation.src_path)
                elif operation.operation == 'delete':
                    self.ftps_handler.delete_file(operation.src_path)
                elif operation.operation == 'mkdir':
                    self.ftps_handler.make_dir(operation.src_path)
                elif operation.operation == 'rmdir':
                    self.ftps_handler.delete_dir(operation.src_path)
                elif operation.operation == 'rename':
                    self.ftps_handler.rename(operation.src_path, operation.dest_path)
                elif operation.operation == 'move':
                    self.ftps_handler.move(operation.src_path, operation.dest_path)
                self.queue.task_done()
            except Empty:
                continue  # If queue is empty, continue the loop

    def stop(self):
        self.stop_event.set()


def start_monitor(profiles):
    observers = []
    queue_handlers = []

    for name, profile in profiles.items():

        ignore_regex = profile.get('ignore_regex')

        queue = Queue()
        ftps_handler = FTPSHandler(profile)
        event_handler = FileMonitorHandler(queue, ignore_regex)

        queue_handler = QueueHandler(queue, ftps_handler)
        queue_thread = Thread(target=queue_handler.process_queue)
        queue_thread.daemon = True
        queue_thread.start()

        observer = Observer()
        observer.schedule(event_handler, profile['local'], recursive=True)
        observer.start()
        observers.append((observer, ftps_handler))
        queue_handlers.append((queue_handler, queue_thread, queue))

        print(f"Monitoring {name}: {profile['local']} -> {profile['remote']}")
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
            print("Warning: An ππobserver didn't stop cleanly and may still be running.")

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


if __name__ == "__main__":
    if len(sys.argv) < 2:
        script = os.path.basename(__file__)
        print("USAGE:")
        print(f"       {script} profile_name1 profile_name2 ...")
        print(f"   or  {script} all      to use all profiles")
        print(f"   or  {script} ALL      to use all profiles, override disabled")
        exit()

    ini_path = os.path.join(os.path.dirname(__file__), 'ftpsync.ini')

    if not os.path.exists(ini_path):
        print(f'{ini_path} does not exist.')
        exit()

    profiles = load_config(ini_path, sys.argv)
    if len(profiles) == 0:
        print('No valid profiles enabled. Nothing to do.')
        exit()

    print()
    (observers, queue_handlers) = start_monitor(profiles)
    print()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nScript interrupted")
    finally:
        clean_up(observers, queue_handlers)
