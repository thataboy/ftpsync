import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from ftplib import FTP_TLS, error_perm, error_temp
import re
import time
import sys
from queue import Queue, Empty
from threading import Thread, Event
from crypty import encrypt, decrypt
from config_loader import load_config

SYNC_FILE_DELETION = True
SYNC_FOLDER_DELETION = True
ENCRYPT_PASSWORD = True

ERR_NO_DIR = 1
ERR_OTHER = 2


class FileOperation:
    def __init__(self, operation, file_path):
        self.operation = operation  # 'upload', 'delete', 'rmdir''
        self.file_path = file_path


class FTPSUploadHandler(FileSystemEventHandler):

    def __init__(self, queue, ignore_regex):
        self.queue = queue
        self.ignore_regex = re.compile(ignore_regex)

    def should_process(self, file_path):
        return self.ignore_regex is None or self.ignore_regex.search(file_path) is None

    def on_modified(self, event):
        if not event.is_directory and self.should_process(event.src_path):
            self.queue.put(FileOperation('upload', event.src_path))

    def on_created(self, event):
        if not event.is_directory and self.should_process(event.src_path):
            self.queue.put(FileOperation('upload', event.src_path))

    def on_deleted(self, event):
        if self.should_process(event.src_path):
            if event.is_directory:
                if SYNC_FOLDER_DELETION:
                    self.queue.put(FileOperation('rmdir', event.src_path))
            else:
                if SYNC_FILE_DELETION:
                    self.queue.put(FileOperation('delete', event.src_path))


class FTPSHandler:
    def __init__(self, profile):
        self.ftp_host = profile['host']
        self.ftp_user = profile['user']
        self.ftp_pwd = decrypt(profile['pwd']) if ENCRYPT_PASSWORD else profile['password']
        self.remote_dir = profile['remote']
        self.local_folder = profile['local']
        self.ftps = None
        self.errors = set()

    def connect(self):
        self.ftps = FTP_TLS(self.ftp_host)
        self.ftps.login(self.ftp_user, self.ftp_pwd)
        self.ftps.prot_p()
        self.ftps.cwd(self.remote_dir)

    def close_connection(self):
        if self.ftps:
            try:
                self.ftps.quit()
            finally:
                self.ftps = None

    def get_remote_path(self, file_path):
        """
        Translate local to remote path based
        on the `local` and `remote` root folders in config
        """
        relative_path = os.path.relpath(file_path, start=self.local_folder)
        # normalize path so Windows path becomes Unix path
        relative_path = os.path.normpath(relative_path).replace(os.sep, '/')
        return f'{self.remote_dir}/{relative_path}'

    def upload_file(self, file_path):
        if self.ftps is None:
            self.connect()

        remote_path = self.get_remote_path(file_path)

        if ERR_NO_DIR in self.errors:
            self.errors.discard(ERR_NO_DIR)
            remote_dir = os.path.dirname(remote_path)
            self.makedir(remote_dir)

        try:
            with open(file_path, 'rb') as f:
                self.ftps.storbinary(f'STOR {remote_path}', f)
            print(f"Uploaded: {file_path} -> {remote_path} at {time.ctime()}")
        except (error_perm, error_temp):
            self.errors.add(ERR_NO_DIR)
            self.upload_file(file_path)
        except Exception as e:
            retry = ERR_OTHER not in self.errors
            print(f"Failed to upload {file_path}: {e}."
                  + " Retrying..." if retry else "")
            if retry:
                # time.sleep(3)
                self.ftps = None
                self.errors.add(ERR_OTHER)
                self.upload_file(file_path)
            self.errors.discard(ERR_OTHER)

    def delete_file(self, file_path):
        if self.ftps is None:
            self.connect()

        remote_path = self.get_remote_path(file_path)

        try:
            self.ftps.delete(remote_path)
            print(f"Deleted: {remote_path} at {time.ctime()}")
        except (error_perm, error_temp) as e:
            print(f"{e}.")
        except Exception as e:
            retry = ERR_OTHER not in self.errors
            print(f"Failed to delete {remote_path}: {e}."
                  + " Retrying..." if retry else "")
            if retry:
                # time.sleep(3)
                self.ftps = None
                self.errors.add(ERR_OTHER)
                self.delete_file(file_path)
            self.errors.discard(ERR_OTHER)

    def delete_dir(self, file_path):
        remote_path = self.get_remote_path(file_path)
        self.do_delete_dir(remote_path)

    def do_delete_dir(self, path):
        """
        Recursively deletes a remote ftp folder and its contents.
        """
        print(f'Removing: {path}')

        if self.ftps is None:
            self.connect()

        try:
            # get listing with type (file or dir or ??)
            listing = self.ftps.mlsd(path, facts=['type'])

            for (item, fact) in listing:
                if item in ['.', '..']:
                    continue
                full_path = f"{path}/{item}"
                if fact['type'] == 'dir':
                    # Recursively delete subdirectory
                    self.do_delete_dir(full_path)
                elif fact['type'] == 'file':
                    try:
                        self.ftps.delete(full_path)
                        print(f'Deleted: {full_path}')
                    except Exception as e:
                        print(f"{e}.")

            # Delete the now (hopefully) empty directory
            try:
                self.ftps.rmd(path)
                print(f'Removed: {path}')
            except Exception as e:
                print(f"{e}.")

        except (error_perm, error_temp) as e:
            print(f"{path} does not seem to exist on server.")
            return
        except Exception as e:
            retry = ERR_OTHER not in self.errors
            print(f"Failed to list {path}: {e}."
                  + " Retrying" if retry else "")
            if retry:
                # time.sleep(3)
                self.ftps = None
                self.errors.add(ERR_OTHER)
                self.do_delete_dir(path)
            self.errors.discard(ERR_OTHER)
            return

    def makedir(self, remote_dir):
        self.ftps.cwd(self.remote_dir)
        relative_path = os.path.relpath(remote_dir, start=self.remote_dir)
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


class QueueHandler:
    def __init__(self, queue, ftps_handler):
        self.queue = queue
        self.ftps_handler = ftps_handler
        self.stop_event = Event()

    def process_queue(self):
        while not self.stop_event.is_set():
            try:
                operation = self.queue.get(timeout=1)  # Wait for 1 second
                if operation.operation == 'upload':
                    self.ftps_handler.upload_file(operation.file_path)
                elif operation.operation == 'delete':
                    self.ftps_handler.delete_file(operation.file_path)
                elif operation.operation == 'rmdir':
                    self.ftps_handler.delete_dir(operation.file_path)
                self.queue.task_done()
            except Empty:
                continue  # If queue is empty, continue the loop

    def stop(self):
        self.stop_event.set()


def start_monitor(names, profiles):
    observers = []
    queue_handlers = []

    for name in names:
        profile = profiles[name]

        if profile['local'].startswith('~'):
            profile['local'] = os.path.expanduser(profile['local'])

        ignore_regex = profile.get('ignore_regex')

        queue = Queue()
        ftps_handler = FTPSHandler(profile)
        event_handler = FTPSUploadHandler(queue, ignore_regex)

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
            print(f"Warning: An observer didn't stop cleanly and may still be running.")

    # Stop all queue handlers and wait for queues to finish
    for queue_handler, queue_thread, queue in queue_handlers:
        queue_handler.stop()

    # Wait for queue threads to finish (with timeout)
    for _, queue_thread, _ in queue_handlers:
        queue_thread.join(timeout=2)  # Wait for up to 2 seconds
        if queue_thread.is_alive():
            print(f"Warning: A queue thread didn't stop cleanly and may still be running.")

    # Close all FTP connections
    for _, handler in observers:
        try:
            handler.close_connection()
        except Exception:
            continue

    print('Cleanup completed')


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"USAGE: {os.path.basename(__file__)} profile_name1 profile_name2 ...")
        print(f"   or  {os.path.basename(__file__)} all")
        exit()

    ini_path = os.path.join(os.path.dirname(__file__), 'ftpsync.ini')
    profiles = load_config(ini_path, ENCRYPT_PASSWORD)

    # get names of profiles from command line
    names = profiles.keys() if sys.argv[1] else sys.argv[1:]
    names = [name for name in names if profiles.get(name)]

    print()
    (observers, queue_handlers) = start_monitor(names, profiles)
    print()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nScript interrupted")
    finally:
        clean_up(observers, queue_handlers)
