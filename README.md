# ftpsync

ftpsync is a Python application that helps web developers synchronize local files with remote FTPS servers. It monitors specified local folders and automatically uploads changes to the corresponding remote FTPS directories.

## Features

- Real-time file synchronization
- Support for multiple FTP profiles
- Secure FTP (FTPS)
- File and folder deletion/renaming/moving synchronization
- Customizable ignore patterns
- Threaded queue for efficient file operations
- Password encryption
- Hierarchical configuration with setting inheritance

The program works in two modes:

- Monitor: runs in the background, monitors for local file changes, and mirrors the changes to remote FTPS server
- Sync: does a one time upload of files that have been modified since some specified time, e.g., last 12 hours.

### Caveats

- ftpsync supports a one way local -> server sync only.

- It has a queuing system and each queue runs in a thread, so it can handle a sizeable file dump into a monitored folder. However, it is somewhat slow (because Python) and is intended to be used as a dev tool, not a robust FTP client.

- There are some weirdness when doing archive compression / decompression in the Mac Finder which causes problems for ftpsync. This doesn't appear to happen while working with archives in the shell.

## Requirements

- Python 3.6+
- configobj
- pycryptodome
- watchdog

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/thataboy/ftp-sync.git
   ```

2. Install the required dependencies:
   ```
   pip install configobj watchdog crypty
   ```

## Configuration

Create a `ftpsync.ini` file in the same directory as the script. Here's an example configuration:

```ini
ignore_regex = '''(
    ^\. |                  # ignore hidden files
    \/\. |                 # ignore hidden folder
    \.(tmp | log | bak)$ |
    __MACOSX |
    ftpsync\.ini$          # probably a good idea
    )'''

[mars]
host = ftp.mars.com

    [[mars.espresso]]
    user = thisboy
    password = 098765

        [[[mars.espresso.dev]]
        local = ~/mars/dev/espresso/
        remote = /public_html/mars/dev/espresso

        [[[mars.espresso.prod]]
        local = ~/mars/espresso/
        remote = /public_html/mars/espresso

    [[mars.mocha]]
    user = thatagirl
    password = 098765
    #...

[pluto]
host = ftp.pluto.com
user = daisy
password = hellothere
# ...

```

The file format is hopefully self-explanatory. It uses the familiar ini file structure where each section, denoted by `[name]`, and subsection, denoted by `[[name]]` represents a profile. Each profile consists of

- `host`: name of ftp host
- `user`: username
- `password`: password in plain text.
- `local`: the local folder to monitor for changes
- `remote`: the corresponding remote directory where files will be uploaded to
- `ignore_regex`: (optional) a regex string to indicate which files should be ignored
- `disabled`: (optional) set to 1 to disable the profile.

Each section inherits all settings above it and can override any setting. This avoids duplication and allows more concise and maintainable configs.

### Some notes on the config file

- The subsection indentation is just for looks and completely optional. It's not Python!

- The `remote` folder *must already exist*. The program will create sub-folders as needed but it will not create the "root" folder.

- **When you run the program, all plain text `password`s will be encrypted**. `password = 12345` becomes `pwd = ofTHava7Hj45pzI++fQdVQO6PRSbQh9TjCBXQvTIbU4=` (for example) and any changes are written to the ini file. If you need to change the password, simply add `password = newpassword` back in and it will be encrypted again when you run the program. The encryption key is randomly generated and placed in ~/.ftpsync.rand

- `ignore_regex` is compiled with the flag `re.VERBOSE`. What this means is white space in the regex will be ignored, so you may use blank spaces and newlines to make the regex more readable. You can also have comments, as the example shows. What this also means, however, is you must explicitly use `\s` to denote a space.

- `ignore_regex` can be multi lines. Wrap multi line strings with triple single `'''` or double quotes `"""`

## Usage

### Example

- Monitor `mars.espresso.dev`. Folder `~/mars/dev/espresso/` will be synced to remote directory `/public_html/mars/dev/`espresso
```
python main.py mars.espresso.dev
```

- Monitor all profiles under `mars`
```
python main.py mars
```

- Monitor all not disabled profiles
```
python main.py all
```

- Sync all files in mars.espresso.prod that have been changed in last 12h
```
python main.py --modified 12h --execute mars.espresso.prod
```

### Help

Run with -h flag to see all options

```
python main.py -h

FTP Sync Tool

positional arguments:
  profiles              Profile(s) to monitor or sync. Or all = all profiles; ALL = all profiles, including disabled ones

options:
  -h, --help            show this help message and exit
  -m MODIFIED, --modified MODIFIED
                        Sync files modified within <integer><time_unit> (e.g.: 30d | 12h | 15m | 30s)
  -x, --execute         Execute sync (by default, only show a preview)
```

## Additional Notes

The following constants in `main.py` control the sync behavior:

- `SYNC_FILE_DELETION`: Set to `True` to sync file deletions (default: True)
- `SYNC_FOLDER_DELETION`: Set to `True` to sync folder deletions (default: True)
- `SYNC_FILE_MOVE`: Set to `True` to sync file renames/moves (default: True)
- `SYNC_FOLDER_MOVE`: Set to `True` to sync folder renames/moves (default: True)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

[MIT License](LICENSE)


