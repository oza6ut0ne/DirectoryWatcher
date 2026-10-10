#!/usr/bin/env python3

import ctypes
from datetime import datetime
from logging import getLogger, INFO, Formatter, StreamHandler, FileHandler
import os
import re
import struct
import sys
import threading

IS_WINDOWS = sys.platform == 'win32'
IS_LINUX = sys.platform.startswith('linux')

if IS_WINDOWS:
    import ctypes.wintypes


def _norm(path):
    return path.casefold() if IS_WINDOWS else path


LOG_DIR = 'log'
LOG_FILE_NAME = LOG_DIR + os.sep + datetime.now().strftime('%F_%H-%M-%S.log')
LOG_FILE_PATH = _norm(os.path.abspath(LOG_FILE_NAME))

if os.path.exists(LOG_DIR):
    if os.path.isfile(LOG_DIR):
        raise RuntimeError('cannot create directory "log"')
else:
    os.mkdir(LOG_DIR)

logger = getLogger(__name__)
logger.setLevel(INFO)
formatter = Formatter(fmt='[%(asctime)s.%(msecs)03d]%(message)s',
                      datefmt='%Y/%m/%d %X')

stream_handler = StreamHandler()
stream_handler.setFormatter(formatter)
stream_handler.setLevel(INFO)
logger.addHandler(stream_handler)

file_handler = FileHandler(LOG_FILE_NAME)
file_handler.setFormatter(formatter)
file_handler.setLevel(INFO)
logger.addHandler(file_handler)


if IS_WINDOWS:
    kernel32 = ctypes.windll.kernel32

    FILE_NOTIFY_CHANGE_FILE_NAME = 0x01
    FILE_NOTIFY_CHANGE_DIR_NAME = 0x02
    FILE_NOTIFY_CHANGE_ATTRIBUTES = 0x04
    FILE_NOTIFY_CHANGE_SIZE = 0x08
    FILE_NOTIFY_CHANGE_LAST_WRITE = 0x010
    FILE_NOTIFY_CHANGE_LAST_ACCESS = 0x020
    FILE_NOTIFY_CHANGE_CREATION = 0x040
    FILE_NOTIFY_CHANGE_SECURITY = 0x0100

    FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    FILE_FLAG_OVERLAPPED = 0x40000000
    FILE_LIST_DIRECTORY = 1
    FILE_SHARE_READ = 0x01
    FILE_SHARE_WRITE = 0x02
    FILE_SHARE_DELETE = 0x04
    OPEN_EXISTING = 3

    FILE_ACTION_CREATED = 1
    FILE_ACTION_DELETED = 2
    FILE_ACTION_MODIFIED = 3
    FILE_ACTION_RENAMED_OLD_NAME = 4
    FILE_ACTION_RENAMED_NEW_NAME = 5

    FILE_NOTIFY_FLAGS = \
        FILE_NOTIFY_CHANGE_FILE_NAME \
      | FILE_NOTIFY_CHANGE_DIR_NAME \
      | FILE_NOTIFY_CHANGE_ATTRIBUTES \
      | FILE_NOTIFY_CHANGE_SIZE \
      | FILE_NOTIFY_CHANGE_LAST_WRITE \
      | FILE_NOTIFY_CHANGE_LAST_ACCESS \
      | FILE_NOTIFY_CHANGE_CREATION \
      | FILE_NOTIFY_CHANGE_SECURITY


    class FILE_NOTIFY_INFORMATION(ctypes.Structure):
        _fields_ = [('NextEntryOffset', ctypes.wintypes.DWORD),
                    ('Action', ctypes.wintypes.DWORD),
                    ('FileNameLength', ctypes.wintypes.DWORD),
                    ('FileName', (ctypes.c_char * 1))]

    LPFNI = ctypes.POINTER(FILE_NOTIFY_INFORMATION)


    def get_handle(path):
        handle = kernel32.CreateFileW(
            path,
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None
        )
        return handle


    def parse_event_buffer(buffer, nbytes):
        results = []
        while nbytes.value > 0:
            fni = ctypes.cast(buffer, LPFNI)[0]
            ptr = ctypes.addressof(fni) + FILE_NOTIFY_INFORMATION.FileName.offset
            filename = ctypes.string_at(ptr, fni.FileNameLength)
            results.append((fni.Action, filename.decode('utf-16')))
            offset = fni.NextEntryOffset
            if offset == 0:
                break
            buffer = buffer[offset:]
            nbytes.value -= offset
        return results


    def _events_windows(directory_path, recursive):
        handle = get_handle(directory_path)
        event_buffer = ctypes.create_string_buffer(2048)
        nbytes = ctypes.wintypes.DWORD()

        while True:
            kernel32.ReadDirectoryChangesW(
                handle,
                ctypes.byref(event_buffer),
                len(event_buffer),
                recursive,
                FILE_NOTIFY_FLAGS,
                ctypes.byref(nbytes),
                None,
                None
            )

            for action, filename in parse_event_buffer(event_buffer, nbytes):
                yield action, os.path.join(directory_path, filename)

else:
    FILE_ACTION_CREATED = 1
    FILE_ACTION_DELETED = 2
    FILE_ACTION_MODIFIED = 3
    FILE_ACTION_RENAMED_OLD_NAME = 4
    FILE_ACTION_RENAMED_NEW_NAME = 5

if IS_LINUX:
    IN_MODIFY = 0x00000002
    IN_MOVED_FROM = 0x00000040
    IN_MOVED_TO = 0x00000080
    IN_CREATE = 0x00000100
    IN_DELETE = 0x00000200
    IN_Q_OVERFLOW = 0x00004000
    IN_IGNORED = 0x00008000
    IN_ISDIR = 0x40000000
    IN_CLOEXEC = 0o2000000

    IN_WATCH_FLAGS = IN_MODIFY | IN_MOVED_FROM | IN_MOVED_TO | IN_CREATE | IN_DELETE

    INOTIFY_EVENT_FMT = 'iIII'  # wd, mask, cookie, len
    INOTIFY_EVENT_SIZE = struct.calcsize(INOTIFY_EVENT_FMT)

    libc = ctypes.CDLL(None, use_errno=True)
    libc.inotify_init1.argtypes = [ctypes.c_int]
    libc.inotify_init1.restype = ctypes.c_int
    libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p,
                                       ctypes.c_uint32]
    libc.inotify_add_watch.restype = ctypes.c_int

    def _oserror():
        err = ctypes.get_errno()
        return OSError(err, os.strerror(err))

    def _events_linux(directory_path, recursive):
        fd = libc.inotify_init1(IN_CLOEXEC)
        if fd < 0:
            raise _oserror()

        watches = {}  # wd -> directory path

        def add_watch(path):
            wd = libc.inotify_add_watch(fd, os.fsencode(path), IN_WATCH_FLAGS)
            if wd < 0:
                return None
            watches[wd] = path
            return wd

        def add_tree(top, emit):
            for dirpath, dirnames, filenames in os.walk(top):
                if add_watch(dirpath) is None:
                    continue
                if emit:
                    for name in dirnames + filenames:
                        yield FILE_ACTION_CREATED, os.path.join(dirpath, name)

        try:
            if add_watch(directory_path) is None:
                raise _oserror()
            if recursive:
                for _ in add_tree(directory_path, False):
                    pass

            while watches:
                buf = os.read(fd, 65536)
                pos = 0
                while pos < len(buf):
                    wd, mask, _cookie, length = struct.unpack_from(
                        INOTIFY_EVENT_FMT, buf, pos)
                    pos += INOTIFY_EVENT_SIZE
                    name = buf[pos:pos + length].rstrip(b'\0')
                    pos += length

                    if mask & IN_Q_OVERFLOW:
                        logger.warning('[!!!] inotify queue overflowed; '
                                       'some events were lost.')
                        continue
                    if mask & IN_IGNORED:
                        watches.pop(wd, None)
                        continue
                    base = watches.get(wd)
                    if base is None or not name:
                        continue
                    fullpath = os.path.join(base, os.fsdecode(name))

                    if mask & IN_CREATE:
                        action = FILE_ACTION_CREATED
                    elif mask & IN_DELETE:
                        action = FILE_ACTION_DELETED
                    elif mask & IN_MODIFY:
                        action = FILE_ACTION_MODIFIED
                    elif mask & IN_MOVED_FROM:
                        action = FILE_ACTION_RENAMED_OLD_NAME
                    elif mask & IN_MOVED_TO:
                        action = FILE_ACTION_RENAMED_NEW_NAME
                    else:
                        continue
                    yield action, fullpath

                    if (recursive and mask & IN_ISDIR
                            and mask & (IN_CREATE | IN_MOVED_TO)):
                        yield from add_tree(fullpath, True)
        finally:
            os.close(fd)


def _decode(contents):
    for encoding in ('utf-8', 'sjis'):
        try:
            return contents.decode(encoding)
        except UnicodeDecodeError:
            pass
    return contents.decode('utf-8', errors='replace')


def watch_directory(directory_path, recursive=True, dump=True,
                    match=None, exclude=None):
    if IS_WINDOWS:
        events = _events_windows(directory_path, recursive)
    elif IS_LINUX:
        events = _events_linux(directory_path, recursive)
    else:
        raise RuntimeError('unsupported platform: ' + sys.platform)

    for action, fullpath in events:
        if _norm(fullpath) == LOG_FILE_PATH:
            continue
        if match is not None and not re.search(match, fullpath):
            continue
        if exclude is not None and re.search(exclude, fullpath):
            continue

        if action == FILE_ACTION_CREATED:
            logger.info('[ + ] %s', fullpath)
        elif action == FILE_ACTION_DELETED:
            logger.info('[ - ] %s', fullpath)
        elif action == FILE_ACTION_MODIFIED:
            if os.path.isdir(fullpath):
                continue
            logmessages = []
            logmessages.append('[ * ] ' + fullpath)

            if dump:
                logmessages.append('[vvv] Dumping contents...')
                try:
                    f = open(fullpath, "rb")
                    contents = f.read()
                    f.close()
                    logmessages.append(_decode(contents))
                    logmessages.append('[^^^] Dump complete.')
                except Exception as e:
                    logmessages.append('[!!!] <%s> %s' % (e.__class__.__name__, e))
                    logmessages.append('[!!!] Dump failed.')

            logger.info('\n'.join(logmessages))

        elif action == FILE_ACTION_RENAMED_OLD_NAME:
            logger.info('[ < ] %s', fullpath)
        elif action == FILE_ACTION_RENAMED_NEW_NAME:
            logger.info('[ > ] %s', fullpath)
        else:
            logger.info('[???] %s', fullpath)



if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('paths', nargs='*', default=['.'])
    parser.add_argument('-r', '--recursive', action='store_true')
    parser.add_argument('-d', '--dump', action='store_true')
    parser.add_argument('-m', '--match')
    parser.add_argument('-e', '--exclude')
    args = parser.parse_args()

    for path in args.paths:
        abspath = os.path.abspath(path)
        monitor_thread = threading.Thread(
            target=watch_directory,
            args=(abspath, args.recursive, args.dump, args.match, args.exclude)
        )
        logger.info('Spawning monitoring thread for path: %s', abspath)
        monitor_thread.start()
