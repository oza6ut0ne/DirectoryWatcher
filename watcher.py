import ctypes.wintypes
import datetime
import os
import re
import threading


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


class Logger():
    lock = threading.Lock()

    @classmethod
    def set_filepath(self, filepath):
        self.filepath = filepath

    @classmethod
    def log(self, *args, **kargs):
        with self.lock:
            try:
                self.__log(self, *args, **kargs)
            except AttributeError:
                print(*args, **kargs)

    def __log(self, *args, **kargs):
        with open(self.filepath, 'a') as f:
            print(*args, **kargs, file=f)


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


def watch_directory(directory_path, recursive=True, dump=True,
                    oneline=False, match=None, exclude=None):
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

        results = parse_event_buffer(event_buffer, nbytes)
        for action, filename in results:
            now = datetime.datetime.now()
            date = now.strftime('[%Y/%m/%d %X]')

            logmessages = ['']
            if oneline:
                logmessages[-1] += date
            elif action != FILE_ACTION_RENAMED_NEW_NAME:
                logmessages[-1] += ('\n' + date + '\n')

            fullpath = os.path.join(directory_path, filename)
            if match is not None and not re.search(match, fullpath):
                continue
            if exclude is not None and re.search(exclude, fullpath):
                continue

            if action == FILE_ACTION_CREATED:
                logmessages[-1] += ('[ + ] ' + ('' if oneline else 'Created ') + fullpath)
            elif action == FILE_ACTION_DELETED:
                logmessages[-1] += ('[ - ] ' + ('' if oneline else 'Deleted ') + fullpath)
            elif action == FILE_ACTION_MODIFIED:
                if os.path.isdir(fullpath):
                    continue
                logmessages[-1] += ('[ * ] ' + ('' if oneline else 'Modified ') + fullpath)

                if dump:
                    if not oneline:
                        logmessages.append('[vvv] Dumping contents...')
                    try:
                        f = open(fullpath, "rb")
                        contents = f.read()
                        f.close()
                        logmessages.append(contents.decode('sjis'))
                        if not oneline:
                            logmessages.append('[^^^] Dump complete.')
                    except Exception as e:
                        logmessages.append('[!!!] <%s> %s' % (e.__class__.__name__, e))
                        if not oneline:
                            logmessages.append('[!!!] Dump failed.')

            elif action == FILE_ACTION_RENAMED_OLD_NAME:
                logmessages[-1] += ('[ > ] ' + ('' if oneline else 'Renamed from: ') + fullpath)
            elif action == FILE_ACTION_RENAMED_NEW_NAME:
                logmessages[-1] += ('[ < ] ' + ('' if oneline else 'Renamed to: ') + fullpath)
            else:
                logmessages[-1] += ('[???] ' + ('' if oneline else 'Unknown: ') + fullpath)

            Logger.log('\n'.join(logmessages), flush=True)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('paths', nargs='*', default=['.'])
    parser.add_argument('-r', '--recursive', action='store_true')
    parser.add_argument('-d', '--dump', action='store_true')
    parser.add_argument('-o', '--oneline', action='store_true')
    parser.add_argument('-m', '--match')
    parser.add_argument('-e', '--exclude')
    args = parser.parse_args()

    for path in args.paths:
        abspath = os.path.abspath(path)
        monitor_thread = threading.Thread(
            target=watch_directory,
            args=(abspath, args.recursive, args.dump, args.oneline, args.match, args.exclude)
        )
        Logger.log('Spawning monitoring thread for path: %s' % abspath)
        monitor_thread.start()
