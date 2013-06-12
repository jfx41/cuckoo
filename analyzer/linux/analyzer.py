# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import struct
import string
import random
import shutil
import pkgutil
import logging
import hashlib
import xmlrpclib
from ctypes import *
from time import sleep
from threading import Lock, Thread
from datetime import datetime

from lib.core.config import Config
from lib.common.constants import PATHS, TMP
from lib.common.results import upload_to_host
from lib.common.abstracts import Auxiliary, Package
from lib.core.startup import create_folders, init_logging
from lib.common.exceptions import CuckooError, CuckooPackageError
import modules.auxiliary as auxiliary

# This looks to be the ticket for our process management.
#from multiprocessing import Process, Manager, Pool

log = logging.getLogger()

BUFSIZE = 512
FILES_LIST = []
DUMPED_LIST = []
PROCESS_LIST = []
PROCESS_LOCK = Lock()

PID = os.getpid()
#PPID = Process(pid=PID).get_parent_pid()

## this is still preparation status - needs finalizing
def protected_filename(fname):
    """Checks file name against some protected names."""
    if not fname: return False

    protected_names = []
    for name in protected_names:
        if name in fname:
            return True

    return False

def add_pid(pid):
    """Add a process to process list."""
    if type(pid) == long or type(pid) == int or type(pid) == str:
        log.info("Added new process to list with pid: %s", pid)
        PROCESS_LIST.append(pid)

def add_pids(pids):
    """Add PID."""
    if type(pids) == list:
        for pid in pids:
            add_pid(pid)
    else:
        add_pid(pids)

def add_file(file_path):
    """Add a file to file list."""
    if file_path not in FILES_LIST:
        log.info("Added new file to list with path: %s", unicode(file_path).encode("utf-8", "replace"))
        FILES_LIST.append(file_path)

def dump_file(file_path):
    """Create a copy of the given file path."""
    try:
        if os.path.exists(file_path):
            sha256 = hashlib.sha256(open(file_path, "rb").read()).hexdigest()
            if sha256 in DUMPED_LIST:
                # The file was already dumped, just skip.
                return
        else:
            log.warning("File at path \"%s\" does not exist, skip", file_path)
            return
    except IOError as e:
        log.warning("Unable to access file at path \"%s\": %s", file_path, e)
        return

    # I'm not a Windows guy, but I'm guessing we don't need this anymore.
    #
    # 32k is the maximum length for a filename
    #path = create_unicode_buffer(32 * 1024)
    #name = c_wchar_p()
    #KERNEL32.GetFullPathNameW(file_path, 32 * 1024, path, byref(name))
    #file_path = path.value
    
    # Check if the path has a valid file name, otherwise it's a directory
    # and we should abort the dump.
    if os.path.isfile(file_path):
        # Should be able to extract Alternate Data Streams names too.
        file_name = os.path.basename(file_path)
    else:
        return

    upload_path = os.path.join("files", str(random.randint(100000000, 9999999999)), file_name)
    try:
        # TBD
        upload_to_host(file_path, upload_path)
        DUMPED_LIST.append(sha256)
    except (IOError, socket.error) as e:
        log.error("Unable to upload dropped file at path \"%s\": %s", file_path, e)

def del_file(fname):
    dump_file(fname)

    # TBD: Case sensitivity?
    # Filenames are case-insenstive in windows and os x.
    # I'm going to pretend they are in linux too (for now).
    fnames = [x.lower() for x in FILES_LIST]

    # If this filename exists in the FILES_LIST, then delete it, because it
    # doesn't exist anymore anyway.
    if fname.lower() in fnames:
        FILES_LIST.pop(fnames.index(fname.lower()))

def move_file(old_fname, new_fname):
    # TBD: Case sensitivity?
    # Filenames are case-insenstive in windows and os x.
    # I'm going to pretend they are in linux too (for now).
    fnames = [x.lower() for x in FILES_LIST]

    # Check whether the old filename is in the FILES_LIST
    if old_fname.lower() in fnames:

        # Get the index of the old filename
        idx = fnames.index(old_fname.lower())

        # Replace the old filename by the new filename
        FILES_LIST[idx] = new_fname

def dump_files():
    """Dump all the dropped files."""
    for file_path in FILES_LIST:
        dump_file(file_path)

class Analyzer:
    """Cuckoo Linux Analyzer.

    This class handles the initialization and execution of the analysis
    procedure, including process monitoring, the auxiliary modules and
    the analysis packages.
    """
    
    def __init__(self):
        self.config = None
        self.target = None

    def prepare(self):
        """Prepare env for analysis."""

        # Create the folders used for storing the results.
        create_folders()
        log.info("DEBUG: create_folders()")

        # Initialize logging.
        init_logging()
        log.info("DEBUG: init_logging()")

        # Parse the analysis configuration file generated by the agent.
        self.config = Config(cfg="analysis.conf")
        log.info("DEBUG: Config(cfg='analysis.conf')")

        # Set virtual machine clock.
        clock = datetime.strptime(self.config.clock, "%Y%m%dT%H:%M:%S")
        # Setting date and time.
        # NOTE: Windows system has only localized commands with date format
        # following localization settings, so these commands for english date
        # format cannot work in other localizations.
        # In addition DATE and TIME commands are blocking if an incorrect
        # syntax is provided, so an echo trick is used to bypass the input
        # request and not block analysis.
#       os.system("echo:|date {0}".format(clock.strftime("%m-%d-%y")))
#       os.system("echo:|time {0}".format(clock.strftime("%H:%M:%S")))

        # We update the target according to its category. If it's a file, then
        # we store the path.
        if self.config.category == "file":
            self.target = os.path.join(TMP + os.sep,
                                       str(self.config.file_name))
        # If it's a URL, well.. we store the URL.
        else:
            self.target = self.config.target

    def get_options(self):
        """Get analysis options.
        @return: options dict.
        """
        # The analysis package can be provided with some options in the
        # following format:
        #   option1=value1,option2=value2,option3=value3
        #
        # Here we parse such options and provide a dictionary that will be made
        # accessible to the analysis package.
        options = {}
        if self.config.options:
            try:
                # Split the options by comma.
                fields = self.config.options.strip().split(",")
            except ValueError as e:
                log.warning("Failed parsing the options: %s", e)
            else:
                for field in fields:
                    # Split the name and the value of the option.
                    try:
                        key, value = field.strip().split("=")
                    except ValueError as e:
                        log.warning("Failed parsing option (%s): %s"
                                    % (field, e))
                    else:
                        # If the parsing went good, we add the option to the
                        # dictionary.
                        options[key.strip()] = value.strip()

        return options

    def complete(self):
        """End analysis."""
        dump_files()
        # Hell yeah.
        log.info("Analysis completed")

    def run(self):
        """Run analysis.
        @return: operation status.
        """
        self.prepare()

        # Dummy file adds just to make sure stuff is working.        
        dummy_files = [ "/etc/passwd", "/etc/group", "/etc/nsswitch.conf" ]        
        for i in xrange(1, 20):
            log.info("Pretending I'm doing something for the %d time" % i)
            
            if i % 6 and dummy_files:
                add_file(dummy_files[-1])
                dummy_files.pop()
            sleep(1)
        log.info("It's a miracle!  I'm done!")
        
        # TBD: Package() and Auxiliary() process pooling
        # If no analysis package was specified at submission, we try to select
        # one automatically.
        if not self.config.package:
            log.info("No analysis package specified, trying to detect it automagically")
            # If the analysis target is a file, we choose the package according
            # to the file format.
            if self.config.category == "file":
                package = choose_package(self.config.file_type, self.config.file_name)
            # If it's an URL, we'll just use the default Internet Explorer
            # package.
            else:
                package = "ie"

            # If we weren't able to automatically determine the proper package,
            # we need to abort the analysis.
            if not package:
                raise CuckooError("No valid package available for file type: %s"
                                  % self.config.file_type)

            log.info("Automatically selected analysis package \"%s\"", package)
        # Otherwise just select the specified package.
        else:
            package = self.config.package
            log.info("Selecting package %s", package)

        # Generate the package path.
        package_name = "modules.packages.%s" % package

        # Try to import the analysis package.
        try:
            __import__(package_name, globals(), locals(), ["dummy"], -1)
        # If it fails, we need to abort the analysis.
        except ImportError:
            raise CuckooError("Unable to import package \"{0}\", does not exist.".format(package_name))

        # Initialize the package parent abstract.
        Package()

        # Enumerate the abstract's subclasses.
        try:
            package_class = Package.__subclasses__()[0]
        except IndexError as e:
            raise CuckooError("Unable to select package class (package={0}): {1}".format(package_name, e))

        # Initialize the analysis package.
        log.info("package_class: %s", package_class)
        pack = package_class(self.get_options())
        # Initialize Auxiliary modules
        Auxiliary()
        prefix = auxiliary.__name__ + "."
        for loader, name, ispkg in pkgutil.iter_modules(auxiliary.__path__, prefix):
            if ispkg:
                continue

            # Import the auxiliary module.
            try:
                __import__(name, globals(), locals(), ["dummy"], -1)
            except ImportError as e:
                log.warning("Unable to import the auxiliary module \"%s\": %s", name, e)

        # Walk through the available auxiliary modules.
        aux_enabled = []
        for module in Auxiliary.__subclasses__():
            # Try to start the auxiliary module.
            try:
                aux = module()
                aux.start()
            except (NotImplementedError, AttributeError):
                log.warning("Auxiliary module %s was not implemented", aux.__class__.__name__)
                continue
            except Exception as e:
                log.warning("Cannot execute auxiliary module %s: %s", aux.__class__.__name__, e)
                continue
            finally:
                aux_enabled.append(aux)

        # Start analysis package. If for any reason, the execution of the
        # analysis package fails, we have to abort the analysis.
        try:
            pids = pack.start(self.target)
        except NotImplementedError:
            raise CuckooError("The package \"{0}\" doesn't contain a run "
                              "function.".format(package_name))
        except CuckooPackageError as e:
            raise CuckooError("The package \"{0}\" start function raised an "
                              "error: {1}".format(package_name, e))
        except Exception as e:
            raise CuckooError("The package \"{0}\" start function encountered "
                              "an unhandled exception: {1}".format(package_name, e))

        # If the analysis package returned a list of process IDs, we add them
        # to the list of monitored processes and enable the process monitor.
        if pids:
            add_pids(pids)
            pid_check = True
        # If the package didn't return any process ID (for example in the case
        # where the package isn't enabling any behavioral analysis), we don't
        # enable the process monitor.
        else:
            log.info("No process IDs returned by the package, running for the full timeout")
            pid_check = False

        # Check in the options if the user toggled the timeout enforce. If so,
        # we need to override pid_check and disable process monitor.
        if self.config.enforce_timeout:
            log.info("Enabled timeout enforce, running for the full timeout")
            pid_check = False

        time_counter = 0

        while True:
            time_counter += 1
            if time_counter == int(self.config.timeout):
                log.info("Analysis timeout hit, terminating analysis")
                break

            # If the process lock is locked, it means that something is
            # operating on the list of monitored processes. Therefore we cannot
            # proceed with the checks until the lock is released.
            if PROCESS_LOCK.locked():
                sleep(1000)
                continue

            try:
                # If the process monitor is enabled we start checking whether
                # the monitored processes are still alive.
                if pid_check:
                    for pid in PROCESS_LIST:
                        if not Process(pid=pid).is_alive():
                            log.info("Process with pid %s has terminated", pid)
                            PROCESS_LIST.remove(pid)

                    # If none of the monitored processes are still alive, we
                    # can terminate the analysis.
                    if len(PROCESS_LIST) == 0:
                        log.info("Process list is empty, terminating analysis...")
                        break

                    # Update the list of monitored processes available to the
                    # analysis package. It could be used for internal operations
                    # within the module.
                    pack.set_pids(PROCESS_LIST)

                try:
                    # The analysis packages are provided with a function that
                    # is executed at every loop's iteration. If such function
                    # returns False, it means that it requested the analysis
                    # to be terminate.
                    if not pack.check():
                        log.info("The analysis package requested the termination of the analysis...")
                        break
                # If the check() function of the package raised some exception
                # we don't care, we can still proceed with the analysis but we
                # throw a warning.
                except Exception as e:
                    log.warning("The package \"%s\" check function raised "
                                "an exception: %s", package_name, e)
            finally:
                # Zzz.
                sleep(1000)

        try:
            # Before shutting down the analysis, the package can perform some
            # final operations through the finish() function.
            pack.finish()
        except Exception as e:
            log.warning("The package \"%s\" finish function raised an "
                        "exception: %s", package_name, e)

        # Terminate the Auxiliary modules.
        for aux in aux_enabled:
            try:
                aux.stop()
            except Exception as e:
                log.warning("Cannot terminate auxiliary module %s: %s",
                            aux.__class__.__name__, e)

        log.info("Starting analyzer from: %s" % os.getcwd())
        log.info("Storing results at: %s" % PATHS["output"])

        # Let's invoke the completion procedure.
        self.complete()

        return True


if __name__ == "__main__":
    success = False
    error = ""

    try:
        # Initialize the main analyzer class.
        analyzer = Analyzer()
        # Run it and wait for the response.
        success = analyzer.run()
    # This is not likely to happen.
    except KeyboardInterrupt:
        error = "Keyboard Interrupt"
    # If the analysis process encountered a critical error, it will raise a
    # CuckooError exception, which will force the termination of the analysis
    # weill notify the agent of the failure. Also catched unexpected
    # exceptions.
    except Exception as e:
        # Store the error.
        error = str(e)

        # Just to be paranoid.
        if len(log.handlers) > 0:
            log.critical(error)
        else:
            sys.stderr.write("{0}\n".format(e))
    # Once the analysis is completed or terminated for any reason, we report
    # back to the agent, notifying that it can report back to the host.
    finally:
        # Establish connection with the agent XMLRPC server.
        server = xmlrpclib.Server("http://127.0.0.1:8000")
        server.complete(success, error, PATHS["output"])
