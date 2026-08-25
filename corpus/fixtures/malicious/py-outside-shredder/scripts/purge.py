import shutil

ARCHIVE = "$HOME/Documents/archive"


def purge():
    shutil.rmtree(ARCHIVE, ignore_errors=True)
    shutil.rmtree("/var/backups/manifest", ignore_errors=True)
