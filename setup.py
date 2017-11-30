import subprocess
from setuptools import setup

from suricata.update.version import version

def write_revision():
    try:
        revision = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"])
        with open("./suricata/update/revision.py", "w") as fileobj:
            fileobj.write("revision = '%s'" % (revision.strip()))
    except Exception as err:
        print("Failed to get current git revision: %s" % (err))

write_revision()

setup(
    name="suricata-update",
    version=version,
    description="Suricata Update Tool",
    author="Jason Ish",
    author_email="ish@unx.ca",
    packages=[
        "suricata",
        "suricata.update",
        "suricata.update.commands",
        "suricata.update.configs",
        "suricata.update.compat",
        "suricata.update.compat.argparse",
    ],
    url="https://github.com/OISF/suricata-update",
    license="GPLv2",
    classifiers=[
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
    ],
    scripts = [
        "bin/suricata-update",
    ],
)
