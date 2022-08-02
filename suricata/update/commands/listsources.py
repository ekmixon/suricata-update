# Copyright (C) 2017 Open Information Security Foundation
#
# You can copy, redistribute or modify this Program under the terms of
# the GNU General Public License version 2 as published by the Free
# Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# version 2 along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.

from __future__ import print_function

import logging

from suricata.update import config
from suricata.update import sources
from suricata.update import util
from suricata.update.commands.updatesources import update_sources
from suricata.update import exceptions

logger = logging.getLogger()

def register(parser):
    parser.add_argument("--free", action="store_true",
                        default=False, help="List all freely available sources")
    parser.add_argument("--enabled", action="store_true",
                        help="List all enabled sources")
    parser.add_argument("--all", action="store_true",
                        help="List all sources (including deprecated and obsolete)")
    parser.set_defaults(func=list_sources)

def list_sources():
    if (
        enabled := config.args().enabled
        or config.args().subcommand == "list-enabled-sources"
    ):
        found = False

        if config_sources := config.get("sources"):
            found = True
            print(f"From {config.filename}:")
            for source in config_sources:
                print(f"  - {source}")

        if local := config.get("local"):
            found = True
            print("Local files/directories:")
            for filename in local:
                print(f"  - {filename}")

        if enabled_sources := sources.get_enabled_sources():
            found = True
            print("Enabled sources:")
            for source in enabled_sources.values():
                print(f'  - {source["source"]}')

        # If no enabled sources were found, log it.
        if not found:
            logger.warning("No enabled sources.")
        return 0

    free_only = config.args().free
    if not sources.source_index_exists(config):
        logger.info("No source index found, running update-sources")
        try:
            update_sources()
        except exceptions.ApplicationError as err:
            logger.warning("%s: will use bundled index.", err)
    index = sources.load_source_index(config)
    for name, source in index.get_sources().items():
        is_not_free = source.get("subscribe-url")
        if free_only and is_not_free:
            continue
        if not config.args().all and (
            source.get("deprecated") is not None
            or source.get("obsolete") is not None
        ):
            continue
        print(f'{util.bright_cyan("Name")}: {util.bright_magenta(name)}')
        print(
            f'  {util.bright_cyan("Vendor")}: {util.bright_magenta(source["vendor"])}'
        )

        print(
            f'  {util.bright_cyan("Summary")}: {util.bright_magenta(source["summary"])}'
        )

        print(
            f'  {util.bright_cyan("License")}: {util.bright_magenta(source["license"])}'
        )

        if "tags" in source:
            print(
                f'  {util.bright_cyan("Tags")}: {util.bright_magenta(", ".join(source["tags"]))}'
            )

        if "replaces" in source:
            print(
                f'  {util.bright_cyan("Replaces")}: {util.bright_magenta(", ".join(source["replaces"]))}'
            )

        if "parameters" in source:
            print(
                f'  {util.bright_cyan("Parameters")}: {util.bright_magenta(", ".join(source["parameters"]))}'
            )

        if "subscribe-url" in source:
            print(
                f'  {util.bright_cyan("Subscription")}: {util.bright_magenta(source["subscribe-url"])}'
            )

        if "deprecated" in source:
            print(
                f'  {util.orange("Deprecated")}: {util.bright_magenta(source["deprecated"])}'
            )

        if "obsolete" in source:
            print(
                f'  {util.orange("Obsolete")}: {util.bright_magenta(source["obsolete"])}'
            )
