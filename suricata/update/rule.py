# Copyright (C) 2017-2019 Open Information Security Foundation
# Copyright (c) 2011 Jason Ish
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

""" Module for parsing Snort-like rules.

Parsing is done using regular expressions and the job of this module
is to do its best at parsing out fields of interest from the rule
rather than perform a sanity check.

The methods that parse multiple rules for a provided input
(parse_file, parse_fileobj) return a list of rules instead of dict
keyed by ID as its not the job of this module to detect or deal with
duplicate signature IDs.
"""

from __future__ import print_function

import sys
import re
import logging
import io

logger = logging.getLogger(__name__)

# Compile an re pattern for basic rule matching.
rule_pattern = re.compile(r"^(?P<enabled>#)*[\s#]*"
                r"(?P<raw>"
                r"(?P<header>[^()]+)"
                r"\((?P<options>.*)\)"
                r"$)")

# Rule actions we expect to see.
actions = (
    "alert", "log", "pass", "activate", "dynamic", "drop", "reject", "sdrop")

class NoEndOfOptionError(Exception):
    """Exception raised when the end of option terminator (semicolon) is
    missing."""
    pass

class Rule(dict):
    """Class representing a rule.

    The Rule class is a class that also acts like a dictionary.

    Dictionary fields:

    - **group**: The group the rule belongs to, typically the filename.
    - **enabled**: True if rule is enabled (uncommented), False is
      disabled (commented)
    - **action**: The action of the rule (alert, pass, etc) as a
      string
    - **proto**: The protocol of the rule.
    - **direction**: The direction string of the rule.
    - **gid**: The gid of the rule as an integer
    - **sid**: The sid of the rule as an integer
    - **rev**: The revision of the rule as an integer
    - **msg**: The rule message as a string
    - **flowbits**: List of flowbit options in the rule
    - **metadata**: Metadata values as a list
    - **references**: References as a list
    - **classtype**: The classification type
    - **priority**: The rule priority, 0 if not provided
    - **noalert**: Is the rule a noalert rule
    - **features**: Features required by this rule
    - **raw**: The raw rule as read from the file or buffer

    :param enabled: Optional parameter to set the enabled state of the rule
    :param action: Optional parameter to set the action of the rule
    :param group: Optional parameter to set the group (filename) of the rule

    """

    def __init__(self, enabled=None, action=None, group=None):
        dict.__init__(self)
        self["enabled"] = enabled
        self["action"] = action
        self["proto"] = None
        self["source_addr"] = None
        self["source_port"] = None
        self["direction"] = None
        self["dest_addr"] = None
        self["dest_port"] = None
        self["group"] = group
        self["gid"] = 1
        self["sid"] = None
        self["rev"] = 0
        self["msg"] = None
        self["flowbits"] = []
        self["metadata"] = []
        self["references"] = []
        self["classtype"] = None
        self["priority"] = 0
        self["noalert"] = False

        self["features"] = []

        self["raw"] = None

    def __getattr__(self, name):
        return self[name]

    @property
    def id(self):
        """ The ID of the rule.

        :returns: A tuple (gid, sid) representing the ID of the rule
        :rtype: A tuple of 2 ints
        """
        return (int(self.gid), int(self.sid))

    @property
    def idstr(self):
        """Return the gid and sid of the rule as a string formatted like:
        '[GID:SID]'"""
        return f"[{str(self.gid)}:{str(self.sid)}]"

    def brief(self):
        """ A brief description of the rule.

        :returns: A brief description of the rule
        :rtype: string
        """
        return "%s[%d:%d] %s" % (
            "" if self.enabled else "# ", self.gid, self.sid, self.msg)

    def __hash__(self):
        return self["raw"].__hash__()

    def __str__(self):
        """ The string representation of the rule.

        If the rule is disabled it will be returned as commented out.
        """
        return self.format()

    def format(self):
        if self.noalert and "noalert;" not in self.raw:
            self.raw = re.sub(r'( *sid\: *[0-9]+\;)', r' noalert;\1', self.raw)
        return f'{u"" if self.enabled else u"# "}{self.raw}'

def find_opt_end(options):
    """ Find the end of an option (;) handling escapes. """
    offset = 0

    while True:
        i = options[offset:].find(";")
        if options[offset + i - 1] == "\\":
            offset += 2
        else:
            return offset + i

class BadSidError(Exception):
    """Raises exception when sid is of type null"""

def parse(buf, group=None):
    """ Parse a single rule for a string buffer.

    :param buf: A string buffer containing a single Snort-like rule

    :returns: An instance of of :py:class:`.Rule` representing the parsed rule
    """

    if type(buf) == type(b""):
        buf = buf.decode("utf-8")
    buf = buf.strip()

    m = rule_pattern.match(buf)
    if not m:
        return None

    enabled = m.group("enabled") != "#"
    header = m.group("header").strip()

    rule = Rule(enabled=enabled, group=group)

    # If a decoder rule, the header will be one word.
    if len(header.split(" ")) == 1:
        action = header
        direction = None
    else:
        states = ["action",
                  "proto",
                  "source_addr",
                  "source_port",
                  "direction",
                  "dest_addr",
                  "dest_port",
                  ]
        rem = header
        for state_ in states:
            if not rem:
                return None
            if rem[0] == "[":
                end = rem.find("]")
                if end < 0:
                    return
                end += 1
                token = rem[:end].strip()
                rem = rem[end:].strip()
            else:
                end = rem.find(" ")
                if end < 0:
                    token = rem
                    rem = ""
                else:
                    token = rem[:end].strip()
                    rem = rem[end:].strip()

            if state_ == "action":
                action = token
            elif state_ == "proto":
                rule["proto"] = token
            elif state_ == "source_addr":
                rule["source_addr"] = token
            elif state_ == "source_port":
                rule["source_port"] = token
            elif state_ == "direction":
                direction = token
            elif state_ == "dest_addr":
                rule["dest_addr"] = token
            elif state_ == "dest_port":
                rule["dest_port"] = token

    if action not in actions:
        return None

    rule["action"] = action
    rule["direction"] = direction
    rule["header"] = header

    options = m.group("options")

    while options:
        index = find_opt_end(options)
        if index < 0:
            raise NoEndOfOptionError("no end of option")
        option = options[:index].strip()
        options = options[index + 1:].strip()

        if option.find(":") > -1:
            name, val = [x.strip() for x in option.split(":", 1)]
        else:
            name = option
            val = None

        if name in ["gid", "sid", "rev"]:
            rule[name] = int(val)
        elif name == "metadata":
            if name not in rule:
                rule[name] = []
            rule[name] += [v.strip() for v in val.split(",")]
        elif name == "flowbits":
            rule.flowbits.append(val)
            if val and val.find("noalert") > -1:
                rule["noalert"] = True
        elif name == "noalert":
            rule["noalert"] = True
        elif name == "reference":
            rule.references.append(val)
        elif name == "msg":
            if val and val.startswith('"') and val.endswith('"'):
                val = val[1:-1]
            rule[name] = val
        else:
            rule[name] = val

        if name.startswith("ja3"):
            rule["features"].append("ja3")

    if rule["msg"] is None:
        rule["msg"] = ""

    if not rule["sid"]:
        raise BadSidError("Sid cannot be of type null")

    rule["raw"] = m.group("raw").strip()

    return rule

def parse_fileobj(fileobj, group=None):
    """ Parse multiple rules from a file like object.

    Note: At this time rules must exist on one line.

    :param fileobj: A file like object to parse rules from.

    :returns: A list of :py:class:`.Rule` instances, one for each rule parsed
    """
    rules = []
    buf = ""
    for line in fileobj:
        try:
            if type(line) == type(b""):
                line = line.decode()
        except:
            pass
        if line.rstrip().endswith("\\"):
            buf = f"{buf}{line.rstrip()[:-1]} "
            continue
        buf = buf + line
        try:
            if rule := parse(buf, group):
                rules.append(rule)
        except Exception as err:
            logger.error("Failed to parse rule: %s: %s", buf.rstrip(), err)
        buf = ""
    return rules

def parse_file(filename, group=None):
    """ Parse multiple rules from the provided filename.

    :param filename: Name of file to parse rules from

    :returns: A list of :py:class:`.Rule` instances, one for each rule parsed
    """
    with io.open(filename, encoding="utf-8") as fileobj:
        return parse_fileobj(fileobj, group)

class FlowbitResolver(object):

    setters = ["set", "setx", "unset", "toggle"]
    getters = ["isset", "isnotset"]

    def __init__(self):
        self.enabled = []

    def resolve(self, rules):
        required = self.get_required_flowbits(rules)
        if enabled := self.set_required_flowbits(rules, required):
            self.enabled += enabled
            return self.resolve(rules)
        return self.enabled

    def set_required_flowbits(self, rules, required):
        enabled = []
        for rule in [rule for rule in rules.values() if not rule.enabled]:
            for option, value in map(self.parse_flowbit, rule.flowbits):
                if option in self.setters and value in required:
                    rule.enabled = True
                    enabled.append(rule)
        return enabled

    def get_required_rules(self, rulemap, flowbits, include_enabled=False):
        """Returns a list of rules that need to be enabled in order to satisfy
        the list of required flowbits.

        """
        required = []

        for rule in list(rulemap.values()):
            if not rule:
                continue
            required.extend(
                rule
                for option, value in map(self.parse_flowbit, rule.flowbits)
                if option in self.setters
                and value in flowbits
                and (not rule.enabled or include_enabled)
            )

        return required

    def get_required_flowbits(self, rules):
        required_flowbits = set()
        for rule in [rule for rule in rules.values() if rule and rule.enabled]:
            for option, value in map(self.parse_flowbit, rule.flowbits):
                if option in self.getters:
                    required_flowbits.add(value)
        return required_flowbits

    def parse_flowbit(self, flowbit):
        tokens = flowbit.split(",", 1)
        if len(tokens) == 1:
            return tokens[0], None
        elif len(tokens) == 2:
            return tokens[0], tokens[1]
        else:
            raise Exception(f"Flowbit parse error on {flowbit}")

def enable_flowbit_dependencies(rulemap):
    """Helper function to resolve flowbits, wrapping the FlowbitResolver
    class. """
    resolver = FlowbitResolver()
    return resolver.resolve(rulemap)

def format_sidmsgmap(rule):
    """ Format a rule as a sid-msg.map entry. """
    try:
        return " || ".join([str(rule.sid), rule.msg] + rule.references)
    except:
        logger.error(f"Failed to format rule as sid-msg.map: {str(rule)}")
        return None

def format_sidmsgmap_v2(rule):
    """ Format a rule as a v2 sid-msg.map entry.

    eg:
    gid || sid || rev || classification || priority || msg || ref0 || refN
    """
    try:
        return " || ".join([
            str(rule.gid), str(rule.sid), str(rule.rev),
            "NOCLASS" if rule.classtype is None else rule.classtype,
            str(rule.priority), rule.msg] + rule.references)
    except:
        logger.error("Failed to format rule as sid-msg-v2.map: %s" % (
            str(rule)))
        return None

def parse_var_names(var):
    """ Parse out the variable names from a string. """
    return [] if var is None else re.findall("\$([\w_]+)", var)
