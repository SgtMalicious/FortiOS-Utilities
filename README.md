## Description

Python utility scripts for working with a Fortinet FortiGate FortiOS configuration file offline.

* policy_view - print policies offline from a configuration file (missing feature of the cli)

## Requirements

* Python >= 2.6

## Caveats for Policy script

* ANSI colors are specific to the BASH shell. Have not tested with others.
* Requires Python >= 2.7 to support the OrderedDict collection or installation of ordereddict (easy_install ordereddict)
* Primarily written with VDOMs enabled but will now skip certain logic if they are not.
* Can support IPv6 policies with a little editing: s/config firewall policy/config firewall policy6/
* Added new multi-select interface logic which is still new.

## License

Copyright (c) 2014 William Allison

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
