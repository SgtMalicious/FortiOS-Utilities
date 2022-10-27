## Description

Python utility scripts for working with a Fortinet FortiGate FortiOS policy configuration file offline or via the API.

* policy_view - print policies offline from a configuration file (missing feature of the cli)
* api_view - print policies using the FortiOS API on the firewall directly (missing feature of the cli)

## Requirements

* Python >= 3.6
* The API policy viewer requires an API key.

## Caveats for Policy script

* ANSI colors are specific to the BASH shell. Have not tested with others.
* Requires Python >= 3.6 to support newer printing style.
* Requires the requests module (python -m pip install requests)
* Primarily written with VDOMs enabled but will now skip certain logic if they are not. (not relevant to api)
* Supports IPv6 policy entries. FortiOS version < 6.4, create a symlink called policy_view6
* Supports policies using ISDB addresses. May not work properly with FortiOS < 6.4
* Added new multi-select interface logic.
* Added API policy viewer that doesn't require downloading the configuration file. (new)
* Updated print functions from old style to modern formatted string literal style.
* Updated ANSI coloring coding to look less like gibberish.

## License

Copyright (c) 2022 William Allison

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
