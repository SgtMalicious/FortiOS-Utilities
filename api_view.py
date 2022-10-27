#!/usr/bin/env python3

import sys
import requests
import argparse

from policy_view import clr,fgPolicy,print_policy,dump_policy

requests.packages.urllib3.disable_warnings()

def load_key(key_file):
	""" Return the key used for API calls """
	with open(key_file,'r') as f:
		key = f.read().strip()
	return(key)

def process_results(results=[]):
	""" Return a list of fgPolicy objects from the API call results """
	policies = []
	for p in results:
		policy = fgPolicy(p['policyid'])
		if p['status'] != 'enable':
			policy.set_disable()
		try:
			for intf in p['srcintf']:
				policy.set_srcintf(intf['name'])
			for intf in p['dstintf']:
				policy.set_dstintf(intf['name'])
			for addr in p['srcaddr']:
				policy.add_src(addr['name'])
			if p['internet-service-src'] == 'enable':
				for addr in p['internet-service-src-name']:
					policy.add_src(addr['name'])
			for addr in p['dstaddr']:
				policy.add_dst(addr['name'])
			for addr in p['dstaddr6']:
				policy.add_dst(addr['name'] + "(6)")
			for addr in p['srcaddr6']:
				policy.add_src(addr['name'] + "(6)")
			if p['internet-service'] == 'enable':
				policy.add_svc('Predefined')
				for addr in p['internet-service-name']:
					policy.add_src(addr['name'])
			for svc in p['service']:
				policy.add_svc(svc['name'])
			if p['schedule'] != 'always':
				policy.set_schedule()
			if p['ippool'] == 'enable':
				policy.set_nat('D')
			if p['nat'] == 'enable':
				policy.set_nat('S')
			if len(p['groups']):
				policy.set_webauth()
				policy.set_action(policy.action + "~")
			if p['utm-status'] == 'enable':
				policy.set_attack()
			if p['per-ip-shaper'] != '':
				policy.set_traffic()
			if p['traffic-shaper'] != '':
				policy.set_traffic()
			if p['logtraffic'] != 'utm':
				policy.set_log()
			policy.set_action(p['action'])
		except KeyError:
			# pass over these for short results
			pass

		policies.append(policy)
	return policies

if __name__ == "__main__":

	parser = argparse.ArgumentParser(description='Use FortiOS API to view policy information')
	parser.add_argument('-k', '--keyfile', help='The file containaing the API key', required=True)
	parser.add_argument('-a', '--address', help='The hostname or address of the firewall', required=True)
	parser.add_argument('-e', '--exact', help='Use exact case sensitive matches for interface/zone names', action='store_true')
	parser.add_argument('-v', '--vdom', metavar='VDOM', help='Specify a different VDOM from the default')

	group = parser.add_mutually_exclusive_group()
	group.add_argument('-f', '--free', help='Print policy ids that are available or free to reuse',action='store_true')
	group.add_argument('-d', '--dump', help='Dump all policies in CSV format',action='store_true')
	group.add_argument('-p', '--policy', nargs=1, metavar='ID', type=int, help='Print single policy')
	group.add_argument('-z', '--zones', nargs=2, metavar='ZONE', help='Show policies <from zone> <to zone> ')

	args = parser.parse_args()

	api_payload={}
	api_authorization_key = load_key(args.keyfile)

	api_headers = {'Authorization': f'Bearer {api_authorization_key}'}

	fw_url = f'https://{args.address}/api/v2/cmdb/firewall/policy/'

	if args.vdom:
		api_payload['vdom'] = args.vdom

	if args.policy:
		api_payload['filter'] = f'policyid=={args.policy[0]}'

	elif args.free:
		""" return only policy id and status """
		api_payload['format'] = 'policyid|status'

	elif args.dump:
		""" dummy for validating arguments """

	elif args.zones:
		if args.exact:
			api_payload['filter'] = [f'srcintf=={args.zones[0]}',f'dstintf=={args.zones[1]}']
		else:
			api_payload['filter'] = [f'srcintf=@{args.zones[0]}',f'dstintf=@{args.zones[1]}']

	else:
		parser.print_usage()
		sys.exit(1)

	try:
		r = requests.get(fw_url,params=api_payload,headers=api_headers,verify=False,timeout=5)
	except (requests.Timeout, requests.ConnectionError) as exception: 
		sys.stderr.write("There was a connection error: {}\n".format(exception))
		sys.exit(1)

	if r.status_code != 200:
		sys.stderr.write(f"There was an API error: {r.reason}\n")
		sys.exit(1)

	policies = process_results((r.json()['results']))

	if len(policies) == 0:
		sys.stderr.write("No policies matching query returned.\n")
		sys.exit(1)

	if args.dump:
		print("ID\tFrom\tTo\tSrc-address\tDst-address\tService\tAction\tState\tAttack\tSchedule\tTraffic Shaping\tLogging\tNAT")
		for p in policies:
			dump_policy(p)
	elif args.free:
		pol_dict = {}
		for p in policies:
			pol_dict[p.id] = p.disabled

		ids = list(pol_dict)
		ids.sort()

		for i in range(1,ids[-1]+1):
			if i in ids:
				if pol_dict[i]:
					print(f'{clr.Blu}Available{clr.End}: {i}')
			else:
				print(f'{clr.Grn}{"Free":>9}{clr.End}: {i}')
	else:
		print_policy(policies)
	
# vim: ts=4 sw=4 nowrap noexpandtab
