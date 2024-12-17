import json
a = {
"attack_change_mode_1.pcap":#多一个reserve不为0的CM Open
	[
	"11f200000006015acb41ff00"
	],

	"attack_change_mode_2.pcap": #多一个reserve不为0的CM Open
	[
	"140200000006015acb41ff00",
	"13ba00000006015acb41ff00",
	"13e300000006015acb40ff00",
	],

	"attack_change_mode_3.pcap": #多一个CM Close
	[
	"12c700000006015acb40ff00",

	],

	"attack_change_mode_4.pcap": #多一个reserve不为0的CM Open
	[
	"14dd00000006015acb40ff00",
	"152000000006015acb40ff00",
	"150d00000006015acb41ff00",

	],

	"attack_change_mode_5.pcap":#多一个reserve不为0的CM Open
	[
	]
}

json_str = json.dumps(a, indent=4)
with open('extra_function_requests_ground_truth', 'w') as json_file:
    json_file.write(json_str)