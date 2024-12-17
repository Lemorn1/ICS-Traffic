import dpkt
import argparse
import os
import socket
import binascii
import json
from pprint import pprint
from scipy import stats

ground_truth = {
	"pccc":{
		"change_mode":"70002900********000000000000000000000000000000000000000001000200a1000400********b1001500****4b0220672401074d0*********0f00****800*",	
		"change_variable":"70003300********000000000000000000000000000000000000000001000200a1000400********b1001f****************************************************************",
		}}

def input_intial():
	parser = argparse.ArgumentParser()
	parser.add_argument("-n", "--interaction_num", type=int, help="the file",default=1000)
	parser.add_argument("-a", "--attack", type=str, help="the file",default="no")
	parser.add_argument("-t", "--tolent_threshold", type=float, help="tolent_threshold",default=0.05)
	parser.add_argument("-p", "--protocol", type=str, help="protocol",default="pccc")
	parser.add_argument("-m", "--mode", type=str, help="protocol",default="pccc")


	# parser.add_argument("-s", "--session_type", type=str, help="session_type",default="same")

	
	# parser.add_argument("-n", "--packet_num", type=int, help="the exponent",default = 50)
	args = parser.parse_args()
	attack = args.attack
	interaction_num = args.interaction_num
	tolent_threshold = args.tolent_threshold
	protocol = args.protocol
	mode = args.mode
	# session_type = args.session_type
	return protocol,interaction_num,tolent_threshold,attack,mode

def generate_compare_file_pair(dict_file_template):
	compare_file_pair = []
	processed_files = []
	for file1 in dict_file_template:#选出第一个pcap文件，依次和后面的2，3，4，5，6比较，比较完后将1放入compared_pcap里
		for file2 in dict_file_template:#选取同1比较的文件
			if file2 not in processed_files and file2 != file1:
				compare_file_pair.append((file1,file2))
		processed_files.append(file1)
	compare_num = len(compare_file_pair)
	return compare_file_pair,compare_num

def pre_process_pcap(file,packet_num):#读取当前路径下特定file的流量文件
	pcap_dict = {}
	def input_pcap(file):
		with open(file,'rb') as fr:
			pcap = dpkt.pcap.Reader(fr)
			for timestamp,buffer in pcap:
				ethernet_init = dpkt.ethernet.Ethernet(buffer)
				if isinstance(ethernet_init.data.data, dpkt.tcp.TCP):
					if len(binascii.b2a_hex(ethernet_init.data.data.data).decode()) != 0:
						ip_send = socket.inet_ntoa(ethernet_init.data.src)
						ip_recv = socket.inet_ntoa(ethernet_init.data.dst)
						break
		#get the payload
		with open(file,'rb') as fr:
			pcap = dpkt.pcap.Reader(fr)
			interaction_num = 0
			payload_list = {}
			temp_send_NO = 0
			TCP_sequence_number = []
			last_packet = ""
			for timestamp,buffer in pcap:
				ethernet = dpkt.ethernet.Ethernet(buffer)
				if isinstance(ethernet.data.data, dpkt.icmp.ICMP) or isinstance(ethernet.data.data, bytes) or isinstance(ethernet.data.data, dpkt.udp.UDP):
					continue
				payload = binascii.b2a_hex(ethernet.data.data.data).decode()
				if len(payload) == 0 or ethernet.data.data.seq in TCP_sequence_number:
					continue
				ip = socket.inet_ntoa(ethernet.data.src)
				TCP_sequence_number.append(ethernet.data.data.seq)
				#NO 由 (send)+(interaction).(NO in interaction)组成。{'send1.1': '', 'recv1.1': '', 'send2.1': '', 'recv2.1': '', 'send3.1': '', 'send3.2': '', 'recv3.1': '
				if ip == ip_send:
					if last_packet != "ES":
						interaction_num += 1
						if interaction_num == packet_num:
							break
						temp_send_NO = 0
					temp_send_NO += 1
					payload_list["ES"+str(interaction_num)+"."+str(temp_send_NO)] = payload
					last_packet = "ES"
				else:
					if last_packet != "PLC":
						temp_recv_NO = 0
					temp_recv_NO += 1
					payload_list["PLC"+str(interaction_num)+"."+str(temp_recv_NO)] = payload
					last_packet = "PLC"
		return payload_list
	pcap_dict=input_pcap(file)#
	return pcap_dict



def label_packets(pcap_dict,direction):
	NO_label_payloads = {}
	for NO in pcap_dict:
		if direction in NO:		
			length = len(pcap_dict[NO])
			NO_label_payloads[NO] = {str(length)+"-"+str(NO):pcap_dict[NO]}
	return NO_label_payloads

def find_dynamic_fields_in_templates(NO_label_payloads_send,NO_label_payloads_recv,compare_file_pair):
	dynamic_fields_in_send = {}
	dynamic_fields_in_recv = {}
	for file_pair in compare_file_pair:
		file1,file2 = file_pair[0],file_pair[1]

		#从NO_label_payloads_send中只提取label和payload
		label_payload_file1_send = {}
		label_payload_file2_send = {}
		for NO,label_payload in NO_label_payloads_send[file1].items():
			for label,payload in label_payload.items():
				label_payload_file1_send[label] = payload

		for NO,label_payload in NO_label_payloads_send[file2].items():
			for label,payload in label_payload.items():
				label_payload_file2_send[label] = payload

		for label,payload_1 in label_payload_file1_send.items():
			if label not in dynamic_fields_in_send:
				dynamic_fields_in_send[label] = {}
			if label in label_payload_file2_send:
				payload_2 = label_payload_file2_send[label]
				diff_bytes = diff_sequence(payload_1,payload_2)
				if diff_bytes != []:
					dynamic_fields_in_send[label][str(file1)+"-"+str(file2)] = diff_bytes
			# else:
			# 	dynamic_fields_in_send[label][str(file1)+"-"+str(file2)] = []


		#从NO_label_payloads_send中只提取label和payload
		label_payload_file1_recv = {}
		label_payload_file2_recv = {}
		for NO,label_payload in NO_label_payloads_recv[file1].items():
			for label,payload in label_payload.items():
				label_payload_file1_recv[label] = payload

		for NO,label_payload in NO_label_payloads_recv[file2].items():
			for label,payload in label_payload.items():
				label_payload_file2_recv[label] = payload

		for label,payload_1 in label_payload_file1_recv.items():
			if label not in dynamic_fields_in_recv:
				dynamic_fields_in_recv[label] = {}
			if label in label_payload_file2_recv:
				payload_2 = label_payload_file2_recv[label]
				diff_bytes = diff_sequence(payload_1,payload_2)
				if diff_bytes != []:
					dynamic_fields_in_recv[label][str(file1)+"-"+str(file2)] = diff_bytes
			# else:
			# 	print("different",label,str(file1)+"-"+str(file2))
			# 	dynamic_fields_in_recv[label][str(file1)+"-"+str(file2)] = []

	return dynamic_fields_in_send,dynamic_fields_in_recv


def diff_sequence(sequence_1,sequence_2):#以字节为单位，比较两个字符串的差异，并返回不同字节的偏移量
	sequence_1_list = [sequence_1[x:x+2] for x in range(0,len(sequence_1),2)]#将字符串按字节区分
	sequence_2_list = [sequence_2[x:x+2] for x in range(0,len(sequence_1),2)]#将字符串按字节区分
	diff = []
	temp = []
	for n in range(len(sequence_1_list)):
		if sequence_1_list[n] != sequence_2_list[n] or "**" in [sequence_1_list[n], sequence_2_list[n]]:
		#if sequence_1_list[n] != sequence_2_list[n]:
			diff.append(n)
			# temp.append((sequence_1,sequence_2,n,sequence_1_list[n],sequence_2_list[n]))
	return diff


# {'48-ES1.1': {}, '96-ES2.1': {}, '56-ES3.1': {}, '116-ES4.1': {'n-rp-1.pcap-n-rp-3.pcap': [4, 5, 6, 7, 12, 13, 14, 55, 56], 'n-rp-1.pcap-n-rp-2.pcap': [4, 5, 6, 7, 12, 13, 55, 56], 'n-rp-1.pca

# def get_dynamic_union(dynamic_fields_in_send):
# 	dynamic_union = {}
# 	for label,comp_offsets_dict in dynamic_fields_in_send.items():
# 		# for comp,offsets_list in comp_offsets_dict.items():
# 		dynamic_union[label] = sorted(set().union(*comp_offsets_dict.values()))
# 	return dynamic_union

#在这里也引入动态字段可信度，用来避免生成的模板失去特征性
def get_dynamic_union(dynamic_fields_in_send,dynamic_threshold):
	dynamic_union = {}
	result = {}
	for NO,comp_offsets_dict in dynamic_fields_in_send.items():
		result[NO] = {}
		# for comp,offsets_list in comp_offsets_dict.items():
		for compare_file,offsets in comp_offsets_dict.items():
			for offset in offsets:
				if offset not in result[NO]:
					result[NO][offset] = 1
				else:
					result[NO][offset] += 1
	# print(4444,result)
	result_filtered = {}
	for NO,offset_num in result.items():
		if offset_num != {}:
			result_filtered[NO] = []
			for offset,num in offset_num.items():
				if num/10 >=  dynamic_threshold:
					result_filtered[NO].append(offset)
			if result_filtered[NO] == []:
				del result_filtered[NO]
	# print(5555,result_filtered)

	# dynamic_union = {}
	# for label,comp_offsets_dict in dynamic_fields_in_send.items():
	# 	# for comp,offsets_list in comp_offsets_dict.items():
	# 	dynamic_union[label] = sorted(set().union(*comp_offsets_dict.values()))
	# print(6666,dynamic_union)


		# dynamic_union[NO] = sorted(set().union(*comp_offsets_dict.values()))
	return result_filtered


def generate_template(dynamic_union,NO_label_payloads_send,template_files):
	label_payloads_1 = NO_label_payloads_send[template_files[0]]
	NO_template = {}
	# Update NO_template based on indices from dynamic_union
	for key_group, indices in dynamic_union.items():
	    for es_key, value in label_payloads_1.items():
	        if key_group in value:
	            original_string = value[key_group]
	            # Create a list of characters for easier manipulation
	            char_list = list(original_string)
	            # Replace specified indices with '**'
	            for index in indices:
	                if index*2 < len(char_list):  # Multiply by 2 for hex representation
	                    char_list[index*2] = '*'
	                    char_list[index*2+1] = '*'
	            # Update the dict with the modified string
	            NO_template[es_key] = ''.join(char_list)
	return NO_template
def get_file(protocol,type):
	if type == "normal":
		# List all files in the current directory
		if protocol == "umas1":
			files_result = [file for file in os.listdir('.') if file.startswith("s") and file.endswith('.pcap')]
		elif protocol == "umas2":
			files_result = [file for file in os.listdir('.') if file.startswith("s") and file.endswith('.pcap')]
		else:
			files_result = [file for file in os.listdir('.') if file.startswith("n") and file.endswith('.pcap')]

	if type == "attack":

		# List all files in the current directory
		if protocol == "umas1":
			files_result = [file for file in os.listdir('.') if file.startswith("s") and file.endswith('.pcap')]
		elif protocol == "umas2":
			files_result = [file for file in os.listdir('.') if file.startswith("s") and file.endswith('.pcap')]
		else:
			files_result = [file for file in os.listdir('.') if file.startswith("a") and file.endswith('.pcap')]
	return files_result


def template_match(templates,payloads,tolent_threshold_value):
	result = {}
	# 加了一个容忍度，在template和payload长度相同的情况下，允许不同的字段个数为len * error_tolent，即如果超过5%的字段不相同，才认为不匹配。
	# 容忍度的原因是因为，有些高字节可能会过很长时间才变化，如果按照完全匹配的话，会匹配失败。而这种情况又是少数，所以使用了很小的值。
	for NO,payload in payloads.items():
		flag = False
		if "ES" in NO:
			for label,template in templates.items():
				if len(template) == len(payload):
					tolent_count = 0
					for i in range(0,len(template)):
						
						tolent_threshold = tolent_threshold_value * len(template)
						if template[i] == "*":#????
							if i == len(template)-1:#如果最后一个是“*”，那就直接continue，轮不到给break下面的代码了，flag就始终不会true。因此在这里就要给true
								flag = True
								break
							else:
								continue
						if template[i] != payload[i]:
							tolent_count += 1
							if tolent_count >= tolent_threshold:
								break
						# print(i,len(template)-1)
						if i == len(template)-1:
							flag = True
			if not flag:
				result[NO] = payload

	return result



def AIAF(template_files,attack_file,packet_num,tolent_threshold,dynamic_threshold):
	global compare_num,NO_label_payloads_send,pair_session_candidate,formula,all_reference_requests
	NO_label_payloads_send = {}
	NO_label_payloads_recv = {}
	for file in template_files:
		pcap_dict = pre_process_pcap(file,packet_num)
		NO_label_payloads_send[file] = label_packets(pcap_dict,"ES")
		NO_label_payloads_recv[file] = label_packets(pcap_dict,"PLC")
	#step_1: 生成文件比较对
	compare_file_pair,compare_num = generate_compare_file_pair(template_files)

	#step_2: 根据文件比较对两两比较，每次比较产生一组templates的动态字段
	NO_label_payloads_send
	dynamic_fields_in_send,dynamic_fields_in_recv = find_dynamic_fields_in_templates(NO_label_payloads_send,NO_label_payloads_recv,compare_file_pair)
	


	#step_3 找到攻击报文
	#step_3.1: 比较所有文件的动态字段，生成他们的并集

	dynamic_union = get_dynamic_union(dynamic_fields_in_send,dynamic_threshold)

	#step_3.2: 根据动态字段并集，和第一个流量文件，生成packet template
	NO_template = generate_template(dynamic_union,NO_label_payloads_send,template_files)
	#step_3.3: 获取malicious session中的流量，利用packet template找到其中的attack request
	
	pcap_dict_3 = pre_process_pcap(attack_file,5000)
	requests_num = len([NO for NO in pcap_dict_3 if "ES" in NO])
	packets_num = len(pcap_dict_3)
	attack_requests = template_match(NO_template,pcap_dict_3,tolent_threshold)
	all_attack_requests = [packet for NO,packet in pcap_dict_3.items() if "ES" in NO]

	return attack_requests,NO_template,all_attack_requests,packets_num,requests_num


def check(attack_requests,truth,attack):


	if type(truth) == dict:
		truth = truth.values()
	
	result = {
		"TP":0,
		"FP":0,
		"TN":0,
		"FN":0
	}
	# if "upload" in attack or "download" in attack or "mode" in attack:
	for packet in attack_requests.values():
		flag_P = False
		for template_packet in truth:
			if template_packet == packet:
				flag_P = True
				break
		if flag_P:
			result["TP"] += 1
		else:
			result["FP"] += 1
			print(11111,packet)

	for template_packet in truth:
		flag_N = False
		for packet in attack_requests.values():
			if template_packet == packet:
				flag_N = True
				break
		if not flag_N:
			result["FN"] += 1
			# print(1111)
			# print(template_packet)


	# else:
	# 	for packet in attack_requests.values():
	# 		flag_P = False
	# 		if len(truth) == len(packet):
	# 			for i in range(0,len(truth)):
	# 				if truth[i] == "*":#????
	# 					if i == len(truth)-1:#如果最后一个是“*”，那就直接continue，轮不到给break下面的代码了，flag就始终不会true。因此在这里就要给true
	# 						flag_P = True
	# 						break
	# 					else:
	# 						continue
	# 				if truth[i] != packet[i]:
	# 					break
	# 				if i == len(truth)-1:
	# 					flag_P = True
	# 		if flag_P:
	# 			result["TP"] += 1
	# 		else:
	# 			result["FP"] += 1
	# 	#change variable里面一共有15个报文，即ground truth有15条，不在TP里，就是FN
	# 	result["FN"] = 6 - result["TP"]
	return result

def calculate_precision_recall_f1(matrix):
	TP_num = matrix["TP"]
	FN_num = matrix["FN"]
	FP_num = matrix["FP"]
	if TP_num == 0 and FP_num == 0:
		precision = "None"
		recall = "None"
		f1_score = "None"
	else:
		precision = TP_num/(TP_num + FP_num)
		recall = TP_num/(TP_num + FN_num)
		f1_score = 2*precision*recall/(precision+recall)

	
	result = {
		"precision":precision,
		"recall":recall,
		"f1_score":f1_score,

	}
	return result
result_final = {}
result_final_detail = {}
requests_num = {}
packets_num = {}
# for tolent_threshold in [round(i * 0.01, 2) for i in range(11)]:
for tolent_threshold in [0.03]:

	result_final[tolent_threshold] = {}
	result_final_detail[tolent_threshold] = {}
	for dynamic_threshold in [0]:
	# for dynamic_threshold in [round(i * 0.1, 2) for i in range(11)]:
		result_final[tolent_threshold][dynamic_threshold] = {}
		result_final_detail[tolent_threshold][dynamic_threshold] = {}

		protocol,packet_num,tolent_threshold_no	,attack,mode = input_intial()
		file_group = get_file(protocol,"normal")
		attack_files = get_file(protocol,"attack")

		print("attack_files",attack_files)
		print("file_group",file_group)
		check_result_all = {}

		for attack_file in attack_files:
			print("\n")
			print("attack_file",attack_file)
			check_result_all[attack_file] = {}
			attack_request,match_templates,all_attack_requests,packet_num,request_num = AIAF(file_group,attack_file,packet_num,tolent_threshold,dynamic_threshold)

			# print("match_templates")
			# pprint(match_templates)

			# print("attack_request")
			# pprint(attack_request)
			if mode == "extra_packets":
				truth = all_attack_requests
			elif mode == "extra_function":
				with open("extra_function_requests_ground_truth",'r') as f:
					truths = json.load(f)
				truth = truths[attack_file]
			elif mode == "re_exp":
				truth = ground_truth[protocol][attack]
			else:
				raise ("mode error")
			# print(4444,truth)
			check_result = check(attack_request,truth,attack)

			check_result_all[attack_file] = check_result
			requests_num[attack_file] = request_num
			packets_num[attack_file] = packet_num
			result_final[tolent_threshold][dynamic_threshold][attack_file] = calculate_precision_recall_f1(check_result)
			result_final_detail[tolent_threshold][dynamic_threshold][attack_file] = check_result

pprint(check_result_all)
print("result_final")
pprint(result_final)

print("result_final_detail")
pprint(result_final_detail)

print("requests_num")
pprint(requests_num)

print("packets_num")
pprint(packets_num)