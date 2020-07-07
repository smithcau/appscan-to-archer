#!/usr/bin/env python3
__author__ = "Carter Smith"
__version__ = "0.1"
from lxml import etree as ET
import sys
import pprint
import os
import xlsxwriter
import datetime
import csv
import time
_csv_headers = []
_csv_rows = ['hostname', 'issue_severity', 'issue_cvss_score', 'reason_for_suspicion', 'advisory_name', 'advisory_risk', 'advisory_cause', 'advisory_info', 'affected_url', 'affected_html_entity', 'remediation_info', 'xml_report_filename', 'original_http_traffic', 'test_http_traffic', 'remediation_name_and_additional_info', 'issue_entity', 'issue_reasoning', 'issue_original_http_traffic', 'issue_test_http_traffic', 'issue_url', 'advisory_threatclassification_and_additional_info', 'xml_file', 'issue_cvss']

def usage():
	print("./{} <appscan report 1>.xml".format(sys.argv[0]))


def open_xml_file(xml_file):
	fcontents = open(xml_file,'r')
	contents = fcontents.read()
	fcontents.close()
	return ET.XML(contents)


def get_main_scan_summary_info(xml_root,xml_file,debug_log):
	try:
		hostname = ""
		total_low_sev_count = ""
		total_med_sev_count = ""
		total_high_sev_count = ""
		
		summaryinfo = xml_root.find('Summary/Hosts')
		if summaryinfo is not None:
			for child in summaryinfo.iter():
				if child.tag=="Host":
					hostname = child.attrib['Name']
				elif child.tag=="TotalLowSeverityIssues" and child.text:
					total_low_sev_count = child.text
				elif child.tag=="TotalMediumSeverityIssues" and child.text:
					total_med_sev_count = child.text
				elif child.tag=="TotalHighSeverityIssues" and child.text:
					total_high_sev_count = child.text
			
			#check we have all props, if so break out the loop by returning the props in a dict
			if (hostname != "" and total_low_sev_count != "" and total_med_sev_count != "" and total_high_sev_count != ""):
				return debug_log,{"hostname": hostname,"total_low_sev_count": total_low_sev_count,"total_med_sev_count": total_med_sev_count,"total_high_sev_count": total_high_sev_count}

		#error as we should never reach here
		print("[-] Error - could not parse summary stats from xml report?")
		debug_log += "[-] Error - could not parse summary stats from xml report? in " + xml_file + "\r\n\r\n\r\n"
		return debug_log,{"hostname": "N/A - Bad Report File","total_low_sev_count": 0,"total_med_sev_count": 0,"total_high_sev_count": 0}
	except Exception as e:
		print("[-] Error - could not parse summary stats from xml report?")
		debug_log += "[-] Error - could not parse summary stats from xml report? in " + xml_file + "\n"
		debug_log += "[-] Error exception details" + str(e) + "\n\n\n"
		return debug_log,{"hostname": "N/A - Bad Report File","total_low_sev_count": 0,"total_med_sev_count": 0,"total_high_sev_count": 0}


def get_remediation_info(xml_root,xml_file,debug_log):
	try:
		remediationinfo = xml_root.find('Results/RemediationTypes')
		remediation_name_and_additional_info = ""
		fix_id = ""
		remediation_info_array = []
		if remediationinfo is not None:
			for child in remediationinfo.iter():
				if child.tag=="RemediationType":
					#check if this fix_id has already been added to the array
					this_remediation_is_in_array = False
					for remediation_element in remediation_info_array:
						if fix_id == remediation_element["remediation_fix_id"]:
							this_remediation_is_in_array = True

					if fix_id!="" and not this_remediation_is_in_array:
						#we have come to end of this section, so add remediation info and fix_id to array then reset the vars for the next one
						#print "adding " + fix_id  
						remediation_info_array.append({'remediation_fix_id':fix_id,'remediation_name_and_additional_info':remediation_name_and_additional_info})
						#remediation_name_and_additional_info = ""					

					#grab the fix_id
					fix_id = child.attrib['ID']
					
				elif child.tag=="Name" and child.text:
					#grab the remediation name
					remediation_name_and_additional_info = child.text.replace('\n'," | ")

				elif child.tag =="text" and child.text:
					#grab the remediation additional info
					remediation_name_and_additional_info +=  " | " + child.text.replace('\n'," | ")
					if child.getnext() is None:
						this_remediation_is_in_array = False
						for remediation_element in remediation_info_array:
							if fix_id == remediation_element["remediation_fix_id"]:
								this_remediation_is_in_array = True
						if not this_remediation_is_in_array:
							#we are on the last recommendation and it's not already been submitted, so submit it to the array
							remediation_info_array.append({'remediation_fix_id':fix_id,'remediation_name_and_additional_info':remediation_name_and_additional_info})
											
				elif child.tag =="indentText" and child.text:
					#grab the remediation additional info
					remediation_name_and_additional_info +=  " | " + child.text.replace('\n'," | ")
					if child.getnext() is None:
						this_remediation_is_in_array = False
						for remediation_element in remediation_info_array:
							if fix_id == remediation_element["remediation_fix_id"]:
								this_remediation_is_in_array = True
						if not this_remediation_is_in_array:
							#we are on the last recommendation and it's not already been submitted, so submit it to the array
							remediation_info_array.append({'remediation_fix_id':fix_id,'remediation_name_and_additional_info':remediation_name_and_additional_info})

				elif child.tag =="link" and child.text:
					#grab the remediation additional info
					remediation_name_and_additional_info +=  " | " + child.text.replace('\n'," | ")
					if child.getnext() is None:
						this_remediation_is_in_array = False
						for remediation_element in remediation_info_array:
							if fix_id == remediation_element["remediation_fix_id"]:
								this_remediation_is_in_array = True
						if not this_remediation_is_in_array:
							#we are on the last recommendation and it's not already been submitted, so submit it to the array
							remediation_info_array.append({'remediation_fix_id':fix_id,'remediation_name_and_additional_info':remediation_name_and_additional_info})


			print("[+] Parsed " + str(len(remediation_info_array)) + " remediation entries...")
			return debug_log,remediation_info_array
		else:
			print("[-] Error - could not find remediation info in xml file " + xml_file)
			debug_log +="[-] Error - could not find remediation info in xml file " + xml_file + "\n\n\n"
			return debug_log,[]
	
	except Exception as e:
		print("[-] Error - could not find remediation info in xml file " + xml_file)
		debug_log +="[-] Error - could not find remediation info in xml file " + xml_file + "\n"	
		debug_log += "[-] Error exception details" + str(e) + "\n\n\n"
		return debug_log,[]
		
		
def get_advisory_info(xml_root,xml_file,remediation_info_array,debug_log):
	try:
		advisoryinfo = xml_root.find('Results/IssueTypes')
		advisory_remediation_fix_id_ref = ""
		advisory_issuetype_id =""
		advisory_name = ""
		advisory_threatclassification_and_additional_info = ""
		advisory_cause = ""
		advisory_risk = ""
		advisory_info_array = []

		if advisoryinfo is not None:
			for child in advisoryinfo.iter():
				if child.tag=="RemediationID" and child.text:
					#reset section_completed flag to prevent additional text and indentText fields being appended
					section_completed = False
					for fix_id in remediation_info_array:
						#get the advisory_issuetype_id for this remedation fix_id. this is just a precationary binding check
						if child.text == fix_id["remediation_fix_id"]:
							advisory_remediation_fix_id_ref = fix_id["remediation_fix_id"]
							advisory_issuetype_id = child.getparent().attrib["ID"]

				elif child.tag=="name" and child.getparent().tag=="advisory" and child.text:
					advisory_name = child.text.replace('\n'," | ")
					
				elif child.tag=="name" and child.getparent().tag=="threatClassification" and child.text:
					advisory_threatclassification_and_additional_info = child.text.replace('\n'," | ")

				elif child.tag=="text" and child.text and not section_completed:
					advisory_threatclassification_and_additional_info += " | " + child.text.replace('\n'," | ")			

				elif child.tag=="indentText" and child.text and not section_completed:
					advisory_threatclassification_and_additional_info += " | " + child.text.replace('\n'," | ")	

				elif child.tag=="cause" and child.text:
					advisory_cause = child.text.replace('\n'," | ")

				elif child.tag=="securityRisk" and child.text:
					advisory_risk = child.text.replace('\n'," | ")

				elif child.tag=="affectedProduct":
					#end of section has been reached as far as advisory details is concerned. set flag
					section_completed = True
					advisory_info_array.append({'advisory_remediation_fix_id_ref':advisory_remediation_fix_id_ref,'advisory_issuetype_id':advisory_issuetype_id,'advisory_name':advisory_name,'advisory_threatclassification_and_additional_info':advisory_threatclassification_and_additional_info,'advisory_cause':advisory_cause,'advisory_risk':advisory_risk})
					
					
			print("[+] Parsed " + str(len(advisory_info_array)) + " advisory entries...")
			return debug_log,advisory_info_array
		else:
			print("[-] Error - could not find advisory info in xml file " + xml_file)
			debug_log +="[-] Error - could not find advisory info in xml file " + xml_file + "\n\n\n"		
			return debug_log,[]
	
	except Exception as e:
		print("[-] Error - could not find advisory info in xml file " + xml_file)
		debug_log +="[-] Error - could not find advisory info in xml file " + xml_file + "\n"	
		debug_log += "[-] Error exception details" + str(e) + "\n\n\n"
		return debug_log,[]


def get_issue_info_and_write_excel_data_in_memory(xml_root,xml_file,summary_info_dict,remediation_info_array,advisory_info_array,high_sev_count,med_sev_count,low_sev_count,debug_log):
	try:
		issuesinfo = xml_root.find('Results/Issues')
		issue_issuetype_id =""
		issue_url =""
		issue_severity =""
		issue_cvss =""
		issue_entity =""
		issue_reasoning =""
		issue_original_http_traffic =""
		issue_test_http_traffic =""
		issue_count = 0
		
		#add to total issue counts for final summary of all docs
		high_sev_count += int(summary_info_dict["total_high_sev_count"])
		med_sev_count += int(summary_info_dict["total_med_sev_count"])
		low_sev_count += int(summary_info_dict["total_low_sev_count"])
				
		if issuesinfo is not None:
			for child in issuesinfo.iter():
				if child.tag=="Issue":
					for issuetype_id in advisory_info_array:
						#find the matching advisory_issue_type_id for the issue_IssueTypeID so the advisory and issues can be binded correctly.
						if child.attrib["IssueTypeID"] == issuetype_id["advisory_issuetype_id"]:
							issue_issuetype_id = child.attrib["IssueTypeID"]
							#reset the issues variables for this new issue
							issue_url =""
							issue_severity =""
							issue_cvss =""
							issue_entity =""
							issue_reasoning =""
							issue_original_http_traffic =""
							issue_test_http_traffic =""
				
				elif child.tag=="Url" and child.getparent().tag=="Issue" and child.text:
					issue_url = child.text
				

				elif child.tag=="Severity" and child.getparent().tag=="Issue" and child.text:
					issue_severity = child.text
					
				elif child.tag=="Score" and child.getparent().tag=="CVSS" and child.text:
					issue_cvss = child.text
									
				#watch this, might not be safe to use. if so just remove it
				elif child.tag=="Entity" and child.getparent().tag=="Issue":
					issue_entity = pprint.pformat(list(child.attrib.items())).replace('\n'," | ")
					
				#we only want to extract one instance of test variant data, so check if reasoning is already populated			
				elif child.tag=="Reasoning" and issue_reasoning == "" and child.text:
					issue_reasoning = child.text.replace('\n'," | ")

				#we only want to extract one instance of test variant data, so check if OG HTTP traffic is already populated			
				elif child.tag=="OriginalHttpTraffic" and issue_original_http_traffic == "" and child.text:
					issue_original_http_traffic = child.text.encode('utf-8')
					
				#we only want to extract one instance of test variant data, so check if test HTTP traffic is already populated			
				if child.tag=="TestHttpTraffic" and child.text is not None and child.text.replace('\n'," | "):
					#this is our last check before commiting an entry to excel in memory and flushing for the next xml report file
					if issue_test_http_traffic != "":
						#do nothing, we've already committed this issue to excel memory
						sys.stdout.write(".")
					else:
						#we've not submitted this issue to excel memory yet and this is the last element of the this issue. now commit all if severity is not just "informational".
						issue_test_http_traffic = child.text.encode('utf-8')
						if issue_severity != "Informational":
							#build excel array row accordingly, based on severity
							issue_count +=1
							
							for advisory in advisory_info_array:						
								if issue_issuetype_id == advisory["advisory_issuetype_id"]:
									#found matching advisory for this issue
									#now find matching remediation:
									for remediation in remediation_info_array:
										if advisory["advisory_remediation_fix_id_ref"] == remediation["remediation_fix_id"]:
											#found matching remediation fix id, now we can commit the row to excel memory

											if issue_severity == "High":
												
												high_severity_excel_row_array.append({'hostname':summary_info_dict["hostname"],'issue_severity':issue_severity,'issue_cvss':issue_cvss,'issue_reasoning':issue_reasoning,'advisory_name':advisory["advisory_name"],'advisory_risk':advisory["advisory_risk"],'advisory_cause':advisory["advisory_cause"],'advisory_threatclassification_and_additional_info':advisory["advisory_threatclassification_and_additional_info"],'issue_url':issue_url,'issue_entity':issue_entity,'remediation_name_and_additional_info':remediation["remediation_name_and_additional_info"],'issue_original_http_traffic':issue_original_http_traffic,'issue_test_http_traffic':issue_test_http_traffic,'xml_file':xml_file})
												issue_issuetype_id =""#(extracted from remediation_fix_id)
																						
											elif issue_severity == "Medium":
												
												medium_severity_excel_row_array.append({'hostname':summary_info_dict["hostname"],'issue_severity':issue_severity,'issue_cvss':issue_cvss,'issue_reasoning':issue_reasoning,'advisory_name':advisory["advisory_name"],'advisory_risk':advisory["advisory_risk"],'advisory_cause':advisory["advisory_cause"],'advisory_threatclassification_and_additional_info':advisory["advisory_threatclassification_and_additional_info"],'issue_url':issue_url,'issue_entity':issue_entity,'remediation_name_and_additional_info':remediation["remediation_name_and_additional_info"],'issue_original_http_traffic':issue_original_http_traffic,'issue_test_http_traffic':issue_test_http_traffic,'xml_file':xml_file})
												issue_issuetype_id =""#(extracted from remediation_fix_id)
												
											elif issue_severity == "Low":
												
												low_severity_excel_row_array.append({'hostname':summary_info_dict["hostname"],'issue_severity':issue_severity,'issue_cvss':issue_cvss,'issue_reasoning':issue_reasoning,'advisory_name':advisory["advisory_name"],'advisory_risk':advisory["advisory_risk"],'advisory_cause':advisory["advisory_cause"],'advisory_threatclassification_and_additional_info':advisory["advisory_threatclassification_and_additional_info"],'issue_url':issue_url,'issue_entity':issue_entity,'remediation_name_and_additional_info':remediation["remediation_name_and_additional_info"],'issue_original_http_traffic':issue_original_http_traffic,'issue_test_http_traffic':issue_test_http_traffic,'xml_file':xml_file})
												issue_issuetype_id =""#(extracted from remediation_fix_id)
																
			print("")
			print("[+] XML doc has " + summary_info_dict["total_high_sev_count"] + " high severity issues")
			print("[+] XML doc has " + summary_info_dict["total_med_sev_count"] + " medium severity issues")
			print("[+] XML doc has " + summary_info_dict["total_low_sev_count"] + " low severity issues")
			print("[+] Will add " + str(issue_count) + " non informational issues to master Excel spreadsheet...")
				
			#check if any and all issues were parsed as expected
			if issue_count == 0:
				debug_log += "[-] Error - did not add any issues for xml file " + xml_file + "\n\n\n"
				return debug_log,high_severity_excel_row_array,medium_severity_excel_row_array,low_severity_excel_row_array,high_sev_count,med_sev_count,low_sev_count
				
			elif issue_count < (int(summary_info_dict["total_high_sev_count"]) + int(summary_info_dict["total_med_sev_count"]) + int(summary_info_dict["total_low_sev_count"])):
				debug_log += "[-] Warning - possible parsing issue. Could not parse all issues:\n"
				debug_log += "[-] " + xml_file + " had " +  summary_info_dict["total_high_sev_count"] + " high severity issues\n"
				debug_log += "[-] " + xml_file + " had " +  summary_info_dict["total_med_sev_count"] + " medium severity issues\n"
				debug_log += "[-] " + xml_file + " had " +  summary_info_dict["total_low_sev_count"] + " low severity issues\n"				
				debug_log += "[-] But only " + str(issue_count) + " issues were parsed and added to report\n\n\n"
				return debug_log,high_severity_excel_row_array,medium_severity_excel_row_array,low_severity_excel_row_array,high_sev_count,med_sev_count,low_sev_count				
	
			else:
				return debug_log,high_severity_excel_row_array,medium_severity_excel_row_array,low_severity_excel_row_array,high_sev_count,med_sev_count,low_sev_count
			
	except Exception as e:
		debug_log += "[-] Error processing issue details in " + xml_file + "\n"
		debug_log += "[-] Error exception details" + str(e) + "\n\n\n"
		return debug_log,[]


def saveToFile(high_severity_excel_row_array,medium_severity_excel_row_array,low_severity_excel_row_array):
	dict_ = high_severity_excel_row_array
	dict_ += medium_severity_excel_row_array
	dict_ += low_severity_excel_row_array
	fname = "output/" + sys.argv[1].split(".")[0] + str(int(time.time())) + '.csv'
	if not os.path.exists(fname):
		with open(fname, 'w'): pass
	with open(fname, 'w') as csvfile:
		writer = csv.DictWriter(csvfile, fieldnames=_csv_rows)
		writer.writeheader()
		for i in dict_:
			writer.writerow(i)

if __name__=="__main__":
	if len(sys.argv) != 2:
		usage()
		exit()
	xml_file = sys.argv[1]
	debug_log = ""
	low_severity_excel_row_array = []
	medium_severity_excel_row_array = []
	high_severity_excel_row_array = []
	high_sev_count = 0
	med_sev_count = 0
	low_sev_count = 0
	report_count = 0
	print("[+] Working on " + xml_file + "...")
	xml_root = open_xml_file(xml_file)
	#get main scan summary info
	debug_log,summary_info_dict = get_main_scan_summary_info(xml_root,xml_file,debug_log)
	#only proceed with parsing if there are actual issues and not a dud XML report
	if int(summary_info_dict["total_high_sev_count"]) + int(summary_info_dict["total_med_sev_count"]) + int(summary_info_dict["total_low_sev_count"]) == 0:
		print("[-] Skipping this XML file. No issues were found")
	#get remediation info
	debug_log,remediation_info_array = get_remediation_info(xml_root,xml_file,debug_log)
	#get advisory info
	debug_log,advisory_info_array = get_advisory_info(xml_root,xml_file,remediation_info_array,debug_log)
	#get issue info then write excel data in memory for this xml report
	debug_log,high_severity_excel_row_array,medium_severity_excel_row_array,low_severity_excel_row_array,high_sev_count,med_sev_count,low_sev_count = get_issue_info_and_write_excel_data_in_memory(xml_root,xml_file,summary_info_dict,remediation_info_array,advisory_info_array,high_sev_count,med_sev_count,low_sev_count,debug_log)
	report_count+=1
	#write the excel file to disk
	saveToFile(high_severity_excel_row_array,medium_severity_excel_row_array,low_severity_excel_row_array)
	#check debug_log for any content:
	if debug_log != "":
		tmpfile = open("debug_log.txt","w")
		tmpfile.write(debug_log)
		tmpfile.close()
		print("[-] Warning: debug log has entries, check debug_log.txt for parsing problems")
