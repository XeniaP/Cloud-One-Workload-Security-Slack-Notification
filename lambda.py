import json
import urllib.request

# Intrusion Preventionand Firewall Events
def IPSFirewall(event_info, ws_event):
    if(ws_event["ActionString"]):
        event_info += "\n*Action:* {}".format(ws_event["ActionString"])
    elif(ws_event["DestinationIP"] and ws_event["SourceIP"]):
        event_info += "\n*Source/Destination IP:* {}/{}".format(ws_event["SourceIP"], ws_event["DestinationIP"])
    elif(ws_event["DestinationPort"] and ws_event["SourcePort"]):
        event_info += "\n*Source/Destination Port:* {}/{}".format(ws_event["SourcePort"], ws_event["DestinationPort"])
    elif(ws_event["DirectionString"]):
        event_info += "\n*Direction:* {}".format(ws_event["DirectionString"])
    elif(ws_event["ProtocolString"]):
        event_info += "\n*Protocol:* {}".format(ws_event["ProtocolString"])
    elif(ws_event["SeverityString"]):
        event_info += "\n*Severity:* {}".format(ws_event["SeverityString"])    
    elif(ws_event["ProcessName"]):
        event_info += "\n*Process Name:* {}".format(ws_event["ProcessName"])
    elif(ws_event["Reason"]):
        event_info += "\n*Rule:* {}".format(ws_event["Reason"])
    return event_info

# Log Inspection Events
def OSSEC(event_info, ws_event):
    if(ws_event["OSSEC_Action"]):
        event_info += "\n*Action:* {}".format(ws_event["OSSEC_Action"])
    elif(ws_event["OSSEC_Command"]):
        event_info += "\n*Command:* {}".format(ws_event["OSSEC_Command"])
    elif(ws_event["OSSEC_Data"]):
        event_info += "\n*Data:* {}".format(ws_event["OSSEC_Data"])
    elif(ws_event["OSSEC_Description"]):
        event_info += "\n*Description:* {}".format(ws_event["OSSEC_Description"])
    elif(ws_event["OSSEC_FullLog"]):
        event_info += "\n*FullLog:* {}".format(ws_event["OSSEC_FullLog"])
    elif(ws_event["OSSEC_Groups"]):
        event_info += "\n*Groups:* {}".format(ws_event["OSSEC_Groups"])
    elif(ws_event["OSSEC_ID"]):
        event_info += "\n*ID:* {}".format(ws_event["OSSEC_ID"])
    elif(ws_event["OSSEC_Level"]):
        event_info += "\n*Level:* {}".format(ws_event["OSSEC_Level"])
    elif(ws_event["OSSEC_Location"]):
        event_info += "\n*Location:* {}".format(ws_event["OSSEC_Location"])
    elif(ws_event["OSSEC_Log"]):
        event_info += "\n*Log:* {}".format(ws_event["OSSEC_Log"])
    elif(ws_event["OSSEC_ProgramName"]):
        event_info += "\n*ProgramName:* {}".format(ws_event["OSSEC_ProgramName"])
    elif(ws_event["OSSEC_Protocol"]):
        event_info += "\n*Protocol:* {}".format(ws_event["OSSEC_Protocol"])
    elif(ws_event["OSSEC_SourceIP"] and ws_event["OSSEC_DestinationIP"]):
        event_info += "\n*Source/Destination IP:* {}/{}".format(ws_event["OSSEC_SourceIP"], ws_event["OSSEC_DestinationIP"])
    elif(ws_event["OSSEC_SourcePort"] and ws_event["OSSEC_DestinationPort"]):
        event_info += "\n*Source/Destination Port:* {}/{}".format(ws_event["OSSEC_SourcePort"], ws_event["OSSEC_DestinationPort"])
    elif(ws_event["OSSEC_SourceUser"] and ws_event["OSSEC_DestinationUser"]):
        event_info += "\n*Source/Destination User:* {}/{}".format(ws_event["OSSEC_SourceUser"], ws_event["OSSEC_DestinationUser"])
    elif(ws_event["OSSEC_Status"]):
        event_info += "\n*Status:* {}".format(ws_event["OSSEC_Status"])
    elif(ws_event["OSSEC_SystemName"]):
        event_info += "\n*SystemName:* {}".format(ws_event["OSSEC_SystemName"])
    elif(ws_event["OSSEC_URL"]):
        event_info += "\n*URL:* {}".format(ws_event["OSSEC_URL"])
    return event_info

# Host General Info
def host_Info(ws_event):
    """
    Update a Slack channel
    """
    hostinfo = ""
    if(ws_event["Hostname"]):
        hostinfo += "\n*HostName:* {}".format(ws_event["Hostname"])
    elif(ws_event["HostInstanceID"]):
        hostinfo += "\n*InstanceID:* {}".format(ws_event["HostInstanceID"])
    elif(ws_event["HostLastIPUsed"]):
        hostinfo += "\n*Last Ip Used:* {}".format(ws_event["HostLastIPUsed"])
    elif(ws_event["HostOS"]):
        hostinfo += "\n*Operative System:* {}".format(ws_event["HostOS"])
    elif(ws_event["HostAgentVersion"]):
        hostinfo += "\n*Agent Version:* {}".format(ws_event["HostAgentVersion"])
    elif(ws_event["LogDate"]):
        hostinfo += "\n*Date:* {}".format(ws_event["LogDate"])
    return hostinfo

# General Events
def parse_log(ws_event):
    event_info= ""
    if(ws_event['EventType'] == "AntiMalwareEvent"): #Anti-Malware Module
        event_info = "*Event Type:* {}\n*Malware Type:* {}\n*Malware Name:* {}\n*Action:* {}\n*File:* {}".format(ws_event["EventType"], ws_event["MajorVirusTypeString"], ws_event["MalwareName"], ws_event["ScanResultString"], ws_event["InfectedFilePath"])
    elif(ws_event["EventType"] == "WebReputationEvent"): #Web Reputation Module
        event_info = "*Event Type:* {}\n*Target IP:* {}\n*Target URL:* {}\n*Risk:* {}".format(ws_event["EventType"], ws_event["TargetIP"], ws_event["URL"], ws_event["Risk"])
    elif(ws_event["EventType"] == "IntegrityEvent"): #File Integrity Monitoring Module
        event_info = "*Event Type:* {}\n*File/Registry:* {}\n*Entity:* {}\n*Process:* {}\n*Change:* {}\n*User:* {}\n*Severity:* {}\n*FIM Rule:* {}".format(ws_event["EventType"], ws_event["Key"], ws_event["EntityType"], ws_event["Process"], ws_event["ChangeString"], ws_event["User"], ws_event["SeverityString"], ws_event["Reason"])
    elif(ws_event["EventType"] == "LogInspectionEvent"): #Log Inspection Module
        event_info_aux = "*Event Type:* {}".format(ws_event["EventType"])
        event_info = OSSEC(event_info_aux, ws_event)
    elif(ws_event["EventType"] == "PayloadLog" or ws_event["EventType"] == "PacketLog"): #Intrusion Prevention Module y Firewall Module
        event_info_aux = "*Event Type:* {}".format(ws_event["EventType"])
        event_info = IPSFirewall(event_info_aux, ws_event)
    return event_info
 
# Slack channel Info   
def update_ops(message):
  """
  Update a Slack channel
  """
  slack_url = "<SLACK_INCOMMING_WEBHOOK_URL>"
  slack_message = {
    "blocks": message
  }

  headers = { 'Content-type': 'application/json' }
  request = urllib.request.Request(slack_url, data=bytes(json.dumps(slack_message), encoding="utf-8"), headers=headers)
  response = urllib.request.urlopen(request)
  print(response.read())

def lambda_handler(event, content):
  """
  Format and send the incoming Deep Security event to Slack
  """
  result = { 'statusCode': 500, 'message': "" }
  if not type(event) == type({}):
    # Not a valid event
    result['statusCode'] = 500
    result['message'] = "Invalid event passed to the Lambda function"
  else:
    if event:
      if 'Records' in event:
        for record in event['Records']:
          if 'Sns' in record and 'Message' in record['Sns']:
            deep_security_events = None
            try:
              deep_security_events = json.loads(record['Sns']['Message'])
              print("Records converted and ready for processing")
            except Exception as err:
              result['statusCode'] = 500
              result['message'] = "Could not convert the SNS message from JSON to a dict\n{}".format(err)
            if deep_security_events:
              for i, deep_security_event in enumerate(deep_security_events):
                message = [
                    {"type": "divider"},
                    {"type": "section","text":{"type": "mrkdwn","text":  host_Info(deep_security_event)}},
                    {"type": "section","text":{"type": "mrkdwn","text": parse_log(deep_security_event)}}
                ]
                if update_ops(message):
                  result['statusCode'] = 200
                  result['message'] += 'Message #{} sent to Slack\n'.format(i)
                else:
                  result['statusCode'] = 500
                  result['message'] += 'Could not send message #{} to Slack\n'.format(i)
          else:
            result['statusCode'] = 500
            result['message'] = 'Record is NOT an SNS message. Stopping processing'
      else:
        result['statusCode'] = 500
        result['message'] = 'Event contains 0 records'
  print(result)
  return result