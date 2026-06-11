import json
import pathlib
import os
import glob


import pathlib
temp = pathlib.PosixPath
pathlib.PosixPath = pathlib.WindowsPath


output_path = pathlib.Path("E:/Projects/PracticeProjects/siem-parser/output/json")

def load_events(file):
    try:
        input_path = pathlib.PosixPath("E:/Projects/PracticeProjects/siem-parser/data/windows-exe-host")
        input_file = input_path / file
        events_data = input_file.read_text(encoding='utf-8')
        events_data = events_data.splitlines()
        return events_data
    except FileNotFoundError:
        print(f"Error: The file at {file_path} was not found.")
        return None

def count_events(file):
        lines = load_events(file)
        event_count = {}
        for line in lines:
            if line.strip():
                event_dict = json.loads(line)
                event_id = "EventID " + str(event_dict['EventID'])
                if event_id in event_count:
                    event_count[event_id] +=1
                else:
                    event_count[event_id] = 1  
        write_events(event_count,file)

def write_events(data,file):
    file = pathlib.Path(file)
    output_path.mkdir(parents=True, exist_ok=True)
    output_file = output_path / f"{file.stem}_counts.json"
    with open(output_file , 'w') as d:
        data = json.dumps(data)
        d.write(data)

def write_all_event_counts(data_files):
    eventIDs = []
    for file in data_files.values():
        count_events(file)
    unique_event_ids = set()
    for file in output_path.iterdir():
        with open(file, 'r', encoding='utf-8') as f:
                # Load the count dictionary
                data = json.load(f)
                # Add all keys (EventIDs) to the set
                unique_event_ids.update(data.keys())
    final_output = output_path.parent / "eventids.txt"
    with open(final_output, 'w', encoding='utf-8') as f:
        for eid in sorted(unique_event_ids):
            f.write(f"{eid}\n")

def get_event_details(event_id, file):
    lines = load_events(file)
    events = {}
    for line in lines:
        new_event = {}
        line = json.loads(line)
        if event_id == line['EventID']:
            #Check if event exists and add count
            for event in events.values():
                if event['SourceImage'] == line['SourceImage'] and event['TargetImage'] == line['TargetImage']:
                    event['EventCount'] =+ 1
            # if not make new event
            else:
                uid = f"{line['EventID']}_{line['SourceImage']}_{line['TargetImage']}"
                events[uid] = {
                'EventCount' : 1,
                'EventID': line['EventID'],
                'SourceImage': line['SourceImage'],
                'TargetImage' : line['TargetImage']
                }
    readable_report = list(events.values())
    return readable_report

def log_query(event_id , file, source_image=None, target_image=None ):
    event_id_data = get_event_details (event_id, file)
    total_events = 0
    event_id_count = 0
    query_count = 0
    query_result = {}
    lines = load_events(file)
    for line in lines:
        if line.strip():
            total_events +=1
    query_result ['Total_file_events'] = total_events
    for event in event_id_data:
        event_id_count += event['EventCount']    
    query_result ['Total_event_id_count'] = event_id_count
     
    for event in event_id_data:
        if (source_image is not None and source_image in event['SourceImage']) or (target_image is not None and target_image in event["TargetImage"]):
            query_count = event['EventCount']
    query_result['query_event_count'] = query_count
    return query_result


data_files = {
    "empire_vbs" : "empire_launcher_vbs_2020-09-04160940.json",
    "sharpview_discovery" : "cmd_sharpview_pcre_net_2020-10-2920232423.json",
    "powershell_listener" : "psh_powershell_httplistener_2020-11-0204130683.json",
    "python_webserver" : "psh_python_webserver_2020-10-2900161507.json"

}

# write_all_event_counts(data_files)
# print(get_event_details(10, data_files["sharpview_discovery"]))
print(log_query(10 , data_files["sharpview_discovery"] ,  target_image="lsass"))