import json
import pathlib
import os
import glob


import pathlib
temp = pathlib.PosixPath
pathlib.PosixPath = pathlib.WindowsPath


output_path = pathlib.Path("E:/Projects/PracticeProjects/siem-parser/output")

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
        data = str(data)
        d.write(data)



data_files = {
    "empire_vbs" : "empire_launcher_vbs_2020-09-04160940.json",
    "sharpview_discovery" : "cmd_sharpview_pcre_net_2020-10-2920232423.json",
    "powershell_listener" : "psh_powershell_httplistener_2020-11-0204130683.json",
    "python_webserver" : "psh_python_webserver_2020-10-2900161507.json"

}

print(count_events(data_files['sharpview_discovery']))
