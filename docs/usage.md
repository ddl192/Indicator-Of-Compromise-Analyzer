
![USAGE](https://github.com/user-attachments/assets/a723a6b0-d35d-43ed-bfca-7e661f4c3dfa)

# How to use the analyzer?

- Make sure you have Python 3 installed.

- Open terminal and navigate to the root folder of the project, then to the src directory.

- To run the code, use this command:

```bash
python analyzer.py
```

# What is included in this project?

- The main code, called "analyzer.py", is used to look for suspicious entries in files.

- The file "ioc_list.json" contains a list of Indicators of Compromise (IOCs) that are used for scanning.

- The sample log file for testing is called "apache.log".

- "alerts.csv" is where all alerts found are saved after analysis.

- Tests can be run using the "test_analyzer.py" file located in the "tests" directory to ensure everything works correctly.

- The manual is in the "docs/usage.md" folder (this manual).

- README.md contains general information about the project.

# How to add your own indicators (IOCs)?

- Open the file "ioc_list.json" in any text editor.

- Put your IP addresses, domains, hashes, process names and file paths in the appropriate sections.

- Save your file.

# Here is an example of what it should look like: 

- The JSON has the following parameters:

**{
  "ips": ["1.2.3.4"],
  "domains": ["malicious.com"],
  "file_hashes": ["abc123"],
  "process_names": ["badprocess.exe"],
  "file_paths": ["C:/malware/path"]
}**


# To make sure everything works, run:
```
python test_analyzer.py
```

# TIPS

- Check the paths when you move files to make sure they are not corrupted.

- The analyzer prints notifications to terminal and saves them in the file "alerts.csv".




