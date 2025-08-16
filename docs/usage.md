---

# How to use the analyzer?

- Make sure you have Python 3 installed

- Open terminal and navigate to the root folder of the project

- To run the code, use this command:

python src/analyzer.py

# What is included in the project?

- The main code, called "src/analyzer.py", is used to look for suspicious entries in files.

- The file "src/ioc_list.json" contains a list of Indicators of Compromise (IOCs) that are used for scanning.

- The sample log file for testing is called "src/apache.log".

- "src/alerts.csv" is where all alerts found are saved after analysis.

- Tests run using the "tests/test_analyzer.py" file to make sure everything is working correctly.

- The manual is in the "docs/usage.md" folder (this manual).

- README.md contains general information about the project.

# How to add your own indicators (IOCs)?

- Open the file "src/ioc_list.json" in any text editor

- Put your IP addresses, domains, hashes, process names and file paths in the appropriate sections

- Save the file.

Here is an example of what it should look like:

The json has the following parameters: "ips": "1.2.3.4", "domains": "malicious.com", "file_hashes": "abc123", "process_names": "badprocess.exe", "file_paths": "C:/malware/path".

To make sure everything works, run:

python tests/test_analyzer.py

or

To test units, use bash -m tests/test_analyzer.py.

# TIPS:

- Check the routes when you move files to make sure they are not corrupted.
- The analyzer prints notifications to terminal and saves them in the file "src/alerts.csv".


---
