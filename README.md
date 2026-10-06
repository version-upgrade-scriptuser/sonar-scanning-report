# sonar-scanning-report
**Sonar Report Repository:** Repository used to collect, generate, and maintain SonarQube analysis reports for application repositories. It provides a centralized view of code quality metrics such as bugs, vulnerabilities, code smells, code coverage, code duplication, security hotspots, and quality gate status.


# SonarQube Report Generation – Steps
# 1. Connect to Accenture VPN:
vpn: dcn-b6fpa-extranet.accenture.com
Accenture VPN: 125.19.135.160

- First, connect to the Accenture VPN to ensure you have access to the required SonarQube resources.

# 2. Open the SonarQube Folder

- Navigate to the sonarqube folder containing the reporting scripts.

# Requirement: Python 3.*

# 3. Run the SonarQube Report Script

- Run the following command:

python sonarqube_all_projects_report.py

# 4. Select the Scan Option

- When prompted, select Option 2 to use the consumerx_sonar_project_list.txt file and scan all repositories listed in the file.

# 5. Check the Output Folder

- After the scan completes, an output folder will be created with the current date in the following format:

 sonarqube_reports_{date}


# For example:

sonarqube_reports_01Aug2026

# 6. Generated Reports

- The dated output folder will contain the following files:

  All_Projects_Issues.csv
  All_Projects_Report_{date}.xlsx
  All_Projects_Summary_{date}.csv
  Executive_Sonar_Report_{date}.pdf

## These files contain the detailed issues, project-level reports, summaries, and executive-level SonarQube analysis results.