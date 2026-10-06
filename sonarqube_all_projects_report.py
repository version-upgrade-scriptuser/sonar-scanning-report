#!/usr/bin/env python3

import os
import re
import sys
import json
import base64
import argparse
from datetime import datetime

import requests
import pandas as pd

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak
)


# ==========================================================
# Configuration
# ==========================================================

SONAR_URL = "https://sonar.unileversolutions.com"

# For local testing, you can hardcode token here.
# Do not commit real token to Git.
HARDCODED_TOKEN = "squ_cb6599d1599bf805713ac756d1a87604c3779b82"

# OUTPUT_DIR = "sonarqube_reports"
OUTPUT_DIR = f"sonarqube_reports_{datetime.now().strftime('%d%b%Y')}"

SUMMARY_CSV = "All_Projects_Summary.csv"
ISSUES_CSV = "All_Projects_Issues.csv"
SUMMARY_EXCEL = "All_Projects_Report.xlsx"
EXECUTIVE_PDF = "Executive_Sonar_Report.pdf"

DEFAULT_METRICS = [
    "bugs",
    "vulnerabilities",
    "security_hotspots",
    "code_smells",
    "coverage",
    "duplicated_lines_density",
    "reliability_rating",
    "security_rating",
    "sqale_rating",
    "ncloc",
    "complexity",
    "cognitive_complexity",
    "sqale_index"
]

RATING_MAP = {
    "1.0": "A",
    "2.0": "B",
    "3.0": "C",
    "4.0": "D",
    "5.0": "E",
    "1": "A",
    "2": "B",
    "3": "C",
    "4": "D",
    "5": "E"
}


# ==========================================================
# Utility Functions
# ==========================================================

def normalize_url(url):
    return url.rstrip("/")


def now_string():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def create_dir(path):
    os.makedirs(path, exist_ok=True)


def safe_filename(value):
    value = str(value)
    value = re.sub(r"[^\w.\-]+", "_", value)
    value = value.strip("_")
    return value[:150] if value else "unknown"


def to_int(value, default=0):
    try:
        if value in [None, "", "None"]:
            return default
        return int(float(value))
    except Exception:
        return default


def to_float(value, default=0.0):
    try:
        if value in [None, "", "None"]:
            return default
        return float(value)
    except Exception:
        return default


def rating(value):
    if value is None:
        return ""
    return RATING_MAP.get(str(value), str(value))


def get_token():
    """
    Priority:
    1. HARDCODED_TOKEN
    2. SONAR_TOKEN environment variable
    """

    if HARDCODED_TOKEN and HARDCODED_TOKEN != "squ_your_token_here":
        return HARDCODED_TOKEN

    token = os.getenv("SONAR_TOKEN")

    if not token:
        print("ERROR: Token not found.")
        print("Either update HARDCODED_TOKEN in script or set environment variable.")
        print("")
        print("PowerShell:")
        print('$env:SONAR_TOKEN="your-token"')
        print("")
        print("Git Bash/Linux:")
        print('export SONAR_TOKEN="your-token"')
        sys.exit(1)

    return token


def build_headers(token):
    """
    Same working format as your validation script.
    """

    auth_string = base64.b64encode(
        f"{token}:".encode()
    ).decode()

    headers = {
        "Authorization": f"Basic {auth_string}",
        "Accept": "application/json",
        "User-Agent": "curl/8.0.1"
    }

    return headers


# ==========================================================
# SonarQube Client
# ==========================================================

class SonarQubeClient:

    def __init__(self, sonar_url, token, verify_ssl=True, timeout=60, debug=False):
        self.sonar_url = normalize_url(sonar_url)
        self.headers = build_headers(token)
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.debug = debug

    def get(self, endpoint, params=None):
        url = f"{self.sonar_url}{endpoint}"

        response = requests.get(
            url,
            headers=self.headers,
            params=params,
            timeout=self.timeout,
            verify=self.verify_ssl
        )

        if self.debug:
            print("")
            print("URL    :", response.url)
            print("STATUS :", response.status_code)

        if response.status_code != 200:
            print("")
            print("API Failed")
            print("URL    :", response.url)
            print("STATUS :", response.status_code)
            print("RESPONSE:")
            print(response.text[:3000])

        response.raise_for_status()

        try:
            return response.json()
        except Exception:
            raise Exception(f"Invalid JSON response from {response.url}")

    def validate_connection(self):
        print("Validating authentication...")

        data = self.get("/api/authentication/validate")

        print(json.dumps(data, indent=2))

        valid = data.get("valid", False)

        if not valid:
            raise Exception("Token validation failed.")

        print("Authentication successful.")

    def get_all_projects(self, page_size=500):
        """
        Primary endpoint:
        /api/projects/search

        Fallback endpoint:
        /api/components/search_projects
        """

        try:
            return self._get_all_projects_from_projects_search(page_size)
        except Exception as ex:
            print("")
            print("Primary API failed: /api/projects/search")
            print("Trying fallback API: /api/components/search_projects")
            print("Reason:", str(ex))
            return self._get_all_projects_from_components_search(page_size)

    def _get_all_projects_from_projects_search(self, page_size=500):
        projects = []
        page = 1

        while True:
            data = self.get(
                "/api/projects/search",
                params={
                    "p": page,
                    "ps": page_size
                }
            )

            components = data.get("components", [])
            paging = data.get("paging", {})

            projects.extend(components)

            total = paging.get("total", len(projects))
            actual_page_size = paging.get("pageSize", page_size)

            if page * actual_page_size >= total:
                break

            page += 1

        return projects

    def _get_all_projects_from_components_search(self, page_size=500):
        projects = []
        page = 1

        while True:
            data = self.get(
                "/api/components/search_projects",
                params={
                    "p": page,
                    "ps": page_size
                }
            )

            components = data.get("components", [])
            paging = data.get("paging", {})

            projects.extend(components)

            total = paging.get("total", len(projects))
            actual_page_size = paging.get("pageSize", page_size)

            if page * actual_page_size >= total:
                break

            page += 1

        return projects

    def get_quality_gate(self, project_key):
        try:
            data = self.get(
                "/api/qualitygates/project_status",
                params={
                    "projectKey": project_key
                }
            )

            return data.get("projectStatus", {}).get("status", "UNKNOWN")

        except Exception as ex:
            return f"ERROR: {str(ex)}"

    def get_measures(self, project_key, metrics):
        try:
            data = self.get(
                "/api/measures/component",
                params={
                    "component": project_key,
                    "metricKeys": ",".join(metrics)
                }
            )

            measures = {}

            component = data.get("component", {})

            for item in component.get("measures", []):
                metric_name = item.get("metric")
                metric_value = item.get("value")
                measures[metric_name] = metric_value

            return measures

        except Exception as ex:
            return {
                "error": str(ex)
            }

    def get_project_issues(self, project_key, page_size=500, max_issues=5000):
        all_issues = []
        page = 1

        while True:
            try:
                data = self.get(
                    "/api/issues/search",
                    params={
                        "componentKeys": project_key,
                        "p": page,
                        "ps": page_size,
                        "resolved": "false"
                    }
                )

            except Exception as ex:
                all_issues.append({
                    "Project Key": project_key,
                    "Issue Key": "",
                    "Severity": "",
                    "Type": "",
                    "Status": "",
                    "Message": f"ERROR fetching issues: {str(ex)}",
                    "Component": "",
                    "File": "",
                    "Line": "",
                    "Rule": "",
                    "Creation Date": "",
                    "Update Date": "",
                    "Debt": "",
                    "Effort": "",
                    "Author": ""
                })
                return all_issues

            issues = data.get("issues", [])

            if not issues:
                break

            for issue in issues:
                component = issue.get("component", "")
                file_path = component

                if ":" in component:
                    file_path = component.split(":", 1)[1]

                all_issues.append({
                    "Project Key": project_key,
                    "Issue Key": issue.get("key", ""),
                    "Severity": issue.get("severity", ""),
                    "Type": issue.get("type", ""),
                    "Status": issue.get("status", ""),
                    "Message": issue.get("message", ""),
                    "Component": component,
                    "File": file_path,
                    "Line": issue.get("line", ""),
                    "Rule": issue.get("rule", ""),
                    "Creation Date": issue.get("creationDate", ""),
                    "Update Date": issue.get("updateDate", ""),
                    "Debt": issue.get("debt", ""),
                    "Effort": issue.get("effort", ""),
                    "Author": issue.get("author", "")
                })

                if len(all_issues) >= max_issues:
                    return all_issues

            paging = data.get("paging", {})
            total = paging.get("total", len(all_issues))
            actual_page_size = paging.get("pageSize", page_size)

            if page * actual_page_size >= total:
                break

            page += 1

        return all_issues


# ==========================================================
# Report Data Builders
# ==========================================================

def build_summary_row(project, quality_gate, measures):
    project_key = project.get("key", "")
    project_name = project.get("name", project_key)

    row = {
        "Project Key": project_key,
        "Project Name": project_name,
        "Qualifier": project.get("qualifier", ""),
        "Visibility": project.get("visibility", ""),
        "Last Analysis Date": project.get("lastAnalysisDate", ""),
        "Quality Gate": quality_gate,

        "Bugs": to_int(measures.get("bugs")),
        "Vulnerabilities": to_int(measures.get("vulnerabilities")),
        "Security Hotspots": to_int(measures.get("security_hotspots")),
        "Code Smells": to_int(measures.get("code_smells")),

        "Coverage %": to_float(measures.get("coverage")),
        "Duplications %": to_float(measures.get("duplicated_lines_density")),

        "Reliability Rating": rating(measures.get("reliability_rating")),
        "Security Rating": rating(measures.get("security_rating")),
        "Maintainability Rating": rating(measures.get("sqale_rating")),

        "Lines of Code": to_int(measures.get("ncloc")),
        "Complexity": to_int(measures.get("complexity")),
        "Cognitive Complexity": to_int(measures.get("cognitive_complexity")),
        "Technical Debt Minutes": to_int(measures.get("sqale_index")),

        "Report Generated On": now_string()
    }

    return row


def generate_per_project_csv(project_key, issues, csv_dir):
    create_dir(csv_dir)

    file_name = f"{safe_filename(project_key)}_issues.csv"
    path = os.path.join(csv_dir, file_name)

    df = pd.DataFrame(issues)
    df.to_csv(path, index=False, encoding="utf-8-sig")

    return path


# ==========================================================
# Excel Report
# ==========================================================

def write_excel(summary_df, issues_df, output_path):
    with pd.ExcelWriter(output_path, engine="openpyxl") as writer:
        summary_df.to_excel(writer, sheet_name="Summary", index=False)

        failed_df = summary_df[
            summary_df["Quality Gate"]
            .astype(str)
            .str.upper()
            .isin(["ERROR", "FAILED", "WARN"])
        ]

        failed_df.to_excel(
            writer,
            sheet_name="Quality_Gate_Failed",
            index=False
        )

        security_df = summary_df.sort_values(
            by=["Vulnerabilities", "Security Hotspots", "Bugs"],
            ascending=False
        )

        security_df.to_excel(
            writer,
            sheet_name="Security_Risk",
            index=False
        )

        coverage_df = summary_df.sort_values(
            by=["Coverage %"],
            ascending=True
        )

        coverage_df.to_excel(
            writer,
            sheet_name="Coverage_Ranking",
            index=False
        )

        issues_df.to_excel(
            writer,
            sheet_name="All_Issues",
            index=False
        )

        workbook = writer.book

        for sheet_name in workbook.sheetnames:
            worksheet = workbook[sheet_name]
            worksheet.freeze_panes = "A2"

            for column_cells in worksheet.columns:
                max_length = 0
                column_letter = column_cells[0].column_letter

                for cell in column_cells:
                    try:
                        cell_length = len(str(cell.value))
                        if cell_length > max_length:
                            max_length = cell_length
                    except Exception:
                        pass

                worksheet.column_dimensions[column_letter].width = min(
                    max_length + 2,
                    60
                )


# ==========================================================
# PDF Helpers
# ==========================================================

def table_style(header_background):
    return TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), header_background),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP")
    ])


def generate_executive_pdf(summary_df, issues_df, output_path):
    doc = SimpleDocTemplate(
        output_path,
        pagesize=landscape(A4),
        rightMargin=30,
        leftMargin=30,
        topMargin=30,
        bottomMargin=30
    )

    styles = getSampleStyleSheet()
    elements = []

    total_projects = len(summary_df)

    passed_count = len(
        summary_df[
            summary_df["Quality Gate"].astype(str).str.upper() == "OK"
        ]
    )

    failed_count = len(
        summary_df[
            summary_df["Quality Gate"].astype(str).str.upper().isin(
                ["ERROR", "FAILED"]
            )
        ]
    )

    warning_count = len(
        summary_df[
            summary_df["Quality Gate"].astype(str).str.upper() == "WARN"
        ]
    )

    total_bugs = summary_df["Bugs"].sum()
    total_vulnerabilities = summary_df["Vulnerabilities"].sum()
    total_hotspots = summary_df["Security Hotspots"].sum()
    total_code_smells = summary_df["Code Smells"].sum()

    avg_coverage = summary_df["Coverage %"].replace(0, pd.NA).dropna().mean()
    avg_duplications = summary_df["Duplications %"].replace(0, pd.NA).dropna().mean()

    elements.append(
        Paragraph(
            "SonarQube Executive Report - All Projects",
            styles["Title"]
        )
    )

    elements.append(Spacer(1, 10))

    elements.append(
        Paragraph(
            f"Generated On: {now_string()}",
            styles["Normal"]
        )
    )

    elements.append(Spacer(1, 20))

    executive_summary = [
        ["Metric", "Value"],
        ["Total Projects", total_projects],
        ["Quality Gate Passed", passed_count],
        ["Quality Gate Failed", failed_count],
        ["Quality Gate Warning", warning_count],
        ["Total Bugs", int(total_bugs)],
        ["Total Vulnerabilities", int(total_vulnerabilities)],
        ["Total Security Hotspots", int(total_hotspots)],
        ["Total Code Smells", int(total_code_smells)],
        [
            "Average Coverage %",
            round(float(avg_coverage), 2) if not pd.isna(avg_coverage) else "N/A"
        ],
        [
            "Average Duplications %",
            round(float(avg_duplications), 2) if not pd.isna(avg_duplications) else "N/A"
        ]
    ]

    elements.append(
        Paragraph(
            "Executive Summary",
            styles["Heading1"]
        )
    )

    summary_table = Table(
        executive_summary,
        colWidths=[3.0 * inch, 2.0 * inch]
    )

    summary_table.setStyle(
        table_style(colors.HexColor("#1F4E79"))
    )

    elements.append(summary_table)
    elements.append(Spacer(1, 20))

    # Top Risk Projects
    elements.append(
        Paragraph(
            "Top Risk Projects",
            styles["Heading1"]
        )
    )

    risk_df = summary_df.copy()

    risk_df["Risk Score"] = (
        risk_df["Vulnerabilities"] * 5
        + risk_df["Security Hotspots"] * 4
        + risk_df["Bugs"] * 3
        + risk_df["Code Smells"] * 1
    )

    top_risk_df = risk_df.sort_values(
        by="Risk Score",
        ascending=False
    ).head(15)

    risk_table_data = [[
        "Project Name",
        "Quality Gate",
        "Bugs",
        "Vulnerabilities",
        "Hotspots",
        "Code Smells",
        "Coverage %"
    ]]

    for _, row in top_risk_df.iterrows():
        risk_table_data.append([
            str(row["Project Name"])[:45],
            row["Quality Gate"],
            row["Bugs"],
            row["Vulnerabilities"],
            row["Security Hotspots"],
            row["Code Smells"],
            row["Coverage %"]
        ])

    risk_table = Table(
        risk_table_data,
        colWidths=[
            3.2 * inch,
            1.2 * inch,
            0.7 * inch,
            1.1 * inch,
            0.9 * inch,
            1.0 * inch,
            0.9 * inch
        ]
    )

    risk_table.setStyle(
        table_style(colors.HexColor("#C00000"))
    )

    elements.append(risk_table)

    elements.append(PageBreak())

    # Quality Gate Failed / Warning
    elements.append(
        Paragraph(
            "Quality Gate Failed / Warning Projects",
            styles["Heading1"]
        )
    )

    failed_df = summary_df[
        summary_df["Quality Gate"]
        .astype(str)
        .str.upper()
        .isin(["ERROR", "FAILED", "WARN"])
    ]

    fail_table_data = [[
        "Project Name",
        "Quality Gate",
        "Bugs",
        "Vulnerabilities",
        "Hotspots",
        "Coverage %",
        "Duplications %"
    ]]

    if failed_df.empty:
        fail_table_data.append([
            "No failed or warning projects found",
            "",
            "",
            "",
            "",
            "",
            ""
        ])
    else:
        for _, row in failed_df.head(30).iterrows():
            fail_table_data.append([
                str(row["Project Name"])[:50],
                row["Quality Gate"],
                row["Bugs"],
                row["Vulnerabilities"],
                row["Security Hotspots"],
                row["Coverage %"],
                row["Duplications %"]
            ])

    fail_table = Table(
        fail_table_data,
        colWidths=[
            3.5 * inch,
            1.2 * inch,
            0.7 * inch,
            1.1 * inch,
            0.9 * inch,
            0.9 * inch,
            1.0 * inch
        ]
    )

    fail_table.setStyle(
        table_style(colors.HexColor("#7030A0"))
    )

    elements.append(fail_table)

    elements.append(PageBreak())

    # Lowest Coverage
    elements.append(
        Paragraph(
            "Lowest Coverage Projects",
            styles["Heading1"]
        )
    )

    coverage_df = summary_df.sort_values(
        by="Coverage %",
        ascending=True
    ).head(20)

    coverage_table_data = [[
        "Project Name",
        "Coverage %",
        "Quality Gate",
        "Bugs",
        "Vulnerabilities",
        "Code Smells"
    ]]

    for _, row in coverage_df.iterrows():
        coverage_table_data.append([
            str(row["Project Name"])[:55],
            row["Coverage %"],
            row["Quality Gate"],
            row["Bugs"],
            row["Vulnerabilities"],
            row["Code Smells"]
        ])

    coverage_table = Table(
        coverage_table_data,
        colWidths=[
            4.0 * inch,
            1.0 * inch,
            1.2 * inch,
            0.8 * inch,
            1.1 * inch,
            1.0 * inch
        ]
    )

    coverage_table.setStyle(
        table_style(colors.HexColor("#548235"))
    )

    elements.append(coverage_table)

    elements.append(PageBreak())

    # Top Issues
    elements.append(
        Paragraph(
            "Top Open Issues",
            styles["Heading1"]
        )
    )

    issue_table_data = [[
        "Project Key",
        "Severity",
        "Type",
        "Status",
        "Message"
    ]]

    display_issues_df = issues_df.head(40)

    if display_issues_df.empty:
        issue_table_data.append([
            "No open issues found",
            "",
            "",
            "",
            ""
        ])
    else:
        for _, row in display_issues_df.iterrows():
            issue_table_data.append([
                str(row.get("Project Key", ""))[:35],
                str(row.get("Severity", "")),
                str(row.get("Type", "")),
                str(row.get("Status", "")),
                str(row.get("Message", ""))[:90]
            ])

    issue_table = Table(
        issue_table_data,
        colWidths=[
            2.3 * inch,
            1.0 * inch,
            1.0 * inch,
            1.0 * inch,
            5.0 * inch
        ]
    )

    issue_table.setStyle(
        table_style(colors.HexColor("#1F4E79"))
    )

    elements.append(issue_table)

    doc.build(elements)


def generate_project_pdf(project_row, project_issues, output_path):
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=35,
        leftMargin=35,
        topMargin=35,
        bottomMargin=35
    )

    styles = getSampleStyleSheet()
    elements = []

    elements.append(
        Paragraph(
            f"SonarQube Project Report<br/>{project_row['Project Name']}",
            styles["Title"]
        )
    )

    elements.append(Spacer(1, 15))

    summary_data = [
        ["Metric", "Value"],
        ["Project Key", project_row["Project Key"]],
        ["Quality Gate", project_row["Quality Gate"]],
        ["Bugs", project_row["Bugs"]],
        ["Vulnerabilities", project_row["Vulnerabilities"]],
        ["Security Hotspots", project_row["Security Hotspots"]],
        ["Code Smells", project_row["Code Smells"]],
        ["Coverage %", project_row["Coverage %"]],
        ["Duplications %", project_row["Duplications %"]],
        ["Reliability Rating", project_row["Reliability Rating"]],
        ["Security Rating", project_row["Security Rating"]],
        ["Maintainability Rating", project_row["Maintainability Rating"]],
        ["Last Analysis Date", project_row["Last Analysis Date"]]
    ]

    table = Table(
        summary_data,
        colWidths=[2.2 * inch, 3.8 * inch]
    )

    table.setStyle(
        table_style(colors.HexColor("#1F4E79"))
    )

    elements.append(table)
    elements.append(Spacer(1, 20))

    elements.append(
        Paragraph(
            "Top Open Issues",
            styles["Heading1"]
        )
    )

    issue_data = [[
        "Severity",
        "Type",
        "Status",
        "Message"
    ]]

    for issue in project_issues[:25]:
        issue_data.append([
            issue.get("Severity", ""),
            issue.get("Type", ""),
            issue.get("Status", ""),
            str(issue.get("Message", ""))[:80]
        ])

    if len(issue_data) == 1:
        issue_data.append([
            "",
            "",
            "",
            "No open issues found"
        ])

    issue_table = Table(
        issue_data,
        colWidths=[
            0.9 * inch,
            0.9 * inch,
            0.8 * inch,
            4.0 * inch
        ]
    )

    issue_table.setStyle(
        table_style(colors.HexColor("#7030A0"))
    )

    elements.append(issue_table)

    doc.build(elements)

# ==========================================================
# Project Selection
# ==========================================================

def select_projects(projects):

    print("\n")
    print("=" * 80)
    print("Project Selection Options")
    print("=" * 80)
    print("1. Export all project keys to all_project_list.txt")
    print("2. Read consumerx_sonar_project_list.txt and generate reports")
    print("3. Enter single project key manually")
    print("=" * 80)

    choice = input(
        "Select option [1/2/3]: "
    ).strip()

    # ======================================================
    # OPTION 1
    # ======================================================

    if choice == "1":

        output_file = "all_project_list.txt"

        with open(
            output_file,
            "w",
            encoding="utf-8"
        ) as file:

            for project in sorted(
                projects,
                key=lambda x: x.get("key", "")
            ):
                file.write(
                    f"{project.get('key', '')}\n"
                )

        print("")
        print(
            f"Project list exported: {output_file}"
        )

        print(
            f"Total Projects Exported: {len(projects)}"
        )

        sys.exit(0)

    # ======================================================
    # OPTION 2
    # ======================================================

    elif choice == "2":

        file_name = "consumerx_sonar_project_list.txt"

        if not os.path.exists(file_name):

            print("")
            print(
                f"ERROR: {file_name} not found."
            )

            print(
                "Create consumerx_sonar_project_list.txt and add "
                "one project key per line."
            )

            sys.exit(1)

        with open(
            file_name,
            "r",
            encoding="utf-8"
        ) as file:

            project_keys = {

                line.strip()

                for line in file

                if line.strip()
            }

        filtered_projects = [

            project

            for project in projects

            if project.get("key") in project_keys
        ]

        print("")
        print(
            f"Projects Requested : {len(project_keys)}"
        )

        print(
            f"Projects Found     : {len(filtered_projects)}"
        )

        if not filtered_projects:

            print("No matching projects found.")
            sys.exit(1)

        return filtered_projects

    # ======================================================
    # OPTION 3
    # ======================================================

    elif choice == "3":

        project_key = input(
            "\nEnter Project Key: "
        ).strip()

        filtered_projects = [

            project

            for project in projects

            if project.get("key") == project_key
        ]

        if not filtered_projects:

            print("")
            print(
                f"Project not found: {project_key}"
            )

            sys.exit(1)

        return filtered_projects

    else:

        print("Invalid option selected.")
        sys.exit(1)


# ==========================================================
# Main
# ==========================================================

def main():
    parser = argparse.ArgumentParser(
        description="Generate SonarQube reports for all projects."
    )

    parser.add_argument(
        "--url",
        default=SONAR_URL,
        help="SonarQube server URL"
    )

    parser.add_argument(
        "--output",
        default=OUTPUT_DIR,
        help="Output folder"
    )

    parser.add_argument(
        "--max-issues-per-project",
        type=int,
        default=5000,
        help="Maximum open issues to export per project"
    )

    parser.add_argument(
        "--project-pdfs",
        action="store_true",
        help="Generate individual PDF for every project"
    )

    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable SSL verification"
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print API URL and response status"
    )

    args = parser.parse_args()

    sonar_url = normalize_url(args.url)
    token = get_token()
    verify_ssl = not args.insecure

    output_dir = args.output
    csv_dir = os.path.join(output_dir, "csv")
    pdf_dir = os.path.join(output_dir, "pdf")
    json_dir = os.path.join(output_dir, "json")

    create_dir(output_dir)
    create_dir(csv_dir)
    create_dir(pdf_dir)
    create_dir(json_dir)

    client = SonarQubeClient(
        sonar_url=sonar_url,
        token=token,
        verify_ssl=verify_ssl,
        timeout=60,
        debug=args.debug
    )

    print("=" * 80)
    print("SonarQube All Projects Report")
    print("=" * 80)
    print("SonarQube URL :", sonar_url)
    print("Output Folder :", output_dir)
    print("Generated On  :", now_string())
    print("=" * 80)

    client.validate_connection()

    print("")
    print("Fetching all projects...")

    projects = client.get_all_projects()

    print(
        f"Total Projects Found: "
        f"{len(projects)}"
    )

    projects = select_projects(projects)

    print("")
    print(
        f"Projects Selected: "
        f"{len(projects)}"
    )

    for p in projects:

        print(
            f" - {p.get('key')}"
        )

    if not projects:
        print("No projects found. Please verify token Browse permission.")
        sys.exit(1)

    raw_projects_json = os.path.join(json_dir, "projects.json")

    with open(raw_projects_json, "w", encoding="utf-8") as file:
        json.dump(projects, file, indent=2)

    all_summary_rows = []
    all_issues = []

    for index, project in enumerate(projects, start=1):
        project_key = project.get("key", "")
        project_name = project.get("name", project_key)

        print("")
        print(f"[{index}/{len(projects)}] Processing project")
        print("KEY :", project_key)
        print("NAME:", project_name)

        if not project_key:
            print("Skipping project because key is missing.")
            continue

        quality_gate = client.get_quality_gate(project_key)

        measures = client.get_measures(
            project_key,
            DEFAULT_METRICS
        )

        issues = client.get_project_issues(
            project_key,
            max_issues=args.max_issues_per_project
        )

        summary_row = build_summary_row(
            project=project,
            quality_gate=quality_gate,
            measures=measures
        )

        all_summary_rows.append(summary_row)
        all_issues.extend(issues)

        generate_per_project_csv(
            project_key=project_key,
            issues=issues,
            csv_dir=csv_dir
        )

        if args.project_pdfs:
            project_pdf_path = os.path.join(
                pdf_dir,
                f"{safe_filename(project_key)}_report.pdf"
            )

            generate_project_pdf(
                project_row=summary_row,
                project_issues=issues,
                output_path=project_pdf_path
            )

    summary_df = pd.DataFrame(all_summary_rows)
    issues_df = pd.DataFrame(all_issues)

    summary_csv_path = os.path.join(output_dir, SUMMARY_CSV)
    issues_csv_path = os.path.join(output_dir, ISSUES_CSV)
    excel_path = os.path.join(output_dir, SUMMARY_EXCEL)
    executive_pdf_path = os.path.join(output_dir, EXECUTIVE_PDF)

    print("")
    print("Writing CSV reports...")

    summary_df.to_csv(
        summary_csv_path,
        index=False,
        encoding="utf-8-sig"
    )

    issues_df.to_csv(
        issues_csv_path,
        index=False,
        encoding="utf-8-sig"
    )

    print("Writing Excel report...")

    write_excel(
        summary_df=summary_df,
        issues_df=issues_df,
        output_path=excel_path
    )

    print("Writing Executive PDF report...")

    generate_executive_pdf(
        summary_df=summary_df,
        issues_df=issues_df,
        output_path=executive_pdf_path
    )

    print("")
    print("=" * 80)
    print("Report generation completed successfully.")
    print("=" * 80)
    print("Summary CSV      :", summary_csv_path)
    print("Issues CSV       :", issues_csv_path)
    print("Excel Report     :", excel_path)
    print("Executive PDF    :", executive_pdf_path)
    print("Per Project CSVs :", csv_dir)

    if args.project_pdfs:
        print("Per Project PDFs :", pdf_dir)

    print("=" * 80)


if __name__ == "__main__":
    main()