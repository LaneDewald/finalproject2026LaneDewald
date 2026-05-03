# Final Project 26
### INF601 - Advanced Programming in Python
### Lane Dewald
### Mini Project 3
from flask import Flask, render_template, request, session, redirect, url_for
import requests
import json
import os
from datetime import datetime

app = Flask(__name__)

app.secret_key = "cve_lookup_secret_123"

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def get_severity_color(score):
    """Return a color class based on CVSS score."""
    if score is None:
        return "secondary"
    score = float(score)
    if score >= 9.0:
        return "danger"
    elif score >= 7.0:
        return "warning"
    elif score >= 4.0:
        return "info"
    else:
        return "success"

def parse_cve_data(cve_item):
    """
    Pull out the fields we care about from a raw CVE item.
    The NVD API response format is kind of nested so this helps clean it up.
    """
    cve_id = cve_item.get("id", "N/A")
    descriptions = cve_item.get("descriptions", [])
    description = "No description available."
    for d in descriptions:
        if d.get("lang") == "en":
            description = d.get("value", "No description available.")
            break

    cvss_score = None
    cvss_version = None
    cvss_vector = None
    metrics = cve_item.get("metrics", {})

    if "cvssMetricV31" in metrics:
        data = metrics["cvssMetricV31"][0]["cvssData"]
        cvss_score = data.get("baseScore")
        cvss_version = "3.1"
        cvss_vector = data.get("vectorString")
    elif "cvssMetricV30" in metrics:
        data = metrics["cvssMetricV30"][0]["cvssData"]
        cvss_score = data.get("baseScore")
        cvss_version = "3.0"
        cvss_vector = data.get("vectorString")
    elif "cvssMetricV2" in metrics:
        data = metrics["cvssMetricV2"][0]["cvssData"]
        cvss_score = data.get("baseScore")
        cvss_version = "2.0"
        cvss_vector = data.get("vectorString")

    references = []
    for ref in cve_item.get("references", [])[:5]:
        references.append(ref.get("url", ""))

    published = cve_item.get("published", "Unknown")
    if published != "Unknown":
        try:
            dt = datetime.fromisoformat(published.replace("Z", "+00:00"))
            published = dt.strftime("%B %d, %Y")
        except:
            pass

    severity_label = "UNKNOWN"
    if cvss_score is not None:
        score = float(cvss_score)
        if score >= 9.0:
            severity_label = "CRITICAL"
        elif score >= 7.0:
            severity_label = "HIGH"
        elif score >= 4.0:
            severity_label = "MEDIUM"
        else:
            severity_label = "LOW"

    return {
        "id": cve_id,
        "description": description,
        "cvss_score": cvss_score,
        "cvss_version": cvss_version,
        "cvss_vector": cvss_vector,
        "severity_label": severity_label,
        "severity_color": get_severity_color(cvss_score),
        "references": references,
        "published": published,
    }


def query_nvd(keyword=None, cve_id=None, results_per_page=10):
    """Query the NVD API and return parsed results."""
    params = {"resultsPerPage": results_per_page}

    if cve_id:
        params["cveId"] = cve_id.upper().strip()
    elif keyword:
        params["keywordSearch"] = keyword.strip()
    else:
        return None, "Please provide a keyword or CVE ID."

    try:
        response = requests.get(NVD_BASE_URL, params=params, timeout=10)

        if response.status_code == 200:
            data = response.json()
            total = data.get("totalResults", 0)
            vulnerabilities = data.get("vulnerabilities", [])

            parsed = []
            for item in vulnerabilities:
                cve_data = item.get("cve", {})
                parsed.append(parse_cve_data(cve_data))

            return {"results": parsed, "total": total}, None

        elif response.status_code == 404:
            return {"results": [], "total": 0}, None
        else:
            return None, f"API returned status code {response.status_code}. Try again later."

    except requests.exceptions.Timeout:
        return None, "The request timed out. NVD API can be slow sometimes, please try again."
    except requests.exceptions.ConnectionError:
        return None, "Could not connect to NVD API. Check your internet connection."
    except Exception as e:
        return None, f"An unexpected error occurred: {str(e)}"

#Route for searches
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/search", methods=["GET", "POST"])
def search():
    results = None
    error = None
    query = ""
    search_type = "keyword"
    total = 0

    if request.method == "POST":
        query = request.form.get("query", "").strip()
        search_type = request.form.get("search_type", "keyword")

        if not query:
            error = "Please enter a search term."
        else:
            if search_type == "cve_id":
                data, error = query_nvd(cve_id=query)
            else:
                data, error = query_nvd(keyword=query)

            if data:
                results = data["results"]
                total = data["total"]

                #Save search history to session
                if "history" not in session:
                    session["history"] = []

                history_entry = {
                    "query": query,
                    "type": search_type,
                    "count": len(results),
                    "timestamp": datetime.now().strftime("%m/%d/%Y %H:%M"),
                }
                # avoid duplicate consecutive searches
                if not session["history"] or session["history"][-1]["query"] != query:
                    session["history"].insert(0, history_entry)
                    session["history"] = session["history"][:10]  # keep last 10
                    session.modified = True

    return render_template(
        "search.html",
        results=results,
        error=error,
        query=query,
        search_type=search_type,
        total=total,
    )
