from diff_parser import parse_diff_by_commit  # existing function
import time

def analyze_pr_task(self, pr_commits_and_metadata):
    try:
        pr_data = pr_commits_and_metadata["pr_data"]
        commits = pr_data["commits"]
        google_token = pr_commits_and_metadata.get("google_token")
        prompt_intro = pr_commits_and_metadata.get("prompt_intro")
        #print("[DEBUG] Google token in Celery task:", google_token)

        # Analyze diffs (with progress tracking)
        grouped_data = parse_diff_by_commit(commits, self, google_token=google_token, prompt_intro=prompt_intro)

        # Full summary (matches original code)
        summary = {
            "metadata": {
                "title": pr_data["title"],
                "author": pr_data["author"],
                "state": pr_data["state"],
                "url": pr_commits_and_metadata.get("url", "-")
            },
            "commits": format_for_frontend(grouped_data)
        }

        return summary

    except Exception as e:
        self.update_state(state="FAILURE", meta={"exc": str(e)})
        raise e
    
def format_for_frontend(grouped_data):
    formatted_commits = []

    for file in grouped_data:
        file_path = file["file_path"]
        summary = file.get("summary", "No summary provided.")
        commits = file.get("commits", [])

        formatted_commits.append({
            "summary": summary,
            "files_changed": [
                {
                    "file_path": file_path,
                    "change_type": commit.get("change_type"),
                    "added_lines": commit.get("added_lines", []),
                    "removed_lines": commit.get("removed_lines", [])
                }
                for commit in commits
            ]
        })

    return formatted_commits
