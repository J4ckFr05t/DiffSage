from flask import Flask, render_template, request, send_file, jsonify, redirect, url_for, send_file, jsonify, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from scm_utils import get_github_pr_data, get_gitlab_pr_data, get_bitbucket_pr_data, get_azure_devops_pr_data
import google.generativeai as genai
import os
import re
import io
import pandas as pd
import json
from urllib.parse import urlparse, unquote
from utils.encryption import encrypt_token, decrypt_token
import requests
from dotenv import load_dotenv

load_dotenv()


app = Flask(__name__)

CLOUDRUN_ANALYZE_URL = os.getenv("CLOUDRUN_ANALYZE_URL", "http://localhost:8080/analyze")  # local test fallback
CLOUDRUN_STATUS_URL = os.getenv("CLOUDRUN_STATUS_URL", "http://localhost:8080/status")

db_url = os.getenv("DATABASE_URL")
if not db_url:
    db_url = "sqlite:///users.db"
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url

secret_key = os.getenv("SECRET_KEY")
app.config['SECRET_KEY'] = secret_key if secret_key else "dev-secret-key"

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)

    # 🔐 Hashed passwords can exceed 150 chars (scrypt, bcrypt, etc.)
    password = db.Column(db.Text, nullable=False)

    is_admin = db.Column(db.Boolean, default=False)
    must_change_password = db.Column(db.Boolean, default=False)
    locked = db.Column(db.Boolean, default=False)

    # 🧪 Encrypted sensitive fields — stored as base64 or ciphertext, use Text
    _github_api_token = db.Column("github_api_token", db.Text)
    _google_api_token = db.Column("google_api_token", db.Text)
    _gitlab_api_token = db.Column("gitlab_api_token", db.Text)
    _bitbucket_username = db.Column("bitbucket_username", db.Text)
    _bitbucket_app_password = db.Column("bitbucket_app_password", db.Text)
    _azdevops_api_token = db.Column("azdevops_api_token", db.Text)

    @property
    def github_api_token(self):
        return decrypt_token(self._github_api_token) if self._github_api_token else None

    @github_api_token.setter
    def github_api_token(self, value):
        self._github_api_token = encrypt_token(value)

    @property
    def google_api_token(self):
        return decrypt_token(self._google_api_token) if self._google_api_token else None

    @google_api_token.setter
    def google_api_token(self, value):
        self._google_api_token = encrypt_token(value)

    @property
    def gitlab_api_token(self):
        return decrypt_token(self._gitlab_api_token) if self._gitlab_api_token else None

    @gitlab_api_token.setter
    def gitlab_api_token(self, value):
        self._gitlab_api_token = encrypt_token(value)

    @property
    def bitbucket_username(self):
        return decrypt_token(self._bitbucket_username) if self._bitbucket_username else None

    @bitbucket_username.setter
    def bitbucket_username(self, value):
        self._bitbucket_username = encrypt_token(value)

    @property
    def bitbucket_app_password(self):
        return decrypt_token(self._bitbucket_app_password) if self._bitbucket_app_password else None

    @bitbucket_app_password.setter
    def bitbucket_app_password(self, value):
        self._bitbucket_app_password = encrypt_token(value)

    @property
    def azdevops_api_token(self):
        return decrypt_token(self._azdevops_api_token) if self._azdevops_api_token else None

    @azdevops_api_token.setter
    def azdevops_api_token(self, value):
        self._azdevops_api_token = encrypt_token(value)

    def __repr__(self):
        return f"<User {self.email}>"
    
class Prompt(db.Model):
    __tablename__ = "prompts"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    prompt_name = db.Column(db.String(150), nullable=False)
    prompt_intro = db.Column(db.Text, nullable=False)
    app_function = db.Column(db.String(100), nullable=False)

    __table_args__ = (db.UniqueConstraint('user_id', 'prompt_name', name='unique_user_prompt'),)
    
def validate_google_token(token):
    try:
        genai.configure(api_key=token)
        model = genai.GenerativeModel("gemini-2.0-flash")
        _ = model.generate_content("Hello", generation_config=genai.types.GenerationConfig(
            temperature=0.1, max_output_tokens=10
        ))
        return True
    except Exception as e:
        print("[Token Validation Error]", e)
        return False
    
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Email already registered. Please log in.", "warning")
            return redirect(url_for("login"))

        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")
        new_user = User(email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        flash("Signup successful!", "success")
        return redirect(url_for("user_dashboard"))

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            if user.locked:
                flash("Your account has been locked. Contact admin.", "danger")
                return redirect(url_for("login"))
            
            login_user(user)

            if user.must_change_password:
                flash("Please change your password before continuing.", "warning")
                return redirect(url_for("force_password_change"))

            flash("Logged in successfully.", "success")
            return redirect(url_for("user_dashboard"))
        else:
            flash("Invalid email or password.", "danger")

    return render_template("login.html")

@app.route("/force_password_change", methods=["GET", "POST"])
@login_required
def force_password_change():
    if request.method == "POST":
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        if new_password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("force_password_change"))

        current_user.password = generate_password_hash(new_password)
        current_user.must_change_password = False  # ✅ mark password change complete
        db.session.commit()

        flash("Password updated successfully.", "success")
        return redirect(url_for("user_dashboard"))  # 👈 send user to dashboard

    return render_template("force_password_change.html")

@app.route("/admin/delete_user/<int:user_id>", methods=["POST"])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash("Unauthorized.", "danger")
        return redirect(url_for("user_dashboard"))

    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("You can't delete your own account here.", "warning")
        return redirect(url_for("user_dashboard"))

    Prompt.query.filter_by(user_id=user.id).delete()
    db.session.delete(user)
    db.session.commit()
    flash(f"User {user.email} deleted.", "success")
    return redirect(url_for("user_dashboard"))

@app.route("/admin/toggle_lock_user/<int:user_id>", methods=["POST"])
@login_required
def toggle_lock_user(user_id):
    if not current_user.is_admin:
        flash("Unauthorized.", "danger")
        return redirect(url_for("user_dashboard"))

    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("You can't lock yourself.", "warning")
        return redirect(url_for("user_dashboard"))

    user.locked = not user.locked
    db.session.commit()
    status = "locked" if user.locked else "unlocked"
    flash(f"User {user.email} has been {status}.", "info")
    return redirect(url_for("user_dashboard"))

@app.route("/dashboard")
@login_required
def user_dashboard():
    prompts = Prompt.query.filter_by(user_id=current_user.id).all()
    users = []
    if current_user.is_admin:
        users = User.query.all()
    return render_template("user.html", user_email=current_user.email, users=users, is_admin=current_user.is_admin, prompts=prompts)

@app.route("/update_password", methods=["POST"])
@login_required
def update_password():
    current = request.form.get("current_password")
    new = request.form.get("new_password")
    confirm = request.form.get("confirm_password")

    if not check_password_hash(current_user.password, current):
        flash("Current password is incorrect.", "error")
        return redirect(url_for("user_dashboard"))

    if new != confirm:
        flash("New passwords do not match.", "error")
        return redirect(url_for("user_dashboard"))

    current_user.password = generate_password_hash(new)
    db.session.commit()
    flash("Password updated successfully!", "success")
    return redirect(url_for("user_dashboard"))

@app.route("/update_github_token", methods=["POST"])
@login_required
def update_token():
    token = request.form.get("github_api_token")

    if not token or len(token) < 10:
        flash("Invalid GitHub token.", "error")
        return redirect(url_for("user_dashboard"))

    current_user.github_api_token = token
    db.session.commit()
    flash("GitHub token updated successfully!", "success")
    return redirect(url_for("user_dashboard"))

@app.route("/update_google_token", methods=["POST"])
@login_required
def update_google_token():
    token = request.form.get("google_api_token")

    if not token or len(token) < 10:
        flash("Invalid Google token.", "error")
        return redirect(url_for("user_dashboard"))

    current_user.google_api_token = token
    db.session.commit()
    flash("Google token updated successfully!", "success")
    return redirect(url_for("user_dashboard"))

@app.route("/update_gitlab_token", methods=["POST"])
@login_required
def update_gitlab_token():
    token = request.form.get("gitlab_api_token")

    if not token or len(token) < 10:
        flash("Invalid GitLab token.", "error")
        return redirect(url_for("user_dashboard"))

    current_user.gitlab_api_token = token
    db.session.commit()
    flash("GitLab token updated successfully!", "success")
    return redirect(url_for("user_dashboard"))

@app.route("/update_bitbucket_credentials", methods=["POST"])
@login_required
def update_bitbucket_credentials():
    username = request.form.get("bitbucket_username")
    app_password = request.form.get("bitbucket_app_password")

    if not username or not app_password:
        flash("Both Bitbucket username and app password are required.", "error")
        return redirect(url_for("user_dashboard"))

    current_user.bitbucket_username = username
    current_user.bitbucket_app_password = app_password
    db.session.commit()
    flash("Bitbucket credentials updated successfully!", "success")
    return redirect(url_for("user_dashboard"))

@app.route("/update_azdevops_token", methods=["POST"])
@login_required
def update_azdevops_token():
    token = request.form.get("azdevops_api_token")

    if not token or len(token) < 10:
        flash("Invalid Azure DevOps token.", "error")
        return redirect(url_for("user_dashboard"))

    current_user.azdevops_api_token = token
    db.session.commit()
    flash("Azure DevOps token updated successfully!", "success")
    return redirect(url_for("user_dashboard"))


@app.route("/summarize", methods=["POST"])
@login_required
def summarize():
    data = request.get_json()

    selected_prompt = data.get("selected_prompt", "default")
    selected_platform = data.get("selected_platform", "github")

    if selected_prompt == "default":
        prompt_intro = "Summarize this pull request in a concise, general overview."
    else:
        prompt_obj = Prompt.query.filter_by(user_id=current_user.id, prompt_name=selected_prompt).first()
        if not prompt_obj:
            return jsonify({"error": "Selected prompt not found."}), 400
        prompt_intro = prompt_obj.prompt_intro

    pr_url = data.get("pr_url")
    if not pr_url:
        return jsonify({"error": "Missing PR URL"}), 400

    if not current_user.google_api_token:
        return jsonify({
            "error": "Google API tokens are required. Please set them up in your Account Info."
        }), 400

    if not validate_google_token(current_user.google_api_token):
        return jsonify({"error": "Invalid Google token. Please make sure your token is correct and try again."}), 400

    try:
        print("Parsing PR URL...")

        if selected_platform == "github":
            user_token = current_user.github_api_token
            parsed = parse_github_url(pr_url)
            pr_data = get_github_pr_data(parsed, user_token)
        elif selected_platform == "gitlab":
            user_token = current_user.gitlab_api_token
            parsed = parse_gitlab_url(pr_url)
            pr_data = get_gitlab_pr_data(parsed, user_token)
        elif selected_platform == "bitbucket":
            user_token = current_user.bitbucket_app_password
            bb_username = current_user.bitbucket_username
            parsed = parse_bitbucket_url(pr_url)
            pr_data = get_bitbucket_pr_data(parsed, bb_username, user_token)
        elif selected_platform == "azdevops":
            user_token = current_user.azdevops_api_token
            parsed = parse_azure_devops_url(pr_url)
            pr_data = get_azure_devops_pr_data(parsed, user_token)
        else:
            return jsonify({"error": "Unsupported platform selected."}), 400

        if "error" in pr_data:
            return jsonify({"error": pr_data["error"]}), 400

        print("Fetched PR data.")

        # ✅ Call Cloud Run async task
        payload = {
            "pr_data": pr_data,
            "url": pr_url,
            "google_token": current_user.google_api_token,
            "prompt_intro": prompt_intro
        }

        response = requests.post(CLOUDRUN_ANALYZE_URL, json=payload)

        if response.status_code == 200:
            return jsonify(response.json())  # includes task_id
        else:
            return jsonify({"error": "Cloud Run task submission failed.", "details": response.text}), 500

    except Exception as e:
        print("Error during summarization:", e)
        return jsonify({"error": str(e)}), 500

@app.route("/configure_prompt", methods=["POST"])
@login_required
def configure_prompt():
    app_function = request.form.get("app_function")
    prompt_name = request.form.get("prompt_name")
    prompt_intro = request.form.get("prompt_intro")

    if not all([app_function, prompt_name, prompt_intro]):
        flash("All prompt fields are required.", "error")
        return redirect(url_for("user_dashboard"))

    # Check if prompt with same name already exists for this user
    existing = Prompt.query.filter_by(user_id=current_user.id, prompt_name=prompt_name).first()
    if existing:
        flash("You already have a prompt with that name. Please use a different name.", "error")
        return redirect(url_for("user_dashboard"))

    new_prompt = Prompt(
        user_id=current_user.id,
        app_function=app_function,
        prompt_name=prompt_name,
        prompt_intro=prompt_intro
    )
    db.session.add(new_prompt)
    db.session.commit()
    flash("Prompt saved successfully!", "success")
    return redirect(url_for("user_dashboard"))

@app.route("/delete_prompt", methods=["POST"])
@login_required
def delete_prompt():
    prompt_name = request.form.get("prompt_name")

    # Find the prompt by name (assuming prompt_name is unique)
    prompt_to_delete = Prompt.query.filter_by(user_id=current_user.id, prompt_name=prompt_name).first()

    if prompt_to_delete:
        db.session.delete(prompt_to_delete)
        db.session.commit()
        flash(f"Prompt '{prompt_name}' deleted successfully.", "success")
    else:
        flash("Prompt not found or already deleted.", "danger")
    
    return redirect(url_for("user_dashboard"))

@app.route("/delete_account", methods=["POST"])
@login_required
def delete_account():
    try:
        # Delete all prompts belonging to the user
        Prompt.query.filter_by(user_id=current_user.id).delete()

        # Then delete the user
        user_email = current_user.email  # Save for feedback
        db.session.delete(current_user)
        db.session.commit()
        logout_user()

        flash(f"Account {user_email} has been deleted.", "success")
        return redirect(url_for("signup"))
    except Exception as e:
        print("[Account Deletion Error]", e)
        flash("An error occurred while deleting your account.", "danger")
        return redirect(url_for("user_dashboard"))


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.", "success")
    return redirect(url_for("login"))


@app.route("/result/<task_id>")
def show_result(task_id):
    task = AsyncResult(task_id, app=celery)
    if task.state == "SUCCESS":
        return render_template("index.html", summary=task.result)
    elif task.state in ["PENDING", "STARTED", "PROGRESS"]:
        return render_template("index.html", task_id=task.id)
    else:
        return render_template("index.html", error="Task failed or was canceled.")

@app.route("/")
def root_redirect():
    if current_user.is_authenticated:
        return redirect(url_for("user_dashboard"))
    else:
        return redirect(url_for("login"))

@app.route("/task_status/<task_id>")
def task_status(task_id):
    try:
        response = requests.get(f"{CLOUDRUN_STATUS_URL}/{task_id}")
        return jsonify(response.json())
    except Exception as e:
        return jsonify({"state": "FAILURE", "error": str(e)}), 500

@app.route("/download_excel", methods=["POST"])
def download_excel():
    try:
        pr_url = request.form.get("pr_url", "")
        count = int(request.form.get("commit_count"))
        rows = []

        match = re.search(r"github\.com/([^/]+/[^/]+)/pull/(\d+)", pr_url)
        if match:
            repo = match.group(1).replace("/", "_")
            pr_number = match.group(2)
        else:
            repo = "unknown_repo"
            pr_number = "unknown_pr"

        seen_files = set()

        for i in range(count):
            reason = request.form.get(f"reason_{i}")
            file_count = int(request.form.get(f"file_count_{i}"))

            for j in range(file_count):
                file_name = request.form.get(f"file_{i}_{j}")
                key = (file_name, reason)

                if key not in seen_files:
                    seen_files.add(key)
                    rows.append({
                        "File Name": file_name,
                        "Reason to Change": reason
                    })


        df = pd.DataFrame(rows)

        output = io.BytesIO()
        with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
            df.to_excel(writer, index=False, sheet_name="Summary")

        output.seek(0)
        filename = f"diffsage_{repo}_pr{pr_number}.xlsx"
        return send_file(
            output,
            as_attachment=True,
            download_name=filename,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )

    except Exception as e:
        return f"Error creating Excel file: {str(e)}", 500

def parse_github_url(url):
    """
    Parses a GitHub Pull Request or Compare URL and returns a dict with type info.
    """
    url = url.strip()
    pr_pattern = r"https://github\.com/([^/]+)/([^/]+)/pull/(\d+)"
    compare_pattern = r"https://github\.com/([^/]+)/([^/]+)/compare/(.+)\.\.\.(.+)"

    pr_match = re.match(pr_pattern, url)
    if pr_match:
        return {
            "type": "pr",
            "repo": f"{pr_match.group(1)}/{pr_match.group(2)}",
            "pr_number": int(pr_match.group(3))
        }

    compare_match = re.match(compare_pattern, url)
    if compare_match:
        return {
            "type": "compare",
            "repo": f"{compare_match.group(1)}/{compare_match.group(2)}",
            "base": compare_match.group(3),
            "head": compare_match.group(4)
        }

    raise ValueError("Unsupported or invalid GitHub URL.")

def parse_gitlab_url(url):
    """
    Parses a GitLab Merge Request (MR) URL and returns a dict with type info.
    """
    url = url.strip()
    mr_pattern = r"https://gitlab\.com/([^/]+(?:/[^/]+)*)/-/merge_requests/(\d+)"

    mr_match = re.match(mr_pattern, url)
    print(mr_match)
    if mr_match:
        return {
            "url": url,
            "type": "mr",  # Merge Request in GitLab
            "repo": mr_match.group(1),
            "mr_id": int(mr_match.group(2))
        }

    raise ValueError("Unsupported or invalid GitLab Merge Request URL.")

def parse_bitbucket_url(url):
    """
    Parses a Bitbucket Pull Request URL and returns a dict with type info.
    """
    url = url.strip()
    pr_pattern = r"https://bitbucket\.org/([^/]+)/([^/]+)/pull-requests/(\d+)"

    pr_match = re.match(pr_pattern, url)
    print(url,pr_match)
    if pr_match:
        return {
            "url": url,
            "type": "pr",  # Pull Request in Bitbucket
            "workspace": pr_match.group(1),
            "repo": pr_match.group(2),
            "pr_id": int(pr_match.group(3))
        }

    raise ValueError("Unsupported or invalid Bitbucket Pull Request URL.")

def parse_azure_devops_url(url):
    """
    Parses an Azure DevOps Pull Request URL and returns a dict with type info.
    Supports format:
    https://dev.azure.com/{organization}/{project}/_git/{repo}/pullrequest/{pr_id}
    or
    https://dev.azure.com/{organization}/{project}/_apis/git/repositories/{repo}/pullRequests/{pr_id}
    """
    url = url.strip()
    parsed = urlparse(url)
    path = unquote(parsed.path)  # Decode any URL-encoded characters
    path_parts = path.strip("/").split("/")

    if "pullrequest" in path_parts:
        try:
            org = path_parts[0]
            project = path_parts[1]
            if "_apis" in path_parts:
                repo = path_parts[5]
                pr_id = path_parts[7]
            else:
                repo = path_parts[3]
                pr_id = path_parts[5]

            return {
                "url": url,
                "type": "pr",
                "organization": org,
                "project": project,
                "repo": repo,
                "pr_id": int(pr_id)
            }
        except (IndexError, ValueError):
            raise ValueError("Malformed Azure DevOps PR URL structure.")

    raise ValueError("Unsupported or invalid Azure DevOps PR URL.")

if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Automatically create tables if they don't exist

        admin_email = "admin"
        existing_admin = User.query.filter_by(email=admin_email).first()
        if not existing_admin:
            admin_user = User(
                email=admin_email,
                password=generate_password_hash("admin"),
                is_admin=True,
                must_change_password=True
            )
            db.session.add(admin_user)
            db.session.commit()
            print(f"[INIT] Admin account created: {admin_email} / admin")

    app.run(host="0.0.0.0", port=3000, debug=True)
