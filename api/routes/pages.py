from flask import Blueprint, render_template


pages_bp = Blueprint(
    "pages",
    __name__
)


@pages_bp.get("/")
def home():
    return render_template("login.html")


@pages_bp.get("/login")
def login_page():
    return render_template("login.html")


@pages_bp.get("/register")
def register_page():
    return render_template("register.html")


@pages_bp.get("/dashboard")
def dashboard_page():
    return render_template("dashboard.html")