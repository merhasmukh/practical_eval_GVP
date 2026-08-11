from unittest.mock import patch, MagicMock
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from core.database import Base
from core.config import Settings
from models.schema import Department, Role, Student, User
from services.auth_service import ensure_role, hash_password
from services.oauth_service import (
    authenticate_google_user,
    exchange_code_for_user_info,
    get_google_auth_url,
    is_google_auth_configured,
)


def setup_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def test_is_google_auth_configured():
    custom_settings = Settings(google_client_id="client-123", google_client_secret="secret-456")
    with patch("services.oauth_service.settings", custom_settings):
        assert is_google_auth_configured() is True

    empty_settings = Settings(google_client_id="")
    with patch("services.oauth_service.settings", empty_settings):
        assert is_google_auth_configured() is False


def test_get_google_auth_url():
    custom_settings = Settings(
        google_client_id="my-client-id",
        google_redirect_uri="http://localhost:8501",
        google_hosted_domain="gujaratvidyapith.org",
    )
    with patch("services.oauth_service.settings", custom_settings):
        url = get_google_auth_url(state="xyz123")
        assert "accounts.google.com" in url
        assert "client_id=my-client-id" in url
        assert "redirect_uri=http%3A%2F%2Flocalhost%3A8501" in url
        assert "hd=gujaratvidyapith.org" in url
        assert "state=xyz123" in url


def test_authenticate_google_user_success():
    db = setup_db()
    faculty_role = ensure_role(db, "Faculty")
    user = User(
        username="drpatel",
        full_name="Dr. Asha Patel",
        email="asha@gujaratvidyapith.org",
        password_hash=hash_password("Dummy@123"),
        role_id=faculty_role.id,
        is_active=True,
    )
    db.add(user)
    db.commit()

    google_info = {
        "email": "asha@gujaratvidyapith.org",
        "name": "Dr. Asha Patel",
        "email_verified": True,
    }
    authenticated_user, err = authenticate_google_user(db, google_info)
    assert err is None
    assert authenticated_user is not None
    assert authenticated_user.email == "asha@gujaratvidyapith.org"
    assert authenticated_user.last_login is not None


def test_authenticate_google_user_first_time_student_setup():
    db = setup_db()
    google_info = {
        "email": "250160450310.gvp@gujaratvidyapith.org",
        "name": "New Student",
    }
    authenticated_user, err = authenticate_google_user(db, google_info)
    assert authenticated_user is None
    assert err == "FIRST_TIME_STUDENT_SETUP"


def test_register_google_student_creates_account_and_profile():
    from models.schema import Department, Program
    from services.oauth_service import register_google_student
    db = setup_db()
    dept = Department(name="Computer Science", code="CS")
    db.add(dept)
    db.flush()
    prog = Program(name="Master of Computer Applications", code="MCA", total_semesters=4, department_id=dept.id)
    db.add(prog)
    db.commit()

    google_info = {
        "email": "250160450310.gvp@gujaratvidyapith.org",
        "name": "Rohan Sharma",
    }
    user, err = register_google_student(db, google_info, program_id=prog.id, semester=2, full_name="Rohan Sharma")
    assert err is None
    assert user is not None
    assert user.username == "250160450310"
    assert user.email == "250160450310.gvp@gujaratvidyapith.org"
    assert user.student is not None
    assert user.student.enrollment_no == "250160450310"
    assert user.student.program == "MCA"
    assert user.student.semester == 2

    # Verify subsequent login succeeds directly without onboarding
    authenticated_user, auth_err = authenticate_google_user(db, google_info)
    assert auth_err is None
    assert authenticated_user is not None
    assert authenticated_user.id == user.id


def test_register_google_student_9_digits():
    from models.schema import Department, Program
    from services.oauth_service import register_google_student
    db = setup_db()
    dept = Department(name="Computer Science", code="CS")
    db.add(dept)
    db.flush()
    prog = Program(name="Post Graduate Diploma", code="PGDCA", total_semesters=2, department_id=dept.id)
    db.add(prog)
    db.commit()

    google_info = {
        "email": "210160450.gvp@gujaratvidyapith.org",
        "name": "Nine Digit Student",
    }
    user, err = register_google_student(db, google_info, program_id=prog.id, semester=1, full_name="Nine Digit Student")
    assert err is None
    assert user is not None
    assert user.username == "210160450"
    assert user.email == "210160450.gvp@gujaratvidyapith.org"
    assert user.student is not None
    assert user.student.enrollment_no == "210160450"
    assert user.student.program == "PGDCA"
    assert user.student.semester == 1


def test_authenticate_google_user_unregistered_faculty_fails():
    db = setup_db()
    google_info = {
        "email": "newfaculty@gujaratvidyapith.org",
        "name": "Unregistered Faculty",
    }
    authenticated_user, err = authenticate_google_user(db, google_info)
    assert authenticated_user is None
    assert "not registered" in err.lower()


def test_authenticate_google_user_preregistered_student_success():
    db = setup_db()
    student_role = ensure_role(db, "Student")
    user = User(
        username="250160450310",
        full_name="Valid Student",
        email="250160450310.gvp@gujaratvidyapith.org",
        password_hash=hash_password("Dummy@123"),
        role_id=student_role.id,
        is_active=True,
    )
    db.add(user)
    db.flush()
    student = Student(user_id=user.id, enrollment_no="250160450310", semester=1, program="MCA")
    db.add(student)
    db.commit()

    google_info = {
        "email": "250160450310.gvp@gujaratvidyapith.org",
        "name": "Valid Student",
    }
    authenticated_user, err = authenticate_google_user(db, google_info)
    assert err is None
    assert authenticated_user is not None
    assert authenticated_user.username == "250160450310"
    assert authenticated_user.email == "250160450310.gvp@gujaratvidyapith.org"


def test_authenticate_google_user_domain_restriction():
    db = setup_db()
    custom_settings = Settings(google_hosted_domain="gujaratvidyapith.org")
    with patch("services.oauth_service.settings", custom_settings):
        google_info = {
            "email": "student@gmail.com",
            "name": "Outside User",
        }
        authenticated_user, err = authenticate_google_user(db, google_info)
        assert authenticated_user is None
        assert "gujaratvidyapith.org" in err


def test_authenticate_google_user_locked_account():
    db = setup_db()
    student_role = ensure_role(db, "Student")
    user = User(
        username="student1",
        full_name="Student One",
        email="s1@gujaratvidyapith.org",
        password_hash=hash_password("Dummy@123"),
        role_id=student_role.id,
        is_active=True,
        account_locked=True,
    )
    db.add(user)
    db.commit()

    google_info = {"email": "s1@gujaratvidyapith.org"}
    authenticated_user, err = authenticate_google_user(db, google_info)
    assert authenticated_user is None
    assert "locked" in err.lower()


def test_exchange_code_for_user_info_mock():
    custom_settings = Settings(google_client_id="cid", google_client_secret="csec")
    with patch("services.oauth_service.settings", custom_settings), \
         patch("requests.post") as mock_post, \
         patch("requests.get") as mock_get:

        mock_token_resp = MagicMock()
        mock_token_resp.status_code = 200
        mock_token_resp.json.return_value = {"access_token": "mock-token-xyz"}
        mock_post.return_value = mock_token_resp

        mock_userinfo_resp = MagicMock()
        mock_userinfo_resp.status_code = 200
        mock_userinfo_resp.json.return_value = {
            "email": "test@gujaratvidyapith.org",
            "name": "Test User",
        }
        mock_get.return_value = mock_userinfo_resp

        info, err = exchange_code_for_user_info("mock-auth-code")
        assert err is None
        assert info is not None
        assert info["email"] == "test@gujaratvidyapith.org"
        assert info["name"] == "Test User"
