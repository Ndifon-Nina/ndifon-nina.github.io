"""
Run this once to make an existing user an admin.

Usage:
    python make_admin.py your_email@example.com

The user must already have registered a normal account first.
"""
import sys
from app import app
import database

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python make_admin.py <email>")
        sys.exit(1)

    email = sys.argv[1].strip().lower()

    with app.app_context():
        user = database.get_user_by_email(email)
        if not user:
            print(f"No account found with email: {email}")
            print("Register that account in BlindSpot first, then run this script again.")
            sys.exit(1)

        database.promote_to_admin(email)
        print(f"{email} is now an admin. Log out and back in to see the Admin link.")
