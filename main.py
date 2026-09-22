from aws.inventory import (
    inventory_dashboard
)

from aws.permissions import (
    get_user_permissions
)

from aws.simulator import (
    simulate_permission
)

from aws.search import (
    search_permission
)

from aws.compare import (
    compare_users,
    user_exists
)

from aws.report import (
    generate_report
)


# =====================================================
# MAIN MENU
# =====================================================

def show_main_menu():

    print("\n" + "=" * 65)
    print("          IAM ACCESS AUDITOR & PERMISSION ANALYZER")
    print("=" * 65)
    print("1. IAM Inventory")
    print("2. Permission Analysis")
    print("3. Compare Users")
    print("4. Generate Audit Report")
    print("5. Exit")
    print("=" * 65)


# =====================================================
# PERMISSION MENU
# =====================================================

def show_permission_menu():

    print("\n" + "=" * 65)
    print("                PERMISSION ANALYSIS")
    print("=" * 65)
    print("1. View User Permissions")
    print("2. Check User Permission")
    print("3. Search Users by Permission")
    print("4. Back")
    print("=" * 65)


# =====================================================
# PERMISSION ANALYSIS
# =====================================================

def permission_analysis():

    while True:

        show_permission_menu()

        choice = input("\nChoose an option (1-4): ").strip()

        # --------------------------------------------
        # VIEW USER PERMISSIONS
        # --------------------------------------------

        if choice == "1":

            while True:

                username = input("\nEnter username: ").strip()

                if not username:

                    print("[ERROR] Username cannot be empty.")
                    continue

                if get_user_permissions(username):
                    break

                print(f"[ERROR] User '{username}' does not exist.")

        # --------------------------------------------
        # CHECK USER PERMISSION
        # --------------------------------------------

        elif choice == "2":

            while True:

                username = input("\nEnter username: ").strip()

                if not username:

                    print("[ERROR] Username cannot be empty.")
                    continue

                if not user_exists(username):

                    print(f"[ERROR] User '{username}' does not exist.")
                    continue

                break

            while True:

                permission = input(
                    "\nEnter permission (Example: s3:GetObject): "
                ).strip()

                if not permission:

                    print("[ERROR] Permission cannot be empty.")
                    continue

                if simulate_permission(username, permission):
                    break

        # --------------------------------------------
        # SEARCH USERS BY PERMISSION
        # --------------------------------------------

        elif choice == "3":

            while True:

                permission = input(
                    "\nEnter permission (Example: s3:GetObject): "
                ).strip()

                if not permission:

                    print("[ERROR] Permission cannot be empty.")
                    continue

                if search_permission(permission):
                    break

        # --------------------------------------------
        # BACK
        # --------------------------------------------

        elif choice == "4":

            return

        else:

            print("[ERROR] Invalid option. Please choose between 1 and 4.")


# =====================================================
# MAIN PROGRAM
# =====================================================

def main():

    while True:

        show_main_menu()

        choice = input("\nSelect an option (1-5): ").strip()

        # --------------------------------------------
        # IAM INVENTORY
        # --------------------------------------------

        if choice == "1":

            inventory_dashboard()

        # --------------------------------------------
        # PERMISSION ANALYSIS
        # --------------------------------------------

        elif choice == "2":

            permission_analysis()

        # --------------------------------------------
        # COMPARE USERS
        # --------------------------------------------

        elif choice == "3":

            while True:

                user1 = input("\nEnter first username: ").strip()

                if not user1:

                    print("[ERROR] Username cannot be empty.")
                    continue

                if not user_exists(user1):

                    print(f"[ERROR] User '{user1}' does not exist.")
                    continue

                break

            while True:

                user2 = input("Enter second username: ").strip()

                if not user2:

                    print("[ERROR] Username cannot be empty.")
                    continue

                if not user_exists(user2):

                    print(f"[ERROR] User '{user2}' does not exist.")
                    continue

                if user1 == user2:

                    print("[ERROR] Please choose two different users.")
                    continue

                break

            compare_users(user1, user2)

        # --------------------------------------------
        # GENERATE AUDIT REPORT
        # --------------------------------------------

        elif choice == "4":

            generate_report()

        # --------------------------------------------
        # EXIT
        # --------------------------------------------

        elif choice == "5":

            print("\nThank you for using IAM Access Auditor.")
            print("Goodbye!")
            break

        else:

            print("[ERROR] Invalid option. Please select between 1 and 5.")


# =====================================================
# ENTRY POINT
# =====================================================

if __name__ == "__main__":

    try:

        main()

    except KeyboardInterrupt:

        print("\n\nProgram terminated by user.")

    except Exception as e:

        print(f"\nUnexpected Error : {e}")
