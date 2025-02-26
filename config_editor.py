import json
import os
import hashlib

if __name__ == "__main__":
    config = None
    if os.path.exists("config.json"):
        with open("config.json", "r") as f:
            config = json.load(f)
            try:
                config["config"]
            except KeyError:
                config = None
    if config is None:
        print(f"Config.json not found or empty, creating...")
        config = {"config": []}
        print(f"Enter the conversation id you got: ")
        user_data = {"conversation_id": input()}
        print(f"Enter the cookies you got: ")
        user_data["cookies"] = input()
        config["config"].append(user_data)
    again = True
    while True:
        if again:
            num = len(config["config"])
            print(f"You have {num} cookies in your config.json file.")
        print("----------")
        print(f"1. Add")
        print(f"2. Check")
        print(f"3. Edit")
        print(f"4. Delete")
        print(f"5. Set password")
        print(f"6. Exit")
        choice = input()
        if choice == "1":
            print(f"Enter the conversation id you got: ")
            user_data = {"conversation_id": input()}
            print(f"Enter the cookies you got: ")
            user_data["cookies"] = input()
            config["config"].append(user_data)
            again = True
        elif choice == "2":
            print(f"Enter the index of the cookies you want to check: ")
            index = int(input())
            print(f"conversation id: {config['config'][index-1]['conversation_id']}")
            print(f"cookies: {config['config'][index-1]['cookies']}")
            again = False
        elif choice == "3":
            print(f"Enter the index of the cookies you want to edit: ")
            index = int(input())
            print(f"Enter the new conversation id: ")
            config["config"][index - 1]["conversation_id"] = input()
            print(f"Enter the new cookies: ")
            config["config"][index - 1]["cookies"] = input()
            again = False
        elif choice == "4":
            print(f"Enter the index of the cookies you want to delete: ")
            index = int(input())
            config["config"].pop(index - 1)
            again = True
        elif choice == "5":
            print(f"Enter the password, blank to remove: ")
            password = input()
            with open("password.txt", "w") as f:
                if password != "":
                    f.write(hashlib.sha256(password.encode()).hexdigest())
                    print(f"Password set.")
                else:
                    f.write("")
                    print(f"Password removed.")
        elif choice == "6":
            with open("config.json", "w") as f:
                json.dump(config, f, indent=4)
            break
        else:
            print(f"Invalid choice.")
            again = False
