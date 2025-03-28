import json
import os
import hashlib

if __name__ == "__main__":
    config = None
    path = os.path.dirname(os.path.realpath(__file__))
    os.chdir(path)
    if os.path.exists("config.json"):
        with open("config.json", "r") as f:
            config = json.load(f)
            try:
                config["config"]
            except KeyError:
                config = None
    if config is None:
        print(f"配置文件不存在或为空，创建新配置...") # La agordo-dosiero ne ekzistas aŭ estas malplena, kreante novan agordon...
        config = {"config": [], "delete_chat": True}
        print(f"输入cookies: ") # Enmetu cookies:
        user_data = {"cookies": input()}
        config["config"].append(user_data)
    
    # Certigu ke la kampo delete_chat ekzistas
    if "delete_chat" not in config:
        config["delete_chat"] = True
    
    again = True
    while True:
        if again:
            num = len(config["config"])
            print(f"\n当前有 {num} 个配置。") # Nun estas {num} agordoj.
            print(f"自动删除旧对话: {'开启' if config['delete_chat'] else '关闭'}") # Aŭtomata forigo de malnovaj konversacioj: {'aktiva' if config['delete_chat'] else 'malaktiva'}
            
        print("----------")
        print(f"1. 添加新配置") # Aldoni novan agordon
        print(f"2. 删除所有配置") # Forigi ĉiujn agordojn
        print(f"3. 设置密码") # Agordi pasvorton
        print(f"4. 切换自动删除旧对话") # Ŝanĝi aŭtomatan forigadon de malnovaj konversacioj
        print(f"5. 保存并退出") # Konservi kaj eliri
        choice = input()
        
        if choice == "1":
            print(f"输入cookies: ") # Enmetu cookies:
            user_data = {"cookies": input()}
            config["config"].append(user_data)
            print("\n成功添加配置！") # Sukcese aldonis agordon!
            again = True
        
        elif choice == "2":
            print("确定要删除所有配置吗? (y/n)") # Ĉu vi certas ke vi volas forigi ĉiujn agordojn? (y/n)
            if input().lower() == 'y':
                config["config"] = []
                print("已删除所有配置") # Ĉiuj agordoj estas forigitaj
            again = True
        
        elif choice == "3":
            print(f"输入新密码（留空则删除密码）: ") # Enmetu novan pasvorton (lasu malplena por forigi pasvorton):
            password = input()
            with open("password.txt", "w") as f:
                if password != "":
                    f.write(hashlib.sha256(password.encode()).hexdigest())
                    print(f"密码已设置") # Pasvorto estas agordita
                else:
                    f.write("")
                    print(f"密码已删除") # Pasvorto estas forigita
            again = False
        
        elif choice == "4":
            config["delete_chat"] = not config["delete_chat"]
            print(f"自动删除旧对话已{'开启' if config['delete_chat'] else '关闭'}") # Aŭtomata forigo de malnovaj konversacioj estas {'aktiva' if config['delete_chat'] else 'malaktiva'}
            again = True
        
        elif choice == "5":
            with open("config.json", "w") as f:
                json.dump(config, f, indent=4)
            print("配置已保存") # Agordoj estas konservitaj
            break
        
        else:
            print(f"无效的选择") # Nevalida elekto
            again = False
