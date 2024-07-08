import os
import requests
import json


default_configs = {
	"debug_dir": "patched/",
	"extract_dir":"./",
	"script_file": "solve.py",
	"pwn_process": "r",
	"tab": "\t",
	"template_file": "~/.config/spwn/template.py",
	"custom_template_prefix": "template_",
	"suppress_warnings": False,
	"yara_rules": "~/.config/spwn/findcrypt3.rules",
	"preanalysis_commands": [],
	"postanalysis_commands": [],
	"preanalysis_scripts": [],
	"postanalysis_scripts": [],
	"idafree_command": "",
	"decompiler_command": "~/binaryninja/binaryninja {binary}"
}

default_template = '''
#!/usr/bin/env python3

from pwn import *

{bindings}

context.binary = exe


def conn():
    if args.LOCAL:
        r = exe.process()
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r


def main():
    r = conn()
    
	{interactions}

    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
'''[1:-1]


class ConfigGenerator:
	def maybe_create_config(self):
		self.create_config_files()
		self.download_yara_rules()

	def create_config_files(self):
		config_dir = os.path.expanduser("~/.config")
		if not os.path.exists(config_dir):
			os.mkdir(config_dir)

		configs_dir = os.path.expanduser("~/.config/spwn")
		if not os.path.exists(configs_dir):
			os.mkdir(configs_dir)

		configs_file = os.path.expanduser("~/.config/spwn/config.json")
		template_file = os.path.expanduser("~/.config/spwn/template.py")

		if not os.path.exists(configs_file):
			with open(configs_file, "w") as f:
				json.dump(default_configs, f, indent='\t')
		else:
			with open(configs_file) as f:
				user_configs = json.load(f)
			new_configs = default_configs | user_configs
			with open(configs_file, "w") as f:
				json.dump(new_configs, f, indent='\t')

		if not os.path.exists(template_file):
			with open(template_file, "w") as f:
				f.write(default_template)

	def download_yara_rules(self):
		rules_path = os.path.expanduser("~/.config/spwn/findcrypt3.rules")
		if not os.path.exists(rules_path):
			r = requests.get("https://raw.githubusercontent.com/polymorf/findcrypt-yara/master/findcrypt3.rules")
			assert r.status_code == 200, "Cannot download yara rules"

			with open(rules_path, "w") as f:
				f.write(r.text)
