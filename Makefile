.PHONY: gdbserver startgdb init pythonenv pytools init toolchain

# 安装toolchain
toolchain:
	curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | sudo gpg --dearmor -o /usr/share/keyrings/microsoft.gpg
	echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft.gpg] https://packages.microsoft.com/ubuntu/$(shell lsb_release -rs)/prod noble main" | sudo tee /etc/apt/sources.list.d/microsoft-prod.list
	sudo apt update
	sudo apt install -y gcc-arm-none-eabi dotnet-runtime-8.0 gdb-multiarch

# 设置python环境
pythonenv:
	pyenv virtualenv 3.12.4 embedded

# 安装开发工具
pytools:
	pip install -r requirements.txt

# 初始化开发环境
init: pythonenv pytools toolchain

gdbserver:
	pyocd gdbserver -t py32f003x6

startgdb:
	gdb-multiarch Projects/PY32F003-STK/Example/Chacha20/build/Project/Project.elf
