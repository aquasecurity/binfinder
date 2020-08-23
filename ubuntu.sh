apt update -y > /dev/null 2>&1
apt install -y file > /dev/null 2>&1
find / -executable -type f -exec file {} \; | grep -i elf