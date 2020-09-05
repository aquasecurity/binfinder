apk add file > /dev/null 2>&1
apk --no-cache add findutils > /dev/null 2>&1
find / -executable -type f -exec file {} \; | grep -i elf