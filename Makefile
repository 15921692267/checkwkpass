all:
	mpicc -Wall -Wno-format-truncation -g -o checkwkpass checkwkpass.c -lcrypt -lssl -lcrypto

indent: checkwkpass.c
	indent checkwkpass.c  -nbad -bap -nbc -bbo -hnl -br -brs -c33 -cd33 -ncdb -ce -ci4 \
	-cli0 -d0 -di1 -nfc1 -i8 -ip0 -l160 -lp -npcs -nprs -npsl -sai \
	-saf -saw -ncs -nsc -sob -nfca -cp33 -ss -ts8 -il1

