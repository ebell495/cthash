cthash-fuzz: cthash-fuzz.cpp
	clang++ -g -std=c++20 -fsanitize=fuzzer,address,undefined,nullability -fno-sanitize-recover=undefined,nullability -o cthash-fuzz cthash-fuzz.cpp