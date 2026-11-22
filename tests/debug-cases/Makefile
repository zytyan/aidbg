CFLAGS ?= -std=c11 -Wall -Wextra -g3 -O0 -fno-omit-frame-pointer
CXXFLAGS ?= -std=c++17 -Wall -Wextra -g3 -O0 -fno-omit-frame-pointer
OUT ?= ../../target/debug-cases

C_CASES := D01 D02 D03 D04 D05 D06 D07 D08
CXX_CASES := D09 D10
ASAN_CASES := D13 D14 D15
ASAN_TARGETS := $(ASAN_CASES) asan-probe
ASAN39_CC ?=
ASAN_FLAGS := -fsanitize=address -fno-pie -no-pie

.PHONY: all asan asan39 memcheck
all: $(addprefix $(OUT)/,$(C_CASES) $(CXX_CASES))
asan: $(addprefix $(OUT)/,$(ASAN_TARGETS))
asan39: $(addprefix $(OUT)/asan39/,$(ASAN_TARGETS))

memcheck: $(addprefix $(OUT)/memcheck/,$(ASAN_CASES))

$(addprefix $(OUT)/,$(C_CASES)): $(OUT)/%: cases/%.c cases/fixture.h
	@mkdir -p "$(@D)"
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o "$@" "$<" -pthread

$(addprefix $(OUT)/,$(CXX_CASES)): $(OUT)/%: cases/%.cc cases/fixture.h
	@mkdir -p "$(@D)"
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) -o "$@" "$<"

$(addprefix $(OUT)/,$(ASAN_TARGETS)): $(OUT)/%: cases/%.c cases/fixture.h
	@mkdir -p "$(@D)"
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $(ASAN_FLAGS) -o "$@" "$<"

$(addprefix $(OUT)/memcheck/,$(ASAN_CASES)): $(OUT)/memcheck/%: cases/%.c cases/fixture.h
	@mkdir -p "$(@D)"
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o "$@" "$<"

$(addprefix $(OUT)/asan39/,$(ASAN_TARGETS)): $(OUT)/asan39/%: cases/%.c cases/fixture.h
	@test -n "$(ASAN39_CC)" || { echo 'Set ASAN39_CC to Clang using a 39-bit compiler-rt.' >&2; exit 2; }
	@mkdir -p "$(@D)"
	$(ASAN39_CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $(ASAN_FLAGS) -o "$@" "$<"
