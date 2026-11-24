int fixture_linked(int input) {
    static volatile int bias = 9;
    return input + bias;
}
