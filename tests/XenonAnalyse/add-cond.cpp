int add(int a, int b)
{
    int c = a + b;
    return c == 0 ? 50000 : c;
}

extern "C" int _start()
{
    return add(1, 2);
}