int add(int a, int b)
{
    return a + b;
}

extern "C" int _start()
{
    return add(1, 2);
}