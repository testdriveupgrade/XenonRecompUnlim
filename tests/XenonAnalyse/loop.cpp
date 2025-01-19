int loop(int a)
{
    int result = 0;
    for (int i = 0; i < a; i++)
    {
        result = result * 31 + i;
        result *= result;
    }
    return result;
}

extern "C" int _start()
{
    return loop(30);
}
