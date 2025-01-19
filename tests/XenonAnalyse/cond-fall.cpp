int cond(int a)
{
    int v = 2;
    if (a == 1)
    {
        v += 5;
    }

    return v;
}

extern "C" int _start()
{
    return cond(0);
}
