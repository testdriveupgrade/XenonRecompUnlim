int cond(int a)
{
    if (a == 1)
    {
        return 5;
    }
    else if (a == 4)
    {
        return 9;
    }

    return 0;
}

extern "C" int _start()
{
    return cond(0);
}
