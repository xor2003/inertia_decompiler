int inc_one(int value)
{
    return value + 1;
}

int dec_one(int value)
{
    return value - 1;
}

int apply_twice(int (*fn)(int), int value)
{
    value = fn(value);
    value = fn(value);
    return value;
}

int select_and_apply(int which, int value)
{
    int (*fn)(int);

    if (which != 0) {
        fn = inc_one;
    } else {
        fn = dec_one;
    }
    return apply_twice(fn, value);
}

int combine_args(int first, int second, int third)
{
    return first + second * 3 + third * 7;
}

int nested_arguments(int value)
{
    return combine_args(inc_one(value), value + 2, value + 3);
}

int main(void)
{
    if (apply_twice(inc_one, 5) != 7) {
        return 1;
    }
    if (apply_twice(dec_one, 8) != 6) {
        return 2;
    }
    if (select_and_apply(1, 5) != 7) {
        return 3;
    }
    if (select_and_apply(0, 8) != 6) {
        return 4;
    }
    if (nested_arguments(2) != 50 || nested_arguments(-3) != -5 ||
        nested_arguments(0) != 28) {
        return 5;
    }
    return 255;
}
